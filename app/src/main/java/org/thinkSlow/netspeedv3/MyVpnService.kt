package org.thinkSlow.netspeedv3

import android.R
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import kotlin.experimental.xor
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/* ============================================================
 *  PROTOCOL CONSTANTS (MUST MATCH C++)
 * ============================================================ */

private const val PKT_HELLO: Byte = 1
private const val PKT_WELCOME: Byte = 2
private const val PKT_CLIENT_ACK: Byte = 3
private const val PKT_DATA: Byte = 4

private const val HEADER_SIZE = 5
private const val SERVER_PORT = 5555
private const val DEFAULT_MTU = 1320


private const val IPPROTO_TCP = 6
private const val TCP_FLAG_SYN = 0x02
private const val TCP_OPTION_MSS = 2
private const val TCP_OPTION_END = 0
private const val TCP_OPTION_NOP = 1

private const val CLAMP_MSS = 1160

/* ============================================================
 *  PACKET HEADER (5 BYTES, PACKED)
 * ============================================================ */
data class PacketHeader(
    val type: Byte,
    val sessionId: Int
) {
    fun toByteArray(): ByteArray =
        byteArrayOf(
            type,
            (sessionId shr 24).toByte(),
            (sessionId shr 16).toByte(),
            (sessionId shr 8).toByte(),
            sessionId.toByte()
        )

    companion object {
        fun fromByteArray(buf: ByteArray): PacketHeader {
            // Use .toLong() and mask with 0xFFFFFFFFL to treat as unsigned
            val sid = (
                    ((buf[1].toInt() and 0xFF) shl 24) or
                            ((buf[2].toInt() and 0xFF) shl 16) or
                            ((buf[3].toInt() and 0xFF) shl 8) or
                            (buf[4].toInt() and 0xFF)
                    )
            return PacketHeader(buf[0], sid)
        }
    }
}
private const val P: Long = 127
private const val G: Long = 9

private fun modExp(base: Long, exp: Long, mod: Long): Long {
    var result = 1L
    var b = base % mod
    var e = exp
    while (e > 0) {
        if ((e and 1L) == 1L) result = (result * b) % mod
        b = (b * b) % mod
        e = e shr 1
    }
    return result
}
private fun checksum(buf: ByteArray, off: Int, len: Int): Int {
    var sum = 0
    var i = off

    while (i + 1 < off + len) {
        sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
        i += 2
    }

    if (i < off + len) {
        sum += (buf[i].toInt() and 0xFF) shl 8
    }

    while (sum shr 16 != 0) {
        sum = (sum and 0xFFFF) + (sum shr 16)
    }

    return sum.inv() and 0xFFFF
}

/**
 * Updates a 16-bit ones' complement checksum incrementally.
 * Follows RFC 1624 logic: HC' = ~(~HC + ~m + m')
 */
private fun updateChecksumIncremental(oldChecksum: Int, oldVal: Int, newVal: Int): Int {
    // 1. Get the sum of the components (~HC + ~m + m')
    // We use long to handle potential carries beyond 16 bits
    var sum = (oldChecksum.inv() and 0xFFFF).toLong() +
            (oldVal.inv() and 0xFFFF).toLong() +
            (newVal and 0xFFFF).toLong()

    // 2. Fold 32-bit sum into 16 bits (handle carries)
    while (sum shr 16 != 0L) {
        sum = (sum and 0xFFFFL) + (sum shr 16)
    }

    // 3. Return the bitwise complement
    return sum.inv().toInt() and 0xFFFF
}

/**
 * Clamps the TCP MSS value incrementally to avoid packet fragmentation.
 * Uses the dynamic currentClampMss value which can be updated by PMTUD.
 * * @param pkt The byte array containing the packet.
 * @param len The length of the IP packet.
 * @param pktOffset The offset where the IP header starts in the array.
 * @param mssLimit The current dynamic MSS limit (pass currentClampMss here).
 */
private fun clampTcpMssIncremental(pkt: ByteArray, len: Int, pktOffset: Int, mssLimit: Int) {
    // Minimum 40 bytes required for IPv4 (20) + TCP (20)
    if (len < 40) return

    // Parse IP Header Length (IHL) to find TCP start
    val ihl = (pkt[pktOffset].toInt() and 0x0F) * 4

    // Ensure the protocol is TCP (6)
    val proto = pkt[pktOffset + 9].toInt() and 0xFF
    if (proto != IPPROTO_TCP) return

    val tcpStart = pktOffset + ihl

    // MSS Clamping is only relevant for SYN packets (initial handshake)
    val tcpFlags = pkt[tcpStart + 13].toInt() and 0xFF
    if (tcpFlags and TCP_FLAG_SYN == 0) return

    // Parse TCP Header Length
    val tcpHdrLen = ((pkt[tcpStart + 12].toInt() shr 4) and 0xF) * 4

    // Iterate through TCP options to find the MSS option (Kind 2)
    var opt = tcpStart + 20
    val optEnd = tcpStart + tcpHdrLen

    while (opt + 3 < optEnd) {
        val kind = pkt[opt].toInt() and 0xFF

        // Handle standard options
        if (kind == TCP_OPTION_END) break
        if (kind == TCP_OPTION_NOP) {
            opt++
            continue
        }

        val size = pkt[opt + 1].toInt() and 0xFF

        // Check for MSS Option (Kind 2, Size 4)
        if (kind == TCP_OPTION_MSS && size == 4) {
            val mssOff = opt + 2
            val oldMss = ((pkt[mssOff].toInt() and 0xFF) shl 8) or (pkt[mssOff + 1].toInt() and 0xFF)

            // Use the dynamic mssLimit updated by handleInboundPacket
            if (oldMss > mssLimit) {
                // 1. Update MSS bytes
                pkt[mssOff] = (mssLimit shr 8).toByte()
                pkt[mssOff + 1] = mssLimit.toByte()

                // 2. Incrementally update TCP Checksum
                // TCP Checksum offset is 16 within the TCP header
                val oldTcpCheck = ((pkt[tcpStart + 16].toInt() and 0xFF) shl 8) or
                        (pkt[tcpStart + 17].toInt() and 0xFF)

                val newTcpCheck = updateChecksumIncremental(oldTcpCheck, oldMss, mssLimit)

                pkt[tcpStart + 16] = (newTcpCheck shr 8).toByte()
                pkt[tcpStart + 17] = newTcpCheck.toByte()
            }
            return
        }

        // Move to the next option
        opt += if (size < 2) 1 else size
    }
}
private fun xorKeyFromSecret(secret: Long): Byte {
    val s = secret.toInt()
    return ((s xor (s shr 8) xor (s shr 16) xor (s shr 24)) and 0xFF).toByte()
}

/* ============================================================
 *  VPN SERVICE
 * ============================================================ */
@SuppressLint("VpnServicePolicy")
class MyVpnService : VpnService() {

    companion object {
        const val ACTION_STOP = "STOP_VPN"
        private const val TAG = "ThinkSlowVPN"
    }
    private val socketLock = ReentrantLock()
    @Volatile
    private var running = false
    private var currentSessionId: Int = 0
    private var tunInterface: ParcelFileDescriptor? = null
    private var serverIp: String = ""
    private var assignedIpStr: String = "0.0.0.0" // Store this for UI updates
    private var currentClampMss = CLAMP_MSS
    private var globalSocket: DatagramSocket? = null


    // Helper to safely send through the shared socket
    private fun safeSocketSend(packet: DatagramPacket) {
        socketLock.withLock {
            try {
                globalSocket?.send(packet)
            } catch (e: Exception) {
                // If send fails, we might need to handle it,
                // but the Uplink thread will catch the exception in the loop
                throw e
            }
        }
    }
    private fun updateVpnMtu(newMtu: Int) {
        Log.i(TAG, "PMTUD: Lowering MTU to $newMtu")

        // 1. Update the clamping value (MTU - 40 for IP/TCP - 80 for safety)
        // We use a safe margin to avoid "re-fragmentation"
        currentClampMss = newMtu - 120

        // 2. We can't easily change the MTU of an existing TUN interface without re-establishing it.
        // However, by updating our internal CLAMP_MSS, the TCP connections will naturally shrink
        // to the new size, effectively solving the problem without a restart.
        // Use the stored IP string so the UI stays consistent
        broadcastVpnStatus(assignedIpStr)
    }

    private fun broadcastVpnStatus(assignedIp: String) {
        val intent = Intent("vpn_status_update") // Changed from "VPN_UPDATE" to match Fragment
        intent.putExtra("ip", assignedIp)
        intent.putExtra("mtu", DEFAULT_MTU)
        intent.putExtra("mss", currentClampMss)
        intent.putExtra("sid", currentSessionId.toUInt().toString())
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }
    private fun handleInboundPacket(pkt: ByteArray, len: Int, pktOffset: Int) {
        // 1. Check for IPv4 (0x45) at the correct offset
        if ((pkt[pktOffset].toInt() and 0xF0) != 0x40) return

        // 2. Check for ICMP (Protocol 1)
        val proto = pkt[pktOffset + 9].toInt() and 0xFF
        if (proto == 1) {
            Log.i(TAG, "PMTUD: Received an ICMP packet inside the tunnel!")
            val ihl = (pkt[pktOffset].toInt() and 0x0F) * 4
            val icmpStart = pktOffset + ihl
            val icmpType = pkt[icmpStart].toInt() and 0xFF
            val icmpCode = pkt[icmpStart + 1].toInt() and 0xFF

            // Type 3, Code 4 = Fragmentation Needed
            if (icmpType == 3 && icmpCode == 4) {
                val nextHopMtu = ((pkt[icmpStart + 6].toInt() and 0xFF) shl 8) or
                        (pkt[icmpStart + 7].toInt() and 0xFF)

                if (nextHopMtu in 576..DEFAULT_MTU) {
                    updateVpnMtu(nextHopMtu)
                }
            }
        }
    }
    /* ============================================================
     *  SIMPLE XOR ENCRYPTION (TEMP)
     * ============================================================ */
    object Encryption {
        var key: Byte = 'K'.code.toByte()

        // Pass the buffer and offset to avoid creating new objects
        fun cryptInPlace(data: ByteArray, offset: Int, len: Int) {
            for (i in offset until (offset + len)) {
                data[i] = data[i] xor key
            }
        }
    }

    /* ============================================================
     *  SERVICE ENTRY
     * ============================================================ */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.action?.let {
            if (it == ACTION_STOP) {
                disconnectVpn()
                return START_NOT_STICKY
            }
        }

        serverIp = intent?.getStringExtra("server_ip") ?: ""
        if (serverIp.isEmpty()) {
            sendToast("Invalid server IP")
            stopSelf()
            return START_NOT_STICKY
        }

        startForegroundNotification()

        if (!running) {
            Thread {
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_DISPLAY)
                vpnMainLoop()
            }.start()
        }

        return START_STICKY
    }

    /* ============================================================
     *  MAIN VPN LOOP
     * ============================================================ */
    /* ============================================================
         * MAIN VPN LOOP (MULTI-THREADED FULL-DUPLEX)
         * ============================================================ */
    private fun vpnMainLoop() {
        Log.i(TAG, "VPN multi-threaded loop starting")

        // Initial socket creation
        val socket = DatagramSocket()
        protect(socket)
        globalSocket = socket

        val serverAddr = InetSocketAddress(serverIp, SERVER_PORT)

        try {
            val assignedIp = performHandshake(socket, serverAddr, DatagramPacket(ByteArray(1600), 1600))
            createTun(assignedIp)
            broadcastVpnStatus(assignedIp)

            val fd = tunInterface!!.fileDescriptor
            val tunIn = FileInputStream(fd)
            val tunOut = FileOutputStream(fd)

            socket.sendBufferSize = 1024 * 1024
            socket.receiveBufferSize = 1024 * 1024

            running = true

            // --- THREAD 1: UPLINK (TUN -> UDP) ---
            val uplinkThread = Thread {
                val sendBuffer = ByteArray(1600)
                try {
                    while (running) {
                        val len = tunIn.read(sendBuffer, HEADER_SIZE, DEFAULT_MTU)
                        if (len > 0) {
                            clampTcpMssIncremental(sendBuffer, len, HEADER_SIZE, currentClampMss)

                            // Prep Header
                            sendBuffer[0] = PKT_DATA
                            sendBuffer[1] = (currentSessionId shr 24).toByte()
                            sendBuffer[2] = (currentSessionId shr 16).toByte()
                            sendBuffer[3] = (currentSessionId shr 8).toByte()
                            sendBuffer[4] = currentSessionId.toByte()

                            Encryption.cryptInPlace(sendBuffer, HEADER_SIZE, len)

                            // Use safeSend instead of direct socket.send
                            val packet = DatagramPacket(sendBuffer, HEADER_SIZE + len, serverAddr)

                            socketLock.withLock {
                                if (running) globalSocket?.send(packet)
                            }
                        }
                    }
                } catch (e: Exception) {
                    if (running) {
                        Log.e(TAG, "Uplink failure: ${e.message}")
                        // Here is where you would trigger a "reconnectNeeded" flag
                    }
                }
            }

            // --- THREAD 2: DOWNLINK (UDP -> TUN) ---
            val downlinkThread = Thread {
                val recvBuffer = ByteArray(1600)
                try {
                    while (running) {
                        // We must receive on the specific socket instance
                        val recvPacket = DatagramPacket(recvBuffer, recvBuffer.size)

                        // Receive is a blocking call; if the socket is closed
                        // by the other thread, this will throw an exception
                        socket.receive(recvPacket)

                        val totalLen = recvPacket.length
                        if (totalLen < HEADER_SIZE) continue

                        val hdr = PacketHeader.fromByteArray(recvBuffer)
                        if (hdr.type != PKT_DATA) continue

                        currentSessionId = hdr.sessionId
                        val payloadLen = totalLen - HEADER_SIZE

                        Encryption.cryptInPlace(recvBuffer, HEADER_SIZE, payloadLen)
                        handleInboundPacket(recvBuffer, payloadLen, HEADER_SIZE)

                        tunOut.write(recvBuffer, HEADER_SIZE, payloadLen)
                    }
                } catch (e: Exception) {
                    if (running) Log.e(TAG, "Downlink failure: ${e.message}")
                }
            }

            uplinkThread.start()
            downlinkThread.start()

            uplinkThread.join()
            downlinkThread.join()

        } catch (e: Exception) {
            Log.e(TAG, "VPN Main Loop Error", e)
        } finally {
            socketLock.withLock {
                socket.close()
                globalSocket = null
            }
            disconnectVpn()
        }
    }


    /* ============================================================
     *  HANDSHAKE
     * ============================================================ */
    private fun performHandshake(
        socket: DatagramSocket,
        server: InetSocketAddress,
        recvPacket: DatagramPacket
    ): String {

        val magic = (System.currentTimeMillis() and 0xffffffffL).toInt()
        val hello = ByteArray(13)
        val privateA = (1000..5000).random().toLong()
        val yc = modExp(G, privateA, P).toInt()

        PacketHeader(PKT_HELLO, 0).toByteArray().copyInto(hello, 0)

        // client_magic
                hello[5] = (magic shr 24).toByte()
                hello[6] = (magic shr 16).toByte()
                hello[7] = (magic shr 8).toByte()
                hello[8] = magic.toByte()

        // yc (client public DH)
                hello[9]  = (yc shr 24).toByte()
                hello[10] = (yc shr 16).toByte()
                hello[11] = (yc shr 8).toByte()
                hello[12] = yc.toByte()


        socket.send(DatagramPacket(hello, hello.size, server))
        Log.i(TAG, "HELLO sent")

        socket.receive(recvPacket)
        val hdr = PacketHeader.fromByteArray(recvPacket.data)
        require(hdr.type == PKT_WELCOME) { "Expected WELCOME" }
// Save the session ID globally
        this.currentSessionId = hdr.sessionId
        Log.i(TAG, "Handshake successful. Registered Session ID:${currentSessionId.toUInt()}")
        val ip =
            ((recvPacket.data[5].toInt() and 0xFF) shl 24) or
                    ((recvPacket.data[6].toInt() and 0xFF) shl 16) or
                    ((recvPacket.data[7].toInt() and 0xFF) shl 8) or
                    (recvPacket.data[8].toInt() and 0xFF)
        val ys =
            ((recvPacket.data[9].toInt() and 0xFF) shl 24) or
                    ((recvPacket.data[10].toInt() and 0xFF) shl 16) or
                    ((recvPacket.data[11].toInt() and 0xFF) shl 8) or
                    (recvPacket.data[12].toInt() and 0xFF)
        val sharedSecret = modExp(ys.toLong(), privateA, P)
        Encryption.key = xorKeyFromSecret(sharedSecret)

        Log.i(TAG, "Derived XOR key = ${Encryption.key.toUByte()}")

        val ipStr = intToIp(ip)
        Log.i(TAG, "Assigned VPN IP = $ipStr")

// Inside performHandshake, after getting WELCOME:
        val ack = PacketHeader(PKT_CLIENT_ACK, currentSessionId).toByteArray()
        socket.send(DatagramPacket(ack, ack.size, server))
        Log.i(TAG, "CLIENT_ACK sent with Session ID: ${currentSessionId.toUInt()}")
        // Inside performHandshake, right before the return:
        this.assignedIpStr = ipStr
        return ipStr
    }

    /* ============================================================
     *  TUN CREATION
     * ============================================================ */
    private fun createTun(ip: String) {
        tunInterface = Builder()
            .setSession("ThinkSlow VPN")
            .addAddress(ip, 24)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)
            .setMtu(DEFAULT_MTU)
            .establish()

        Log.i(TAG, "TUN created with IP $ip")
    }

    /* ============================================================
     *  CLEANUP
     * ============================================================ */
    fun disconnectVpn() {
        if (!running) return
        running = false

        try {
            tunInterface?.close()
            tunInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "TUN close failed", e)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            stopForeground(STOP_FOREGROUND_REMOVE)
        else
            stopForeground(true)

        sendToast("VPN Disconnected") // This is the trigger for your UI fix
        stopSelf()
    }

    override fun onDestroy() {
        disconnectVpn()
        super.onDestroy()
    }

    /* ============================================================
     *  UTIL
     * ============================================================ */
    private fun intToIp(ip: Int): String =
        "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

    private fun sendToast(msg: String) {
        val intent = Intent("vpn_toast")
        intent.putExtra("msg", msg)
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }

    private fun startForegroundNotification() {
        val channelId = "vpn_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(
                    NotificationChannel(
                        channelId,
                        "VPN Service",
                        NotificationManager.IMPORTANCE_LOW
                    )
                )
        }

        val notification =
            NotificationCompat.Builder(this, channelId)
                .setContentTitle("ThinkSlow VPN")
                .setContentText("VPN is running")
                .setSmallIcon(R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build()

        startForeground(1, notification)
    }
}
