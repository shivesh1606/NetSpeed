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

private fun recomputeChecksums(pkt: ByteArray, len: Int) {
    // ---- IP checksum ----
    pkt[10] = 0
    pkt[11] = 0
    val ipChecksum = checksum(pkt, 0, (pkt[0].toInt() and 0x0F) * 4)
    pkt[10] = (ipChecksum shr 8).toByte()
    pkt[11] = ipChecksum.toByte()

    // ---- TCP checksum ----
    val ihl = (pkt[0].toInt() and 0x0F) * 4
    pkt[ihl + 16] = 0
    pkt[ihl + 17] = 0

    val tcpLen = len - ihl
    val pseudo = ByteArray(12 + tcpLen)

    // src + dst IP
    System.arraycopy(pkt, 12, pseudo, 0, 8)
    pseudo[8] = 0
    pseudo[9] = IPPROTO_TCP.toByte()
    pseudo[10] = (tcpLen shr 8).toByte()
    pseudo[11] = tcpLen.toByte()

    System.arraycopy(pkt, ihl, pseudo, 12, tcpLen)
    val tcpChecksum = checksum(pseudo, 0, pseudo.size)

    pkt[ihl + 16] = (tcpChecksum shr 8).toByte()
    pkt[ihl + 17] = tcpChecksum.toByte()
}

private fun clampTcpMssIfNeeded(pkt: ByteArray, len: Int) {
    if (len < 40) return  // min IPv4 + TCP

    // ---- IP header ----
    val ihl = (pkt[0].toInt() and 0x0F) * 4
    if (ihl < 20) return

    val proto = pkt[9].toInt() and 0xFF
    if (proto != IPPROTO_TCP) return

    // ---- TCP header ----
    val tcpStart = ihl
    val tcpFlags = pkt[tcpStart + 13].toInt() and 0xFF
    if (tcpFlags and TCP_FLAG_SYN == 0) return

    val tcpHdrLen = ((pkt[tcpStart + 12].toInt() shr 4) and 0xF) * 4
    if (tcpHdrLen <= 20) return

    // ---- TCP options ----
    var opt = tcpStart + 20
    val optEnd = tcpStart + tcpHdrLen

    while (opt < optEnd) {
        val kind = pkt[opt].toInt() and 0xFF

        when (kind) {
            TCP_OPTION_END -> return
            TCP_OPTION_NOP -> opt += 1
            TCP_OPTION_MSS -> {
                val mssOffset = opt + 2
                val oldMss =
                    ((pkt[mssOffset].toInt() and 0xFF) shl 8) or
                            (pkt[mssOffset + 1].toInt() and 0xFF)

                if (oldMss > CLAMP_MSS) {
                    pkt[mssOffset]     = (CLAMP_MSS shr 8).toByte()
                    pkt[mssOffset + 1] = CLAMP_MSS.toByte()
                    recomputeChecksums(pkt, len)
                }
                return
            }
            else -> {
                val size = pkt[opt + 1].toInt() and 0xFF
                if (size < 2) return
                opt += size
            }
        }
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

    @Volatile
    private var running = false
    private var currentSessionId: Int = 0 // Store this globally in the class
    private var tunInterface: ParcelFileDescriptor? = null
    private var serverIp: String = ""

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
    private fun vpnMainLoop() {
        Log.i(TAG, "VPN loop started")

        var socket = DatagramSocket()
        socket.soTimeout = 2000
        protect(socket)

        val serverAddr = InetSocketAddress(serverIp, SERVER_PORT)
        // Create a buffer large enough for MTU + Header
        // Using 1600 to be safe
        val sendBuffer = ByteArray(1600)
        val recvBuffer = ByteArray(1600)
        val recvPacket = DatagramPacket(recvBuffer, recvBuffer.size)
        try {
            val assignedIp = performHandshake(socket, serverAddr, recvPacket)
            createTun(assignedIp)

            val fd = tunInterface!!.fileDescriptor
            val tunIn = FileInputStream(fd)
            val tunOut = FileOutputStream(fd)

            running = true
            socket.soTimeout = 1
            socket.sendBufferSize = 1024 * 1024 // 1MB buffer
            socket.receiveBufferSize = 1024 * 1024
            while (running) {
                var hasData = false
                /* ---- TUN → UDP ---- */
                // 1. Read from TUN directly into the buffer AFTER the 5-byte header space
                val len = tunIn.read(sendBuffer, HEADER_SIZE, DEFAULT_MTU)
                if (len > 0) {

                    // 2. Generate and write header into the first 5 bytes (0..4)
                    val headerBytes = PacketHeader(PKT_DATA, currentSessionId).toByteArray()
                    System.arraycopy(headerBytes, 0, sendBuffer, 0, HEADER_SIZE)

                    // 3. Encrypt the payload starting from index 5
                    Encryption.cryptInPlace(sendBuffer, HEADER_SIZE, len)

                    // 4. Send the whole thing (Header + Encrypted Payload)
                    /* ---- TUN → UDP ---- */
// ... (read and encrypt logic) ...
                    try {
                        socket.send(DatagramPacket(sendBuffer, HEADER_SIZE + len, serverAddr))
                    } catch (e: Exception) {
                        Log.w(TAG, "Send failed, recreating socket: ${e.message}")
                        try { socket.close() } catch (_: Exception) {}

                        socket = DatagramSocket()
                        protect(socket)
                        socket.soTimeout = 200 // <--- CRITICAL: Add this or receive() will freeze the app
                    }

                }

                /* ---- UDP → TUN ---- */
                try {
                    socket.receive(recvPacket)
                    val totalLen = recvPacket.length
                    if (totalLen < HEADER_SIZE) continue

                    // 1. Parse header from the start of recvBuffer
                    val hdr = PacketHeader.fromByteArray(recvBuffer)
                    if (hdr.type != PKT_DATA) continue
                    // Ensure we update our local ID if the server ever sends a new one
                    currentSessionId = hdr.sessionId
                    val payloadLen = totalLen - HEADER_SIZE
                    // 2. Decrypt the payload in-place starting at index 5
                    Encryption.cryptInPlace(recvBuffer, HEADER_SIZE, payloadLen)
                    // 3. Write decrypted data to TUN
                    tunOut.write(recvBuffer, HEADER_SIZE, payloadLen)

                } catch (e: SocketTimeoutException) {
                    // Ignore timeout
                } catch (e: Exception) {
                // We don't need to recreate the socket here because
                // the TUN -> UDP block above will catch the error and do it.
                Log.w(TAG, "Receive failed (waiting for recovery): ${e.message}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "VPN error", e)
            sendToast("VPN Error: ${e.message}")
        } finally {
            socket.close()
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

        sendToast("VPN Disconnected")
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
