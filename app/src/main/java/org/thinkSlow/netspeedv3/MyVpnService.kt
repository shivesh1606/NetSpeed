package org.thinkSlow.netspeedv3

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import kotlin.experimental.xor
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import org.thinkSlow.netspeedv3.vpn.AccessStore
import org.thinkSlow.netspeedv3.vpn.NoiseCrypto
import java.util.concurrent.atomic.AtomicLong
import org.thinkSlow.netspeedv3.vpn.SessionLocks
import org.thinkSlow.netspeedv3.vpn.V2Client
import org.thinkSlow.netspeedv3.vpn.V2Wire

/* ============================================================
 *  PROTOCOL CONSTANTS (MUST MATCH C++)
 * ============================================================ */

private const val PKT_HELLO: Byte = 1
private const val PKT_WELCOME: Byte = 2
private const val PKT_CLIENT_ACK: Byte = 3
private const val PKT_DATA: Byte = 4
private const val PKT_BYE: Byte = 5
private const val PKT_KEEPALIVE: Byte = 6

private const val KEEPALIVE_INTERVAL_MS = 15_000L // Send keepalive every 15s
private const val HANDSHAKE_ATTEMPTS = 4          // HELLO retries (matches Windows client)
private const val HANDSHAKE_TIMEOUT_MS = 5_000    // Wait per attempt for WELCOME
private const val WELCOME_SIZE = 13               // header(5) + assigned_ip(4) + ys(4)

private const val HEADER_SIZE = 5
private const val SERVER_PORT = 5555
private const val DEFAULT_MTU = 1320


private const val IPPROTO_TCP = 6
private const val TCP_FLAG_SYN = 0x02
private const val TCP_OPTION_MSS = 2
private const val TCP_OPTION_END = 0
private const val TCP_OPTION_NOP = 1

private const val CLAMP_MSS = 1160

/* Protocol v2 (Cpp-VPN-Core design docs 01-03): Noise IK handshake + ChaCha20-Poly1305 transport */
private const val V2_MTU = 1420            // design 01 §3: 1500 - 20 - 8 - 14 - 16 - margin
private const val V2_CLAMP_MSS = V2_MTU - 40
private const val V2_REKEY_AFTER_MS = 120_000L  // design 02 §7
private const val V2_REJECT_AFTER_MS = 180_000L
private const val V2_RETRY_MS = 5_000L     // new HS_INIT every 5 s (+ jitter) until HS_RESP

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
        const val VPN_NOTIF_ID = 200 // Unique — Speed service uses 100
        private const val TAG = "ThinkSlowVPN"

        /** Static flag so the UI can check if VPN is active even after process recreation */
        @Volatile
        var isActive = false
            private set

        /** The currently assigned VPN IP — survives fragment recreation */
        @Volatile
        var activeIpStr: String = ""
            private set

        /** Current session ID as unsigned string — survives fragment recreation */
        @Volatile
        var activeSessionId: String = ""
            private set

        /** Current MTU value */
        @Volatile
        var activeMtu: Int = DEFAULT_MTU
            private set

        /** Current MSS clamp value */
        @Volatile
        var activeMss: Int = CLAMP_MSS
            private set

        /** "Noise IK · ChaCha20-Poly1305" (v2) or "XOR (legacy v1)" */
        @Volatile
        var activeSecurity: String = ""
            private set

        /** Node name (v2) or server IP (v1) shown in the "Connected to" banner */
        @Volatile
        var activeServerName: String = ""
            private set

        /** Intent extras for starting a v2 connection from the imported access */
        const val EXTRA_PROTOCOL = "protocol"
        const val EXTRA_NODE_ID = "node_id"
    }
    private val socketLock = ReentrantLock()
    @Volatile
    private var running = false

    /**
     * Token for the current connection attempt (null when idle). Set when a connect starts,
     * cleared exactly once by disconnectVpn() — so cleanup also runs when the handshake fails,
     * and a late teardown from an old session can never kill a newer one.
     */
    private val activeSession = AtomicReference<Any?>(null)
    private var currentSessionId: Int = 0
    private var tunInterface: ParcelFileDescriptor? = null
    private var serverIp: String = ""
    private var assignedIpStr: String = "0.0.0.0" // Store this for UI updates
    private var currentClampMss = CLAMP_MSS
    private var globalSocket: DatagramSocket? = null
    private var serverAddress: InetSocketAddress? = null

    /** Write end of the current session's wake pipe; a byte here pops the uplink out of poll() */
    private var wakeWriteFd: FileDescriptor? = null

    // Protocol v2 state
    private var protocolV2 = false
    private var nodeId: String? = null
    private var v2Client: V2Client? = null
    private var currentMtu = DEFAULT_MTU


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
        activeMss = currentClampMss

        // 2. We can't easily change the MTU of an existing TUN interface without re-establishing it.
        // However, by updating our internal CLAMP_MSS, the TCP connections will naturally shrink
        // to the new size, effectively solving the problem without a restart.
        // Use the stored IP string so the UI stays consistent
        broadcastVpnStatus(assignedIpStr)
    }

    private fun broadcastVpnStatus(assignedIp: String) {
        val intent = Intent("vpn_status_update") // Changed from "VPN_UPDATE" to match Fragment
        intent.putExtra("ip", assignedIp)
        intent.putExtra("mtu", currentMtu)
        intent.putExtra("mss", currentClampMss)
        intent.putExtra("sid", if (protocolV2) activeSessionId else currentSessionId.toUInt().toString())
        intent.putExtra("security", activeSecurity)
        intent.putExtra("server", activeServerName)
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

                if (nextHopMtu in 576..currentMtu) {
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
                val session = activeSession.get()
                // Off the main thread: sending PKT_BYE here would throw NetworkOnMainThreadException
                if (session != null) Thread { disconnectVpn(session) }.start() else stopSelf()
                return START_NOT_STICKY
            }
        }

        protocolV2 = intent?.getStringExtra(EXTRA_PROTOCOL) == "v2"
        nodeId = intent?.getStringExtra(EXTRA_NODE_ID)
        serverIp = intent?.getStringExtra("server_ip") ?: ""
        if (!protocolV2 && serverIp.isEmpty()) {
            sendToast("Invalid server IP")
            stopSelf()
            return START_NOT_STICKY
        }

        startForegroundNotification()

        val session = Any()
        if (activeSession.compareAndSet(null, session)) {
            Thread {
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_DISPLAY)
                if (protocolV2) vpnMainLoopV2(session) else vpnMainLoop(session)
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
    private fun vpnMainLoop(session: Any) {
        Log.i(TAG, "VPN multi-threaded loop starting")

        var socket: DatagramSocket? = null
        var pipe: Array<FileDescriptor>? = null
        var failureMsg: String? = null

        try {
            val sock = DatagramSocket()
            socket = sock
            protect(sock)
            socketLock.withLock {
                // User may have hit Disconnect before we got here
                if (activeSession.get() !== session) return
                globalSocket = sock
            }
            currentSessionId = 0
            currentMtu = DEFAULT_MTU
            currentClampMss = CLAMP_MSS

            val serverAddr = InetSocketAddress(serverIp, SERVER_PORT)
            serverAddress = serverAddr

            val assignedIp = performHandshake(sock, serverAddr)
            val tun = createTun(assignedIp)
            val wakePipe = Os.pipe() // [0] read end (uplink polls it), [1] write end (disconnectVpn)
            pipe = wakePipe

            socketLock.withLock {
                // Disconnect during handshake/establish: don't leave a TUN up that blackholes traffic
                if (activeSession.get() !== session) {
                    tun.close()
                    return
                }
                tunInterface = tun
                wakeWriteFd = wakePipe[1]
                running = true

                // Update static state so UI survives recreation
                isActive = true
                activeIpStr = assignedIp
                activeSessionId = currentSessionId.toUInt().toString()
                activeMtu = DEFAULT_MTU
                activeMss = currentClampMss
                activeSecurity = "XOR (legacy v1, not encrypted)"
                activeServerName = serverIp
            }
            broadcastVpnStatus(assignedIp)

            val fd = tun.fileDescriptor
            val tunIn = FileInputStream(fd)
            val tunOut = FileOutputStream(fd)

            sock.sendBufferSize = 1024 * 1024
            sock.receiveBufferSize = 1024 * 1024

            // --- THREAD 1: UPLINK (TUN -> UDP) ---
            val uplinkThread = Thread {
                val sendBuffer = ByteArray(1600)
                // Wait on the TUN *and* the wake pipe: closing the TUN doesn't wake a thread
                // blocked in read(), so disconnectVpn() writes a byte to the pipe instead
                val tunPoll = StructPollfd().apply { this.fd = tun.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                val wakePoll = StructPollfd().apply { this.fd = wakePipe[0]; events = OsConstants.POLLIN.toShort() }
                val pollFds = arrayOf(tunPoll, wakePoll)
                try {
                    while (running) {
                        tunPoll.revents = 0
                        wakePoll.revents = 0
                        try {
                            Os.poll(pollFds, -1)
                        } catch (e: ErrnoException) {
                            if (e.errno == OsConstants.EINTR) continue
                            throw e
                        }
                        if (wakePoll.revents.toInt() != 0) break // disconnectVpn() woke us
                        if ((tunPoll.revents.toInt() and OsConstants.POLLIN) == 0) break // TUN closed/errored

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

                            // Send on this session's socket: once closed it throws, so a
                            // stale thread can't leak packets into a newer session
                            socketLock.withLock {
                                if (running) sock.send(packet)
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

                        // Receive is a blocking call; disconnectVpn() closes the
                        // socket, which makes this throw and ends the thread
                        sock.receive(recvPacket)

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

            // --- THREAD 3: KEEPALIVE ---
            val keepaliveThread = Thread {
                val kaBuffer = ByteArray(HEADER_SIZE)
                try {
                    while (running) {
                        Thread.sleep(KEEPALIVE_INTERVAL_MS)
                        if (!running) break

                        kaBuffer[0] = PKT_KEEPALIVE
                        kaBuffer[1] = (currentSessionId shr 24).toByte()
                        kaBuffer[2] = (currentSessionId shr 16).toByte()
                        kaBuffer[3] = (currentSessionId shr 8).toByte()
                        kaBuffer[4] = currentSessionId.toByte()

                        val packet = DatagramPacket(kaBuffer, HEADER_SIZE, serverAddr)
                        socketLock.withLock {
                            if (running) sock.send(packet)
                        }
                        Log.d(TAG, "Keepalive sent")
                    }
                } catch (e: InterruptedException) {
                    // Normal on shutdown
                } catch (e: Exception) {
                    if (running) Log.e(TAG, "Keepalive failure: ${e.message}")
                }
            }

            uplinkThread.start()
            downlinkThread.start()
            keepaliveThread.start()

            uplinkThread.join()
            downlinkThread.join()
            keepaliveThread.interrupt() // wake from sleep
            keepaliveThread.join(2000)  // wait max 2s

        } catch (e: Exception) {
            // If we were stopped, the exception is just the closed socket waking us — not an error
            if (activeSession.get() === session) {
                Log.e(TAG, "VPN Main Loop Error", e)
                if (!running) failureMsg = "Connection failed: ${e.message ?: e.javaClass.simpleName}"
            }
        } finally {
            disconnectVpn(session, failureMsg ?: "VPN Disconnected")
            socket?.close() // no-op if disconnectVpn already closed it
            // Uplink has exited by now (joined above), so nothing is polling the pipe
            pipe?.let { p ->
                socketLock.withLock { if (wakeWriteFd === p[1]) wakeWriteFd = null }
                p.forEach { runCatching { Os.close(it) } }
            }
        }
    }


    /* ============================================================
     *  HANDSHAKE
     * ============================================================ */
    private fun performHandshake(
        socket: DatagramSocket,
        server: InetSocketAddress
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


        // Retry HELLO with a per-attempt timeout so an unreachable server can't hang us forever.
        // The same HELLO (same DH secret) is resent, so whichever WELCOME arrives matches our key.
        val recvBuf = ByteArray(1600)
        val recvPacket = DatagramPacket(recvBuf, recvBuf.size)
        var gotWelcome = false
        socket.soTimeout = HANDSHAKE_TIMEOUT_MS
        try {
            for (attempt in 1..HANDSHAKE_ATTEMPTS) {
                socket.send(DatagramPacket(hello, hello.size, server))
                Log.i(TAG, "HELLO sent (attempt $attempt/$HANDSHAKE_ATTEMPTS)")

                recvPacket.length = recvBuf.size // receive() shrinks length to the last datagram
                try {
                    socket.receive(recvPacket)
                } catch (e: SocketTimeoutException) {
                    continue
                }
                if (recvPacket.length >= WELCOME_SIZE && recvBuf[0] == PKT_WELCOME) {
                    gotWelcome = true
                    break
                }
            }
        } finally {
            // Back to blocking for the tunnel; ignore if the socket was closed by a stop
            runCatching { socket.soTimeout = 0 }
        }
        if (!gotWelcome) throw SocketTimeoutException("server not responding")

        val hdr = PacketHeader.fromByteArray(recvPacket.data)
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
    private fun createTun(ip: String, prefix: Int = 24, mtu: Int = DEFAULT_MTU): ParcelFileDescriptor {
        val builder = Builder()
            .setSession("ThinkSlow VPN")
            .addAddress(ip, prefix)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)
            .setMtu(mtu)

        // Apply split tunneling — exclude selected apps from VPN
        val settingsPrefs = getSharedPreferences(
            VpnSettingsFragment.PREFS_NAME, MODE_PRIVATE
        )
        val splitEnabled = settingsPrefs.getBoolean(
            VpnSettingsFragment.KEY_SPLIT_TUNNEL_ENABLED, false
        )
        if (splitEnabled) {
            val excluded = settingsPrefs.getStringSet(
                VpnSettingsFragment.KEY_EXCLUDED_APPS, emptySet()
            ) ?: emptySet()
            for (pkg in excluded) {
                try {
                    builder.addDisallowedApplication(pkg)
                    Log.i(TAG, "Split tunnel: excluding $pkg")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to exclude $pkg: ${e.message}")
                }
            }
        }

        // establish() returns null if VPN permission was revoked
        val tun = builder.establish() ?: throw IllegalStateException("VPN permission not granted")
        Log.i(TAG, "TUN created with IP $ip")
        return tun
    }

    /* ============================================================
     *  CLEANUP
     * ============================================================ */
    /**
     * Tears down [session] — runs at most once per session, whether it was connected,
     * still handshaking, or failed. Safe to call from any thread.
     */
    private fun disconnectVpn(session: Any, message: String = "VPN Disconnected") {
        socketLock.withLock {
            if (!activeSession.compareAndSet(session, null)) return
            Log.i(TAG, "disconnect: $message")
            running = false
            isActive = false
            activeIpStr = ""
            activeSessionId = ""

            activeSecurity = ""
            activeServerName = ""

            // Best-effort: send PKT_BYE so the server frees our session.
            // Only if WELCOME gave us a session ID — otherwise the server has nothing to free.
            if (currentSessionId != 0) sendByePacket()
            v2Client?.let { client ->
                sendV2Bye(client) // authenticated BYE (protocol v2)
                client.wipe()
            }
            v2Client = null

            // Closing the socket wakes any thread blocked in receive() (handshake or downlink)
            globalSocket?.close()
            globalSocket = null

            // Wake the uplink out of poll() — closing the TUN alone wouldn't
            wakeWriteFd?.let { runCatching { Os.write(it, byteArrayOf(1), 0, 1) } }
            wakeWriteFd = null

            try {
                tunInterface?.close()
            } catch (e: Exception) {
                Log.e(TAG, "TUN close failed", e)
            }
            tunInterface = null
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            stopForeground(STOP_FOREGROUND_REMOVE)
        else
            stopForeground(true)

        sendToast(message) // This is the trigger for your UI fix
        stopSelf()
    }

    override fun onDestroy() {
        activeSession.get()?.let { disconnectVpn(it) }
        super.onDestroy()
    }

    /* ============================================================
     *  UTIL
     * ============================================================ */
    /**
     * Send PKT_BYE to the server (best-effort, fire 3 times for UDP reliability).
     * Must be called BEFORE the socket is closed.
     */
    private fun sendByePacket() {
        try {
            val addr = serverAddress ?: return
            val byeData = PacketHeader(PKT_BYE, currentSessionId).toByteArray()
            val packet = DatagramPacket(byeData, byeData.size, addr)

            socketLock.withLock {
                val sock = globalSocket ?: return
                // Send 3 times — UDP is unreliable, and this is best-effort
                repeat(3) {
                    try {
                        sock.send(packet)
                    } catch (_: Exception) { }
                    Thread.sleep(10) // tiny gap between retries
                }
            }
            Log.i(TAG, "PKT_BYE sent (3x) for session ${currentSessionId.toUInt()}")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to send BYE: ${e.message}")
        }
    }

    /** Protocol v2 BYE, sent 3x like the v1 one. Called with socketLock held. */
    private fun sendV2Bye(client: V2Client) {
        val addr = serverAddress ?: return
        val sock = globalSocket ?: return
        val buf = ByteArray(V2Wire.TRANSPORT_MIN_LEN)
        val n = client.sealBye(System.currentTimeMillis(), buf)
        if (n == 0) return
        repeat(3) {
            runCatching { sock.send(DatagramPacket(buf, n, addr)) }
            Thread.sleep(10)
        }
        Log.i(TAG, "v2 BYE sent (3x)")
    }

    /* ============================================================
     *  PROTOCOL V2 LOOP (Noise IK + ChaCha20-Poly1305, tickets)
     * ============================================================ */
    private fun vpnMainLoopV2(session: Any) {
        Log.i(TAG, "VPN v2 loop starting")
        var socket: DatagramSocket? = null
        var pipe: Array<FileDescriptor>? = null
        var failureMsg: String? = null

        try {
            val store = AccessStore(this)
            val bundle = store.bundle() ?: throw IllegalStateException("no VPN access imported")
            val node = bundle.nodes.firstOrNull { it.id == nodeId } ?: bundle.nodes.first()
            val ticket = bundle.ticketInfo
            if (ticket.isExpired()) {
                throw IllegalStateException("your access expired on ${AccessStore.formatDate(ticket.exp)}")
            }
            val deviceKey = store.deviceKey()
            val client = V2Client(deviceKey, node.pub, ticket = bundle.ticket)
            deviceKey.fill(0)

            val sock = DatagramSocket()
            socket = sock
            protect(sock)
            val serverAddr = InetSocketAddress(InetAddress.getByName(node.host), node.port) // DNS names allowed
            socketLock.withLock {
                if (activeSession.get() !== session) return
                globalSocket = sock
                serverAddress = serverAddr
                v2Client = client
            }
            currentSessionId = 0 // v1 only
            currentMtu = V2_MTU
            currentClampMss = V2_CLAMP_MSS

            performHandshakeV2(sock, serverAddr, client)
            val assignedIp = V2Wire.ipToString(client.tunIp())
            assignedIpStr = assignedIp
            // /32: the server's pool prefix is not sent; every route goes through the tunnel anyway
            val tun = createTun(assignedIp, 32, V2_MTU)
            val wakePipe = Os.pipe()
            pipe = wakePipe

            socketLock.withLock {
                if (activeSession.get() !== session) {
                    tun.close()
                    return
                }
                tunInterface = tun
                wakeWriteFd = wakePipe[1]
                running = true
                isActive = true
                activeIpStr = assignedIp
                activeSessionId = client.handshakeId()
                activeMtu = V2_MTU
                activeMss = currentClampMss
                activeSecurity = "Noise IK · ${SessionLocks.name(client.cipherId())}"
                activeServerName = node.id
            }
            broadcastVpnStatus(assignedIp)

            val tunIn = FileInputStream(tun.fileDescriptor)
            val tunOut = FileOutputStream(tun.fileDescriptor)
            sock.sendBufferSize = 1024 * 1024
            sock.receiveBufferSize = 1024 * 1024
            val lastRecvMs = AtomicLong(System.currentTimeMillis()) // last authenticated packet

            fun send(buf: ByteArray, n: Int) {
                if (n <= 0) return
                socketLock.withLock { if (running) sock.send(DatagramPacket(buf, n, serverAddr)) }
            }

            // --- UPLINK: TUN -> seal -> UDP ---
            val uplinkThread = Thread {
                val ipBuf = ByteArray(V2_MTU + 64)
                val out = ByteArray(V2_MTU + 64 + V2Wire.TRANSPORT_MIN_LEN)
                val tunPoll = StructPollfd().apply { this.fd = tun.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                val wakePoll = StructPollfd().apply { this.fd = wakePipe[0]; events = OsConstants.POLLIN.toShort() }
                val pollFds = arrayOf(tunPoll, wakePoll)
                try {
                    while (running) {
                        tunPoll.revents = 0
                        wakePoll.revents = 0
                        try {
                            Os.poll(pollFds, -1)
                        } catch (e: ErrnoException) {
                            if (e.errno == OsConstants.EINTR) continue
                            throw e
                        }
                        if (wakePoll.revents.toInt() != 0) break
                        if ((tunPoll.revents.toInt() and OsConstants.POLLIN) == 0) break
                        val len = tunIn.read(ipBuf, 0, V2_MTU)
                        if (len > 0) {
                            clampTcpMssIncremental(ipBuf, len, 0, currentClampMss)
                            send(out, client.sealData(ipBuf, 0, len, System.currentTimeMillis(), out))
                        }
                    }
                } catch (e: Exception) {
                    if (running) Log.e(TAG, "v2 uplink failure: ${e.message}")
                }
            }

            // --- DOWNLINK: UDP -> open -> TUN (also rekey responses and server BYE) ---
            val downlinkThread = Thread {
                val recvBuf = ByteArray(2048)
                val plain = ByteArray(2048)
                val ack = ByteArray(V2Wire.ACK_LEN)
                try {
                    while (running) {
                        val pkt = DatagramPacket(recvBuf, recvBuf.size)
                        sock.receive(pkt)
                        when (client.receive(recvBuf, pkt.length, System.currentTimeMillis(), ack, plain)) {
                            V2Client.Event.DATA -> {
                                lastRecvMs.set(System.currentTimeMillis())
                                val n = client.lengths[1]
                                handleInboundPacket(plain, n, 0)
                                tunOut.write(plain, 0, n)
                            }
                            V2Client.Event.KEEPALIVE -> lastRecvMs.set(System.currentTimeMillis())
                            V2Client.Event.ESTABLISHED -> { // rekey completed
                                lastRecvMs.set(System.currentTimeMillis())
                                send(ack, client.lengths[0])
                                activeSessionId = client.handshakeId()
                                Log.i(TAG, "v2 rekeyed: hsid=${client.handshakeId()}")
                                broadcastVpnStatus(assignedIp)
                            }
                            V2Client.Event.BYE -> {
                                Log.i(TAG, "v2 server ended the session")
                                Thread { disconnectVpn(session, "Disconnected: the server ended the session (access revoked or server restarted)") }.start()
                                break
                            }
                            V2Client.Event.NONE -> {}
                        }
                    }
                } catch (e: Exception) {
                    if (running) Log.e(TAG, "v2 downlink failure: ${e.message}")
                }
            }

            // --- TIMER: keepalive, rekey, reject-after, silence ---
            val timerThread = Thread {
                val buf = ByteArray(V2Wire.TRANSPORT_MIN_LEN)
                try {
                    while (running) {
                        Thread.sleep(1000)
                        if (!running) break
                        val now = System.currentTimeMillis()
                        val age = client.sessionAgeMs(now)
                        if (age >= V2_REJECT_AFTER_MS) {
                            Thread { disconnectVpn(session, "Disconnected: the session could not be renewed (is your access still valid?)") }.start()
                            break
                        }
                        if (age >= V2_REKEY_AFTER_MS &&
                            (!client.handshakeInFlight() || now - client.handshakeStartedMs() >= V2_RETRY_MS)) {
                            val init = client.startHandshake(now)
                            send(init, init.size)
                            Log.i(TAG, "v2 rekey: HS_INIT sent (session age ${age / 1000} s)")
                        }
                        val ka = (client.keepaliveSeconds().takeIf { it > 0 } ?: 15) * 1000L
                        if (now - client.lastSendMs() >= ka) send(buf, client.sealKeepalive(now, buf))
                        if (now - lastRecvMs.get() > 3 * ka) {
                            Thread { disconnectVpn(session, "Disconnected: no reply from the server for ${3 * ka / 1000} s") }.start()
                            break
                        }
                    }
                } catch (e: InterruptedException) {
                    // shutdown
                } catch (e: Exception) {
                    if (running) Log.e(TAG, "v2 timer failure: ${e.message}")
                }
            }

            uplinkThread.start()
            downlinkThread.start()
            timerThread.start()
            uplinkThread.join()
            downlinkThread.join()
            timerThread.interrupt()
            timerThread.join(2000)
        } catch (e: Exception) {
            if (activeSession.get() === session) {
                Log.e(TAG, "VPN v2 loop error", e)
                if (!running) failureMsg = "Connection failed: ${e.message ?: e.javaClass.simpleName}"
            }
        } finally {
            disconnectVpn(session, failureMsg ?: "VPN Disconnected")
            socket?.close()
            pipe?.let { p ->
                socketLock.withLock { if (wakeWriteFd === p[1]) wakeWriteFd = null }
                p.forEach { runCatching { Os.close(it) } }
            }
        }
    }

    /** HS_INIT -> HS_RESP -> ACK with 4 attempts (new msg1 each time, design 02 §4). */
    private fun performHandshakeV2(sock: DatagramSocket, server: InetSocketAddress, client: V2Client) {
        val recvBuf = ByteArray(2048)
        val plain = ByteArray(2048)
        val ack = ByteArray(V2Wire.ACK_LEN)
        try {
            for (attempt in 1..HANDSHAKE_ATTEMPTS) {
                val init = client.startHandshake(System.currentTimeMillis())
                sock.send(DatagramPacket(init, init.size, server))
                Log.i(TAG, "v2 HS_INIT sent (attempt $attempt/$HANDSHAKE_ATTEMPTS)")
                val deadline = System.currentTimeMillis() + V2_RETRY_MS + NoiseCrypto.random.nextInt(334)
                while (true) {
                    val left = deadline - System.currentTimeMillis()
                    if (left <= 0) break
                    sock.soTimeout = left.toInt()
                    val pkt = DatagramPacket(recvBuf, recvBuf.size)
                    try {
                        sock.receive(pkt)
                    } catch (e: SocketTimeoutException) {
                        break
                    }
                    if (client.receive(recvBuf, pkt.length, System.currentTimeMillis(), ack, plain) ==
                        V2Client.Event.ESTABLISHED) {
                        sock.send(DatagramPacket(ack, client.lengths[0], server))
                        Log.i(TAG, "v2 established: hsid=${client.handshakeId()} ip=${V2Wire.ipToString(client.tunIp())}")
                        return
                    }
                }
            }
        } finally {
            runCatching { sock.soTimeout = 0 }
        }
        // A v2 node answers only clients it accepts, so silence can also mean "not authorized"
        throw SocketTimeoutException("no answer from the server (access not accepted, or server unreachable)")
    }

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

        // Tap notification → open app
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val openAppPending = PendingIntent.getActivity(
            this, 1, openAppIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            else
                PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification =
            NotificationCompat.Builder(this, channelId)
                .setContentTitle("ThinkSlow VPN")
                .setContentText("VPN is running")
                .setSmallIcon(R.drawable.ic_vpn)
                .setOngoing(true)
                .setContentIntent(openAppPending)
                .setOnlyAlertOnce(true)
                .build()

        startForeground(VPN_NOTIF_ID, notification)
    }
}
