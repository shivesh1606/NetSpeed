package com.example.netspeedv3

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
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
private const val DEFAULT_MTU = 1200

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
            val sid =
                ((buf[1].toInt() and 0xFF) shl 24) or
                        ((buf[2].toInt() and 0xFF) shl 16) or
                        ((buf[3].toInt() and 0xFF) shl 8) or
                        (buf[4].toInt() and 0xFF)

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

    private var tunInterface: ParcelFileDescriptor? = null
    private var serverIp: String = ""

    /* ============================================================
     *  SIMPLE XOR ENCRYPTION (TEMP)
     * ============================================================ */
    object Encryption {
        var key: Byte = 'K'.code.toByte()

        fun crypt(data: ByteArray, len: Int): ByteArray {
            val out = ByteArray(len)
            for (i in 0 until len) out[i] = data[i] xor key
            return out
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
            Thread { vpnMainLoop() }.start()
        }

        return START_STICKY
    }

    /* ============================================================
     *  MAIN VPN LOOP
     * ============================================================ */
    private fun vpnMainLoop() {
        Log.i(TAG, "VPN loop started")

        val socket = DatagramSocket()
        socket.soTimeout = 2000
        protect(socket)

        val serverAddr = InetSocketAddress(serverIp, SERVER_PORT)
        val buffer = ByteArray(32767)
        val recvPacket = DatagramPacket(buffer, buffer.size)

        try {
            val assignedIp = performHandshake(socket, serverAddr, recvPacket)
            createTun(assignedIp)

            val fd = tunInterface!!.fileDescriptor
            val tunIn = FileInputStream(fd)
            val tunOut = FileOutputStream(fd)

            running = true
            socket.soTimeout = 200

            while (running) {
                /* ---- TUN → UDP ---- */
                val len = tunIn.read(buffer)
                if (len > 0) {
                    val header = PacketHeader(PKT_DATA, 0).toByteArray()
                    val encrypted = Encryption.crypt(buffer, len)

                    val out = ByteArray(header.size + encrypted.size)
                    System.arraycopy(header, 0, out, 0, header.size)
                    System.arraycopy(encrypted, 0, out, header.size, encrypted.size)

                    socket.send(DatagramPacket(out, out.size, serverAddr))
                }

                /* ---- UDP → TUN ---- */
                try {
                    socket.receive(recvPacket)
                    val totalLen = recvPacket.length
                    if (totalLen < HEADER_SIZE) continue

                    val hdr = PacketHeader.fromByteArray(buffer)
                    if (hdr.type != PKT_DATA) continue

                    val payloadLen = totalLen - HEADER_SIZE
                    val payload = Encryption.crypt(buffer.copyOfRange(5, 5 + payloadLen), payloadLen)
                    tunOut.write(payload)

                } catch (_: SocketTimeoutException) {}
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

        val ack = ByteArray(6)
        PacketHeader(PKT_CLIENT_ACK, 0).toByteArray().copyInto(ack, 0)
        socket.send(DatagramPacket(ack, ack.size, server))

        Log.i(TAG, "CLIENT_ACK sent")
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
            androidx.core.app.NotificationCompat.Builder(this, channelId)
                .setContentTitle("ThinkSlow VPN")
                .setContentText("VPN is running")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build()

        startForeground(1, notification)
    }
}
