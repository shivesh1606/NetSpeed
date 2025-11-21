package com.example.netspeedv3

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

@SuppressLint("VpnServicePolicy")
class MyVpnService : VpnService() {

    private var tunInterface: ParcelFileDescriptor? = null
    @Volatile private var running = false
    private var serverIp: String = ""

    companion object {
        const val ACTION_STOP = "STOP_VPN"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

        // Handle STOP action
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
        startVPN()

        return START_STICKY
    }

    private fun startForegroundNotification() {
        val channelId = "vpn_channel"
        val channelName = "VPN Service"

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                channelName,
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                ?.createNotificationChannel(channel)
        }

        val notification = androidx.core.app.NotificationCompat.Builder(this, channelId)
            .setContentTitle("ThinkSlow VPN")
            .setContentText("VPN is running")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .build()

        startForeground(1, notification)
    }

    private fun startVPN() {
        try {
            val builder = Builder()
            builder.setSession("ThinkSlow VPN")
            builder.addAddress("10.8.0.2", 24)
            builder.addDnsServer("8.8.8.8")
            builder.addRoute("0.0.0.0", 0) // Capture all traffic

            tunInterface = builder.establish()
            if (tunInterface == null) {
                sendToast("Failed to create TUN interface")
                stopSelf()
                return
            }
        } catch (e: Exception) {
            sendToast("VPN setup failed: ${e.message}")
            stopSelf()
            return
        }

        running = true
        Thread { vpnLoop() }.start()
        sendToast("VPN Connected")
    }

    private fun vpnLoop() {
        val fd = tunInterface?.fileDescriptor ?: return
        val tunIn = FileInputStream(fd)
        val tunOut = FileOutputStream(fd)

        val socket = DatagramSocket()
        socket.soTimeout = 200
        protect(socket)

        val server = InetSocketAddress(serverIp, 5555)
        val buffer = ByteArray(32767)
        val recvPacket = DatagramPacket(buffer, buffer.size)

        try {
            while (running) {
                val len = tunIn.read(buffer)
                if (len > 0) {
                    socket.send(DatagramPacket(buffer, len, server))
                }

                try {
                    socket.receive(recvPacket)
                    tunOut.write(buffer, 0, recvPacket.length)
                } catch (_: SocketTimeoutException) {}
            }
        } catch (e: Exception) {
            sendToast("VPN Loop Error: ${e.message}")
        } finally {
            socket.close()
        }
    }

    fun disconnectVpn() {
        running = false
        try {
            tunInterface?.close()
            tunInterface = null
        } catch (_: Exception) {}

        // Remove foreground notification
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        sendToast("VPN Disconnected")
        stopSelf()
    }

    override fun onDestroy() {
        disconnectVpn()
        super.onDestroy()
    }

    private fun sendToast(msg: String) {
        val intent = Intent("vpn_toast")
        intent.putExtra("msg", msg)
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }
}
