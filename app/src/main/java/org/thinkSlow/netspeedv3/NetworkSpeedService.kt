package org.thinkSlow.netspeedv3

import android.app.*
import android.content.Intent
import android.net.TrafficStats
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import kotlin.math.max

class NetworkSpeedService : Service() {

    companion object {
        const val CHANNEL_ID = "speed_channel"
        const val NOTIF_ID = 1
        const val ACTION_SERVICE_STOPPED = "org.thinkSlow.netspeedv3.SERVICE_STOPPED"

        @Volatile private var currentDownloadSpeed = 0.0 // Mbps
        @Volatile private var currentUploadSpeed = 0.0   // Mbps

        fun getCurrentDownloadSpeed(): Double = currentDownloadSpeed
        fun getCurrentUploadSpeed(): Double = currentUploadSpeed
    }

    private val handler = Handler(Looper.getMainLooper())
    private var lastRx = 0L
    private var lastTx = 0L
    private var lastTime = 0L
    private var intervalMs: Long = 1000 // 2 seconds

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        lastRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
        lastTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
        lastTime = System.currentTimeMillis()
        startForeground(NOTIF_ID, buildNotification("Starting..."))
        handler.post(updateRunnable)
    }

    private val updateRunnable = object : Runnable {
        override fun run() {
            try {
                val nowRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
                val nowTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
                val nowTime = System.currentTimeMillis()

                val timeDiffSec = max(1.0, (nowTime - lastTime) / 1000.0)
                val deltaRx = nowRx - lastRx
                val deltaTx = nowTx - lastTx

                val downMbps = (deltaRx * 8) / (timeDiffSec * 1_000_000)
                val upMbps = (deltaTx * 8) / (timeDiffSec * 1_000_000)

                currentDownloadSpeed = downMbps
                currentUploadSpeed = upMbps

                val content = String.format("⬇ %.2f Mbps | ⬆ %.2f Mbps", downMbps, upMbps)
                updateNotification(content)

                lastRx = nowRx
                lastTx = nowTx
                lastTime = nowTime
            } catch (e: Exception) {
                e.printStackTrace()
            } finally {
                handler.postDelayed(this, intervalMs)
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Network Speed",
                NotificationManager.IMPORTANCE_LOW
            )
            channel.setShowBadge(false)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(content: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            else
                PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Live Internet Speed")
            .setContentText(content)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setOnlyAlertOnce(true)
            .setDeleteIntent(
                PendingIntent.getBroadcast(
                    this, 0,
                    Intent(ACTION_SERVICE_STOPPED),
                    PendingIntent.FLAG_IMMUTABLE
                )
            )
            .build()
    }

    private fun updateNotification(content: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(content))
    }

    override fun onDestroy() {
        handler.removeCallbacks(updateRunnable)

        // Notify MainActivity that service stopped
        sendBroadcast(Intent(ACTION_SERVICE_STOPPED))
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
