package org.thinkSlow.netspeedv3

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.TrafficStats
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton

class SpeedFragment : Fragment(R.layout.fragment_speed) {

    private lateinit var toggleBtn: MaterialButton
    private lateinit var speedTv: TextView           // Hidden legacy view
    private lateinit var speedValueTv: TextView      // Big number display
    private lateinit var downloadTv: TextView        // Download card value
    private lateinit var uploadTv: TextView          // Upload card value

    // Data usage views
    private lateinit var tvDataTotal: TextView
    private lateinit var tvDataDown: TextView
    private lateinit var tvDataUp: TextView
    private lateinit var viewDataProgress: View

    // Track data usage from when fragment was created
    private var sessionStartRx = 0L
    private var sessionStartTx = 0L

    private var isServiceRunning = false
    private var pendingStart = false  // Tracks if we just requested a start
    private val handler = Handler(Looper.getMainLooper())
    private val updateInterval = 1000L

    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) toggleService()
            else Toast.makeText(requireContext(), "Notification permission denied", Toast.LENGTH_SHORT).show()
        }

    private val serviceStoppedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == NetworkSpeedService.ACTION_SERVICE_STOPPED) {
                isServiceRunning = false
                pendingStart = false
                updateButton()
            }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        toggleBtn = view.findViewById(R.id.btn_toggle)
        speedTv = view.findViewById(R.id.tv_speed)
        speedValueTv = view.findViewById(R.id.tv_speed_value)
        downloadTv = view.findViewById(R.id.tv_download_speed)
        uploadTv = view.findViewById(R.id.tv_upload_speed)

        // Data usage views
        tvDataTotal = view.findViewById(R.id.tv_data_total)
        tvDataDown = view.findViewById(R.id.tv_data_down)
        tvDataUp = view.findViewById(R.id.tv_data_up)
        viewDataProgress = view.findViewById(R.id.view_data_progress)

        // Capture baseline for data usage
        sessionStartRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
        sessionStartTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)

        toggleBtn.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                toggleService()
            }
        }

        val filter = IntentFilter(NetworkSpeedService.ACTION_SERVICE_STOPPED)
        ContextCompat.registerReceiver(
            requireContext(),
            serviceStoppedReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        // Restore state from service's static flag
        restoreServiceState()

        startUpdatingSpeed()
    }

    override fun onResume() {
        super.onResume()
        // If we had a pending start, check if the service actually started
        if (pendingStart && NetworkSpeedService.isActive) {
            isServiceRunning = true
            pendingStart = false
            updateButton()
        } else if (!pendingStart) {
            restoreServiceState()
        }
    }

    /** Sync the button/UI with whether the service is actually running */
    private fun restoreServiceState() {
        isServiceRunning = NetworkSpeedService.isActive
        updateButton()
    }

    private fun toggleService() {
        if (!isServiceRunning && !pendingStart) {
            startSpeedService()
            pendingStart = true
            // Don't flip isServiceRunning yet — wait for confirmation
            // Use a short delay to check if the service actually started
            handler.postDelayed({
                if (NetworkSpeedService.isActive) {
                    isServiceRunning = true
                    pendingStart = false
                    updateButton()
                } else {
                    // Service failed to start
                    pendingStart = false
                }
            }, 500)
            // Show "Stop" immediately for responsiveness
            isServiceRunning = true
            updateButton()
        } else if (isServiceRunning) {
            stopSpeedService()
            isServiceRunning = false
            pendingStart = false
            updateButton()
        }
    }

    private fun updateButton() {
        toggleBtn.text =
            if (isServiceRunning)
                getString(R.string.stop_notification)
            else
                getString(R.string.start_notification)
    }

    private fun startSpeedService() {
        val intent = Intent(requireContext(), NetworkSpeedService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            requireContext().startForegroundService(intent)
        else
            requireContext().startService(intent)
    }

    private fun stopSpeedService() {
        requireContext().stopService(Intent(requireContext(), NetworkSpeedService::class.java))
    }

    private val updateSpeedRunnable = object : Runnable {
        override fun run() {
            if (!isAdded) return

            val downSpeed = NetworkSpeedService.getCurrentDownloadSpeed()
            val upSpeed = NetworkSpeedService.getCurrentUploadSpeed()

            // Update legacy hidden text
            speedTv.text = getString(R.string.speed_format, downSpeed, upSpeed)

            // Update new UI cards
            speedValueTv.text = String.format("%.1f", downSpeed)
            downloadTv.text = String.format("%.1f", downSpeed)
            uploadTv.text = String.format("%.1f", upSpeed)

            // Update data usage
            updateDataUsage()

            handler.postDelayed(this, updateInterval)
        }
    }

    private fun updateDataUsage() {
        val currentRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
        val currentTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)

        val deltaRx = (currentRx - sessionStartRx).coerceAtLeast(0L)
        val deltaTx = (currentTx - sessionStartTx).coerceAtLeast(0L)
        val total = deltaRx + deltaTx

        tvDataTotal.text = formatBytes(total)
        tvDataDown.text = "${formatBytes(deltaRx)} down"
        tvDataUp.text = "${formatBytes(deltaTx)} up"

        // Progress bar: show ratio relative to 1 GB cap (just for visual)
        val capBytes = 1_000_000_000L // 1 GB visual cap
        val ratio = (total.toFloat() / capBytes).coerceIn(0f, 1f)
        viewDataProgress.post {
            val parent = viewDataProgress.parent as? View ?: return@post
            val parentWidth = parent.width
            if (parentWidth > 0) {
                val lp = viewDataProgress.layoutParams
                lp.width = (parentWidth * ratio).toInt().coerceAtLeast(if (total > 0) 4 else 0)
                viewDataProgress.layoutParams = lp
            }
        }
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1_000 -> "$bytes B"
            bytes < 1_000_000 -> String.format("%.1f KB", bytes / 1_000.0)
            bytes < 1_000_000_000 -> String.format("%.1f MB", bytes / 1_000_000.0)
            else -> String.format("%.2f GB", bytes / 1_000_000_000.0)
        }
    }

    private fun startUpdatingSpeed() {
        handler.post(updateSpeedRunnable)
    }

    override fun onDestroyView() {
        handler.removeCallbacks(updateSpeedRunnable)
        requireContext().unregisterReceiver(serviceStoppedReceiver)
        super.onDestroyView()
    }
}
