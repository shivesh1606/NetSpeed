package com.yourname.netspeedv3

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment

class SpeedFragment : Fragment(R.layout.fragment_speed) {

    private lateinit var toggleBtn: Button
    private lateinit var speedTv: TextView

    private var isServiceRunning = false
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
                updateButton()
            }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        toggleBtn = view.findViewById(R.id.btn_toggle)
        speedTv = view.findViewById(R.id.tv_speed)

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

        startUpdatingSpeed()
    }

    private fun toggleService() {
        if (!isServiceRunning) startSpeedService() else stopSpeedService()
        isServiceRunning = !isServiceRunning
        updateButton()
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
            val downSpeed = NetworkSpeedService.getCurrentDownloadSpeed()
            val upSpeed = NetworkSpeedService.getCurrentUploadSpeed()

            speedTv.text = getString(
                R.string.speed_format,
                downSpeed,
                upSpeed
            )
            handler.postDelayed(this, updateInterval)
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
