package com.example.netspeedv3

import android.Manifest
import android.content.*
import android.content.pm.PackageManager
import android.net.TrafficStats
import android.os.*
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import android.graphics.Color
import android.content.res.ColorStateList
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController

class MainActivity : AppCompatActivity() {

    private lateinit var toggleBtn: Button
    private lateinit var speedTv: TextView

    private var isServiceRunning = false
    private val handler = Handler(Looper.getMainLooper())
    private val updateInterval = 1000L // 1 second

    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) toggleService()
            else Toast.makeText(this, "Notification permission denied", Toast.LENGTH_SHORT).show()
        }

    private val serviceStoppedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == NetworkSpeedService.ACTION_SERVICE_STOPPED) {
                isServiceRunning = false
                updateButton()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val rootView = findViewById<View>(R.id.main) // your root ConstraintLayout ID

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val controller = window.insetsController
            controller?.systemBarsBehavior =
                WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE

            // Optional: light status bar icons (for dark background)
            controller?.setSystemBarsAppearance(
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS,
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
            )

            rootView.setOnApplyWindowInsetsListener { view, insets ->
                val statusBarHeight = insets.getInsets(WindowInsets.Type.statusBars()).top
                val navBarHeight = insets.getInsets(WindowInsets.Type.navigationBars()).bottom
                // Add padding so your content doesn’t overlap status/navigation bars
                view.setPadding(0, statusBarHeight, 0, navBarHeight)
                insets
            }
        } else {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility =
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or View.SYSTEM_UI_FLAG_LAYOUT_STABLE
            @Suppress("DEPRECATION")
            window.statusBarColor = Color.TRANSPARENT
        }


        window.decorView.fitsSystemWindows = true

        toggleBtn = findViewById(R.id.btn_toggle)
        speedTv = findViewById(R.id.tv_speed)

        toggleBtn.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                toggleService()
            }
        }

        val filter = IntentFilter(NetworkSpeedService.ACTION_SERVICE_STOPPED)
        ContextCompat.registerReceiver(
            this,
            serviceStoppedReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )



        startUpdatingSpeed() // Always show live speed
    }

    private fun toggleService() {
        if (!isServiceRunning) startSpeedService() else stopSpeedService()
        isServiceRunning = !isServiceRunning
        updateButton()
    }

    private fun updateButton() {
        if (isServiceRunning) {
            toggleBtn.text = "Stop Notification"
            toggleBtn.backgroundTintList =
                ColorStateList.valueOf(Color.parseColor("#D32F2F")) // red
        } else {
            toggleBtn.text = "Start Notification"
            toggleBtn.backgroundTintList =
                ColorStateList.valueOf(Color.parseColor("#1976D2")) // blue
        }
    }

    private fun startSpeedService() {
        val intent = Intent(this, NetworkSpeedService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            startForegroundService(intent)
        else
            startService(intent)
        Toast.makeText(this, "Notification started", Toast.LENGTH_SHORT).show()
    }

    private fun stopSpeedService() {
        stopService(Intent(this, NetworkSpeedService::class.java))
        Toast.makeText(this, "Notification stopped", Toast.LENGTH_SHORT).show()
    }

    // Live speed (always active)
    private val updateSpeedRunnable = object : Runnable {
        override fun run() {
            val downSpeed = NetworkSpeedService.getCurrentDownloadSpeed()
            val upSpeed = NetworkSpeedService.getCurrentUploadSpeed()

            if (downSpeed == 0.0 && upSpeed == 0.0) {
                // If service isn't running, fallback to direct TrafficStats read
                val rx = TrafficStats.getTotalRxBytes()
                val tx = TrafficStats.getTotalTxBytes()

                speedTv.text = "Reading network..."
            } else {
                speedTv.text = "⬇ ${"%.2f".format(downSpeed)} Mbps | ⬆ ${"%.2f".format(upSpeed)} Mbps"
            }

            handler.postDelayed(this, updateInterval)
        }
    }

    private fun startUpdatingSpeed() {
        handler.post(updateSpeedRunnable)
    }

    private fun stopUpdatingSpeed() {
        handler.removeCallbacks(updateSpeedRunnable)
    }

    override fun onDestroy() {
        unregisterReceiver(serviceStoppedReceiver)
        stopUpdatingSpeed()
        super.onDestroy()
    }
}
