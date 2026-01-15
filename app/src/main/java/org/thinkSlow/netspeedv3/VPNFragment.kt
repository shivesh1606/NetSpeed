package org.thinkSlow.netspeedv3

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.localbroadcastmanager.content.LocalBroadcastManager

class VPNFragment : Fragment(R.layout.fragment_vpn) {

    private lateinit var connectBtn: Button
    private lateinit var disconnectBtn: Button
    private lateinit var serverIpInput: EditText
    private lateinit var statusTextView: TextView

    // Existing views...
    private lateinit var infoPanel: View
    private lateinit var tvAssignedIp: TextView
    private lateinit var tvActiveMss: TextView
    private lateinit var tvSessionId: TextView

    private val vpnStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            // Handle simple toast/status messages
            intent?.getStringExtra("msg")?.let { msg ->
                statusTextView.text = msg
                updateButtons(msg)

                // PERFECT UX FIX: Hide panel only when the service confirms disconnection
                if (msg.contains("Disconnected")) {
                    infoPanel.visibility = View.GONE
                }
            }

            // Handle session-specific info updates
            if (intent?.action == "vpn_status_update") {
                // Show panel only when we actually have live data
                infoPanel.visibility = View.VISIBLE
                tvAssignedIp.text = intent.getStringExtra("ip") ?: "0.0.0.0"
                tvSessionId.text = intent.getStringExtra("sid") ?: "N/A"

                val mtu = intent.getIntExtra("mtu", 1320)
                val mss = intent.getIntExtra("mss", 1160)
                tvActiveMss.text = "$mtu (MSS: $mss)"
            }
        }
    }
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { startVpn() }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Initialize the new UI elements
        infoPanel = view.findViewById(R.id.ll_info_panel)
        tvAssignedIp = view.findViewById(R.id.tv_assigned_ip)
        tvActiveMss = view.findViewById(R.id.tv_active_mss)
        tvSessionId = view.findViewById(R.id.tv_session_id)

        // Existing button initializations...
        connectBtn = view.findViewById(R.id.btn_connect_vpn)
        disconnectBtn = view.findViewById(R.id.btn_disconnect_vpn)
        serverIpInput = view.findViewById(R.id.et_server_ip)
        statusTextView = view.findViewById(R.id.tv_vpn_status)

        connectBtn.setOnClickListener { requestVpnPermission() }
        disconnectBtn.setOnClickListener { stopVpn() }

        updateButtons(isVpnRunning = false)
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter()
        filter.addAction("vpn_toast")
        filter.addAction("vpn_status_update") // Listen for the detailed info

        LocalBroadcastManager.getInstance(requireContext())
            .registerReceiver(vpnStatusReceiver, filter)
    }

    override fun onPause() {
        super.onPause()
        LocalBroadcastManager.getInstance(requireContext())
            .unregisterReceiver(vpnStatusReceiver)
    }

    private fun requestVpnPermission() {
        val serverIp = serverIpInput.text.toString().trim()
//        val clientTunIp= clientIpInput.text.toString().trim()
        if (serverIp.isEmpty()) {
            Toast.makeText(requireContext(), "Enter server IP", Toast.LENGTH_SHORT).show()
            return
        }
//        if(clientTunIp.isEmpty()){
//            Toast.makeText(requireContext(), "Enter client Tun IP", Toast.LENGTH_SHORT).show()}

        val intent = VpnService.prepare(requireContext())
        if (intent != null) vpnPermissionLauncher.launch(intent)
        else startVpn()
    }

    private fun startVpn() {
        val serverIp = serverIpInput.text.toString().trim()
//        val clientTunIp = clientIpInput.text.toString().trim()

        val intent = Intent(requireContext(), MyVpnService::class.java)
        intent.putExtra("server_ip", serverIp)
//        intent.putExtra("client_tun_ip", clientTunIp)
        requireContext().startService(intent)

        statusTextView.text = "VPN Connected…"
        updateButtons(isVpnRunning = true)
    }

    private fun stopVpn() {
        val intent = Intent(requireContext(), MyVpnService::class.java)
        intent.action = MyVpnService.ACTION_STOP
        requireContext().startService(intent)

        // We removed 'infoPanel.visibility = View.GONE' from here
        // The receiver above will now handle it when the "Disconnected" toast arrives
        statusTextView.text = "Disconnecting..."
    }
    private fun updateButtons(msg: String) {
        val running = msg.contains("Connected") || msg.contains("Connecting")
        connectBtn.isEnabled = !running
        disconnectBtn.isEnabled = running
    }

    private fun updateButtons(isVpnRunning: Boolean) {
        connectBtn.isEnabled = !isVpnRunning
        disconnectBtn.isEnabled = isVpnRunning
    }
}
