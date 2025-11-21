package com.example.netspeedv3

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

    private val vpnStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val msg = intent?.getStringExtra("msg") ?: return
            statusTextView.text = msg
            updateButtons(msg)
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { startVpn() }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

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
        LocalBroadcastManager.getInstance(requireContext())
            .registerReceiver(vpnStatusReceiver, IntentFilter("vpn_toast"))
    }

    override fun onPause() {
        super.onPause()
        LocalBroadcastManager.getInstance(requireContext())
            .unregisterReceiver(vpnStatusReceiver)
    }

    private fun requestVpnPermission() {
        val serverIp = serverIpInput.text.toString().trim()
        if (serverIp.isEmpty()) {
            Toast.makeText(requireContext(), "Enter server IP", Toast.LENGTH_SHORT).show()
            return
        }

        val intent = VpnService.prepare(requireContext())
        if (intent != null) vpnPermissionLauncher.launch(intent)
        else startVpn()
    }

    private fun startVpn() {
        val serverIp = serverIpInput.text.toString().trim()
        val intent = Intent(requireContext(), MyVpnService::class.java)
        intent.putExtra("server_ip", serverIp)
        requireContext().startService(intent)

        statusTextView.text = "VPN Connecting…"
        updateButtons(isVpnRunning = true)
    }

    private fun stopVpn() {
        val intent = Intent(requireContext(), MyVpnService::class.java)
        intent.action = MyVpnService.ACTION_STOP
        requireContext().startService(intent) // send STOP action

        statusTextView.text = "VPN Disconnected"
        updateButtons(isVpnRunning = false)
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
