package com.yourname.netspeedv3

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
    private  lateinit var clientIpInput: EditText
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
//        clientIpInput = view.findViewById(R.id.et_client_ip)

        connectBtn.setOnClickListener { requestVpnPermission() }
        disconnectBtn.setOnClickListener { stopVpn() }

        // Check authentication status and update UI accordingly
        val activity = requireActivity() as MainActivity
        val googleAuthManager = activity.getGoogleAuthManager()
        
        if (!googleAuthManager.isSignedIn()) {
            connectBtn.isEnabled = false
            statusTextView.text = "VPN service requires authentication. Please sign in first."
        } else {
            connectBtn.isEnabled = true
        }
        
        updateButtons(isVpnRunning = false)
    }

    override fun onResume() {
        super.onResume()
        LocalBroadcastManager.getInstance(requireContext())
            .registerReceiver(vpnStatusReceiver, IntentFilter("vpn_toast"))
            
        // Update UI based on authentication status when fragment resumes
        val activity = requireActivity() as MainActivity
        val googleAuthManager = activity.getGoogleAuthManager()
        
        if (::connectBtn.isInitialized) {
            if (!googleAuthManager.isSignedIn()) {
                connectBtn.isEnabled = false
                statusTextView.text = "VPN service requires authentication. Please sign in first."
            } else {
                connectBtn.isEnabled = true
                // If user was previously disconnected, reset status text
                if (statusTextView.text.contains("requires authentication")) {
                    statusTextView.text = "VPN Disconnected"
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        LocalBroadcastManager.getInstance(requireContext())
            .unregisterReceiver(vpnStatusReceiver)
    }

    private fun requestVpnPermission() {
        // Check if user is authenticated before allowing VPN connection
        val activity = requireActivity() as MainActivity
        val googleAuthManager = activity.getGoogleAuthManager()
        
        if (!googleAuthManager.isSignedIn()) {
            Toast.makeText(requireContext(), "Please sign in to use VPN service", Toast.LENGTH_LONG).show()
            // Optionally redirect to sign in
            // For now, just return without starting VPN
            return
        }
        
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
        requireContext().startService(intent) // send STOP action

        statusTextView.text = "VPN Disconnected"
        updateButtons(isVpnRunning = false)
    }

    private fun updateButtons(msg: String) {
        val running = msg.contains("Connected") || msg.contains("Connecting")
        val activity = requireActivity() as MainActivity
        val googleAuthManager = activity.getGoogleAuthManager()
        
        // Only enable connect button if user is signed in AND VPN is not running
        connectBtn.isEnabled = googleAuthManager.isSignedIn() && !running
        disconnectBtn.isEnabled = running
    }

    private fun updateButtons(isVpnRunning: Boolean) {
        val activity = requireActivity() as MainActivity
        val googleAuthManager = activity.getGoogleAuthManager()
        
        // Only enable connect button if user is signed in AND VPN is not running
        connectBtn.isEnabled = googleAuthManager.isSignedIn() && !isVpnRunning
        disconnectBtn.isEnabled = isVpnRunning
    }
}
