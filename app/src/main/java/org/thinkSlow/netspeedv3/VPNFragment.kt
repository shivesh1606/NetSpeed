package org.thinkSlow.netspeedv3

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
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
    private lateinit var spinnerServers: Spinner

    // Session info panel
    private lateinit var infoPanel: View
    private lateinit var tvAssignedIp: TextView
    private lateinit var tvActiveMss: TextView
    private lateinit var tvSessionId: TextView

    // Auth gate overlay
    private lateinit var authGateLayout: View
    private lateinit var btnGoSignIn: Button

    private val vpnStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            // Handle simple toast/status messages
            intent?.getStringExtra("msg")?.let { msg ->
                statusTextView.text = msg
                updateButtons(msg)

                if (msg.contains("Disconnected")) {
                    infoPanel.visibility = View.GONE
                }
            }

            // Handle session-specific info updates
            if (intent?.action == "vpn_status_update") {
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

        // Session info panel
        infoPanel = view.findViewById(R.id.ll_info_panel)
        tvAssignedIp = view.findViewById(R.id.tv_assigned_ip)
        tvActiveMss = view.findViewById(R.id.tv_active_mss)
        tvSessionId = view.findViewById(R.id.tv_session_id)

        // Auth gate
        authGateLayout = view.findViewById(R.id.ll_auth_gate)
        btnGoSignIn = view.findViewById(R.id.btn_go_sign_in)

        // Main controls
        connectBtn = view.findViewById(R.id.btn_connect_vpn)
        disconnectBtn = view.findViewById(R.id.btn_disconnect_vpn)
        serverIpInput = view.findViewById(R.id.et_server_ip)
        statusTextView = view.findViewById(R.id.tv_vpn_status)
        spinnerServers = view.findViewById(R.id.spinner_saved_servers)

        connectBtn.setOnClickListener { requestVpnPermission() }
        disconnectBtn.setOnClickListener { stopVpn() }
        btnGoSignIn.setOnClickListener {
            (activity as? MainActivity)?.navigateToProfile()
        }

        // Spinner: when user picks a saved server, fill the EditText
        spinnerServers.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                val selected = parent?.getItemAtPosition(pos)?.toString() ?: return
                if (selected != getString(R.string.select_server_hint)) {
                    serverIpInput.setText(selected)
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        updateAuthState()
        restoreVpnState()
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter()
        filter.addAction("vpn_toast")
        filter.addAction("vpn_status_update")

        LocalBroadcastManager.getInstance(requireContext())
            .registerReceiver(vpnStatusReceiver, filter)

        updateAuthState()
        restoreVpnState()
        populateServerSpinner()
    }

    override fun onPause() {
        super.onPause()
        LocalBroadcastManager.getInstance(requireContext())
            .unregisterReceiver(vpnStatusReceiver)
    }

    // ── State Restoration ───────────────────────────────────────

    /** Restore UI if the VPN service is still running (e.g. after app backgrounded) */
    private fun restoreVpnState() {
        if (MyVpnService.isActive) {
            statusTextView.text = "VPN Connected"
            updateButtons(isVpnRunning = true)

            // Restore session info panel
            infoPanel.visibility = View.VISIBLE
            tvAssignedIp.text = MyVpnService.activeIpStr.ifBlank { "0.0.0.0" }
            tvSessionId.text = MyVpnService.activeSessionId.ifBlank { "N/A" }
            tvActiveMss.text = "${MyVpnService.activeMtu} (MSS: ${MyVpnService.activeMss})"
        } else {
            // Only reset if we're not already showing a "Disconnecting..." state
            if (statusTextView.text != "Disconnecting...") {
                statusTextView.text = "VPN Disconnected"
                updateButtons(isVpnRunning = false)
                infoPanel.visibility = View.GONE
            }
        }
    }

    // ── Saved Server Spinner ────────────────────────────────────

    private fun populateServerSpinner() {
        val prefs = requireContext().getSharedPreferences(
            ProfileFragment.PREFS_NAME, Context.MODE_PRIVATE
        )
        val raw = prefs.getString(ProfileFragment.KEY_SAVED_SERVERS, "") ?: ""
        val servers = if (raw.isBlank()) emptyList() else raw.split(",")

        val items = mutableListOf(getString(R.string.select_server_hint))
        items.addAll(servers)

        val adapter = ArrayAdapter(requireContext(), android.R.layout.simple_spinner_item, items)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerServers.adapter = adapter

        // Hide spinner if no saved servers
        spinnerServers.visibility = if (servers.isEmpty()) View.GONE else View.VISIBLE
    }

    // ── Auth Gate ───────────────────────────────────────────────

    private fun updateAuthState() {
        val signedIn = (activity as? MainActivity)?.isUserSignedIn() == true
        if (signedIn) {
            authGateLayout.visibility = View.GONE
            // Don't override button state if VPN is already running
            if (!MyVpnService.isActive) {
                connectBtn.isEnabled = true
            }
        } else {
            authGateLayout.visibility = View.VISIBLE
            connectBtn.isEnabled = false
            disconnectBtn.isEnabled = false
        }
    }

    // ── VPN Controls ────────────────────────────────────────────

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

        statusTextView.text = "VPN Connected…"
        updateButtons(isVpnRunning = true)
    }

    private fun stopVpn() {
        val intent = Intent(requireContext(), MyVpnService::class.java)
        intent.action = MyVpnService.ACTION_STOP
        requireContext().startService(intent)

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
