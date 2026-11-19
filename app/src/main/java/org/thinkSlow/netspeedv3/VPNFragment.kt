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
import android.widget.EditText
import android.widget.ImageView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.google.android.material.button.MaterialButton
import org.thinkSlow.netspeedv3.vpn.AccessStore
import org.thinkSlow.netspeedv3.vpn.BundleNode

class VPNFragment : Fragment(R.layout.fragment_vpn) {

    private lateinit var connectBtn: View            // FrameLayout ring button
    private lateinit var connectRingOuter: View       // Outer ring for styling
    private lateinit var connectIcon: ImageView       // Power icon inside ring
    private lateinit var connectLabel: TextView       // "Connected" / "Disconnected" label
    private lateinit var disconnectBtn: MaterialButton
    private lateinit var serverIpInput: EditText
    private lateinit var statusTextView: TextView
    private lateinit var spinnerServers: Spinner

    // Status banner (connected state)
    private lateinit var statusBanner: View
    private lateinit var statusBannerText: TextView

    // Stats row
    private lateinit var statsRow: View

    // Session info panel
    private lateinit var infoPanel: View
    private lateinit var tvAssignedIp: TextView
    private lateinit var tvActiveMss: TextView
    private lateinit var tvSessionId: TextView

    private lateinit var tvSecurity: TextView

    // Auth gate overlay
    private lateinit var authGateLayout: View
    private lateinit var btnGoSignIn: View

    // Access gate (protocol v2: no imported access, or it expired)
    private lateinit var accessGateLayout: View
    private lateinit var tvAccessGateText: TextView
    private lateinit var btnGoProfile: View

    // Server card, v2: node from the imported access instead of a typed IP
    private lateinit var tvServerNode: TextView
    private lateinit var tvServerDetail: TextView

    private lateinit var accessStore: AccessStore
    private var legacyV1 = false
    private var nodes: List<BundleNode> = emptyList()

    private val vpnStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            // Handle simple toast/status messages
            intent?.getStringExtra("msg")?.let { msg ->
                statusTextView.text = msg
                // updateConnectionUI(false) overwrites the status text, so surface failures as a toast
                // ("Disconnected: ..." is the server ending the session, e.g. access revoked)
                if (msg.startsWith("Connection failed") || msg.startsWith("Disconnected:")) {
                    Toast.makeText(requireContext(), msg, Toast.LENGTH_LONG).show()
                }
                updateConnectionUI(msg.contains("Connected") || msg.contains("Connecting"))

                if (msg.contains("Disconnected")) {
                    infoPanel.visibility = View.GONE
                    statsRow.visibility = View.GONE
                }
            }

            // Handle session-specific info updates
            if (intent?.action == "vpn_status_update") {
                // The tunnel is up. Also covers the first connect: returning from the system
                // VPN-consent dialog runs onResume() before the handshake ends, and that resets the ring.
                updateConnectionUI(true)
                infoPanel.visibility = View.VISIBLE
                statsRow.visibility = View.VISIBLE
                tvAssignedIp.text = intent.getStringExtra("ip") ?: "0.0.0.0"
                tvSessionId.text = intent.getStringExtra("sid") ?: "N/A"

                val mtu = intent.getIntExtra("mtu", 1320)
                val mss = intent.getIntExtra("mss", 1160)
                tvActiveMss.text = "$mtu (MSS: $mss)"
                tvSecurity.text = intent.getStringExtra("security")?.ifBlank { null } ?: "N/A"
                intent.getStringExtra("server")?.takeIf { it.isNotBlank() }?.let {
                    statusBannerText.text = "Connected to $it"
                }
            }
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { startVpn() }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Connect ring button
        connectBtn = view.findViewById(R.id.btn_connect_vpn)
        connectRingOuter = view.findViewById(R.id.connect_ring_outer)
        connectIcon = view.findViewById(R.id.iv_connect_icon)
        connectLabel = view.findViewById(R.id.tv_connect_label)

        // Disconnect button
        disconnectBtn = view.findViewById(R.id.btn_disconnect_vpn)

        // Status banner
        statusBanner = view.findViewById(R.id.ll_status_banner)
        statusBannerText = view.findViewById(R.id.tv_status_banner_text)

        // Stats
        statsRow = view.findViewById(R.id.ll_stats_row)

        // Session info panel
        infoPanel = view.findViewById(R.id.ll_info_panel)
        tvAssignedIp = view.findViewById(R.id.tv_assigned_ip)
        tvActiveMss = view.findViewById(R.id.tv_active_mss)
        tvSessionId = view.findViewById(R.id.tv_session_id)
        tvSecurity = view.findViewById(R.id.tv_security)

        // Auth gate
        authGateLayout = view.findViewById(R.id.ll_auth_gate)
        btnGoSignIn = view.findViewById(R.id.btn_go_sign_in)

        // Access gate
        accessGateLayout = view.findViewById(R.id.ll_access_gate)
        tvAccessGateText = view.findViewById(R.id.tv_access_gate_text)
        btnGoProfile = view.findViewById(R.id.btn_go_profile)

        tvServerNode = view.findViewById(R.id.tv_server_node)
        tvServerDetail = view.findViewById(R.id.tv_server_detail)
        accessStore = AccessStore(requireContext())

        // Server input
        serverIpInput = view.findViewById(R.id.et_server_ip)
        statusTextView = view.findViewById(R.id.tv_vpn_status)
        spinnerServers = view.findViewById(R.id.spinner_saved_servers)

        connectBtn.setOnClickListener { requestVpnPermission() }
        disconnectBtn.setOnClickListener { stopVpn() }
        btnGoSignIn.setOnClickListener {
            (activity as? MainActivity)?.navigateToProfile()
        }
        btnGoProfile.setOnClickListener {
            (activity as? MainActivity)?.navigateToProfile()
        }

        // Spinner: legacy v1 fills the IP field with a saved server; v2 picks a node of the access
        spinnerServers.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                if (!legacyV1) {
                    nodes.getOrNull(pos)?.let { selectNode(it) }
                    return
                }
                val selected = parent?.getItemAtPosition(pos)?.toString() ?: return
                if (selected != getString(R.string.select_server_hint)) {
                    serverIpInput.setText(selected)
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        refreshServerCard()
        restoreVpnState()
        updateAuthState()
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter()
        filter.addAction("vpn_toast")
        filter.addAction("vpn_status_update")

        LocalBroadcastManager.getInstance(requireContext())
            .registerReceiver(vpnStatusReceiver, filter)

        refreshServerCard()
        restoreVpnState()
        updateAuthState()
    }

    override fun onPause() {
        super.onPause()
        LocalBroadcastManager.getInstance(requireContext())
            .unregisterReceiver(vpnStatusReceiver)
    }

    // ── Visual State Management ────────────────────────────────

    private fun updateConnectionUI(isConnected: Boolean) {
        if (isConnected) {
            // Connected: green ring, teal fill, shield icon
            connectRingOuter.setBackgroundResource(R.drawable.ring_connected)
            connectBtn.setBackgroundResource(R.drawable.circle_connected)
            connectIcon.setImageResource(R.drawable.ic_shield_check)
            connectIcon.imageTintList = ContextCompat.getColorStateList(requireContext(), R.color.primaryDark)
            connectLabel.text = getString(R.string.vpn_status_protected)
            connectLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.primaryDark))
            statusTextView.visibility = View.GONE
            statusBanner.visibility = View.VISIBLE
            statusBannerText.text = "Connected to ${currentServerName().ifEmpty { "server" }}"
            disconnectBtn.visibility = View.VISIBLE
            connectBtn.isClickable = false
            spinnerServers.isEnabled = false
        } else {
            // Disconnected: gray ring, white fill, power icon
            connectRingOuter.setBackgroundResource(R.drawable.ring_disconnected)
            connectBtn.setBackgroundResource(R.drawable.circle_disconnected)
            connectIcon.setImageResource(R.drawable.ic_power)
            connectIcon.imageTintList = ContextCompat.getColorStateList(requireContext(), R.color.textSecondary)
            connectLabel.text = "Connect"
            connectLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.textSecondary))
            statusTextView.visibility = View.VISIBLE
            statusTextView.text = getString(R.string.vpn_status_not_connected)
            statusTextView.setTextColor(ContextCompat.getColor(requireContext(), R.color.textTertiary))
            statusBanner.visibility = View.GONE
            disconnectBtn.visibility = View.GONE
            connectBtn.isClickable = true
            spinnerServers.isEnabled = true
        }
    }

    /** Server shown in the banner: what the service connected to, else what is selected here. */
    private fun currentServerName(): String =
        MyVpnService.activeServerName.ifBlank {
            if (legacyV1) serverIpInput.text.toString().trim() else accessStore.selectedNode()?.id ?: ""
        }

    // ── State Restoration ───────────────────────────────────────

    /** Restore UI if the VPN service is still running (e.g. after app backgrounded) */
    private fun restoreVpnState() {
        if (MyVpnService.isActive) {
            updateConnectionUI(true)

            // Restore session info panel
            infoPanel.visibility = View.VISIBLE
            statsRow.visibility = View.VISIBLE
            tvAssignedIp.text = MyVpnService.activeIpStr.ifBlank { "0.0.0.0" }
            tvSessionId.text = MyVpnService.activeSessionId.ifBlank { "N/A" }
            tvActiveMss.text = "${MyVpnService.activeMtu} (MSS: ${MyVpnService.activeMss})"
            tvSecurity.text = MyVpnService.activeSecurity.ifBlank { "N/A" }
        } else {
            // Only reset if we're not already showing a "Disconnecting..." state
            if (statusTextView.text != getString(R.string.vpn_disconnecting)) {
                updateConnectionUI(false)
                infoPanel.visibility = View.GONE
                statsRow.visibility = View.GONE
            }
        }
    }

    // ── Server Card ─────────────────────────────────────────────

    /** Legacy v1: typed IP + saved servers. v2: the nodes of the imported access. */
    private fun refreshServerCard() {
        legacyV1 = VpnSettingsFragment.isLegacyV1(requireContext())
        if (legacyV1) {
            nodes = emptyList()
            serverIpInput.visibility = View.VISIBLE
            tvServerNode.visibility = View.GONE
            tvServerDetail.visibility = View.GONE
            populateServerSpinner()
            return
        }

        serverIpInput.visibility = View.GONE
        tvServerNode.visibility = View.VISIBLE
        nodes = accessStore.bundle()?.nodes ?: emptyList()
        val node = accessStore.selectedNode()
        if (node == null) {
            tvServerNode.text = getString(R.string.access_none_title)
            tvServerDetail.visibility = View.GONE
        } else {
            showNode(node)
        }

        // Spinner only when the access covers more than one server
        if (nodes.size > 1) {
            val adapter = ArrayAdapter(requireContext(), android.R.layout.simple_spinner_item, nodes.map { it.id })
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            spinnerServers.adapter = adapter
            spinnerServers.setSelection(nodes.indexOfFirst { it.id == node?.id }.coerceAtLeast(0), false)
            spinnerServers.visibility = View.VISIBLE
        } else {
            spinnerServers.visibility = View.GONE
        }
    }

    private fun showNode(node: BundleNode) {
        tvServerNode.text = node.id
        tvServerDetail.text = "${node.host}:${node.port}"
        tvServerDetail.visibility = View.VISIBLE
    }

    private fun selectNode(node: BundleNode) {
        if (accessStore.selectedNodeId != node.id) accessStore.selectedNodeId = node.id
        showNode(node)
    }

    // ── Saved Server Spinner (legacy v1) ────────────────────────

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
        val accessProblem = if (signedIn && !legacyV1) accessProblem() else null
        accessGateLayout.visibility = if (accessProblem != null) View.VISIBLE else View.GONE
        accessProblem?.let { tvAccessGateText.text = it }
        if (signedIn) {
            authGateLayout.visibility = View.GONE
            // Don't override button state if VPN is already running
            if (!MyVpnService.isActive) {
                connectBtn.isClickable = accessProblem == null
            }
        } else {
            authGateLayout.visibility = View.VISIBLE
            connectBtn.isClickable = false
            disconnectBtn.isEnabled = false
        }
    }

    /** Why a v2 connect cannot start, or null when the imported access is usable. */
    private fun accessProblem(): String? {
        val bundle = accessStore.bundle()
        if (bundle == null || !accessStore.hasAccess()) return getString(R.string.vpn_access_required)
        val info = bundle.ticketInfo
        if (info.isExpired()) return getString(R.string.vpn_access_expired, AccessStore.formatDate(info.exp))
        return null
    }

    // ── VPN Controls ────────────────────────────────────────────

    private fun requestVpnPermission() {
        if (legacyV1) {
            val serverIp = serverIpInput.text.toString().trim()
            if (serverIp.isEmpty()) {
                Toast.makeText(requireContext(), "Enter server IP", Toast.LENGTH_SHORT).show()
                return
            }
        } else {
            accessProblem()?.let {
                Toast.makeText(requireContext(), it, Toast.LENGTH_SHORT).show()
                updateAuthState()
                return
            }
        }

        val intent = VpnService.prepare(requireContext())
        if (intent != null) vpnPermissionLauncher.launch(intent)
        else startVpn()
    }

    private fun startVpn() {
        val intent = Intent(requireContext(), MyVpnService::class.java)
        if (legacyV1) {
            intent.putExtra("server_ip", serverIpInput.text.toString().trim())
        } else {
            intent.putExtra(MyVpnService.EXTRA_PROTOCOL, "v2")
            intent.putExtra(MyVpnService.EXTRA_NODE_ID, accessStore.selectedNode()?.id)
        }
        requireContext().startService(intent)

        statusTextView.text = getString(R.string.vpn_connecting)
        updateConnectionUI(true)
    }

    private fun stopVpn() {
        val intent = Intent(requireContext(), MyVpnService::class.java)
        intent.action = MyVpnService.ACTION_STOP
        requireContext().startService(intent)

        statusTextView.text = getString(R.string.vpn_disconnecting)
    }
}
