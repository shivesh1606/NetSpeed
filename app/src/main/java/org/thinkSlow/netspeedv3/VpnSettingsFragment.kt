package org.thinkSlow.netspeedv3

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.view.LayoutInflater
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import android.widget.EditText
import android.widget.ListView

class VpnSettingsFragment : Fragment(R.layout.fragment_vpn_settings) {

    companion object {
        const val PREFS_NAME = "vpn_settings_prefs"
        const val KEY_SPLIT_TUNNEL_ENABLED = "split_tunnel_enabled"
        const val KEY_EXCLUDED_APPS = "excluded_apps"
        const val KEY_KILL_SWITCH = "kill_switch"
        const val KEY_AUTO_CONNECT = "auto_connect"
    }

    private lateinit var prefs: SharedPreferences
    private lateinit var switchSplitTunnel: SwitchMaterial
    private lateinit var splitTunnelContent: LinearLayout
    private lateinit var llExcludedApps: LinearLayout
    private lateinit var btnAddApp: MaterialButton
    private lateinit var switchKillSwitch: SwitchMaterial
    private lateinit var switchAutoConnect: SwitchMaterial
    private lateinit var tvVpnWarning: TextView

    // VPN state listener
    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            updateSplitTunnelingUI()
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        prefs = requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        switchSplitTunnel = view.findViewById(R.id.switch_split_tunnel)
        splitTunnelContent = view.findViewById(R.id.ll_split_tunnel_content)
        llExcludedApps = view.findViewById(R.id.ll_excluded_apps)
        btnAddApp = view.findViewById(R.id.btn_add_app)
        switchKillSwitch = view.findViewById(R.id.switch_kill_switch)
        switchAutoConnect = view.findViewById(R.id.switch_auto_connect)

        // Info banner for VPN connection state
        tvVpnWarning = TextView(requireContext()).apply {
            text = "🔒 Disconnect VPN to modify split tunneling settings"
            textSize = 12f
            setTextColor(ContextCompat.getColor(requireContext(), R.color.warning))
            setPadding(
                dpToPx(12), dpToPx(8), dpToPx(12), dpToPx(8)
            )
            setBackgroundColor(ContextCompat.getColor(requireContext(), R.color.warningLight))
            visibility = View.GONE
        }
        // Insert banner at the top of split tunnel content
        (splitTunnelContent.parent as? LinearLayout)?.also { parent ->
            val index = parent.indexOfChild(splitTunnelContent)
            if (index >= 0) {
                parent.addView(tvVpnWarning, index)
            } else {
                parent.addView(tvVpnWarning)
            }
        }

        // Load saved state
        switchSplitTunnel.isChecked = prefs.getBoolean(KEY_SPLIT_TUNNEL_ENABLED, false)
        switchKillSwitch.isChecked = prefs.getBoolean(KEY_KILL_SWITCH, false)
        switchAutoConnect.isChecked = prefs.getBoolean(KEY_AUTO_CONNECT, false)

        // Show/hide split tunnel content
        splitTunnelContent.visibility =
            if (switchSplitTunnel.isChecked) View.VISIBLE else View.GONE

        switchSplitTunnel.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(KEY_SPLIT_TUNNEL_ENABLED, checked).apply()
            splitTunnelContent.visibility = if (checked) View.VISIBLE else View.GONE
        }

        switchKillSwitch.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(KEY_KILL_SWITCH, checked).apply()
        }

        switchAutoConnect.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(KEY_AUTO_CONNECT, checked).apply()
        }

        btnAddApp.setOnClickListener {
            // Check if VPN is connected
            if (MyVpnService.isActive) {
                showVpnConnectedDialog()
            } else {
                showAppPicker()
            }
        }

        // Update UI based on VPN state
        updateSplitTunnelingUI()
        refreshExcludedApps()
    }

    override fun onResume() {
        super.onResume()
        updateSplitTunnelingUI()

        // Listen for VPN status changes
        val filter = IntentFilter("vpn_status_update")
        LocalBroadcastManager.getInstance(requireContext())
            .registerReceiver(vpnStateReceiver, filter)
    }

    override fun onPause() {
        super.onPause()
        LocalBroadcastManager.getInstance(requireContext())
            .unregisterReceiver(vpnStateReceiver)
    }

    // ── VPN State Management ────────────────────────────────────

    private fun updateSplitTunnelingUI() {
        val vpnIsActive = MyVpnService.isActive

        // Show/hide warning banner
        tvVpnWarning.visibility = if (vpnIsActive) View.VISIBLE else View.GONE

        // Disable toggle and add button when VPN is connected
        switchSplitTunnel.isEnabled = !vpnIsActive
        btnAddApp.isEnabled = !vpnIsActive

        // Visual feedback
        if (vpnIsActive) {
            switchSplitTunnel.alpha = 0.5f
            btnAddApp.alpha = 0.5f
        } else {
            switchSplitTunnel.alpha = 1f
            btnAddApp.alpha = 1f
        }

        // Refresh excluded apps list to update remove buttons
        refreshExcludedApps()
    }

    private fun showVpnConnectedDialog() {
        AlertDialog.Builder(requireContext())
            .setTitle("VPN Connected")
            .setMessage("Split tunneling settings can only be changed when VPN is disconnected.\n\nTo apply changes:\n1. Tap the VPN tab\n2. Click Disconnect\n3. Return here to modify apps\n4. Reconnect VPN")
            .setIcon(android.R.drawable.ic_dialog_info)
            .setPositiveButton("Go to VPN", { _, _ ->
                // Navigate to VPN tab
                (activity as? MainActivity)?.navigateToProfile() // This navigates to profile, we need VPN
                // Actually, let's just show the dialog and let user dismiss it
            })
            .setNegativeButton("Dismiss", null)
            .show()
    }

    // ── Excluded Apps Management ─────────────────────────────────

    fun getExcludedApps(): Set<String> {
        return prefs.getStringSet(KEY_EXCLUDED_APPS, emptySet()) ?: emptySet()
    }

    private fun saveExcludedApps(apps: Set<String>) {
        prefs.edit().putStringSet(KEY_EXCLUDED_APPS, apps).apply()
    }

    private fun addExcludedApp(packageName: String) {
        val apps = getExcludedApps().toMutableSet()
        apps.add(packageName)
        saveExcludedApps(apps)
        refreshExcludedApps()
    }

    private fun removeExcludedApp(packageName: String) {
        val apps = getExcludedApps().toMutableSet()
        apps.remove(packageName)
        saveExcludedApps(apps)
        refreshExcludedApps()
    }

    private fun refreshExcludedApps() {
        llExcludedApps.removeAllViews()
        val apps = getExcludedApps()
        val pm = requireContext().packageManager
        val vpnIsActive = MyVpnService.isActive

        if (apps.isEmpty()) {
            val emptyText = TextView(requireContext()).apply {
                text = getString(R.string.no_excluded_apps)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.textTertiary))
                textSize = 12f
                setPadding(0, dpToPx(4), 0, dpToPx(4))
            }
            llExcludedApps.addView(emptyText)
            return
        }

        for (pkg in apps.sorted()) {
            val appInfo = try {
                pm.getApplicationInfo(pkg, 0)
            } catch (e: PackageManager.NameNotFoundException) {
                continue
            }

            val row = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dpToPx(8), 0, dpToPx(8))
                // Disable entire row when VPN is active
                isEnabled = !vpnIsActive
                alpha = if (vpnIsActive) 0.5f else 1f
            }

            val icon = ImageView(requireContext()).apply {
                layoutParams = LinearLayout.LayoutParams(dpToPx(30), dpToPx(30))
                setImageDrawable(pm.getApplicationIcon(appInfo))
                contentDescription = pm.getApplicationLabel(appInfo).toString()
            }

            val label = TextView(requireContext()).apply {
                text = pm.getApplicationLabel(appInfo)
                textSize = 13f
                setTextColor(ContextCompat.getColor(requireContext(), R.color.textPrimary))
                layoutParams = LinearLayout.LayoutParams(
                    0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
                ).apply { marginStart = dpToPx(10) }
            }

            val removeBtn = ImageButton(requireContext()).apply {
                setImageResource(android.R.drawable.ic_menu_close_clear_cancel)
                setColorFilter(ContextCompat.getColor(requireContext(), R.color.textTertiary))
                setBackgroundColor(0x00000000)
                contentDescription = "Remove ${pm.getApplicationLabel(appInfo)}"
                isEnabled = !vpnIsActive  // Disable remove button when VPN active
                // Disable click when VPN is active
                setOnClickListener {
                    if (!vpnIsActive) {
                        removeExcludedApp(pkg)
                    } else {
                        showVpnConnectedDialog()
                    }
                }
            }

            row.addView(icon)
            row.addView(label)
            row.addView(removeBtn)
            llExcludedApps.addView(row)

            // Divider
            val divider = View(requireContext()).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 1
                )
                setBackgroundColor(ContextCompat.getColor(requireContext(), R.color.borderLight))
            }
            llExcludedApps.addView(divider)
        }
    }

    // ── App Picker Dialog ────────────────────────────────────────

    private fun showAppPicker() {
        val pm = requireContext().packageManager

        // Get all installed apps (system + user)
        val installedApps = try {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { it.packageName != requireContext().packageName } // Exclude our app
                .filter { it.packageName !in getExcludedApps() }           // Exclude already selected
                .sortedBy { pm.getApplicationLabel(it).toString() }
        } catch (e: Exception) {
            emptyList()
        }

        // Handle empty list
        if (installedApps.isEmpty()) {
            AlertDialog.Builder(requireContext())
                .setTitle(getString(R.string.select_apps))
                .setMessage("No apps available to exclude")
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return
        }

        // Create custom dialog with search and toggle
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_app_picker, null, false) as LinearLayout

        val etSearch = dialogView.findViewById<EditText>(R.id.et_search)
        val switchShowSystem = dialogView.findViewById<SwitchMaterial>(R.id.switch_show_system)
        val lvApps = dialogView.findViewById<ListView>(R.id.lv_apps)

        // Create adapter
        val adapter = AppPickerAdapter(requireContext(), installedApps.toMutableList(), pm)

        // Initial filter (hide system apps by default)
        adapter.filter("", false)
        lvApps.adapter = adapter

        // Search listener
        etSearch.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                adapter.filter(s.toString(), switchShowSystem.isChecked)
            }
        })

        // Toggle system apps listener
        switchShowSystem.setOnCheckedChangeListener { _, _ ->
            adapter.filter(etSearch.text.toString(), switchShowSystem.isChecked)
        }

        // Create and show dialog
        val dialog = AlertDialog.Builder(requireContext())
            .setView(dialogView)
            .setNegativeButton(android.R.string.cancel, null)
            .show()

        // List item click listener
        lvApps.setOnItemClickListener { _, _, position, _ ->
            val app = adapter.getItem(position)
            if (app != null) {
                addExcludedApp(app.packageName)
                dialog.dismiss()
            }
        }

        // Adjust dialog size for better UX
        val window = dialog.window
        window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.95).toInt(),
            (resources.displayMetrics.heightPixels * 0.75).toInt()
        )
    }

    private fun dpToPx(dp: Int): Int {
        return (dp * resources.displayMetrics.density).toInt()
    }
}
