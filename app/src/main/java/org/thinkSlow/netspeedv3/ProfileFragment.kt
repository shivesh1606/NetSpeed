package org.thinkSlow.netspeedv3

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.ApiException
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial

class ProfileFragment : Fragment(R.layout.fragment_profile) {

    companion object {
        private const val RC_SIGN_IN = 9001
        private const val WEB_CLIENT_ID =
            "1048662886051-ue3sugkp4s6knclsa9ja5c0b14s45feb.apps.googleusercontent.com"
        const val PREFS_NAME = "netspeed_prefs"
        const val KEY_SAVED_SERVERS = "saved_servers"
        const val KEY_DARK_THEME = "dark_theme"
        const val KEY_AUTO_NOTIF = "auto_speed_notif"
    }

    private lateinit var googleSignInClient: GoogleSignInClient
    private lateinit var prefs: SharedPreferences

    // Views
    private lateinit var signedOutLayout: LinearLayout
    private lateinit var signedInLayout: LinearLayout
    private lateinit var btnSignIn: MaterialButton
    private lateinit var btnSignOut: MaterialButton
    private lateinit var ivAvatar: ImageView
    private lateinit var tvName: TextView
    private lateinit var tvEmail: TextView
    private lateinit var switchTheme: SwitchMaterial
    private lateinit var switchAutoNotif: SwitchMaterial

    // Saved servers
    private lateinit var etAddServer: EditText
    private lateinit var btnAddServer: MaterialButton
    private lateinit var llServerList: LinearLayout

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        prefs = requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Configure Google Sign-In
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestIdToken(WEB_CLIENT_ID)
            .requestEmail()
            .requestProfile()
            .build()
        googleSignInClient = GoogleSignIn.getClient(requireActivity(), gso)

        // Bind views
        signedOutLayout = view.findViewById(R.id.ll_signed_out)
        signedInLayout = view.findViewById(R.id.ll_signed_in)
        btnSignIn = view.findViewById(R.id.btn_sign_in)
        btnSignOut = view.findViewById(R.id.btn_sign_out)
        ivAvatar = view.findViewById(R.id.iv_avatar)
        tvName = view.findViewById(R.id.tv_display_name)
        tvEmail = view.findViewById(R.id.tv_email)
        switchTheme = view.findViewById(R.id.switch_theme)
        switchAutoNotif = view.findViewById(R.id.switch_auto_notif)

        // Saved servers views
        etAddServer = view.findViewById(R.id.et_add_server)
        btnAddServer = view.findViewById(R.id.btn_add_server)
        llServerList = view.findViewById(R.id.ll_server_list)

        btnSignIn.setOnClickListener { signIn() }
        btnSignOut.setOnClickListener { signOut() }

        btnAddServer.setOnClickListener {
            val ip = etAddServer.text.toString().trim()
            if (ip.isEmpty()) {
                Toast.makeText(requireContext(), "Enter a server IP", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            addServer(ip)
            etAddServer.text.clear()
        }

        // Load saved settings
        switchTheme.isChecked = prefs.getBoolean(KEY_DARK_THEME, false)
        switchAutoNotif.isChecked = prefs.getBoolean(KEY_AUTO_NOTIF, false)

        // Settings listeners
        switchTheme.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(KEY_DARK_THEME, checked).apply()
            AppCompatDelegate.setDefaultNightMode(
                if (checked) AppCompatDelegate.MODE_NIGHT_YES
                else AppCompatDelegate.MODE_NIGHT_NO
            )
        }

        switchAutoNotif.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(KEY_AUTO_NOTIF, checked).apply()
        }

        // Populate saved server list
        refreshServerList()

        // Check current sign-in state
        updateUI(GoogleSignIn.getLastSignedInAccount(requireContext()))
    }

    // ── Saved Servers ──────────────────────────────────────────

    /** Get saved servers as an ordered list (stored as comma-separated string) */
    fun getSavedServers(): List<String> {
        val raw = prefs.getString(KEY_SAVED_SERVERS, "") ?: ""
        return if (raw.isBlank()) emptyList() else raw.split(",")
    }

    private fun saveServerList(servers: List<String>) {
        prefs.edit().putString(KEY_SAVED_SERVERS, servers.joinToString(",")).apply()
    }

    private fun addServer(ip: String) {
        val servers = getSavedServers().toMutableList()
        if (servers.contains(ip)) {
            Toast.makeText(requireContext(), "Server already saved", Toast.LENGTH_SHORT).show()
            return
        }
        servers.add(ip)
        saveServerList(servers)
        refreshServerList()
    }

    private fun removeServer(ip: String) {
        val servers = getSavedServers().toMutableList()
        servers.remove(ip)
        saveServerList(servers)
        refreshServerList()
    }

    private fun refreshServerList() {
        llServerList.removeAllViews()
        val servers = getSavedServers()

        if (servers.isEmpty()) {
            val empty = TextView(requireContext()).apply {
                text = getString(R.string.no_saved_servers)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.textTertiary))
                textSize = 13f
                setPadding(0, dpToPx(8), 0, 0)
            }
            llServerList.addView(empty)
            return
        }

        for (ip in servers) {
            val card = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                background = ContextCompat.getDrawable(requireContext(), R.drawable.bg_server_card)
                setPadding(dpToPx(14), dpToPx(12), dpToPx(14), dpToPx(12))
                val lp = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
                lp.bottomMargin = dpToPx(8)
                layoutParams = lp
            }

            val label = TextView(requireContext()).apply {
                text = ip
                textSize = 14f
                setTextColor(ContextCompat.getColor(requireContext(), R.color.textPrimary))
                typeface = Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val deleteBtn = ImageButton(requireContext()).apply {
                setImageResource(android.R.drawable.ic_menu_close_clear_cancel)
                setColorFilter(ContextCompat.getColor(requireContext(), R.color.textTertiary))
                setBackgroundColor(0x00000000) // transparent
                contentDescription = "Remove $ip"
                setOnClickListener { removeServer(ip) }
            }

            card.addView(label)
            card.addView(deleteBtn)
            llServerList.addView(card)
        }
    }

    private fun dpToPx(dp: Int): Int {
        return (dp * resources.displayMetrics.density).toInt()
    }

    // ── Auth ────────────────────────────────────────────────────

    private fun signIn() {
        val signInIntent = googleSignInClient.signInIntent
        @Suppress("DEPRECATION")
        startActivityForResult(signInIntent, RC_SIGN_IN)
    }

    @Suppress("DEPRECATION")
    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == RC_SIGN_IN) {
            val task = GoogleSignIn.getSignedInAccountFromIntent(data)
            try {
                val account = task.getResult(ApiException::class.java)
                updateUI(account)
                Toast.makeText(requireContext(), "Welcome, ${account?.displayName}!", Toast.LENGTH_SHORT).show()
            } catch (e: ApiException) {
                Toast.makeText(requireContext(), "Sign-in failed: ${e.statusCode}", Toast.LENGTH_SHORT).show()
                updateUI(null)
            }
        }
    }

    private fun signOut() {
        googleSignInClient.signOut().addOnCompleteListener(requireActivity()) {
            updateUI(null)
            Toast.makeText(requireContext(), "Signed out", Toast.LENGTH_SHORT).show()
        }
    }

    private fun updateUI(account: GoogleSignInAccount?) {
        if (account != null) {
            signedOutLayout.visibility = View.GONE
            signedInLayout.visibility = View.VISIBLE

            tvName.text = account.displayName ?: "User"
            tvEmail.text = account.email ?: ""

            // For a production app, use Glide/Coil to load account.photoUrl
        } else {
            signedOutLayout.visibility = View.VISIBLE
            signedInLayout.visibility = View.GONE
        }
    }
}
