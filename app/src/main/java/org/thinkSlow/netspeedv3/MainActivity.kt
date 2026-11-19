package org.thinkSlow.netspeedv3

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.material.bottomnavigation.BottomNavigationView

class MainActivity : AppCompatActivity() {

    private lateinit var nav: BottomNavigationView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Load default fragment only once (VPN is the primary screen)
        if (savedInstanceState == null) {
            replaceFragment(VPNFragment())
        }

        nav = findViewById(R.id.bottom_nav)
        nav.selectedItemId = R.id.menu_vpn

        // Opened from a cppvpn://import link (only once: not again after a rotation)
        if (savedInstanceState == null) handleAccessLink(intent)

        nav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.menu_vpn -> {
                    replaceFragment(VPNFragment())
                    true
                }
                R.id.menu_speed -> {
                    replaceFragment(SpeedFragment())
                    true
                }
                R.id.menu_settings -> {
                    replaceFragment(VpnSettingsFragment())
                    true
                }
                R.id.menu_profile -> {
                    replaceFragment(ProfileFragment())
                    true
                }
                else -> false
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleAccessLink(intent)
    }

    /**
     * cppvpn://import?b=... from a browser, chat or QR app. Never imports silently: the dialog
     * shows what the link grants first. Afterwards the VPN tab is reloaded with the new access.
     */
    private fun handleAccessLink(intent: Intent?) {
        val uri = intent?.data ?: return
        if (intent.action != Intent.ACTION_VIEW || uri.scheme != "cppvpn" || uri.host != "import") return
        intent.data = null // consumed
        AccessImportUi.confirmAndImport(this, uri.toString()) {
            // Selecting the tab that is already selected does not reload it, so replace explicitly
            if (nav.selectedItemId == R.id.menu_vpn) replaceFragment(VPNFragment())
            else nav.selectedItemId = R.id.menu_vpn
        }
    }

    /** Navigate to the Profile tab programmatically (called from VPNFragment) */
    fun navigateToProfile() {
        nav.selectedItemId = R.id.menu_profile
    }

    /** Check if a Google account is currently signed in */
    fun isUserSignedIn(): Boolean =
        GoogleSignIn.getLastSignedInAccount(this) != null

    private fun replaceFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .setCustomAnimations(
                R.anim.fade_in,
                R.anim.fade_out
            )
            .replace(R.id.container, fragment)
            .commit()
    }
}
