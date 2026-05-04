package org.thinkSlow.netspeedv3

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

        // Load default fragment only once
        if (savedInstanceState == null) {
            replaceFragment(SpeedFragment())
        }

        nav = findViewById(R.id.bottom_nav)

        nav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.menu_speed -> {
                    replaceFragment(SpeedFragment())
                    true
                }
                R.id.menu_vpn -> {
                    replaceFragment(VPNFragment())
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
