package com.yourname.netspeedv3

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView

class MainActivity : AppCompatActivity() {

    private lateinit var googleAuthManager: GoogleAuthManager
    private var wasRedirectedFromVpnTab = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        googleAuthManager = GoogleAuthManager(this)
        
        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        // Load default fragment only once
        if (savedInstanceState == null) {
            replaceFragment(SpeedFragment())
        }

        val nav = findViewById<BottomNavigationView>(R.id.bottom_nav)

        nav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.menu_speed -> {
                    replaceFragment(SpeedFragment())
                    true
                }
                R.id.menu_vpn -> {
                    // Check if user is authenticated before allowing VPN access
                    if (googleAuthManager.isSignedIn()) {
                        replaceFragment(VPNFragment())
                    } else {
                        // Show a toast message and optionally trigger sign-in
                        Toast.makeText(this, "Please sign in to access VPN service", Toast.LENGTH_LONG).show()
                        // Set flag to indicate we were redirected from VPN tab
                        wasRedirectedFromVpnTab = true
                        // Trigger sign-in process
                        googleAuthManager.signIn(this)
                    }
                    true
                }
                else -> false
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_profile -> {
                if (googleAuthManager.isSignedIn()) {
                    googleAuthManager.signOut {
                        invalidateOptionsMenu() // Update menu items
                    }
                } else {
                    googleAuthManager.signIn(this)
                }
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        googleAuthManager.handleActivityResult(
            requestCode,
            resultCode,
            data,
            onAuthSuccess = {
                invalidateOptionsMenu() // Update menu items after successful sign-in
                
                // If the user was redirected from VPN tab, switch to VPN tab after successful sign-in
                if (wasRedirectedFromVpnTab) {
                    wasRedirectedFromVpnTab = false // Reset the flag
                    val nav = findViewById<BottomNavigationView>(R.id.bottom_nav)
                    nav.selectedItemId = R.id.menu_vpn
                    replaceFragment(VPNFragment())
                }
            },
            onAuthFailure = { error ->
                // Handle authentication failure
            }
        )
    }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        val profileItem = menu.findItem(R.id.action_profile)
        if (googleAuthManager.isSignedIn()) {
            profileItem?.title = "Sign Out"
        } else {
            profileItem?.title = "Sign In"
        }
        return super.onPrepareOptionsMenu(menu)
    }

    private fun replaceFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .setCustomAnimations(
                android.R.anim.fade_in,
                android.R.anim.fade_out
            )
            .replace(R.id.container, fragment)
            .commit()
    }

    fun getGoogleAuthManager(): GoogleAuthManager {
        return googleAuthManager
    }
}
