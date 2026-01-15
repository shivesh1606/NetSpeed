package org.thinkSlow.netspeedv3

import org.thinkSlow.netspeedv3.R
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

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
                    replaceFragment(VPNFragment())
                    true
                }
                else -> false
            }
        }
    }

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
