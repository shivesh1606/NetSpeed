package org.thinkSlow.netspeedv3

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat

class AppPickerAdapter(
    context: Context,
    private val apps: MutableList<ApplicationInfo>,
    private val pm: PackageManager
) : ArrayAdapter<ApplicationInfo>(context, R.layout.item_app_picker, apps) {

    private val inflater = LayoutInflater.from(context)
    private var filteredApps = apps.toMutableList()

    override fun getCount(): Int = filteredApps.size

    override fun getItem(position: Int): ApplicationInfo? = filteredApps.getOrNull(position)

    override fun getItemId(position: Int): Long = position.toLong()

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: inflater.inflate(R.layout.item_app_picker, parent, false)

        val app = filteredApps[position]

        val icon = view.findViewById<ImageView>(R.id.iv_app_icon)
        val name = view.findViewById<TextView>(R.id.tv_app_name)
        val pkg = view.findViewById<TextView>(R.id.tv_app_package)

        try {
            icon.setImageDrawable(pm.getApplicationIcon(app))
        } catch (e: Exception) {
            // Fallback: use system icon
            icon.setImageDrawable(app.loadIcon(pm))
        }

        name.text = try {
            pm.getApplicationLabel(app).toString()
        } catch (e: Exception) {
            app.packageName
        }

        pkg.text = app.packageName

        return view
    }

    fun filter(query: String, showSystemApps: Boolean) {
        filteredApps.clear()

        val filtered = apps.filter { app ->
            val matchesQuery = pm.getApplicationLabel(app).toString()
                .lowercase()
                .contains(query.lowercase()) ||
                    app.packageName.lowercase().contains(query.lowercase())

            val isSystemApp = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                              (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0

            matchesQuery && (showSystemApps || !isSystemApp)
        }

        filteredApps.addAll(filtered)
        notifyDataSetChanged()
    }
}
