package org.thinkSlow.netspeedv3

import android.content.Context
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import org.thinkSlow.netspeedv3.vpn.AccessImport
import org.thinkSlow.netspeedv3.vpn.AccessStore
import org.thinkSlow.netspeedv3.vpn.Bundle

/**
 * One confirmation path for every way an access link arrives (cppvpn:// deep link, pasted text,
 * scanned QR code). A link is a credential and a deep link can be opened by any web page or chat,
 * so nothing is stored until the user has seen what it grants and tapped Import.
 */
object AccessImportUi {

    fun confirmAndImport(context: Context, text: String, onImported: () -> Unit) {
        val bundle = try {
            Bundle.fromText(text)
        } catch (e: Bundle.Companion.FormatException) {
            Toast.makeText(context, e.message ?: "This is not a NetSpeed access link", Toast.LENGTH_LONG).show()
            return
        }
        bundle.deviceSk.fill(0) // only the summary is needed here; AccessImport decodes the text again
        val info = bundle.ticketInfo
        if (info.isExpired()) {
            Toast.makeText(context, "This access link expired on ${AccessStore.formatDate(info.exp)}. Ask for a new one.",
                           Toast.LENGTH_LONG).show()
            return
        }

        val servers = if (bundle.nodes.size == 1) "1 server" else "${bundle.nodes.size} servers"
        val grant = "$servers (${bundle.nodes.joinToString(", ") { it.id }}), valid until ${AccessStore.formatDate(info.exp)}"
        var message = context.getString(R.string.import_confirm_msg, grant)
        if (AccessStore(context).hasAccess()) message += "\n\n" + context.getString(R.string.import_replaces)

        AlertDialog.Builder(context)
            .setTitle(R.string.import_confirm_title)
            .setMessage(message)
            .setPositiveButton(R.string.import_access) { _, _ ->
                val result = AccessImport.import(context, text)
                Toast.makeText(context, result.message, Toast.LENGTH_LONG).show()
                if (result.ok) onImported()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }
}
