package org.thinkSlow.netspeedv3.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The imported VPN access (design doc 03 §5): nodes + ticket in SharedPreferences, and the device
 * private key wrapped with an AES-GCM key that lives in the Android Keystore (never leaves it).
 * vpn_access.xml is excluded from backups (backup_rules.xml, data_extraction_rules.xml): a restored copy could not be
 * unwrapped anyway, because the Keystore key is device-bound.
 */
class AccessStore(context: Context) {
    companion object {
        const val PREFS_NAME = "vpn_access"
        private const val KEY_BUNDLE = "bundle"          // bundle with the device key zeroed (base64url)
        private const val KEY_WRAPPED = "device_key"     // iv || AES-GCM(device_sk) (base64url)
        private const val KEY_NODE = "selected_node"
        private const val KEYSTORE_ALIAS = "netspeed_vpn_device_key"

        fun formatDate(unixSeconds: Long): String =
            SimpleDateFormat("d MMM yyyy", Locale.getDefault()).format(Date(unixSeconds * 1000))

        /** Node to select after an import: keep the user's choice when the new access still has it. */
        fun nodeAfterImport(previous: String?, nodes: List<BundleNode>): String =
            nodes.firstOrNull { it.id == previous }?.id ?: nodes.first().id
    }

    class AccessException(msg: String) : Exception(msg)

    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun hasAccess() = prefs.contains(KEY_BUNDLE) && prefs.contains(KEY_WRAPPED)

    /** Nodes and ticket (device key zeroed), or null when nothing is imported / data is damaged. */
    fun bundle(): Bundle? {
        val raw = prefs.getString(KEY_BUNDLE, null)?.let { Base64Url.decode(it) } ?: return null
        return try { Bundle.decode(raw) } catch (e: Bundle.Companion.FormatException) { null }
    }

    var selectedNodeId: String?
        get() = prefs.getString(KEY_NODE, null)
        set(v) = prefs.edit().putString(KEY_NODE, v).apply()

    fun selectedNode(): BundleNode? {
        val b = bundle() ?: return null
        return b.nodes.firstOrNull { it.id == selectedNodeId } ?: b.nodes.first()
    }

    /** Replaces any previous access. The device key is wrapped before anything is written. */
    fun save(b: Bundle) {
        val wrapped = wrap(b.deviceSk)
        prefs.edit()
            .putString(KEY_BUNDLE, Base64Url.encode(b.withoutDeviceKey().encode()))
            .putString(KEY_WRAPPED, Base64Url.encode(wrapped))
            .putString(KEY_NODE, nodeAfterImport(selectedNodeId, b.nodes))
            .apply()
    }

    /** Unwraps the device private key; the caller wipes it after use. */
    fun deviceKey(): ByteArray {
        val wrapped = prefs.getString(KEY_WRAPPED, null)?.let { Base64Url.decode(it) }
            ?: throw AccessException("No VPN access imported")
        if (wrapped.size < 12 + 16) throw AccessException("Stored access is damaged; import it again")
        return try {
            val key = keystoreKey(create = false) ?: throw AccessException(
                "Stored access cannot be unlocked on this device; import it again")
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, wrapped, 0, 12))
            c.doFinal(wrapped, 12, wrapped.size - 12)
        } catch (e: AccessException) {
            throw e
        } catch (e: Exception) {
            throw AccessException("Stored access cannot be unlocked on this device; import it again")
        }
    }

    fun clear() {
        prefs.edit().clear().apply()
        runCatching { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(KEYSTORE_ALIAS) }
    }

    private fun wrap(secret: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, keystoreKey(create = true))
        val iv = c.iv // 12 bytes, chosen by the Keystore
        return iv + c.doFinal(secret)
    }

    private fun keystoreKey(create: Boolean): SecretKey? {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }
}

/** Import from a cppvpn:// link, a pasted string or a scanned QR code. */
object AccessImport {
    class Result(val ok: Boolean, val message: String)

    fun import(context: Context, text: String): Result {
        val bundle = try {
            Bundle.fromText(text)
        } catch (e: Bundle.Companion.FormatException) {
            return Result(false, e.message ?: "This is not a NetSpeed access link")
        }
        val info = bundle.ticketInfo
        if (info.isExpired()) {
            return Result(false, "This access link expired on ${AccessStore.formatDate(info.exp)}. Ask for a new one.")
        }
        return try {
            AccessStore(context).save(bundle)
            val servers = if (bundle.nodes.size == 1) "1 server" else "${bundle.nodes.size} servers"
            Result(true, "VPN access imported: $servers, valid until ${AccessStore.formatDate(info.exp)}")
        } catch (e: Exception) {
            Result(false, "Could not store the access securely: ${e.message ?: e.javaClass.simpleName}")
        } finally {
            bundle.deviceSk.fill(0)
        }
    }

    /** "2 servers · valid until 9 Dec 2026" for the UI. */
    fun summary(b: Bundle): String {
        val servers = if (b.nodes.size == 1) "1 server" else "${b.nodes.size} servers"
        val info = b.ticketInfo
        val until = if (info.isExpired()) "expired on ${AccessStore.formatDate(info.exp)}"
                    else "valid until ${AccessStore.formatDate(info.exp)}"
        return "$servers · $until"
    }
}
