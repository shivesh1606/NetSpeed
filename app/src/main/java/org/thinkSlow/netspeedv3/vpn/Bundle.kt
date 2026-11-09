package org.thinkSlow.netspeedv3.vpn

/*
 * Access bundle from `vpnctl issue` (design doc 03 §5) — mirror of Cpp-VPN-Core auth/Bundle.
 *   cppvpn://import?b=<base64url(bundle)>
 *   bundle v1 = ver u8 | node_count u8 | nodes[] | device_sk 32 | ticket 136
 *   node      = id_len u8 | id | host_len u8 | host | port u16 LE | S_pub 32 | tags u32 LE
 * It contains the device private key: treat it as a secret.
 */
class BundleNode(val id: String, val host: String, val port: Int, val pub: ByteArray, val tags: Int)

class Bundle(val nodes: List<BundleNode>, val deviceSk: ByteArray, val ticket: ByteArray) {
    /** Ticket fields the app shows (design 03 §2 layout; the node verifies the signature). */
    val ticketInfo: TicketInfo get() = TicketInfo.parse(ticket)

    /** Same bundle with the device key zeroed, for storage next to the Keystore-wrapped key. */
    fun withoutDeviceKey() = Bundle(nodes, ByteArray(32), ticket)

    companion object {
        const val URI_PREFIX = "cppvpn://import?b="
        private const val VERSION = 1
        private const val TICKET_LEN = 136
        private const val MAX_NODES = 32

        class FormatException(msg: String) : Exception(msg)

        /** Accepts the full cppvpn:// link or the bare base64url part (whitespace trimmed). */
        fun fromText(text: String): Bundle {
            var s = text.trim()
            if (s.startsWith(URI_PREFIX)) s = s.substring(URI_PREFIX.length)
            val raw = Base64Url.decode(s) ?: throw FormatException("This is not a NetSpeed access link")
            return decode(raw)
        }

        fun decode(p: ByteArray): Bundle {
            var off = 0
            fun need(n: Int) { if (off + n > p.size) throw FormatException("The access link is incomplete") }
            need(2)
            if (p[0].toInt() != VERSION) throw FormatException("Unsupported access link version ${p[0]}")
            val count = p[1].toInt() and 0xff
            if (count < 1 || count > MAX_NODES) throw FormatException("The access link lists no servers")
            off = 2
            val nodes = ArrayList<BundleNode>(count)
            repeat(count) {
                need(1); val idLen = p[off++].toInt() and 0xff
                if (idLen < 1 || idLen > 32) throw FormatException("Bad server name in the access link")
                need(idLen); val id = String(p, off, idLen, Charsets.UTF_8); off += idLen
                need(1); val hostLen = p[off++].toInt() and 0xff
                if (hostLen < 1 || hostLen > 253) throw FormatException("Bad server address in the access link")
                need(hostLen); val host = String(p, off, hostLen, Charsets.UTF_8); off += hostLen
                need(2 + 32 + 4)
                val port = V2Wire.getU16(p, off); off += 2
                val pub = p.copyOfRange(off, off + 32); off += 32
                val tags = V2Wire.getU32(p, off); off += 4
                if (port == 0) throw FormatException("Bad server port in the access link")
                nodes.add(BundleNode(id, host, port, pub, tags))
            }
            need(32 + TICKET_LEN)
            if (off + 32 + TICKET_LEN != p.size) throw FormatException("Unexpected data in the access link")
            return Bundle(nodes, p.copyOfRange(off, off + 32), p.copyOfRange(off + 32, p.size))
        }
    }

    fun encode(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(1) // bundle version
        out.write(nodes.size)
        for (n in nodes) {
            val id = n.id.toByteArray(Charsets.UTF_8)
            val host = n.host.toByteArray(Charsets.UTF_8)
            out.write(id.size); out.write(id)
            out.write(host.size); out.write(host)
            out.write(n.port and 0xff); out.write((n.port ushr 8) and 0xff)
            out.write(n.pub)
            for (i in 0 until 4) out.write((n.tags ushr (8 * i)) and 0xff)
        }
        out.write(deviceSk)
        out.write(ticket)
        return out.toByteArray()
    }

}

/** Readable ticket fields (layout of design 03 §2: nbf @56, exp @60, ticket_id @64, LE). */
class TicketInfo(val keyId: Int, val tags: Int, val nbf: Long, val exp: Long, val ticketId: Long, val userId: ByteArray) {
    fun isExpired(nowSeconds: Long = System.currentTimeMillis() / 1000) = nowSeconds >= exp
    val ticketIdHex: String get() = "%016x".format(ticketId)

    companion object {
        fun parse(t: ByteArray): TicketInfo {
            if (t.size != 136) return TicketInfo(0, 0, 0, 0, 0, ByteArray(16))
            return TicketInfo(
                keyId = t[1].toInt() and 0xff,
                tags = V2Wire.getU32(t, 52),
                nbf = V2Wire.getU32(t, 56).toLong() and 0xffffffffL,
                exp = V2Wire.getU32(t, 60).toLong() and 0xffffffffL,
                ticketId = V2Wire.getU64(t, 64),
                userId = t.copyOfRange(4, 20),
            )
        }
    }
}

/** base64url without padding (RFC 4648 §5). Own implementation: android.util.Base64 is not
 *  available in local unit tests and java.util.Base64 needs API 26 (minSdk is 24). */
object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val LOOKUP = IntArray(128) { -1 }.also { t -> ALPHABET.forEachIndexed { i, c -> t[c.code] = i } }

    fun encode(data: ByteArray): String {
        val sb = StringBuilder((data.size * 4 + 2) / 3)
        var i = 0
        while (i + 2 < data.size) {
            val v = ((data[i].toInt() and 0xff) shl 16) or ((data[i + 1].toInt() and 0xff) shl 8) or (data[i + 2].toInt() and 0xff)
            sb.append(ALPHABET[v ushr 18]).append(ALPHABET[(v ushr 12) and 63]).append(ALPHABET[(v ushr 6) and 63]).append(ALPHABET[v and 63])
            i += 3
        }
        val rest = data.size - i
        if (rest == 1) {
            val v = (data[i].toInt() and 0xff) shl 16
            sb.append(ALPHABET[v ushr 18]).append(ALPHABET[(v ushr 12) and 63])
        } else if (rest == 2) {
            val v = ((data[i].toInt() and 0xff) shl 16) or ((data[i + 1].toInt() and 0xff) shl 8)
            sb.append(ALPHABET[v ushr 18]).append(ALPHABET[(v ushr 12) and 63]).append(ALPHABET[(v ushr 6) and 63])
        }
        return sb.toString()
    }

    /** null for characters outside the alphabet, padding, or an impossible length. */
    fun decode(s: String): ByteArray? {
        if (s.isEmpty() || s.length % 4 == 1) return null
        val out = ByteArray(s.length * 3 / 4)
        var acc = 0
        var bits = 0
        var o = 0
        for (c in s) {
            val v = if (c.code < 128) LOOKUP[c.code] else -1
            if (v < 0) return null
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = (acc ushr bits).toByte()
            }
        }
        if ((acc and ((1 shl bits) - 1)) != 0) return null // non-canonical trailing bits
        return out.copyOf(o)
    }
}
