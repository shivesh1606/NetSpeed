package org.thinkSlow.netspeedv3.vpn

import org.bouncycastle.crypto.digests.Blake2bDigest

/*
 * Protocol v2 wire format (design doc 02 §3) — mirror of Cpp-VPN-Core protocol/v2/Wire.h.
 *   HS_INIT  ver type sender_idx | e 32 | enc(s) 48 | enc(payload1) n+16 | mac1 16 | mac2 16
 *   HS_RESP  ver type sender_idx receiver_idx | e 32 | enc(payload2) 23 | mac1 | mac2   = 97 B
 *   transport: ver type receiver_idx counter_u64 (14 B, the AAD) | ciphertext | tag 16
 * Indexes, counters and lengths little-endian; tun_ip network order; TAI64N big-endian.
 */
object V2Wire {
    const val VERSION: Byte = 0x20
    const val PROLOGUE = "cppvpn-v2"

    const val HS_INIT: Byte = 1
    const val HS_RESP: Byte = 2
    const val ACK: Byte = 3
    const val DATA: Byte = 4
    const val BYE: Byte = 5
    const val KEEPALIVE: Byte = 6

    const val MAC_LEN = 16
    const val MACS_LEN = 32
    const val INIT_HEADER_LEN = 6
    const val RESP_HEADER_LEN = 10
    const val TRANSPORT_HEADER_LEN = 14
    const val TAG_LEN = 16
    const val TAI64N_LEN = 12
    const val HANDSHAKE_ID_LEN = 8
    const val PAYLOAD2_LEN = 7
    const val MAX_OFFER = 8
    const val MAX_TICKET = 512

    const val RESP_LEN = RESP_HEADER_LEN + HandshakeIK.MSG2_OVERHEAD + PAYLOAD2_LEN + MACS_LEN // 97
    const val ACK_LEN = TRANSPORT_HEADER_LEN + HANDSHAKE_ID_LEN + TAG_LEN                    // 38
    const val TRANSPORT_MIN_LEN = TRANSPORT_HEADER_LEN + TAG_LEN                             // 30
    const val INIT_MAX_LEN = INIT_HEADER_LEN + HandshakeIK.MSG1_OVERHEAD + TAI64N_LEN + 1 + MAX_OFFER + 2 + MAX_TICKET + MACS_LEN

    fun putU16(b: ByteArray, off: Int, v: Int) { b[off] = v.toByte(); b[off + 1] = (v ushr 8).toByte() }
    fun putU32(b: ByteArray, off: Int, v: Int) { for (i in 0 until 4) b[off + i] = (v ushr (8 * i)).toByte() }
    fun putU64(b: ByteArray, off: Int, v: Long) { for (i in 0 until 8) b[off + i] = (v ushr (8 * i)).toByte() }
    fun getU16(b: ByteArray, off: Int) = (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8)
    fun getU32(b: ByteArray, off: Int): Int {
        var v = 0
        for (i in 3 downTo 0) v = (v shl 8) or (b[off + i].toInt() and 0xff)
        return v
    }
    fun getU64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }

    fun writeTransportHeader(b: ByteArray, off: Int, type: Byte, receiverIdx: Int, counter: Long) {
        b[off] = VERSION
        b[off + 1] = type
        putU32(b, off + 2, receiverIdx)
        putU64(b, off + 6, counter)
    }

    // ---- TAI64N: label = 2^62 + Unix seconds, then nanoseconds; big-endian ----
    private var lastTai = 0L // nanoseconds since epoch of the last timestamp we produced

    /** Strictly increasing per process (the server rejects a timestamp not newer than the last). */
    @Synchronized
    fun tai64nNow(): ByteArray {
        var ns = System.currentTimeMillis() * 1_000_000L
        if (ns <= lastTai) ns = lastTai + 1
        lastTai = ns
        return tai64n(ns / 1_000_000_000L, (ns % 1_000_000_000L).toInt())
    }

    fun tai64n(unixSeconds: Long, nanos: Int): ByteArray {
        val out = ByteArray(TAI64N_LEN)
        val label = (1L shl 62) + unixSeconds
        for (i in 0 until 8) out[i] = (label ushr (56 - 8 * i)).toByte()
        for (i in 0 until 4) out[8 + i] = (nanos ushr (24 - 8 * i)).toByte()
        return out
    }

    // ---- mac1 (§3.3): key = BLAKE2b-256("mac1----" || pub); mac1 = BLAKE2b-128(key, msg[0:len-32]) ----
    fun mac1Key(staticPub: ByteArray): ByteArray {
        val d = Blake2bDigest(256)
        val label = "mac1----".toByteArray(Charsets.US_ASCII)
        d.update(label, 0, label.size)
        d.update(staticPub, 0, 32)
        return ByteArray(32).also { d.doFinal(it, 0) }
    }

    fun computeMac1(key: ByteArray, msg: ByteArray, lenBeforeMac1: Int): ByteArray {
        val d = Blake2bDigest(key, MAC_LEN, null, null)
        d.update(msg, 0, lenBeforeMac1)
        return ByteArray(MAC_LEN).also { d.doFinal(it, 0) }
    }

    fun verifyMac1(key: ByteArray, pkt: ByteArray, len: Int): Boolean {
        if (len < MACS_LEN) return false
        val mac = computeMac1(key, pkt, len - MACS_LEN)
        var diff = 0
        for (i in 0 until MAC_LEN) diff = diff or (mac[i].toInt() xor pkt[len - MACS_LEN + i].toInt())
        return diff == 0
    }

    // ---- payloads ----
    /** payload1 = ts 12 | offer_n u8 | offer[] | ticket_len u16 | ticket */
    fun encodePayload1(ts: ByteArray, offer: ByteArray, ticket: ByteArray): ByteArray {
        val out = ByteArray(TAI64N_LEN + 1 + offer.size + 2 + ticket.size)
        ts.copyInto(out, 0)
        out[TAI64N_LEN] = offer.size.toByte()
        offer.copyInto(out, TAI64N_LEN + 1)
        putU16(out, TAI64N_LEN + 1 + offer.size, ticket.size)
        ticket.copyInto(out, TAI64N_LEN + 3 + offer.size)
        return out
    }

    data class Payload2(val tunIp: Int, val cipherId: Int, val keepaliveS: Int)

    /** payload2 = tun_ip u32 (network order) | cipher_id u8 | keepalive_s u16 LE */
    fun decodePayload2(p: ByteArray): Payload2? {
        if (p.size != PAYLOAD2_LEN) return null
        val ip = ((p[0].toInt() and 0xff) shl 24) or ((p[1].toInt() and 0xff) shl 16) or
                ((p[2].toInt() and 0xff) shl 8) or (p[3].toInt() and 0xff)
        return Payload2(ip, p[4].toInt() and 0xff, getU16(p, 5))
    }

    fun ipToString(ip: Int) = "${(ip ushr 24) and 0xff}.${(ip ushr 16) and 0xff}.${(ip ushr 8) and 0xff}.${ip and 0xff}"
}
