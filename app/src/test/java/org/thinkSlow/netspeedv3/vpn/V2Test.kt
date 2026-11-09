package org.thinkSlow.netspeedv3.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Random

/** Protocol v2 wire format, replay window and bundle decoding (design docs 02 §3, 01 C6, 03 §5). */
class V2Test {

    @Test fun sizesMatchTheDesignAndTheCppSide() {
        assertEquals(97, V2Wire.RESP_LEN)
        assertEquals(38, V2Wire.ACK_LEN)
        assertEquals(30, V2Wire.TRANSPORT_MIN_LEN)
        val c = V2Client(NoiseCrypto.randomBytes(32), NoiseCrypto.publicKey(NoiseCrypto.randomBytes(32)))
        assertEquals("1 cipher offered, no ticket", 150, c.startHandshake(0).size)
        val t = V2Client(NoiseCrypto.randomBytes(32), NoiseCrypto.publicKey(NoiseCrypto.randomBytes(32)),
                         ticket = ByteArray(136))
        assertEquals("with a 136 B ticket", 286, t.startHandshake(0).size)
    }

    @Test fun transportHeaderIsLittleEndian() {
        val b = ByteArray(14)
        V2Wire.writeTransportHeader(b, 0, V2Wire.DATA, 0x11223344, 0x0102030405060708L)
        assertArrayEquals(byteArrayOf(0x20, 4, 0x44, 0x33, 0x22, 0x11, 8, 7, 6, 5, 4, 3, 2, 1), b)
        assertEquals(0x11223344, V2Wire.getU32(b, 2))
        assertEquals(0x0102030405060708L, V2Wire.getU64(b, 6))
    }

    @Test fun tai64nIsBigEndianAndStrictlyIncreasing() {
        assertArrayEquals(byteArrayOf(0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), V2Wire.tai64n(0, 0))
        var prev = V2Wire.tai64nNow()
        repeat(1000) {
            val next = V2Wire.tai64nNow()
            assertTrue("timestamps must increase even within one millisecond", compare(next, prev) > 0)
            prev = next
        }
    }

    private fun compare(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return 0
    }

    @Test fun mac1CoversTheMessageAndIsKeyedByTheReceiver() {
        val k1 = V2Wire.mac1Key(ByteArray(32) { 7 })
        val k2 = V2Wire.mac1Key(ByteArray(32) { 8 })
        val pkt = ByteArray(100) { 0xab.toByte() }
        V2Wire.computeMac1(k1, pkt, 68).copyInto(pkt, 68)
        assertTrue(V2Wire.verifyMac1(k1, pkt, 100))
        assertFalse(V2Wire.verifyMac1(k2, pkt, 100))
        pkt[0] = 0
        assertFalse(V2Wire.verifyMac1(k1, pkt, 100))
    }

    @Test fun replayWindowMatchesAReferenceModel() {
        val rng = Random(12345)
        val w = ReplayWindow()
        val seen = HashSet<Long>()
        var top = 0L
        var any = false
        repeat(100_000) { i ->
            val base = if (any) top else 0
            val c = if (rng.nextInt(4) == 0 && base > 2500) base - rng.nextInt(2500) else base + rng.nextInt(70)
            val expect = !any || c > top || (top - c < ReplayWindow.WINDOW && c !in seen)
            assertEquals("i=$i c=$c top=$top", expect, w.check(c))
            if (expect) {
                w.update(c); seen.add(c); if (!any || c > top) top = c; any = true
            }
        }
    }

    /**
     * A real bundle written by the C++ `vpnctl issue` (throwaway issuer, already deleted; the two
     * nodes are fake addresses). Decoding it here checks the format across the two implementations.
     */
    private val vpnctlBundle = "cppvpn://import?b=AQIEaW4tMQwzNS4yMDAuMTAuMjCzFTWCuZZDTQenMOmM3V5nq2x23OUJQfMObf9uTde6XCxq" +
        "AQEAAAR1cy0xEnZwbi11cy5leGFtcGxlLm9yZ3AXQ6KPswusNPG5bkWWg2e7JUI29O3HD2MY4RR2tUm1VFoBAgAAVmLc3wtZXeyVwzUE" +
        "pJLZqhOYl8NMuQDBOQCZ0FCEI6ABAQAAPewbsaBQWmjmian5mvkrkWpxs-IhcF-i1Ba_jW91p-nkidQsb61st7Hqw-KpC14CAQAAANLG" +
        "8WrSUxlrF01ggF-awTCviRjvX6vaB8MRs-ALKAFa8mp2c7ofd3zaPvHQPV-79dUqPUhDp3HhSW3h2xRXro71uLKp5tJwqfAtT1xIBEcO"

    @Test fun decodesABundleFromVpnctl() {
        val b = Bundle.fromText("  $vpnctlBundle\n")
        assertEquals(2, b.nodes.size)
        b.nodes[0].let {
            assertEquals("in-1", it.id); assertEquals("35.200.10.20", it.host); assertEquals(5555, it.port)
            assertEquals("NYK5lkNNB6cw6YzdXmerbHbc5QlB8w5t_25N17pcLGo", Base64Url.encode(it.pub))
            assertEquals(0x101, it.tags) // friends (bit 0) + region-in (bit 8)
        }
        b.nodes[1].let {
            assertEquals("us-1", it.id); assertEquals("vpn-us.example.org", it.host); assertEquals(6000, it.port)
            assertEquals("Q6KPswusNPG5bkWWg2e7JUI29O3HD2MY4RR2tUm1VFo", Base64Url.encode(it.pub))
            assertEquals(0x201, it.tags)
        }
        assertEquals(136, b.ticket.size)
        val t = b.ticketInfo
        assertEquals("30c19a5f80604d17", t.ticketIdHex)
        assertEquals(1, t.keyId)
        assertEquals(1, t.tags)
        assertEquals(30 * 86400L, t.exp - t.nbf)
        assertEquals("3dec1bb1a0505a68e689a9f99af92b91", t.userId.joinToString("") { "%02x".format(it) })
        // the ticket binds the bundle's device key
        assertArrayEquals(NoiseCrypto.publicKey(b.deviceSk), b.ticket.copyOfRange(20, 52))
        // re-encoding gives the same bytes
        assertEquals(vpnctlBundle.removePrefix(Bundle.URI_PREFIX), Base64Url.encode(b.encode()))
    }

    @Test fun rejectsMalformedBundles() {
        val raw = Bundle.fromText(vpnctlBundle).encode()
        for (bad in listOf(raw.copyOf(raw.size - 1), raw + byteArrayOf(0), raw.copyOf().also { it[0] = 2 },
                           raw.copyOf().also { it[1] = 0 })) {
            try { Bundle.decode(bad); fail("accepted a malformed bundle") } catch (e: Bundle.Companion.FormatException) { }
        }
        for (text in listOf("", "https://example.org", "cppvpn://import?b=!!!", "cppvpn://import?b=AQ")) {
            try { Bundle.fromText(text); fail("accepted '$text'") } catch (e: Bundle.Companion.FormatException) { }
        }
        val stripped = Bundle.fromText(vpnctlBundle).withoutDeviceKey()
        assertArrayEquals(ByteArray(32), stripped.deviceSk)
    }

    @Test fun reimportKeepsTheSelectedNodeWhenItStillExists() {
        val nodes = Bundle.fromText(vpnctlBundle).nodes // in-1, us-1
        assertEquals("us-1", AccessStore.nodeAfterImport("us-1", nodes))
        assertEquals("first node when nothing was selected", "in-1", AccessStore.nodeAfterImport(null, nodes))
        assertEquals("first node when the old one is gone", "in-1", AccessStore.nodeAfterImport("eu-9", nodes))
    }

    @Test fun base64UrlRoundTripsAndRejectsOtherAlphabets() {
        val rng = Random(1)
        repeat(200) {
            val data = ByteArray(rng.nextInt(80)).also { rng.nextBytes(it) }
            assertArrayEquals(data, Base64Url.decode(Base64Url.encode(data)) ?: if (data.isEmpty()) ByteArray(0) else null)
        }
        assertNull(Base64Url.decode("ab+c"))
        assertNull(Base64Url.decode("abc="))
        assertNull(Base64Url.decode("a"))
    }
}
