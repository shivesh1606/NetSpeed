package org.thinkSlow.netspeedv3.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Noise_IK_25519_ChaChaPoly_BLAKE2b (design doc 02 §10.1) — the SAME vector file as the C++
 * tests (Cpp-VPN-Core tests/protocol/vectors/noise_ik_25519_chachapoly_blake2b.txt, sha256
 * 3205bfc0460a8a3c...): two independent published sets, cacophony and snow.
 */
class NoiseTest {

    private val vectors: Map<String, Map<String, String>> by lazy {
        val text = javaClass.classLoader!!.getResourceAsStream("noise_ik_25519_chachapoly_blake2b.txt")!!
            .bufferedReader().readText()
        val out = mutableMapOf<String, MutableMap<String, String>>()
        var section = ""
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith(";")) continue
            if (line.startsWith("[")) {
                section = line.trim('[', ']'); out[section] = mutableMapOf(); continue
            }
            val eq = line.indexOf('=')
            out.getValue(section)[line.substring(0, eq).trim()] = line.substring(eq + 1).trim()
        }
        out
    }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test fun hmacMatchesPythonHmacBlake2b() {
        // Same reference values as the C++ test (Python hmac + hashlib.blake2b)
        assertEquals(
            "92294f92c0dfb9b00ec9ae8bd94d7e7d8a036b885a499f149dfe2fd2199394aaaf6b8894a1730cccb2cd050f9bcf5062a38b51b0dab33207f8ef35ae2c9df51b",
            NoiseCrypto.hmac("key".toByteArray(), "The quick brown fox jumps over the lazy dog".toByteArray()).hex()
        )
        assertEquals(
            "feb09eb5b1c557085c0a53bdf39ef7bc9af291f21d7c917cd1cf09542aab95362de79b3925fe55d92997423b5a68be1bda2f6518df34fa1053bb3ef559b08200",
            NoiseCrypto.hmac(ByteArray(200) { it.toByte() }, "abc".toByteArray()).hex()
        )
    }

    @Test fun hkdfThreeOutputsMatchPython() {
        val o = NoiseCrypto.hkdf(ByteArray(64) { it.toByte() }, ByteArray(32) { (100 + it).toByte() }, 3)
        assertEquals("2262ed5f40c3324574d00a1e0849a7cc67fb5b6a80211c3c59404bb8e47512b1cb95e73840718c5d68ca345f934f39a52f1f31e8f6d3ed521f0664f46feddae4", o[0].hex())
        assertEquals("f6a6559fa2aaab64d3d2666b83fe3f4fed6fae1959537fedd6a39b6f8d411e6132593234cc2a750244335da5021c27bf7eacbb65cfa608457de6ecc144b90077", o[1].hex())
        assertEquals("07c82c1301c70e885f4662f1f3f7b7bb9e04d81c94a6e1882f812c02ffb69580c93095bb599ad2fced3d3cf38c9c17df4fb3c0029f231247fca69b040e16449e", o[2].hex())
    }

    @Test fun cacophonyVector() = runVector("cacophony")

    @Test fun snowVector() = runVector("snow")

    private fun runVector(name: String) {
        val v = vectors.getValue(name)
        fun f(k: String) = hex(v[k] ?: "")
        val i = HandshakeIK().apply { initInitiator(f("init_static"), f("init_remote_static"), f("init_prologue")); setEphemeral(f("init_ephemeral")) }
        val r = HandshakeIK().apply { initResponder(f("resp_static"), f("resp_prologue")); setEphemeral(f("resp_ephemeral")) }

        val m0 = i.writeMessage1(f("msg0.payload"))!!
        assertArrayEquals("msg0", f("msg0.ciphertext"), m0)
        assertArrayEquals(f("msg0.payload"), r.readMessage1(m0))
        assertArrayEquals(NoiseCrypto.publicKey(f("init_static")), r.rs)

        val m1 = r.writeMessage2(f("msg1.payload"))!!
        assertArrayEquals("msg1", f("msg1.ciphertext"), m1)
        assertArrayEquals(f("msg1.payload"), i.readMessage2(m1))
        assertArrayEquals(i.handshakeHash, r.handshakeHash)
        v["handshake_hash"]?.let { assertEquals(it, i.handshakeHash.hex()) }

        val (iSend, iRecv) = i.split()
        val (rRecv, rSend) = r.split()
        var transport = 0
        var n = 2
        while (v.containsKey("msg$n.payload")) {
            val p = f("msg$n.payload")
            val tx = if (n % 2 == 0) iSend else rSend
            val rx = if (n % 2 == 0) rRecv else iRecv
            val c = tx.encryptWithAd(ByteArray(0), p)
            assertArrayEquals("msg$n", f("msg$n.ciphertext"), c)
            assertArrayEquals(p, rx.decryptWithAd(ByteArray(0), c))
            n++; transport++
        }
        assertTrue(transport >= 2)
    }

    @Test fun tamperingAndLowOrderAreRejected() {
        val is_ = NoiseCrypto.randomBytes(32)
        val rsk = NoiseCrypto.randomBytes(32)
        val prologue = "cppvpn-v2".toByteArray()
        val msg = HandshakeIK().apply { initInitiator(is_, NoiseCrypto.publicKey(rsk), prologue) }.writeMessage1(ByteArray(17))!!
        for (pos in intArrayOf(0, 40, msg.size - 1)) {
            val bad = msg.copyOf().also { it[pos] = (it[pos].toInt() xor 1).toByte() }
            assertNull("byte $pos", HandshakeIK().apply { initResponder(rsk, prologue) }.readMessage1(bad))
        }
        val lowOrder = msg.copyOf().also { java.util.Arrays.fill(it, 0, 32, 0.toByte()) }
        assertNull(HandshakeIK().apply { initResponder(rsk, prologue) }.readMessage1(lowOrder))
        assertNull(HandshakeIK().apply { initResponder(rsk, "cppvpn-v3".toByteArray()) }.readMessage1(msg))
        assertNotNull(HandshakeIK().apply { initResponder(rsk, prologue) }.readMessage1(msg))
    }
}
