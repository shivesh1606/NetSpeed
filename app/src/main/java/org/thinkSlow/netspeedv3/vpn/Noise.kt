package org.thinkSlow.netspeedv3.vpn

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.SecureRandom

/*
 * Noise_IK_25519_ChaChaPoly_BLAKE2b — Kotlin port of Cpp-VPN-Core protocol/noise/Noise.{h,cpp}
 * (design doc 02, decision D1). Follows The Noise Protocol Framework, revision 34:
 *   §4   DH = X25519, HASH = BLAKE2b-512, HMAC per RFC 2104 (block 128), HKDF per §4.3
 *   §5   CipherState / SymmetricState / HandshakeState rules
 *   §7.5 IK:  <- s  ...  -> e, es, s, ss   <- e, ee, se
 *   §12.3 ChaChaPoly nonce = 32 zero bits || 64-bit little-endian n
 * Correctness is gated by the same published vector file as the C++ unit tests
 * (app/src/test/resources/noise_ik_25519_chachapoly_blake2b.txt).
 *
 * Crypto: BouncyCastle (pure Java). Design 02 §9 named Lazysodium; BouncyCastle keeps the vector
 * tests plain JVM unit tests and avoids bundling native libraries (16 KB page-size rules).
 */
object NoiseCrypto {
    const val HASHLEN = 64
    const val DHLEN = 32
    const val KEYLEN = 32
    const val TAGLEN = 16
    private const val BLOCKLEN = 128 // BLAKE2b block length (HMAC, Noise §4.3)
    const val PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_BLAKE2b"

    val random = SecureRandom()

    fun hash(vararg parts: ByteArray): ByteArray {
        val d = Blake2bDigest(HASHLEN * 8)
        for (p in parts) d.update(p, 0, p.size)
        return ByteArray(HASHLEN).also { d.doFinal(it, 0) }
    }

    /** HMAC-HASH(key, data[0] || data[1] || ...) per RFC 2104 with BLAKE2b-512. */
    fun hmac(key: ByteArray, vararg data: ByteArray): ByteArray {
        val k = ByteArray(BLOCKLEN)
        (if (key.size > BLOCKLEN) hash(key) else key).copyInto(k)
        val ipad = ByteArray(BLOCKLEN) { (k[it].toInt() xor 0x36).toByte() }
        val opad = ByteArray(BLOCKLEN) { (k[it].toInt() xor 0x5c).toByte() }
        val inner = hash(ipad, *data)
        val out = hash(opad, inner)
        k.fill(0); ipad.fill(0); opad.fill(0); inner.fill(0)
        return out
    }

    /** Noise §4.3 HKDF: returns 2 or 3 outputs of HASHLEN bytes. */
    fun hkdf(ck: ByteArray, ikm: ByteArray, outputs: Int): Array<ByteArray> {
        val temp = hmac(ck, ikm)
        val o1 = hmac(temp, byteArrayOf(1))
        val o2 = hmac(temp, o1, byteArrayOf(2))
        val result = if (outputs == 3) arrayOf(o1, o2, hmac(temp, o2, byteArrayOf(3))) else arrayOf(o1, o2)
        temp.fill(0)
        return result
    }

    fun publicKey(priv: ByteArray): ByteArray = ByteArray(DHLEN).also { X25519.generatePublicKey(priv, 0, it, 0) }

    /** X25519; null for an all-zero result (low-order point), which aborts the handshake. */
    fun dh(priv: ByteArray, pub: ByteArray): ByteArray? {
        val out = ByteArray(DHLEN)
        return if (X25519.calculateAgreement(priv, 0, pub, 0, out, 0)) out else null
    }

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    /** 96-bit nonce = 4 zero bytes || counter little-endian (Noise §12.3, design 01 C1). */
    fun counterNonce(counter: Long): ByteArray {
        val n = ByteArray(12)
        for (i in 0 until 8) n[4 + i] = (counter ushr (8 * i)).toByte()
        return n
    }

    /** ChaCha20-Poly1305 IETF. Writes ciphertext || tag; returns bytes written. */
    fun aeadSeal(
        key: ByteArray, nonce: ByteArray, ad: ByteArray?, adOff: Int, adLen: Int,
        input: ByteArray?, inOff: Int, len: Int, out: ByteArray, outOff: Int
    ): Int {
        val c = ChaCha20Poly1305()
        c.init(true, AEADParameters(KeyParameter(key), TAGLEN * 8, nonce))
        if (ad != null && adLen > 0) c.processAADBytes(ad, adOff, adLen)
        var n = if (input != null && len > 0) c.processBytes(input, inOff, len, out, outOff) else 0
        n += c.doFinal(out, outOff + n)
        return n
    }

    /** Verifies and decrypts; false on authentication failure. Writes len - 16 bytes. */
    fun aeadOpen(
        key: ByteArray, nonce: ByteArray, ad: ByteArray?, adOff: Int, adLen: Int,
        input: ByteArray, inOff: Int, len: Int, out: ByteArray, outOff: Int
    ): Boolean {
        if (len < TAGLEN) return false
        return try {
            val c = ChaCha20Poly1305()
            c.init(false, AEADParameters(KeyParameter(key), TAGLEN * 8, nonce))
            if (ad != null && adLen > 0) c.processAADBytes(ad, adOff, adLen)
            val n = c.processBytes(input, inOff, len, out, outOff)
            c.doFinal(out, outOff + n)
            true
        } catch (e: InvalidCipherTextException) {
            false
        }
    }
}

/** Noise §5.1. */
class CipherState {
    var key: ByteArray? = null
        private set
    var n: Long = 0
        private set

    fun initializeKey(k: ByteArray) {
        key = k.copyOf(NoiseCrypto.KEYLEN)
        n = 0
    }

    fun hasKey() = key != null

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        val k = key ?: return plaintext.copyOf()
        val out = ByteArray(plaintext.size + NoiseCrypto.TAGLEN)
        NoiseCrypto.aeadSeal(k, NoiseCrypto.counterNonce(n++), ad, 0, ad.size, plaintext, 0, plaintext.size, out, 0)
        return out
    }

    /** null on authentication failure (n not advanced). */
    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray? {
        val k = key ?: return ciphertext.copyOf()
        if (ciphertext.size < NoiseCrypto.TAGLEN) return null
        val out = ByteArray(ciphertext.size - NoiseCrypto.TAGLEN)
        if (!NoiseCrypto.aeadOpen(k, NoiseCrypto.counterNonce(n), ad, 0, ad.size, ciphertext, 0, ciphertext.size, out, 0))
            return null
        n++
        return out
    }
}

/** Noise §5.2. */
class SymmetricState {
    private var ck = ByteArray(NoiseCrypto.HASHLEN)
    var h = ByteArray(NoiseCrypto.HASHLEN)
        private set
    private var cs = CipherState()

    fun initialize(protocolName: String) {
        val name = protocolName.toByteArray(Charsets.US_ASCII)
        h = if (name.size <= NoiseCrypto.HASHLEN) name.copyOf(NoiseCrypto.HASHLEN) else NoiseCrypto.hash(name)
        ck = h.copyOf()
        cs = CipherState()
    }

    fun mixKey(ikm: ByteArray) {
        val (newCk, tempK) = NoiseCrypto.hkdf(ck, ikm, 2)
        ck = newCk
        cs.initializeKey(tempK) // truncated to 32 bytes (HASHLEN 64)
    }

    fun mixHash(data: ByteArray) {
        h = NoiseCrypto.hash(h, data)
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val c = cs.encryptWithAd(h, plaintext)
        mixHash(c)
        return c
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray? {
        val p = cs.decryptWithAd(h, ciphertext) ?: return null
        mixHash(ciphertext)
        return p
    }

    /** c1 = initiator -> responder, c2 = responder -> initiator. */
    fun split(): Pair<CipherState, CipherState> {
        val (k1, k2) = NoiseCrypto.hkdf(ck, ByteArray(0), 2)
        return Pair(CipherState().apply { initializeKey(k1) }, CipherState().apply { initializeKey(k2) })
    }
}

/** IK handshake (Noise §7.5). msg1 = 32 + 48 + payload + 16; msg2 = 32 + payload + 16. */
class HandshakeIK {
    companion object {
        const val MSG1_OVERHEAD = 96
        const val MSG2_OVERHEAD = 48
    }

    private val ss = SymmetricState()
    private var s = ByteArray(32)
    private var sPub = ByteArray(32)
    private var e: ByteArray? = null
    private var ePub = ByteArray(32)
    var rs = ByteArray(32)
        private set
    private var re = ByteArray(32)

    val handshakeHash: ByteArray get() = ss.h

    fun initInitiator(sPriv: ByteArray, rsPub: ByteArray, prologue: ByteArray) {
        s = sPriv.copyOf()
        sPub = NoiseCrypto.publicKey(s)
        rs = rsPub.copyOf()
        ss.initialize(NoiseCrypto.PROTOCOL_NAME)
        ss.mixHash(prologue)
        ss.mixHash(rs) // pre-message: <- s
    }

    fun initResponder(sPriv: ByteArray, prologue: ByteArray) {
        s = sPriv.copyOf()
        sPub = NoiseCrypto.publicKey(s)
        ss.initialize(NoiseCrypto.PROTOCOL_NAME)
        ss.mixHash(prologue)
        ss.mixHash(sPub)
    }

    /** Test vectors use fixed ephemerals; otherwise one is generated when needed. */
    fun setEphemeral(ePriv: ByteArray) {
        e = ePriv.copyOf()
        ePub = NoiseCrypto.publicKey(ePriv)
    }

    private fun ensureEphemeral(): ByteArray {
        e?.let { return it }
        val k = NoiseCrypto.randomBytes(32)
        setEphemeral(k)
        return k
    }

    /** -> e, es, s, ss. null if a DH fails. */
    fun writeMessage1(payload: ByteArray): ByteArray? {
        val ek = ensureEphemeral()
        ss.mixHash(ePub)
        ss.mixKey(NoiseCrypto.dh(ek, rs) ?: return null) // es
        val encS = ss.encryptAndHash(sPub)
        ss.mixKey(NoiseCrypto.dh(s, rs) ?: return null) // ss
        val encP = ss.encryptAndHash(payload)
        return ePub + encS + encP
    }

    fun readMessage1(msg: ByteArray): ByteArray? {
        if (msg.size < MSG1_OVERHEAD) return null
        re = msg.copyOfRange(0, 32)
        ss.mixHash(re)
        ss.mixKey(NoiseCrypto.dh(s, re) ?: return null)
        rs = ss.decryptAndHash(msg.copyOfRange(32, 80)) ?: return null
        ss.mixKey(NoiseCrypto.dh(s, rs) ?: return null)
        return ss.decryptAndHash(msg.copyOfRange(80, msg.size))
    }

    /** <- e, ee, se (responder). */
    fun writeMessage2(payload: ByteArray): ByteArray? {
        val ek = ensureEphemeral()
        ss.mixHash(ePub)
        ss.mixKey(NoiseCrypto.dh(ek, re) ?: return null) // ee
        ss.mixKey(NoiseCrypto.dh(ek, rs) ?: return null) // se
        return ePub + ss.encryptAndHash(payload)
    }

    fun readMessage2(msg: ByteArray): ByteArray? {
        if (msg.size < MSG2_OVERHEAD) return null
        val ek = e ?: return null
        re = msg.copyOfRange(0, 32)
        ss.mixHash(re)
        ss.mixKey(NoiseCrypto.dh(ek, re) ?: return null) // ee
        ss.mixKey(NoiseCrypto.dh(s, re) ?: return null) // se
        return ss.decryptAndHash(msg.copyOfRange(32, msg.size))
    }

    fun split(): Pair<CipherState, CipherState> = ss.split()

    fun wipe() {
        s.fill(0)
        e?.fill(0)
    }
}
