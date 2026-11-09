package org.thinkSlow.netspeedv3.vpn

/*
 * Transport cipher per direction (design doc 01 §2.2, Android row of §4). Same contract as the
 * C++ crypto::SessionLock: nonce = 0^4 || counter_le64 (C1), the 14-byte v2 header is the AAD (C2),
 * 16-byte tag appended. One instance per direction per session.
 */
interface SessionLock {
    val overhead: Int

    /** Writes ciphertext || tag to out[outOff..]; returns bytes written. */
    fun seal(counter: Long, ad: ByteArray, adOff: Int, adLen: Int, input: ByteArray?, inOff: Int, len: Int,
             out: ByteArray, outOff: Int): Int

    /** Verifies and decrypts len bytes (ciphertext + tag); false if forged/modified. */
    fun open(counter: Long, ad: ByteArray, adOff: Int, adLen: Int, input: ByteArray, inOff: Int, len: Int,
             out: ByteArray, outOff: Int): Boolean
}

/** cipher_id 1: ChaCha20-Poly1305 (RFC 8439), the default on phones (no AES hardware assumed). */
class ChaCha20Poly1305Lock(key: ByteArray) : SessionLock {
    private val key = key.copyOf(32)
    override val overhead = NoiseCrypto.TAGLEN

    override fun seal(counter: Long, ad: ByteArray, adOff: Int, adLen: Int, input: ByteArray?, inOff: Int, len: Int,
                      out: ByteArray, outOff: Int): Int =
        NoiseCrypto.aeadSeal(key, NoiseCrypto.counterNonce(counter), ad, adOff, adLen, input, inOff, len, out, outOff)

    override fun open(counter: Long, ad: ByteArray, adOff: Int, adLen: Int, input: ByteArray, inOff: Int, len: Int,
                      out: ByteArray, outOff: Int): Boolean =
        NoiseCrypto.aeadOpen(key, NoiseCrypto.counterNonce(counter), ad, adOff, adLen, input, inOff, len, out, outOff)

    fun wipe() = key.fill(0)
}

object SessionLocks {
    const val CIPHER_CHACHA20_POLY1305: Int = 1

    /** Cipher ids this client offers in HS_INIT, in preference order. */
    val OFFER: ByteArray = byteArrayOf(CIPHER_CHACHA20_POLY1305.toByte())

    fun create(cipherId: Int, key: ByteArray): SessionLock? = when (cipherId) {
        CIPHER_CHACHA20_POLY1305 -> ChaCha20Poly1305Lock(key)
        else -> null
    }

    fun name(cipherId: Int) = when (cipherId) {
        CIPHER_CHACHA20_POLY1305 -> "ChaCha20-Poly1305"
        2 -> "AES-256-GCM"
        else -> "cipher $cipherId"
    }
}
