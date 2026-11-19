package org.thinkSlow.netspeedv3.vpn

/**
 * Anti-replay window for transport counters (design 01 C6) — RFC 6479 ring of 32 x 64-bit blocks,
 * usable window 1984 counters. Mirror of Cpp-VPN-Core protocol/v2/ReplayWindow.h.
 * check() before decrypting; update() only after the packet authenticated.
 */
class ReplayWindow {
    companion object {
        private const val BLOCKS = 32
        const val WINDOW = (BLOCKS - 1) * 64L
    }

    private val bm = LongArray(BLOCKS)
    private var top = 0L
    private var seenAny = false

    fun check(ctr: Long): Boolean {
        if (!seenAny || java.lang.Long.compareUnsigned(ctr, top) > 0) return true
        if (top - ctr >= WINDOW) return false
        return (bm[((ctr ushr 6) and (BLOCKS - 1).toLong()).toInt()] and (1L shl (ctr and 63).toInt())) == 0L
    }

    fun update(ctr: Long) {
        if (!seenAny) {
            bm.fill(0)
            top = ctr
            seenAny = true
        } else if (java.lang.Long.compareUnsigned(ctr, top) > 0) {
            val cur = top ushr 6
            var diff = (ctr ushr 6) - cur
            if (diff > BLOCKS) diff = BLOCKS.toLong()
            for (i in 1..diff) bm[((cur + i) and (BLOCKS - 1).toLong()).toInt()] = 0
            top = ctr
        }
        val idx = ((ctr ushr 6) and (BLOCKS - 1).toLong()).toInt()
        bm[idx] = bm[idx] or (1L shl (ctr and 63).toInt())
    }
}
