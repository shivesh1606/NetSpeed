package org.thinkSlow.netspeedv3.vpn

/*
 * Protocol v2 initiator (design doc 02 §4) — Kotlin mirror of Cpp-VPN-Core protocol/v2/Client.
 * Socket-free: MyVpnService does the I/O. All methods are synchronized, because the uplink,
 * downlink and timer threads of the service share one instance.
 *
 *   startHandshake()  -> HS_INIT (fresh ephemeral, TAI64N, sender_idx); again after 5 s or for a rekey
 *   receive(HS_RESP)  -> verify, Split, locks; Event.ESTABLISHED + the ACK to send
 *   receive(transport)-> replay window + open(); DATA puts the IPv4 packet in `plain`
 * After a rekey the previous receive key stays valid, so in-flight packets still decrypt.
 */
class V2Client(
    staticPriv: ByteArray,
    serverPub: ByteArray,
    private val offer: ByteArray = SessionLocks.OFFER,
    private val ticket: ByteArray = ByteArray(0),
) {
    enum class Event { NONE, ESTABLISHED, DATA, KEEPALIVE, BYE }

    class Stats {
        var respDrop = 0L; var trDropFormat = 0L; var trDropNoSession = 0L; var trDropReplay = 0L
        var trDropAuth = 0L; var handshakes = 0L
    }

    private class Pending(val hs: HandshakeIK, val localIdx: Int, val startedMs: Long)

    private class Session(
        val localIdx: Int, val remoteIdx: Int, val rx: SessionLock, val tx: SessionLock,
        val params: V2Wire.Payload2, val hsid: ByteArray, val createdMs: Long,
    ) {
        var txCounter = 1L // ACK used 0
        val window = ReplayWindow()
        var lastTxMs = createdMs
    }

    private val sPriv = staticPriv.copyOf()
    private val sPub = NoiseCrypto.publicKey(sPriv)
    private val serverPub = serverPub.copyOf()
    private val mac1KeyServer = V2Wire.mac1Key(serverPub)
    private val mac1KeySelf = V2Wire.mac1Key(sPub)
    private var pending: Pending? = null
    private var current: Session? = null
    private var previous: Session? = null
    val stats = Stats()

    /** [0] = ACK length to send, [1] = plaintext length, set by receive(). */
    val lengths = IntArray(2)

    val publicKey: ByteArray get() = sPub.copyOf()

    @Synchronized fun established() = current != null
    @Synchronized fun handshakeInFlight() = pending != null
    @Synchronized fun handshakeStartedMs() = pending?.startedMs ?: 0L
    @Synchronized fun tunIp() = current?.params?.tunIp ?: 0
    @Synchronized fun cipherId() = current?.params?.cipherId ?: 0
    @Synchronized fun keepaliveSeconds() = current?.params?.keepaliveS ?: 0
    @Synchronized fun handshakeId() = current?.hsid?.joinToString("") { "%02x".format(it) } ?: ""
    @Synchronized fun sessionAgeMs(nowMs: Long) = current?.let { nowMs - it.createdMs } ?: 0L
    @Synchronized fun lastSendMs() = current?.lastTxMs ?: 0L

    private fun newIndex(): Int {
        while (true) {
            val idx = NoiseCrypto.random.nextInt()
            if (idx != 0 && idx != current?.localIdx && idx != previous?.localIdx) return idx
        }
    }

    /** HS_INIT into a new array (0-length on failure). */
    @Synchronized
    fun startHandshake(nowMs: Long): ByteArray {
        val hs = HandshakeIK()
        hs.initInitiator(sPriv, serverPub, V2Wire.PROLOGUE.toByteArray(Charsets.US_ASCII))
        val idx = newIndex()
        val noise = hs.writeMessage1(V2Wire.encodePayload1(V2Wire.tai64nNow(), offer, ticket)) ?: return ByteArray(0)
        val pkt = ByteArray(V2Wire.INIT_HEADER_LEN + noise.size + V2Wire.MACS_LEN)
        pkt[0] = V2Wire.VERSION
        pkt[1] = V2Wire.HS_INIT
        V2Wire.putU32(pkt, 2, idx)
        noise.copyInto(pkt, V2Wire.INIT_HEADER_LEN)
        val n = V2Wire.INIT_HEADER_LEN + noise.size
        V2Wire.computeMac1(mac1KeyServer, pkt, n).copyInto(pkt, n) // mac2 stays zero (reserved, D2)
        pending = Pending(hs, idx, nowMs)
        stats.handshakes++
        return pkt
    }

    /** Feeds one datagram. `ackOut` needs ACK_LEN bytes, `plain` at least `len` bytes. */
    @Synchronized
    fun receive(pkt: ByteArray, len: Int, nowMs: Long, ackOut: ByteArray, plain: ByteArray): Event {
        lengths[0] = 0
        lengths[1] = 0
        if (len < 2 || pkt[0] != V2Wire.VERSION) {
            stats.trDropFormat++; return Event.NONE
        }
        if (pkt[1] == V2Wire.HS_RESP) return onResponse(pkt, len, nowMs, ackOut)

        if (len < V2Wire.TRANSPORT_MIN_LEN || pkt[1] < V2Wire.ACK || pkt[1] > V2Wire.KEEPALIVE) {
            stats.trDropFormat++; return Event.NONE
        }
        val type = pkt[1]
        val receiverIdx = V2Wire.getU32(pkt, 2)
        val counter = V2Wire.getU64(pkt, 6)
        val s = when (receiverIdx) {
            current?.localIdx -> current
            previous?.localIdx -> previous
            else -> null
        } ?: run { stats.trDropNoSession++; return Event.NONE }
        if (!s.window.check(counter)) {
            stats.trDropReplay++; return Event.NONE
        }
        if (!s.rx.open(counter, pkt, 0, V2Wire.TRANSPORT_HEADER_LEN, pkt, V2Wire.TRANSPORT_HEADER_LEN,
                        len - V2Wire.TRANSPORT_HEADER_LEN, plain, 0)) {
            stats.trDropAuth++; return Event.NONE
        }
        s.window.update(counter)
        lengths[1] = len - V2Wire.TRANSPORT_HEADER_LEN - s.rx.overhead
        return when (type) {
            V2Wire.DATA -> Event.DATA
            V2Wire.KEEPALIVE -> { lengths[1] = 0; Event.KEEPALIVE }
            V2Wire.BYE -> { lengths[1] = 0; current = null; previous = null; Event.BYE }
            else -> { lengths[1] = 0; stats.trDropFormat++; Event.NONE }
        }
    }

    private fun onResponse(pkt: ByteArray, len: Int, nowMs: Long, ackOut: ByteArray): Event {
        val p = pending
        if (p == null || len != V2Wire.RESP_LEN || V2Wire.getU32(pkt, 6) != p.localIdx ||
            !V2Wire.verifyMac1(mac1KeySelf, pkt, len)) {
            stats.respDrop++; return Event.NONE
        }
        val noise = pkt.copyOfRange(V2Wire.RESP_HEADER_LEN, len - V2Wire.MACS_LEN)
        val payload = p.hs.readMessage2(noise)
        val params = payload?.let { V2Wire.decodePayload2(it) }
        if (params == null || !offer.contains(params.cipherId.toByte())) {
            stats.respDrop++; return Event.NONE
        }
        val (c2s, s2c) = p.hs.split()
        val tx = SessionLocks.create(params.cipherId, c2s.key!!)
        val rx = SessionLocks.create(params.cipherId, s2c.key!!)
        if (tx == null || rx == null) {
            stats.respDrop++; return Event.NONE
        }
        val s = Session(p.localIdx, V2Wire.getU32(pkt, 2), rx, tx, params,
                        p.hs.handshakeHash.copyOf(V2Wire.HANDSHAKE_ID_LEN), nowMs)
        p.hs.wipe()
        pending = null

        // ACK {handshake_id} with counter 0 (design 02 D3)
        V2Wire.writeTransportHeader(ackOut, 0, V2Wire.ACK, s.remoteIdx, 0)
        s.tx.seal(0, ackOut, 0, V2Wire.TRANSPORT_HEADER_LEN, s.hsid, 0, V2Wire.HANDSHAKE_ID_LEN,
                  ackOut, V2Wire.TRANSPORT_HEADER_LEN)
        lengths[0] = V2Wire.ACK_LEN
        s.lastTxMs = nowMs
        previous = current // old receive key stays valid for in-flight packets
        current = s
        return Event.ESTABLISHED
    }

    private fun seal(s: Session, type: Byte, input: ByteArray?, inOff: Int, len: Int, nowMs: Long, out: ByteArray): Int {
        val ctr = s.txCounter++
        V2Wire.writeTransportHeader(out, 0, type, s.remoteIdx, ctr)
        s.lastTxMs = nowMs
        return V2Wire.TRANSPORT_HEADER_LEN +
                s.tx.seal(ctr, out, 0, V2Wire.TRANSPORT_HEADER_LEN, input, inOff, len, out, V2Wire.TRANSPORT_HEADER_LEN)
    }

    /** DATA for the current session into `out` (needs len + 30 bytes); 0 when not established. */
    @Synchronized
    fun sealData(input: ByteArray, inOff: Int, len: Int, nowMs: Long, out: ByteArray): Int =
        current?.let { seal(it, V2Wire.DATA, input, inOff, len, nowMs, out) } ?: 0

    @Synchronized
    fun sealKeepalive(nowMs: Long, out: ByteArray): Int =
        current?.let { seal(it, V2Wire.KEEPALIVE, null, 0, 0, nowMs, out) } ?: 0

    @Synchronized
    fun sealBye(nowMs: Long, out: ByteArray): Int {
        val s = current ?: return 0
        val n = seal(s, V2Wire.BYE, null, 0, 0, nowMs, out)
        current = null
        previous = null
        return n
    }

    @Synchronized
    fun wipe() {
        sPriv.fill(0)
        pending?.hs?.wipe()
        pending = null
        current = null
        previous = null
    }
}
