package org.thinkSlow.netspeedv3.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

/**
 * Kotlin initiator (this app's V2Client) against the real C++ responder (vpn_server) over UDP —
 * design doc 02 §10.2. Skipped unless CPPVPN_E2E_BUNDLE names a vpnctl bundle file for a running
 * node (ticket mode, e.g. the Docker recipe in the Cpp-VPN-Core tests README). CPPVPN_E2E_PING is
 * the server's tun address to ping (default 10.8.0.1).
 *
 * Checks: handshake + ticket accepted, ICMP echo through the tunnel both ways, rekey (new keys,
 * same address, old keys still decrypt), BYE.
 */
class CrossImplementationTest {

    @Test fun kotlinClientTalksToCppServer() {
        val bundleFile = System.getenv("CPPVPN_E2E_BUNDLE")
        assumeTrue("set CPPVPN_E2E_BUNDLE to run against a live node", !bundleFile.isNullOrBlank())
        val bundle = Bundle.fromText(File(bundleFile!!).readText())
        val node = bundle.nodes[0]
        val pingTarget = ipToInt(System.getenv("CPPVPN_E2E_PING") ?: "10.8.0.1")

        val client = V2Client(bundle.deviceSk, node.pub, ticket = bundle.ticket)
        DatagramSocket().use { sock ->
            sock.soTimeout = 3000
            val server = InetSocketAddress(node.host, node.port)
            val buf = ByteArray(2048)
            val plain = ByteArray(2048)
            val ack = ByteArray(V2Wire.ACK_LEN)

            fun send(p: ByteArray, n: Int = p.size) = sock.send(DatagramPacket(p, n, server))
            fun handshake(): Boolean {
                send(client.startHandshake(now()))
                repeat(5) {
                    val pkt = DatagramPacket(buf, buf.size)
                    try { sock.receive(pkt) } catch (e: SocketTimeoutException) { return false }
                    if (client.receive(buf, pkt.length, now(), ack, plain) == V2Client.Event.ESTABLISHED) {
                        send(ack, client.lengths[0]); return true
                    }
                }
                return false
            }
            fun ping(seq: Int): Boolean {
                val req = icmpEcho(client.tunIp(), pingTarget, 0x4242, seq)
                val out = ByteArray(req.size + V2Wire.TRANSPORT_MIN_LEN)
                send(out, client.sealData(req, 0, req.size, now(), out))
                repeat(10) {
                    val pkt = DatagramPacket(buf, buf.size)
                    try { sock.receive(pkt) } catch (e: SocketTimeoutException) { return false }
                    if (client.receive(buf, pkt.length, now(), ack, plain) == V2Client.Event.DATA) {
                        val n = client.lengths[1]
                        if (n == req.size && plain[9].toInt() == 1 && plain[20].toInt() == 0 &&
                            V2Wire.getU16(byteArrayOf(plain[27], plain[26]), 0) == seq &&
                            plain.copyOfRange(28, n).contentEquals(req.copyOfRange(28, req.size))) return true
                    }
                }
                return false
            }

            assertTrue("handshake with the C++ node (is the ticket valid for it?)", handshake())
            val firstId = client.handshakeId()
            val ip = client.tunIp()
            println("established: hsid=$firstId ip=${V2Wire.ipToString(ip)} cipher=${SessionLocks.name(client.cipherId())}")
            for (seq in 1..3) assertTrue("echo $seq", ping(seq))

            assertTrue("rekey", handshake())
            assertNotEquals("rekey must change the keys", firstId, client.handshakeId())
            assertEquals("rekey keeps the address", ip, client.tunIp())
            for (seq in 4..6) assertTrue("echo $seq after rekey", ping(seq))
            println("rekeyed: hsid=${client.handshakeId()}, 6/6 echo replies")

            val bye = ByteArray(V2Wire.TRANSPORT_MIN_LEN)
            send(bye, client.sealBye(now(), bye))
            assertEquals(0, client.stats.trDropAuth)
        }
    }

    private fun now() = System.currentTimeMillis()

    private fun ipToInt(s: String) = s.split('.').fold(0) { acc, p -> (acc shl 8) or p.toInt() }

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        while (i + 1 < off + len) { sum += ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff); i += 2 }
        if (i < off + len) sum += (b[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv() and 0xffff
    }

    private fun icmpEcho(src: Int, dst: Int, id: Int, seq: Int): ByteArray {
        val p = ByteArray(20 + 8 + 56) { if (it >= 28) (it * 7 + seq).toByte() else 0 }
        p[0] = 0x45; p[2] = (p.size ushr 8).toByte(); p[3] = p.size.toByte(); p[8] = 64; p[9] = 1
        for (i in 0 until 4) { p[12 + i] = (src ushr (24 - 8 * i)).toByte(); p[16 + i] = (dst ushr (24 - 8 * i)).toByte() }
        checksum(p, 0, 20).let { p[10] = (it ushr 8).toByte(); p[11] = it.toByte() }
        p[20] = 8; p[24] = (id ushr 8).toByte(); p[25] = id.toByte(); p[26] = (seq ushr 8).toByte(); p[27] = seq.toByte()
        checksum(p, 20, p.size - 20).let { p[22] = (it ushr 8).toByte(); p[23] = it.toByte() }
        return p
    }
}
