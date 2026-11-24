package dev.kelian.mesh.core.relay

import dev.kelian.mesh.core.protocol.hexToBytes
import dev.kelian.mesh.core.protocol.toHex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayTest {
    private fun pkt(id: String, dest: String, ttl: Int, payload: String = "cipher") =
        Packet(id.hexToBytes(), dest.hexToBytes(), ttl, payload.toByteArray())

    @Test fun packetRoundTripAndInvalid() {
        val p = pkt("0102030405060708", "a1a2a3a4a5a6a7a8", 5)
        val d = Packet.decode(p.encode())!!
        assertEquals(p.msgId.toHex(), d.msgId.toHex()); assertEquals(5, d.ttl); assertEquals("cipher", String(d.payload))
        assertTrue(Packet.decode(ByteArray(10)) == null)
        assertTrue(Packet.decode(p.encode().also { it[0] = 9 }) == null)
        assertTrue(Packet.decode(p.encode().also { it[17] = 99 }) == null)
    }

    @Test fun twoHopsDeliverThroughRelayWhichCannotRead() {
        val net = SimNetwork()
        val a = net.node("A", "aa00000000000001"); val b = net.node("B", "bb00000000000002"); val c = net.node("C", "cc00000000000003")
        net.link(a, b); net.link(b, c)
        a.send(pkt("1111111111111111", "cc00000000000003", 3), 0)
        net.run()
        assertEquals(1, c.inbox.size); assertEquals("cipher", String(c.inbox[0].payload))
        assertEquals(0, b.inbox.size); assertEquals(0, a.inbox.size)
        assertEquals(2, c.inbox[0].ttl) // 3 at A, 2 after B forwarded
    }

    @Test fun ttlLimitsTheNumberOfHops() {
        val net = SimNetwork()
        val n = (0..5).map { net.node("N$it", "0".repeat(15) + it) }
        for (i in 0 until 5) net.link(n[i], n[i + 1])
        n[0].send(pkt("2222222222222222", "0".repeat(15) + "5", 3), 0); net.run()
        assertEquals(0, n[5].inbox.size) // needs 5 hops
        n[0].send(pkt("3333333333333333", "0".repeat(15) + "5", 6), 0); net.run()
        assertEquals(1, n[5].inbox.size)
    }

    @Test fun ringAndFullMeshNeverDeliverTwiceAndGoQuiet() {
        val net = SimNetwork()
        val n = (0..5).map { net.node("N$it", "0".repeat(15) + it) }
        for (i in 0..5) for (j in i + 1..5) net.link(n[i], n[j])
        n[0].send(pkt("4444444444444444", "0".repeat(15) + "3", 7), 0)
        net.run()
        assertEquals(1, n[3].inbox.size)
        assertTrue(n.sumOf { it.transmissions } <= 6 * 5) // each node forwards at most once to its 5 peers
    }

    @Test fun duplicatesAreDropped() {
        val e = RelayEngine({ setOf("aa00000000000001") })
        val raw = pkt("5555555555555555", "aa00000000000001", 3).encode()
        assertTrue(e.onReceive(raw, 0) is RelayDecision.Deliver)
        val second = e.onReceive(raw, 1)
        assertTrue(second is RelayDecision.Drop && second.reason == "duplicate")
    }

    @Test fun cacheIsBoundedAndExpires() {
        val e = RelayEngine({ emptySet() }, cacheCapacity = 10, cacheTtlMs = 1000)
        for (i in 0 until 100) e.onReceive(pkt("%016x".format(i), "ff00000000000000", 4).encode(), i.toLong())
        assertEquals(10, e.cacheSize)
        // oldest entries were evicted: an old id is forwarded again instead of dropped
        assertTrue(e.onReceive(pkt("%016x".format(0), "ff00000000000000", 4).encode(), 200) is RelayDecision.Forward)
        e.onReceive(pkt("%016x".format(777), "ff00000000000000", 4).encode(), 5000)
        assertEquals(1, e.cacheSize) // everything older than the TTL was purged
    }

    @Test fun ownOriginatedPacketIsNotForwardedBack() {
        val e = RelayEngine({ emptySet() })
        val p = pkt("6666666666666666", "ff00000000000000", 4)
        e.markOriginated(p, 0)
        assertTrue(e.onReceive(p.encode(), 1) is RelayDecision.Drop)
    }

    @Test fun lastHopWithTtlOneStillDeliversButDoesNotForward() {
        val e = RelayEngine({ setOf("aa00000000000001") })
        assertTrue(e.onReceive(pkt("7777777777777777", "aa00000000000001", 1).encode(), 0) is RelayDecision.Deliver)
        val e2 = RelayEngine({ emptySet() })
        val d = e2.onReceive(pkt("8888888888888888", "aa00000000000001", 1).encode(), 0)
        assertTrue(d is RelayDecision.Drop && d.reason == "ttl")
    }
}
