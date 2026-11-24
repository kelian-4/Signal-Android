package dev.kelian.mesh.core.relay

import dev.kelian.mesh.core.protocol.hexToBytes
import dev.kelian.mesh.core.protocol.toHex

const val RELAY_VERSION = 1
const val RELAY_HEADER = 18
const val MAX_TTL = 7

/**
 * Opaque envelope relayed between devices. [payload] is ciphertext: a relaying device never
 * needs (and is never able) to read it. [destTag] is an ephemeral per-contact routing tag,
 * never a stable identifier.
 */
class Packet(val msgId: ByteArray, val destTag: ByteArray, val ttl: Int, val payload: ByteArray) {
    fun encode(): ByteArray {
        require(msgId.size == 8 && destTag.size == 8 && ttl in 0..MAX_TTL)
        return byteArrayOf(RELAY_VERSION.toByte()) + msgId + destTag + byteArrayOf(ttl.toByte()) + payload
    }

    fun withTtl(newTtl: Int) = Packet(msgId, destTag, newTtl, payload)

    companion object {
        fun decode(data: ByteArray): Packet? {
            if (data.size < RELAY_HEADER || data[0].toInt() != RELAY_VERSION) return null
            val ttl = data[17].toInt() and 0xFF
            if (ttl > MAX_TTL) return null
            return Packet(data.copyOfRange(1, 9), data.copyOfRange(9, 17), ttl, data.copyOfRange(18, data.size))
        }
    }
}

sealed class RelayDecision {
    class Deliver(val packet: Packet) : RelayDecision()
    class Forward(val packet: Packet) : RelayDecision()
    class Drop(val reason: String) : RelayDecision()
}

/**
 * Simple relay rules: de-duplicate by msgId (bounded LRU cache with time limit), deliver packets
 * addressed to us, otherwise forward with TTL-1 until TTL runs out. Not thread-safe.
 */
class RelayEngine(
    private val ownTags: () -> Set<String>,
    private val cacheCapacity: Int = 512,
    private val cacheTtlMs: Long = 60L * 60 * 1000,
) {
    init { require(cacheCapacity >= 1) }

    private val seen = object : LinkedHashMap<String, Long>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?) = size > cacheCapacity
    }

    val cacheSize get() = seen.size

    /** Registers a packet we originate so that it is never re-forwarded back to us. */
    fun markOriginated(p: Packet, nowMs: Long) { seen[p.msgId.toHex()] = nowMs }

    fun markOriginatedIfNew(p: Packet, nowMs: Long) { if (!seen.containsKey(p.msgId.toHex())) markOriginated(p, nowMs) }

    fun onReceive(raw: ByteArray, nowMs: Long): RelayDecision {
        seen.entries.removeAll { nowMs - it.value >= cacheTtlMs }
        val p = Packet.decode(raw) ?: return RelayDecision.Drop("invalid")
        val key = p.msgId.toHex()
        if (seen.containsKey(key)) return RelayDecision.Drop("duplicate")
        seen[key] = nowMs
        if (p.destTag.toHex() in ownTags()) return RelayDecision.Deliver(p)
        if (p.ttl <= 1) return RelayDecision.Drop("ttl")
        return RelayDecision.Forward(p.withTtl(p.ttl - 1))
    }
}

/** In-memory network of nodes used by tests: no radio, deterministic, synchronous. */
class SimNetwork {
    inner class Node(val name: String, val tag: ByteArray, cacheCapacity: Int = 512) {
        val engine = RelayEngine({ setOf(tag.toHex()) }, cacheCapacity)
        val inbox = ArrayList<Packet>()
        val neighbors = LinkedHashSet<Node>()
        var transmissions = 0
        fun send(p: Packet, now: Long) {
            engine.markOriginated(p, now)
            broadcast(p.encode(), null)
        }
        internal fun broadcast(raw: ByteArray, except: Node?) {
            for (n in neighbors) if (n !== except) { transmissions++; queue.add(Triple(n, this, raw)) }
        }
    }

    private val queue = ArrayDeque<Triple<Node, Node, ByteArray>>()
    private var clock = 0L

    fun node(name: String, tagHex: String, cap: Int = 512) = Node(name, tagHex.hexToBytes(), cap)
    fun link(a: Node, b: Node) { a.neighbors.add(b); b.neighbors.add(a) }
    fun unlink(a: Node, b: Node) { a.neighbors.remove(b); b.neighbors.remove(a) }

    /** Delivers queued transmissions until the network is quiet; returns the number processed. */
    fun run(maxSteps: Int = 100_000): Int {
        var steps = 0
        while (queue.isNotEmpty()) {
            check(++steps <= maxSteps) { "relay storm: network never went quiet" }
            val (to, from, raw) = queue.removeFirst()
            clock++
            when (val d = to.engine.onReceive(raw, clock)) {
                is RelayDecision.Deliver -> to.inbox.add(d.packet)
                is RelayDecision.Forward -> to.broadcast(d.packet.encode(), from)
                is RelayDecision.Drop -> {}
            }
        }
        return steps
    }
}
