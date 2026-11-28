package dev.kelian.mesh.core.outbox

import dev.kelian.mesh.core.protocol.hexToBytes
import dev.kelian.mesh.core.protocol.toHex
import java.io.File

class OutboxEntry(val msgIdHex: String, val destTagHex: String, val payload: ByteArray, val createdMs: Long, val attempts: Int)

interface OutboxStore {
    fun load(): List<OutboxEntry>
    fun save(entries: List<OutboxEntry>)
}

class InMemoryOutboxStore : OutboxStore {
    private var data: List<OutboxEntry> = emptyList()
    override fun load() = data
    override fun save(entries: List<OutboxEntry>) { data = entries.toList() }
}

class FileOutboxStore(private val file: File) : OutboxStore {
    override fun load(): List<OutboxEntry> {
        if (!file.exists()) return emptyList()
        return file.readLines().filter { it.isNotBlank() }.mapNotNull { line ->
            val p = line.split(' ')
            if (p.size < 4) return@mapNotNull null
            runCatching { OutboxEntry(p[0], p[1], (p.getOrElse(4) { "" }).hexToBytes(), p[2].toLong(), p[3].toInt()) }.getOrNull()
        }
    }

    override fun save(entries: List<OutboxEntry>) {
        val tmp = File(file.path + ".tmp")
        tmp.writeText(entries.joinToString("\n") { "${it.msgIdHex} ${it.destTagHex} ${it.createdMs} ${it.attempts} ${it.payload.toHex()}" })
        if (!tmp.renameTo(file)) { file.delete(); check(tmp.renameTo(file)) { "cannot replace outbox file" } }
    }
}

class Outbox(private val store: OutboxStore, private val maxEntries: Int = 1000) {
    private val entries = ArrayList(store.load())

    fun enqueue(msgId: ByteArray, destTag: ByteArray, payload: ByteArray, nowMs: Long): Boolean {
        val id = msgId.toHex()
        if (entries.any { it.msgIdHex == id }) return false
        if (entries.size >= maxEntries) return false
        entries.add(OutboxEntry(id, destTag.toHex(), payload, nowMs, 0))
        store.save(entries); return true
    }

    fun pending(): List<OutboxEntry> = entries.toList()
    fun pendingFor(destTagHex: String) = entries.filter { it.destTagHex == destTagHex }

    fun markAttempt(msgIdHex: String) {
        val i = entries.indexOfFirst { it.msgIdHex == msgIdHex }
        if (i < 0) return
        val e = entries[i]
        entries[i] = OutboxEntry(e.msgIdHex, e.destTagHex, e.payload, e.createdMs, e.attempts + 1)
        store.save(entries)
    }

    fun ack(msgId: ByteArray): Boolean {
        val removed = entries.removeAll { it.msgIdHex == msgId.toHex() }
        if (removed) store.save(entries)
        return removed
    }
}
