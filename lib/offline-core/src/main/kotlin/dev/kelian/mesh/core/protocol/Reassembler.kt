package dev.kelian.mesh.core.protocol

sealed class RxResult {
    object Partial : RxResult()
    object Invalid : RxResult()
    class Complete(val msgId: ByteArray, val payload: ByteArray) : RxResult()
    class Duplicate(val msgId: ByteArray) : RxResult()
    class Ack(val msgId: ByteArray) : RxResult()
}

class Reassembler {
    private class Entry(val firstSeenMs: Long, val total: Int) {
        val frags = HashMap<Int, ByteArray>()
    }

    private val partial = HashMap<String, Entry>()
    private val completed = HashMap<String, Long>()

    fun accept(data: ByteArray, nowMs: Long): RxResult {
        partial.entries.removeAll { nowMs - it.value.firstSeenMs >= PARTIAL_TTL_MS }
        completed.entries.removeAll { nowMs - it.value >= DEDUP_TTL_MS }
        val f = Frame.decode(data) ?: return RxResult.Invalid
        if (f.type == TYPE_ACK) return RxResult.Ack(f.msgId)
        val key = f.msgId.toHex()
        if (completed.containsKey(key)) return RxResult.Duplicate(f.msgId)
        var entry = partial[key]
        if (entry == null) {
            entry = Entry(nowMs, f.fragTotal)
            partial[key] = entry
        } else if (entry.total != f.fragTotal) {
            return RxResult.Invalid
        }
        if (!entry.frags.containsKey(f.fragIndex)) entry.frags[f.fragIndex] = f.payload
        if (entry.frags.size == entry.total) {
            var size = 0
            for (i in 0 until entry.total) size += entry.frags.getValue(i).size
            val out = ByteArray(size)
            var pos = 0
            for (i in 0 until entry.total) {
                val part = entry.frags.getValue(i)
                System.arraycopy(part, 0, out, pos, part.size)
                pos += part.size
            }
            partial.remove(key)
            completed[key] = nowMs
            return RxResult.Complete(f.msgId, out)
        }
        return RxResult.Partial
    }
}
