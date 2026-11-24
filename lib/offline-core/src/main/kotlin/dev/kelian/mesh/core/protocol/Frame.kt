package dev.kelian.mesh.core.protocol

/** Constants of the BLE test protocol v1 (see spec/PROTOCOL.md). */
const val PROTOCOL_VERSION = 1
const val TYPE_TEXT = 0x01
const val TYPE_ACK = 0x02
const val HEADER_SIZE = 14
const val MSG_ID_SIZE = 8
const val PARTIAL_TTL_MS = 5L * 60 * 1000
const val DEDUP_TTL_MS = 60L * 60 * 1000
const val MAX_FRAGMENTS = 65535

fun ByteArray.toHex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        sb.append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 0x0F])
    }
    return sb.toString()
}

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "odd hex length" }
    return ByteArray(length / 2) { i -> ((this[2 * i].digitToInt(16) shl 4) or this[2 * i + 1].digitToInt(16)).toByte() }
}

/** One BLE frame: 14-byte big-endian header followed by the payload. */
class Frame(
    val type: Int,
    val msgId: ByteArray,
    val fragIndex: Int,
    val fragTotal: Int,
    val payload: ByteArray,
) {
    fun encode(): ByteArray {
        require(msgId.size == MSG_ID_SIZE) { "msgId must be 8 bytes" }
        val out = ByteArray(HEADER_SIZE + payload.size)
        out[0] = PROTOCOL_VERSION.toByte()
        out[1] = type.toByte()
        System.arraycopy(msgId, 0, out, 2, MSG_ID_SIZE)
        out[10] = (fragIndex shr 8).toByte()
        out[11] = fragIndex.toByte()
        out[12] = (fragTotal shr 8).toByte()
        out[13] = fragTotal.toByte()
        System.arraycopy(payload, 0, out, HEADER_SIZE, payload.size)
        return out
    }

    companion object {
        /** Returns null when the frame is invalid (and must be ignored). */
        fun decode(data: ByteArray): Frame? {
            if (data.size < HEADER_SIZE) return null
            val version = data[0].toInt() and 0xFF
            val type = data[1].toInt() and 0xFF
            if (version != PROTOCOL_VERSION) return null
            if (type != TYPE_TEXT && type != TYPE_ACK) return null
            val idx = ((data[10].toInt() and 0xFF) shl 8) or (data[11].toInt() and 0xFF)
            val total = ((data[12].toInt() and 0xFF) shl 8) or (data[13].toInt() and 0xFF)
            if (total == 0 || idx >= total) return null
            val payload = data.copyOfRange(HEADER_SIZE, data.size)
            if (type == TYPE_ACK && (idx != 0 || total != 1 || payload.isNotEmpty())) return null
            return Frame(type, data.copyOfRange(2, 2 + MSG_ID_SIZE), idx, total, payload)
        }

        fun ack(msgId: ByteArray): Frame = Frame(TYPE_ACK, msgId, 0, 1, ByteArray(0))
    }
}

/** Cuts [payload] into frames that each fit in [maxFrameSize] bytes. */
fun fragment(payload: ByteArray, maxFrameSize: Int, msgId: ByteArray, type: Int = TYPE_TEXT): List<Frame> {
    val chunk = maxFrameSize - HEADER_SIZE
    require(chunk >= 1) { "maxFrameSize too small" }
    val total = maxOf(1, (payload.size + chunk - 1) / chunk)
    require(total <= MAX_FRAGMENTS) { "payload too large" }
    return List(total) { i ->
        val from = i * chunk
        val to = minOf(payload.size, from + chunk)
        Frame(type, msgId, i, total, if (from < to) payload.copyOfRange(from, to) else ByteArray(0))
    }
}
