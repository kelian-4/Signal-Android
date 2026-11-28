package dev.kelian.mesh.core.protocol

object VectorRunner {
    @Suppress("UNCHECKED_CAST")
    private fun Any?.m() = this as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    private fun Any?.l() = this as List<Any?>
    private fun Any?.i() = (this as Long).toInt()

    fun runAll(json: String): List<String> {
        val fails = ArrayList<String>()
        fun check(cond: Boolean, msg: () -> String) { if (!cond) fails.add(msg()) }
        val root = MiniJson(json).parse().m()

        check(root["header_size"].i() == HEADER_SIZE) { "header_size" }
        check((root["partial_ttl_ms"] as Long) == PARTIAL_TTL_MS) { "partial_ttl_ms" }
        check((root["dedup_ttl_ms"] as Long) == DEDUP_TTL_MS) { "dedup_ttl_ms" }

        for (c in root["frame_encoding"].l().map { it.m() }) {
            val name = "frame_encoding/${c["name"]}"
            val frame = Frame(c["type"].i(), (c["msg_id_hex"] as String).hexToBytes(), c["frag_index"].i(),
                c["frag_total"].i(), (c["payload_hex"] as String).hexToBytes())
            check(frame.encode().toHex() == c["frame_hex"]) { "$name: encode mismatch" }
            val d = Frame.decode((c["frame_hex"] as String).hexToBytes())
            check(d != null && d.type == frame.type && d.msgId.toHex() == c["msg_id_hex"] &&
                d.fragIndex == frame.fragIndex && d.fragTotal == frame.fragTotal &&
                d.payload.toHex() == c["payload_hex"]) { "$name: decode mismatch" }
        }

        for (c in root["frame_invalid"].l().map { it.m() }) {
            check(Frame.decode((c["frame_hex"] as String).hexToBytes()) == null) { "frame_invalid/${c["name"]}: accepted" }
        }

        for (c in root["fragmentation"].l().map { it.m() }) {
            val name = "fragmentation/${c["name"]}"
            val frames = fragment((c["text"] as String).toByteArray(Charsets.UTF_8), c["max_frame_size"].i(),
                (c["msg_id_hex"] as String).hexToBytes())
            val got = frames.map { it.encode().toHex() }
            check(got == c["frames_hex"].l().map { it as String }) { "$name: frames differ (got ${got.size})" }
        }
        try {
            fragment(ByteArray(1), HEADER_SIZE, ByteArray(8))
            fails.add("fragment: maxFrameSize 14 must be rejected")
        } catch (_: IllegalArgumentException) { }

        for (sc in root["reassembly"].l().map { it.m() }) {
            val r = Reassembler()
            var n = 0
            for (st in sc["steps"].l().map { it.m() }) {
                n++
                val name = "reassembly/${sc["name"]}#$n"
                val res = r.accept((st["frame_hex"] as String).hexToBytes(), st["t_ms"] as Long)
                val kind = when (res) {
                    is RxResult.Partial -> "partial"
                    is RxResult.Invalid -> "invalid"
                    is RxResult.Complete -> "complete"
                    is RxResult.Duplicate -> "duplicate"
                    is RxResult.Ack -> "ack"
                }
                check(kind == st["expect"]) { "$name: expected ${st["expect"]} got $kind" }
                val gotId = when (res) {
                    is RxResult.Complete -> res.msgId.toHex()
                    is RxResult.Duplicate -> res.msgId.toHex()
                    is RxResult.Ack -> res.msgId.toHex()
                    else -> null
                }
                if (gotId != null) check(gotId == st["msg_id_hex"]) { "$name: msgId $gotId != ${st["msg_id_hex"]}" }
                if (res is RxResult.Complete) check(res.payload.toHex() == st["payload_hex"]) { "$name: payload differs" }
            }
        }

        for (c in root["stats"].l().map { it.m() }) {
            val name = "stats/${c["name"]}"
            val lat = c["latencies_ms"].l().map { it as Long }
            val s = computeStats(lat, c["sent"].i())
            check(s.min == c["min"] as Long?) { "$name: min ${s.min}" }
            check(s.median == c["median"] as Long?) { "$name: median ${s.median}" }
            check(s.max == c["max"] as Long?) { "$name: max ${s.max}" }
            check(Math.abs(s.deliveryRatio - (c["delivery_ratio"] as Number).toDouble()) < 1e-9) { "$name: ratio" }
        }
        for (c in root["csv"].l().map { it.m() }) {
            val rows = c["rows"].l().map { it.m() }.map {
                CsvRow(it["msg_id"] as String, it["created_ms"] as Long, it["state"] as String, it["latency_ms"] as Long?)
            }
            check(buildCsv(rows) == c["csv"]) { "csv/${c["name"]}: output differs" }
        }
        val pol = root["connection_policy"].m()
        check(pol["max_client_links"].i() == MAX_CLIENT_LINKS) { "max_client_links" }
        check((pol["idle_disconnect_ms"] as Long) == IDLE_DISCONNECT_MS) { "idle_disconnect_ms" }
        for (c in pol["should_connect"].l().map { it.m() }) {
            val got = shouldConnect(
                c["pending"] as Boolean, c["ready_links"].i(), c["client_links"].i(),
                c["now_ms"] as Long, c["next_connect_at_ms"] as Long, c["ignore_until_ms"] as Long,
                c["inbound_from_peer"] as Boolean,
            )
            check(got == c["expect"]) { "connection_policy/should_connect/${c["name"]}: got $got" }
        }
        for (c in pol["should_drop_idle"].l().map { it.m() }) {
            val got = shouldDropIdle(c["ready"] as Boolean, c["pending"] as Boolean, c["now_ms"] as Long, c["last_activity_ms"] as Long)
            check(got == c["expect"]) { "connection_policy/should_drop_idle/${c["name"]}: got $got" }
        }
        return fails
    }
}
