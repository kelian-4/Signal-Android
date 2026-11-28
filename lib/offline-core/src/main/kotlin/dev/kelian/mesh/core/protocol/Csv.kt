package dev.kelian.mesh.core.protocol

import java.util.Locale

class CsvRow(val msgId: String, val createdMs: Long, val state: String, val latencyMs: Long?)

const val CSV_HEADER = "msg_id,created_ms,state,latency_ms"

fun buildCsv(rows: List<CsvRow>): String {
    val sorted = rows.sortedBy { it.createdMs }
    val sb = StringBuilder(CSV_HEADER).append('\n')
    for (r in sorted) {
        sb.append(r.msgId).append(',').append(r.createdMs).append(',').append(r.state).append(',')
            .append(r.latencyMs?.toString() ?: "").append('\n')
    }
    val lat = sorted.mapNotNull { it.latencyMs }
    val st = computeStats(lat, sorted.size)
    fun d(v: Long?) = v?.toString() ?: "-"
    sb.append("# sent=").append(sorted.size).append(" acked=").append(lat.size)
        .append(" min_ms=").append(d(st.min)).append(" median_ms=").append(d(st.median))
        .append(" max_ms=").append(d(st.max))
        .append(" delivery_pct=").append(String.format(Locale.US, "%.1f", st.deliveryRatio * 100))
        .append('\n')
    return sb.toString()
}
