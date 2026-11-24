package dev.kelian.mesh.core.protocol

/** Auto-test statistics. Latencies are in ms; stats are null when nothing was acknowledged. */
class LatencyStats(val min: Long?, val median: Long?, val max: Long?, val deliveryRatio: Double)

fun computeStats(latenciesMs: List<Long>, sent: Int): LatencyStats {
    val delivered = latenciesMs.size
    val ratio = if (sent > 0) delivered.toDouble() / sent else 0.0
    if (delivered == 0) return LatencyStats(null, null, null, ratio)
    val s = latenciesMs.sorted()
    val mid = delivered / 2
    val median = if (delivered % 2 == 1) s[mid] else (s[mid - 1] + s[mid]) / 2
    return LatencyStats(s.first(), median, s.last(), ratio)
}
