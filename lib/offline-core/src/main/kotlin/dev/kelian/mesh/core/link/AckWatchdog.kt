package dev.kelian.mesh.core.link

sealed class WatchdogAction {
    object None : WatchdogAction()

    class Reconnect(val stale: Int, val attempt: Int) : WatchdogAction()

    class GiveUp(val stale: Int) : WatchdogAction()
}

class AckWatchdog(private val timeoutMs: Long = 8_000, private val maxRepairs: Int = 5) {
    private val sentAt = LinkedHashMap<String, Long>()
    private var repairs = 0

    fun onSent(msgIdHex: String, nowMs: Long) { sentAt.putIfAbsent(msgIdHex, nowMs) }

    fun onAck(msgIdHex: String) {
        if (sentAt.remove(msgIdHex) != null) repairs = 0
    }

    fun onLinkReplaced(nowMs: Long) { for (k in sentAt.keys.toList()) sentAt[k] = nowMs }

    fun poll(nowMs: Long): WatchdogAction {
        val stale = sentAt.values.count { nowMs - it >= timeoutMs }
        if (stale == 0) return WatchdogAction.None
        if (repairs >= maxRepairs) return WatchdogAction.GiveUp(stale)
        repairs++
        onLinkReplaced(nowMs)
        return WatchdogAction.Reconnect(stale, repairs)
    }

    fun inFlight() = sentAt.size
}

class LinkDiagnostics(
    val tMs: Long, val event: String, val thermalState: String?, val mainThreadBlockMs: Long?,
    val disconnectCode: Int?, val rssi: Int?, val batteryPct: Int?, val screenLocked: Boolean?,
) {
    fun toCsv() = listOf(tMs, event, thermalState ?: "", mainThreadBlockMs ?: "", disconnectCode ?: "", rssi ?: "",
        batteryPct ?: "", screenLocked ?: "").joinToString(",")
}
