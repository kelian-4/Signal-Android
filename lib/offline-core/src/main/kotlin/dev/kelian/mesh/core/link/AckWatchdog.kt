package dev.kelian.mesh.core.link

/** What the link layer must do after [AckWatchdog.poll]. */
sealed class WatchdogAction {
    object None : WatchdogAction()
    /** Cut the link, rescan, reconnect. [stale] = number of messages without ACK. */
    class Reconnect(val stale: Int, val attempt: Int) : WatchdogAction()
    /** Too many failed repairs: stop hammering, wait for the next discovery. */
    class GiveUp(val stale: Int) : WatchdogAction()
}

/**
 * No ACK within [timeoutMs] for a message sent on a link: the link is considered dead even if the
 * OS did not report a disconnection (field test: 27 messages stuck after a 46 s freeze).
 */
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

/** One diagnostic line per link event, to correlate stalls with phone state. */
class LinkDiagnostics(
    val tMs: Long, val event: String, val thermalState: String?, val mainThreadBlockMs: Long?,
    val disconnectCode: Int?, val rssi: Int?, val batteryPct: Int?, val screenLocked: Boolean?,
) {
    fun toCsv() = listOf(tMs, event, thermalState ?: "", mainThreadBlockMs ?: "", disconnectCode ?: "", rssi ?: "",
        batteryPct ?: "", screenLocked ?: "").joinToString(",")
}
