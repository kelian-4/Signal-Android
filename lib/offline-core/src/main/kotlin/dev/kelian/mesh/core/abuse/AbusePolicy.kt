package dev.kelian.mesh.core.abuse

enum class ContactStanding { VERIFIED, ACCEPTED, UNKNOWN, BLOCKED }
class OutgoingContent(val text: String, val hasAttachment: Boolean = false)
enum class Verdict { ALLOW, REJECT_BLOCKED, REJECT_ATTACHMENT, REJECT_LINK, REJECT_ALREADY_REQUESTED, REJECT_DAILY_LIMIT }

private val LINK = Regex("""(?i)(https?://|www\.|\b[a-z0-9-]+\.(com|net|org|io|cm|me|ly|app|xyz|info)\b|[a-z]+://)""")
fun containsLink(text: String) = LINK.containsMatchIn(text)

class AbusePolicy(private val dailyUnknownLimit: Int = 5, private val dayMs: Long = 24L * 60 * 60 * 1000) {
    private val requestedPeers = HashSet<String>()
    private val reported = LinkedHashMap<String, String>()
    private var windowStart = 0L
    private var sentToday = 0

    private fun rollWindow(now: Long) { if (now - windowStart >= dayMs) { windowStart = now; sentToday = 0 } }

    fun checkOutgoing(peerId: String, standing: ContactStanding, c: OutgoingContent, nowMs: Long): Verdict {
        rollWindow(nowMs)
        if (standing == ContactStanding.BLOCKED) return Verdict.REJECT_BLOCKED
        if (standing != ContactStanding.UNKNOWN) return Verdict.ALLOW
        if (c.hasAttachment) return Verdict.REJECT_ATTACHMENT
        if (containsLink(c.text)) return Verdict.REJECT_LINK
        if (peerId in requestedPeers) return Verdict.REJECT_ALREADY_REQUESTED
        if (sentToday >= dailyUnknownLimit) return Verdict.REJECT_DAILY_LIMIT
        return Verdict.ALLOW
    }

    fun recordSent(peerId: String, standing: ContactStanding, nowMs: Long) {
        if (standing != ContactStanding.UNKNOWN) return
        rollWindow(nowMs); requestedPeers.add(peerId); sentToday++
    }

    private val receivedRequests = HashSet<String>()

    fun checkIncoming(peerId: String, standing: ContactStanding, c: OutgoingContent): Verdict {
        if (standing == ContactStanding.BLOCKED) return Verdict.REJECT_BLOCKED
        if (standing != ContactStanding.UNKNOWN) return Verdict.ALLOW
        if (c.hasAttachment) return Verdict.REJECT_ATTACHMENT
        if (containsLink(c.text)) return Verdict.REJECT_LINK
        if (!receivedRequests.add(peerId)) return Verdict.REJECT_ALREADY_REQUESTED
        return Verdict.ALLOW
    }

    fun report(peerId: String, reason: String) { reported[peerId] = reason }
    fun reports(): Map<String, String> = reported.toMap()
}
