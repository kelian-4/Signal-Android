package dev.kelian.mesh.core.engine

import dev.kelian.mesh.core.abuse.AbusePolicy
import dev.kelian.mesh.core.abuse.ContactStanding
import dev.kelian.mesh.core.abuse.OutgoingContent
import dev.kelian.mesh.core.abuse.Verdict
import dev.kelian.mesh.core.backup.BackupBundle
import dev.kelian.mesh.core.backup.BackupCodec
import dev.kelian.mesh.core.backup.BackupContact
import dev.kelian.mesh.core.backup.BackupMessage
import dev.kelian.mesh.core.identity.IdentitySigner
import dev.kelian.mesh.core.link.AckWatchdog
import dev.kelian.mesh.core.link.WatchdogAction
import dev.kelian.mesh.core.outbox.InMemoryOutboxStore
import dev.kelian.mesh.core.outbox.Outbox
import dev.kelian.mesh.core.outbox.OutboxStore
import dev.kelian.mesh.core.protocol.Frame
import dev.kelian.mesh.core.protocol.Reassembler
import dev.kelian.mesh.core.protocol.RxResult
import dev.kelian.mesh.core.protocol.TYPE_ACK
import dev.kelian.mesh.core.protocol.fragment
import dev.kelian.mesh.core.protocol.toHex
import dev.kelian.mesh.core.relay.MAX_TTL
import dev.kelian.mesh.core.relay.Packet
import dev.kelian.mesh.core.relay.RelayDecision
import dev.kelian.mesh.core.relay.RelayEngine
import dev.kelian.mesh.core.verify.ContactTrustBook
import dev.kelian.mesh.core.verify.KeyChangeAlert
import dev.kelian.mesh.core.verify.QrPayload
import dev.kelian.mesh.core.verify.TrustLevel
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom

interface SessionCipher {

    fun canEncrypt(peerPk: ByteArray): Boolean = true
    fun encrypt(peerPk: ByteArray, plain: ByteArray): ByteArray
    fun decrypt(peerPk: ByteArray, data: ByteArray): ByteArray?
    fun seal(recipientPk: ByteArray, plain: ByteArray): ByteArray
    fun open(data: ByteArray): ByteArray?

    fun bundleText(): String? = null

    fun acceptBundleText(text: String): Boolean = false
}

interface LinkSink { fun sendFrame(linkId: String, frame: ByteArray) }

sealed class MeshEvent {
    class Text(val contactId: String, val text: String, val msgIdHex: String) : MeshEvent()
    class ContactRequest(val senderPk: ByteArray, val nickname: String, val text: String) : MeshEvent()
    class Delivered(val msgIdHex: String) : MeshEvent()
    class KeyChanged(val alert: KeyChangeAlert) : MeshEvent()
    class LinkRepair(val linkId: String, val stale: Int) : MeshEvent()

    class ContactAppeared(val contactId: String, val publicKey: ByteArray, val nickname: String) : MeshEvent()

    class SessionReady(val contactId: String) : MeshEvent()
}

sealed class SendResult {
    class Queued(val msgIdHex: String) : SendResult()
    class Rejected(val verdict: Verdict) : SendResult()
    object UnknownContact : SendResult()
    object NoSession : SendResult()
}

object Routing {
    private const val DAY = 24L * 60 * 60 * 1000
    private fun h(label: String, a: ByteArray, b: ByteArray, day: Long): ByteArray {
        val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
        o.write(label.toByteArray()); o.write(a); o.write(b); o.writeLong(day)
        return MessageDigest.getInstance("SHA-256").digest(bo.toByteArray()).copyOf(8)
    }

    fun contactTag(pkA: ByteArray, pkB: ByteArray, nowMs: Long): ByteArray {
        val (x, y) = listOf(pkA, pkB).sortedWith { p, q -> java.util.Arrays.compareUnsigned(p, q) }
        return h("tag", x, y, nowMs / DAY)
    }
    fun inboxTag(pk: ByteArray, nowMs: Long) = h("inbox", pk, ByteArray(0), nowMs / DAY)

    fun validDays(nowMs: Long) = listOf(nowMs, nowMs - DAY)
}

private const val K_TEXT = 1
private const val K_REQUEST = 2
private const val K_DELIVERED = 3
private const val K_BUNDLE_REQUEST = 4
private const val K_BUNDLE_RESPONSE = 5
private const val MAX_BUNDLE_ANSWERS_PER_PEER = 8
private const val BACKLOG_TTL_MS = 10L * 60 * 1000
private const val MAX_BACKLOG = 64

class Contact(val id: String, val nickname: String, var publicKey: ByteArray, var accepted: Boolean)

class MeshEngine(
    val identity: IdentitySigner,
    val nickname: String,
    private val cipher: SessionCipher,
    private val sink: LinkSink,
    private val clock: () -> Long,
    outboxStore: OutboxStore = InMemoryOutboxStore(),
    private val maxFrameSize: Int = 244,
    private val random: SecureRandom = SecureRandom(),
) {
    val trust = ContactTrustBook()
    val abuse = AbusePolicy()
    val events = ArrayList<MeshEvent>()
    val history = ArrayList<BackupMessage>()
    private val outbox = Outbox(outboxStore)
    private val contacts = LinkedHashMap<String, Contact>()
    private val links = LinkedHashSet<String>()
    private val linkMaxFrame = HashMap<String, Int>()
    private class Backlog(val packet: Packet, val fromLink: String, val atMs: Long)
    private val relayBacklog = ArrayDeque<Backlog>()
    private val reassemblers = HashMap<String, Reassembler>()
    private val watchdogs = HashMap<String, AckWatchdog>()
    private val relay = RelayEngine({ ownTags() })

    fun contact(id: String) = contacts[id]
    fun pendingCount() = outbox.pending().size

    private fun ownTags(): Set<String> {
        val now = clock(); val s = HashSet<String>()
        for (t in Routing.validDays(now)) {
            s.add(Routing.inboxTag(identity.publicKey, t).toHex())
            for (c in contacts.values) s.add(Routing.contactTag(identity.publicKey, c.publicKey, t).toHex())
        }
        return s
    }

    fun addContact(contactId: String, qr: QrPayload) = addContactKey(contactId, qr.publicKey, qr.nickname, accepted = true)

    fun addContactKey(contactId: String, publicKey: ByteArray, nickname: String, accepted: Boolean = true) {
        contacts[contactId] = Contact(contactId, nickname, publicKey, accepted)
        trust.add(contactId, publicKey)
    }

    fun contactFor(publicKey: ByteArray): Contact? = contacts.values.firstOrNull { it.publicKey.contentEquals(publicKey) }

    fun requestBundle(contactId: String): Boolean {
        val c = contacts[contactId] ?: return false
        val now = clock()
        enqueue(Routing.inboxTag(c.publicKey, now), cipher.seal(c.publicKey, envelope(K_BUNDLE_REQUEST, ByteArray(0), now)))
        return true
    }

    private val bundleAnswers = HashMap<String, Int>()

    fun markVerified(contactId: String): Boolean {
        val key = contacts[contactId]?.publicKey ?: return false
        return trust.markVerified(contactId, key)
    }

    fun onAuthenticatedKey(contactId: String, key: ByteArray) {
        trust.onKeySeen(contactId, key)?.let { events.add(MeshEvent.KeyChanged(it)); contacts[contactId]?.publicKey = key }
    }

    private fun standing(contactId: String?): ContactStanding {
        val c = contactId?.let { contacts[it] } ?: return ContactStanding.UNKNOWN
        return if (trust.level(c.id) == TrustLevel.VERIFIED) ContactStanding.VERIFIED else ContactStanding.ACCEPTED
    }

    private fun envelope(kind: Int, body: ByteArray, now: Long): ByteArray {
        val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
        o.writeByte(kind); o.writeByte(identity.publicKey.size); o.write(identity.publicKey); o.writeLong(now); o.writeUTF(nickname); o.writeInt(body.size); o.write(body)
        return bo.toByteArray()
    }

    fun sendText(contactId: String, text: String): SendResult {
        val c = contacts[contactId] ?: return SendResult.UnknownContact
        if (!cipher.canEncrypt(c.publicKey)) return SendResult.NoSession
        val now = clock()
        val v = abuse.checkOutgoing(contactId, standing(contactId), OutgoingContent(text), now)
        if (v != Verdict.ALLOW) return SendResult.Rejected(v)
        val id = enqueue(Routing.contactTag(identity.publicKey, c.publicKey, now),
            cipher.encrypt(c.publicKey, envelope(K_TEXT, text.toByteArray(), now)))
        history.add(BackupMessage(id, contactId, true, now, text))
        return SendResult.Queued(id)
    }

    fun sendContactRequest(recipientPk: ByteArray, text: String): SendResult {
        val now = clock(); val peer = recipientPk.toHex()
        val v = abuse.checkOutgoing(peer, ContactStanding.UNKNOWN, OutgoingContent(text), now)
        if (v != Verdict.ALLOW) return SendResult.Rejected(v)
        val id = enqueue(Routing.inboxTag(recipientPk, now), cipher.seal(recipientPk, envelope(K_REQUEST, text.toByteArray(), now)))
        abuse.recordSent(peer, ContactStanding.UNKNOWN, now)
        return SendResult.Queued(id)
    }

    private fun enqueue(tag: ByteArray, payload: ByteArray): String {
        val id = ByteArray(8).also { random.nextBytes(it) }
        outbox.enqueue(id, tag, payload, clock())
        flush()
        return id.toHex()
    }

    fun onLinkUp(linkId: String, maxFrame: Int = maxFrameSize) {
        require(maxFrame >= 20) { "frame size too small" }
        links.add(linkId); linkMaxFrame[linkId] = maxFrame
        reassemblers[linkId] = Reassembler(); watchdogs[linkId] = AckWatchdog()
        flush()
        val now = clock()
        relayBacklog.removeAll { now - it.atMs > BACKLOG_TTL_MS }
        for (b in relayBacklog.toList()) if (b.fromLink != linkId) sendPacket(linkId, b.packet)
    }

    fun onLinkDown(linkId: String) { links.remove(linkId); linkMaxFrame.remove(linkId); reassemblers.remove(linkId); watchdogs.remove(linkId) }

    fun wantsConnection(): Boolean {
        val now = clock()
        relayBacklog.removeAll { now - it.atMs > BACKLOG_TTL_MS }
        return outbox.pending().isNotEmpty() || relayBacklog.isNotEmpty()
    }

    fun linkCount() = links.size

    fun flush() { for (e in outbox.pending()) for (l in links) transmit(l, Packet(e.msgIdHex.hexBytes(), e.destTagHex.hexBytes(), MAX_TTL, e.payload)); }

    private fun String.hexBytes() = ByteArray(length / 2) { ((this[2 * it].digitToInt(16) shl 4) or this[2 * it + 1].digitToInt(16)).toByte() }

    private fun transmit(link: String, p: Packet) {
        relay.markOriginatedIfNew(p, clock())
        sendPacket(link, p)
    }

    private fun sendPacket(link: String, p: Packet) {
        val frames = fragment(p.encode(), linkMaxFrame[link] ?: maxFrameSize, p.msgId)
        watchdogs[link]?.onSent(p.msgId.toHex(), clock())
        for (f in frames) sink.sendFrame(link, f.encode())
    }

    fun tick() {
        for ((l, w) in watchdogs.toMap()) {
            val a = w.poll(clock())
            if (a is WatchdogAction.Reconnect) events.add(MeshEvent.LinkRepair(l, a.stale))
        }
    }

    fun onFrame(linkId: String, bytes: ByteArray) {
        val r = reassemblers[linkId] ?: return
        when (val res = r.accept(bytes, clock())) {
            is RxResult.Ack -> watchdogs[linkId]?.onAck(res.msgId.toHex())
            is RxResult.Complete -> { sink.sendFrame(linkId, Frame.ack(res.msgId).encode()); onPacket(linkId, res.payload) }
            is RxResult.Duplicate -> {
                sink.sendFrame(linkId, Frame.ack(res.msgId).encode())
                delivered[res.msgId.toHex()]?.let { cid -> contacts[cid]?.let { sendDeliveredAck(it, res.msgId) } }
            }
            else -> {}
        }
    }

    private fun onPacket(fromLink: String, raw: ByteArray) {
        when (val d = relay.onReceive(raw, clock())) {
            is RelayDecision.Forward -> {
                val targets = links.filter { it != fromLink }
                for (l in targets) sendPacket(l, d.packet)

                if (targets.isEmpty()) {
                    relayBacklog.addLast(Backlog(d.packet, fromLink, clock()))
                    while (relayBacklog.size > MAX_BACKLOG) relayBacklog.removeFirst()
                }
            }
            is RelayDecision.Deliver -> deliver(d.packet)
            is RelayDecision.Drop -> if (d.reason == "duplicate") reAckIfOurs(raw)
        }
    }

    private fun reAckIfOurs(raw: ByteArray) {
        val p = Packet.decode(raw) ?: return
        val cid = delivered[p.msgId.toHex()] ?: return
        contacts[cid]?.let { sendDeliveredAck(it, p.msgId) }
    }

    private fun deliver(p: Packet) {
        val tag = p.destTag.toHex(); val now = clock()
        val isInbox = Routing.validDays(now).any { Routing.inboxTag(identity.publicKey, it).toHex() == tag }
        if (isInbox) { cipher.open(p.payload)?.let { handleEnvelope(it, null, p) }; return }
        for (c in contacts.values) {
            if (Routing.validDays(now).none { Routing.contactTag(identity.publicKey, c.publicKey, it).toHex() == tag }) continue
            cipher.decrypt(c.publicKey, p.payload)?.let { handleEnvelope(it, c, p); return }
        }
    }

    private val delivered = LinkedHashMap<String, String>()

    private fun sendDeliveredAck(to: Contact, msgId: ByteArray) {
        val now = clock()
        val pkt = Packet(ByteArray(8).also { random.nextBytes(it) }, Routing.contactTag(identity.publicKey, to.publicKey, now), MAX_TTL,
            cipher.encrypt(to.publicKey, envelope(K_DELIVERED, msgId, now)))
        relay.markOriginatedIfNew(pkt, now)
        for (l in links) sendPacket(l, pkt)
    }

    private fun handleEnvelope(plain: ByteArray, from: Contact?, p: Packet) {
        val i = java.io.DataInputStream(plain.inputStream())
        val kind = i.readUnsignedByte(); val pk = ByteArray(i.readUnsignedByte().also { require(it in 32..64) }).also { i.readFully(it) }; i.readLong(); val nick = i.readUTF()
        val body = ByteArray(i.readInt()).also { i.readFully(it) }
        when (kind) {
            K_TEXT -> if (from != null && from.publicKey.contentEquals(pk)) {
                val text = String(body)
                history.add(BackupMessage(p.msgId.toHex(), from.id, false, clock(), text))
                events.add(MeshEvent.Text(from.id, text, p.msgId.toHex()))
                delivered[p.msgId.toHex()] = from.id
                if (delivered.size > 2048) delivered.remove(delivered.keys.first())
                sendDeliveredAck(from, p.msgId)
            }
            K_DELIVERED -> if (from != null && from.publicKey.contentEquals(pk)) {
                if (outbox.ack(body)) events.add(MeshEvent.Delivered(body.toHex()))
            }
            K_BUNDLE_REQUEST -> if (from == null) {
                val hex = pk.toHex()
                var c = contactFor(pk)
                if (c == null) {
                    if (abuse.checkIncoming(hex, ContactStanding.UNKNOWN, OutgoingContent("")) != Verdict.ALLOW) return
                    addContactKey(hex, pk, nick, accepted = false)
                    c = contacts[hex]
                    events.add(MeshEvent.ContactAppeared(hex, pk, nick))
                }
                val answered = (bundleAnswers[hex] ?: 0) + 1
                bundleAnswers[hex] = answered
                if (answered <= MAX_BUNDLE_ANSWERS_PER_PEER) {
                    cipher.bundleText()?.let { text ->
                        val now = clock()
                        enqueue(Routing.inboxTag(pk, now), cipher.seal(pk, envelope(K_BUNDLE_RESPONSE, text.toByteArray(), now)))
                    }
                }

                if (c != null && !cipher.canEncrypt(pk)) requestBundle(c.id)
            }
            K_BUNDLE_RESPONSE -> if (from == null) {
                val c = contactFor(pk) ?: return
                if (cipher.acceptBundleText(String(body))) {
                    events.add(MeshEvent.SessionReady(c.id))
                    flush()
                }
            }
            K_REQUEST -> if (from == null) {
                val text = String(body)
                if (abuse.checkIncoming(pk.toHex(), ContactStanding.UNKNOWN, OutgoingContent(text)) == Verdict.ALLOW)
                    events.add(MeshEvent.ContactRequest(pk, nick, text))
            }
        }
    }

    fun exportBackup(phrase: List<String>, iterations: Int = BackupCodec.DEFAULT_ITERATIONS): ByteArray =
        BackupCodec.encrypt(phrase, BackupBundle(contacts.values.map { BackupContact(it.id, it.nickname, it.publicKey, trust.level(it.id) == TrustLevel.VERIFIED) }, history), iterations = iterations)

    fun importBackup(phrase: List<String>, data: ByteArray, iterations: Int = BackupCodec.DEFAULT_ITERATIONS) {
        val b = BackupCodec.decrypt(phrase, data, iterations)
        for (c in b.contacts) {
            contacts[c.id] = Contact(c.id, c.nickname, c.publicKey, true); trust.add(c.id, c.publicKey)
            if (c.verified) trust.markVerified(c.id, c.publicKey)
        }
        history.addAll(b.messages)
    }
}
