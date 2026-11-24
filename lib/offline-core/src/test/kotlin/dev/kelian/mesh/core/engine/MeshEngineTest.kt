package dev.kelian.mesh.core.engine

import dev.kelian.mesh.core.abuse.Verdict
import dev.kelian.mesh.core.identity.Identity
import dev.kelian.mesh.core.identity.Bip39
import dev.kelian.mesh.core.prekeys.PreKeyBundle
import dev.kelian.mesh.core.protocol.toHex
import dev.kelian.mesh.core.verify.Challenge
import dev.kelian.mesh.core.verify.QrPayload
import dev.kelian.mesh.core.verify.TrustLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** TEST-ONLY cipher (keys derived from public keys, NOT secure). Real builds plug libsignal sessions in here. */
class FakeCipher(private val ownPk: ByteArray) : SessionCipher {
    private val rnd = SecureRandom()
    private fun key(vararg parts: ByteArray) = SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(parts.reduce { a, b -> a + b }), "AES")
    private fun enc(k: SecretKeySpec, plain: ByteArray): ByteArray {
        val iv = ByteArray(12).also { rnd.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, k, GCMParameterSpec(128, iv))
        return iv + c.doFinal(plain)
    }
    private fun dec(k: SecretKeySpec, d: ByteArray): ByteArray? = runCatching {
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, d.copyOfRange(0, 12)))
        c.doFinal(d, 12, d.size - 12)
    }.getOrNull()
    private fun pair(peer: ByteArray) = listOf(ownPk, peer).sortedWith { a, b -> java.util.Arrays.compareUnsigned(a, b) }.let { it[0] + it[1] }
    override fun encrypt(peerPk: ByteArray, plain: ByteArray) = enc(key("pair".toByteArray(), pair(peerPk)), plain)
    override fun decrypt(peerPk: ByteArray, data: ByteArray) = dec(key("pair".toByteArray(), pair(peerPk)), data)
    override fun seal(recipientPk: ByteArray, plain: ByteArray) = enc(key("seal".toByteArray(), recipientPk), plain)
    override fun open(data: ByteArray) = dec(key("seal".toByteArray(), ownPk), data)
}

/** Simulated radio: frames go through a queue; a link can be frozen (frames silently lost). */
class SimRadio {
    class Port(val engine: () -> MeshEngine, val remoteLink: String)
    val clock = longArrayOf(1_000_000L)
    private val queue = ArrayDeque<Triple<() -> MeshEngine, String, ByteArray>>()
    private val ports = HashMap<String, Port>() // "<engineName>/<linkId>"
    val frozen = HashSet<String>()
    var frames = 0

    fun sinkFor(name: String) = object : LinkSink {
        override fun sendFrame(linkId: String, frame: ByteArray) {
            val port = ports["$name/$linkId"] ?: return
            if ("$name/$linkId" in frozen) return
            frames++
            queue.add(Triple(port.engine, port.remoteLink, frame))
        }
    }

    fun connect(a: String, ea: () -> MeshEngine, la: String, b: String, eb: () -> MeshEngine, lb: String) {
        ports["$a/$la"] = Port(eb, lb); ports["$b/$lb"] = Port(ea, la)
        ea().onLinkUp(la); eb().onLinkUp(lb)
    }

    fun run() { var n = 0; while (queue.isNotEmpty()) { check(++n < 200_000) { "radio storm" }; val (e, l, f) = queue.removeFirst(); e().onFrame(l, f) } }
}

class MeshEngineTest {
    private val fast = 1000
    private lateinit var radio: SimRadio

    private fun engine(name: String, id: Identity = Identity.generate()): MeshEngine {
        if (!::radio.isInitialized) radio = SimRadio()
        return MeshEngine(id, name, FakeCipher(id.publicKey), radio.sinkFor(name), { radio.clock[0] })
    }

    /** In-person QR exchange: scan, signature check, challenge-response, then "verified". */
    private fun meetAndVerify(a: MeshEngine, aId: String, b: MeshEngine, bId: String) {
        val now = radio.clock[0]
        val qrB = QrPayload.parse(QrPayload.create(b.identity, b.nickname, now).encode(), now)!!
        val qrA = QrPayload.parse(QrPayload.create(a.identity, a.nickname, now).encode(), now)!!
        a.addContact(bId, qrB); b.addContact(aId, qrA)
        val ch = Challenge.newChallenge()
        assertTrue(Challenge.verify(qrB.publicKey, ch, a.identity.publicKey, Challenge.respond(b.identity, ch, a.identity.publicKey)))
        assertTrue(a.markVerified(bId))
        val ch2 = Challenge.newChallenge()
        assertTrue(Challenge.verify(qrA.publicKey, ch2, b.identity.publicKey, Challenge.respond(a.identity, ch2, b.identity.publicKey)))
        assertTrue(b.markVerified(aId))
    }

    @Test fun endToEndAcceptanceScenarioInSimulation() {
        val ida = Identity.generate(); val idb = Identity.generate()
        lateinit var a: MeshEngine; lateinit var b: MeshEngine
        radio = SimRadio(); a = engine("Alice", ida); b = engine("Bob", idb)
        // 1. identities exist without number/e-mail; 2. add each other by QR; badge only after the in-person proof
        val qrB = QrPayload.parse(QrPayload.create(idb, "Bob", radio.clock[0]).encode(), radio.clock[0])!!
        a.addContact("bob", qrB)
        assertEquals(TrustLevel.UNVERIFIED, a.trust.level("bob"))
        meetAndVerify(a, "alice", b, "bob")
        assertEquals(TrustLevel.VERIFIED, a.trust.level("bob")); assertEquals(TrustLevel.VERIFIED, b.trust.level("alice"))
        // 3. encrypted one-to-one text over the (simulated) link, end-to-end ACK
        radio.connect("Alice", { a }, "L", "Bob", { b }, "L")
        val sent = a.sendText("bob", "Salut Bob, tu es là ?") as SendResult.Queued
        radio.run()
        val got = b.events.filterIsInstance<MeshEvent.Text>().single()
        assertEquals("Salut Bob, tu es là ?", got.text); assertEquals("alice", got.contactId)
        assertTrue(a.events.filterIsInstance<MeshEvent.Delivered>().any { it.msgIdHex == sent.msgIdHex })
        assertEquals(0, a.pendingCount())
        // 4. key change: Bob reinstalls with a new identity -> alert, badge removed
        a.onAuthenticatedKey("bob", Identity.generate().publicKey)
        assertEquals(1, a.events.filterIsInstance<MeshEvent.KeyChanged>().size)
        assertEquals(TrustLevel.UNVERIFIED, a.trust.level("bob"))
        // 5. identity restored from the 24-word phrase; 6. backup export/import (history yes, verification kept, sessions none)
        val restored = Identity.fromPhrase(ida.recoveryPhrase())
        assertEquals(ida.publicKey.toHex(), restored.publicKey.toHex())
        val file = b.exportBackup(idb.recoveryPhrase(), fast)
        val b2 = engine("Bob2", Identity.fromPhrase(idb.recoveryPhrase()))
        b2.importBackup(idb.recoveryPhrase(), file, fast)
        assertEquals("Salut Bob, tu es là ?", b2.history.single().text)
        assertEquals(TrustLevel.VERIFIED, b2.trust.level("alice"))
        assertNotNull(b2.contact("alice"))
    }

    @Test fun messageWaitsInOutboxUntilALinkAppears() {
        radio = SimRadio(); val a = engine("A"); val b = engine("B")
        meetAndVerify(a, "a", b, "b")
        assertTrue(a.sendText("b", "hors ligne d'abord") is SendResult.Queued)
        assertEquals(1, a.pendingCount())
        radio.connect("A", { a }, "L", "B", { b }, "L"); radio.run()
        assertEquals(1, b.events.filterIsInstance<MeshEvent.Text>().size); assertEquals(0, a.pendingCount())
    }

    @Test fun resendNeverShowsTwiceButIsAcknowledgedAgain() {
        radio = SimRadio(); val a = engine("A"); val b = engine("B")
        meetAndVerify(a, "a", b, "b")
        radio.connect("A", { a }, "L", "B", { b }, "L")
        val id = (a.sendText("b", "une fois") as SendResult.Queued).msgIdHex
        radio.frozen.add("B/L") // B's answers are lost: the end-to-end ACK never arrives
        radio.run()
        assertEquals(1, a.pendingCount())
        radio.frozen.clear(); a.flush(); radio.run()
        assertEquals(1, b.events.filterIsInstance<MeshEvent.Text>().size)
        assertEquals(0, a.pendingCount()); assertTrue(a.events.any { it is MeshEvent.Delivered && it.msgIdHex == id })
    }

    @Test fun twoHopRelayThroughAPhoneThatCannotReadIt() {
        radio = SimRadio(); val a = engine("A"); val b = engine("B"); val c = engine("C")
        meetAndVerify(a, "a", b, "b")
        radio.connect("A", { a }, "toC", "C", { c }, "toA"); radio.connect("C", { c }, "toB", "B", { b }, "toC")
        a.sendText("b", "via C"); radio.run()
        assertEquals("via C", b.events.filterIsInstance<MeshEvent.Text>().single().text)
        assertTrue(c.events.isEmpty())
        assertEquals(0, a.pendingCount()) // the delivery ACK came back through the relay
    }

    @Test fun contactRequestIsOneShortPlainText() {
        radio = SimRadio(); val a = engine("A"); val b = engine("B")
        radio.connect("A", { a }, "L", "B", { b }, "L")
        assertEquals(Verdict.REJECT_LINK, (a.sendContactRequest(b.identity.publicKey, "regarde http://x.cm") as SendResult.Rejected).verdict)
        assertTrue(a.sendContactRequest(b.identity.publicKey, "Salut, c'est Awa de la fac") is SendResult.Queued)
        assertEquals(Verdict.REJECT_ALREADY_REQUESTED, (a.sendContactRequest(b.identity.publicKey, "salut ?") as SendResult.Rejected).verdict)
        radio.run()
        val req = b.events.filterIsInstance<MeshEvent.ContactRequest>().single()
        assertEquals("Salut, c'est Awa de la fac", req.text); assertEquals("A", req.nickname)
        assertEquals(a.identity.publicKey.toHex(), req.senderPk.toHex())
    }

    @Test fun frozenLinkIsDetectedByTheWatchdog() {
        radio = SimRadio(); val a = engine("A"); val b = engine("B")
        meetAndVerify(a, "a", b, "b")
        radio.connect("A", { a }, "L", "B", { b }, "L")
        radio.frozen.add("A/L")
        for (i in 1..27) a.sendText("b", "m$i")
        radio.run()
        radio.clock[0] += 46_000; a.tick()
        val repair = a.events.filterIsInstance<MeshEvent.LinkRepair>().single()
        assertEquals("L", repair.linkId); assertTrue(repair.stale >= 27)
        assertEquals(27, a.pendingCount())
        // radio layer reconnects: everything pending is re-sent and finally acknowledged
        radio.frozen.clear(); a.onLinkDown("L"); a.onLinkUp("L"); radio.run()
        assertEquals(27, b.events.filterIsInstance<MeshEvent.Text>().size); assertEquals(0, a.pendingCount())
    }

    @Test fun tagsAreEphemeralAndDifferPerContact() {
        val a = Identity.generate(); val b = Identity.generate(); val c = Identity.generate()
        val day = 24L * 3600 * 1000
        assertEquals(Routing.contactTag(a.publicKey, b.publicKey, 5).toHex(), Routing.contactTag(b.publicKey, a.publicKey, 5).toHex())
        assertFalse(Routing.contactTag(a.publicKey, b.publicKey, 5).toHex() == Routing.contactTag(a.publicKey, c.publicKey, 5).toHex())
        assertFalse(Routing.contactTag(a.publicKey, b.publicKey, 5).toHex() == Routing.contactTag(a.publicKey, b.publicKey, 5 + day).toHex())
    }

    @Test fun preKeyBundleIsSignedAndTamperProof() {
        val id = Identity.generate()
        val bundle = PreKeyBundle.create(id, 7, ByteArray(33) { 1 }, List(5) { it to ByteArray(33) { b -> (b + it).toByte() } })
        val p = PreKeyBundle.parse(bundle.encode())!!
        assertEquals(id.publicKey.toHex(), p.identityKey.toHex()); assertEquals(5, p.oneTimePreKeys.size); assertEquals(7, p.signedPreKeyId)
        val raw = java.util.Base64.getUrlDecoder().decode(bundle.encode()); raw[40] = (raw[40] + 1).toByte()
        assertNull(PreKeyBundle.parse(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw)))
        assertNull(PreKeyBundle.parse("zzz")); assertNull(PreKeyBundle.parse(""))
    }
}
