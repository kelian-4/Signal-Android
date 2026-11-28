package dev.kelian.mesh.signal

import dev.kelian.mesh.core.engine.LinkSink
import dev.kelian.mesh.core.engine.MeshEngine
import dev.kelian.mesh.core.engine.MeshEvent
import dev.kelian.mesh.core.engine.SendResult
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
import java.io.File

class LibsignalTest {
    private class MiniRadio {
        var now = 1_000_000L
        private val queue = ArrayDeque<Triple<MeshEngine, String, ByteArray>>()
        private val peers = HashMap<String, Pair<MeshEngine, String>>()
        fun sink(name: String) = object : LinkSink {
            override fun sendFrame(linkId: String, frame: ByteArray) { peers["$name/$linkId"]?.let { queue.add(Triple(it.first, it.second, frame)) } }
        }
        fun connect(a: MeshEngine, na: String, la: String, b: MeshEngine, nb: String, lb: String) {
            peers["$na/$la"] = b to lb; peers["$nb/$lb"] = a to la
            a.onLinkUp(la); b.onLinkUp(lb)
        }
        fun run() { var n = 0; while (queue.isNotEmpty()) { check(++n < 200_000); val (e, l, f) = queue.removeFirst(); e.onFrame(l, f) } }
    }

    private fun exchangeBundles(a: LibsignalSessionCipher, b: LibsignalSessionCipher, oneWay: Boolean = false) {
        val bb = PreKeyBundle.parse(b.publishBundle().encode(), LibsignalSignatures)!!
        a.acceptPeerBundle(bb)
        if (!oneWay) a.let { val ab = PreKeyBundle.parse(a.publishBundle().encode(), LibsignalSignatures)!!; b.acceptPeerBundle(ab) }
    }

    @Test fun identityIsDeterministicAndRestorableFromThePhrase() {
        val a = LibsignalIdentity.generate()
        val r = LibsignalIdentity.fromPhrase(a.recoveryPhrase())
        assertEquals(a.publicKey.toHex(), r.publicKey.toHex())
        assertEquals(33, a.publicKey.size)
        assertTrue(LibsignalSignatures.verify(a.publicKey, "m".toByteArray(), r.sign("m".toByteArray())))
        assertFalse(LibsignalSignatures.verify(LibsignalIdentity.generate().publicKey, "m".toByteArray(), a.sign("m".toByteArray())))
        assertFalse(LibsignalSignatures.verify(ByteArray(5), "m".toByteArray(), a.sign("m".toByteArray())))
    }

    @Test fun qrAndChallengeWorkWithLibsignalKeys() {
        val a = LibsignalIdentity.generate(); val b = LibsignalIdentity.generate()
        val qr = QrPayload.parse(QrPayload.create(a, "Awa", 5000).encode(), 5100, LibsignalSignatures)!!
        assertEquals(33, qr.publicKey.size)
        assertNull(QrPayload.parse(QrPayload.create(a, "Awa", 5000).encode(), 5100))
        val ch = Challenge.newChallenge()
        assertTrue(Challenge.verify(a.publicKey, ch, b.publicKey, Challenge.respond(a, ch, b.publicKey), LibsignalSignatures))
        assertFalse(Challenge.verify(b.publicKey, ch, b.publicKey, Challenge.respond(a, ch, b.publicKey), LibsignalSignatures))
    }

    @Test fun bundleIsSignedTamperProofAndSmallEnoughForAQr() {
        val c = LibsignalSessionCipher(LibsignalIdentity.generate())
        val text = c.publishBundle().encode()
        assertNotNull(PreKeyBundle.parse(text, LibsignalSignatures))
        assertTrue("bundle is ${text.length} chars", text.length <= 2900)
        val raw = java.util.Base64.getUrlDecoder().decode(text); raw[raw.size / 2] = (raw[raw.size / 2] + 1).toByte()
        assertNull(PreKeyBundle.parse(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw), LibsignalSignatures))
    }

    @Test fun doubleRatchetSessionWorksBothWays() {
        val ia = LibsignalIdentity.generate(); val ib = LibsignalIdentity.generate()
        val a = LibsignalSessionCipher(ia); val b = LibsignalSessionCipher(ib)
        assertFalse(a.canEncrypt(ib.publicKey))
        exchangeBundles(a, b, oneWay = true)
        assertTrue(a.canEncrypt(ib.publicKey)); assertFalse(b.canEncrypt(ia.publicKey))
        val first = a.encrypt(ib.publicKey, "bonjour".toByteArray())
        assertFalse(String(first, Charsets.ISO_8859_1).contains("bonjour"))
        assertEquals("bonjour", String(b.decrypt(ia.publicKey, first)!!))
        assertTrue(b.canEncrypt(ia.publicKey))
        val reply = b.encrypt(ia.publicKey, "salut".toByteArray())
        assertEquals("salut", String(a.decrypt(ib.publicKey, reply)!!))
        val second = a.encrypt(ib.publicKey, "suite".toByteArray())
        assertEquals("suite", String(b.decrypt(ia.publicKey, second)!!))
        val tampered = second.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertNull(b.decrypt(ia.publicKey, tampered))
        assertNull(b.decrypt(LibsignalIdentity.generate().publicKey, second))
    }

    @Test fun sessionsSurviveARestart() {
        val f = File.createTempFile("mesh-signal", ".bin"); f.deleteOnExit()
        val ia = LibsignalIdentity.generate(); val ib = LibsignalIdentity.generate()
        val a = LibsignalSessionCipher(ia, f); val b = LibsignalSessionCipher(ib)
        exchangeBundles(a, b, oneWay = true)
        assertEquals("1", String(b.decrypt(ia.publicKey, a.encrypt(ib.publicKey, "1".toByteArray()))!!))
        val reply = b.encrypt(ia.publicKey, "2".toByteArray())
        val a2 = LibsignalSessionCipher(ia, f)
        assertTrue(a2.canEncrypt(ib.publicKey))
        assertEquals("2", String(a2.decrypt(ib.publicKey, reply)!!))
        assertEquals("3", String(b.decrypt(ia.publicKey, a2.encrypt(ib.publicKey, "3".toByteArray()))!!))
    }

    @Test fun contactRequestsAreSealedToTheRecipientOnly() {
        val ia = LibsignalIdentity.generate(); val ib = LibsignalIdentity.generate()
        val a = LibsignalSessionCipher(ia); val b = LibsignalSessionCipher(ib)
        val sealed = a.seal(ib.publicKey, "salut".toByteArray())
        assertEquals("salut", String(b.open(sealed)!!))
        assertNull(a.open(sealed))
        assertNull(b.open(sealed.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }))
    }

    @Test fun fullStackTextOverTheMeshWithLibsignalAndARelay() {
        val radio = MiniRadio()
        val ia = LibsignalIdentity.generate(); val ib = LibsignalIdentity.generate(); val ic = LibsignalIdentity.generate()
        val ca = LibsignalSessionCipher(ia); val cb = LibsignalSessionCipher(ib); val cc = LibsignalSessionCipher(ic)
        val a = MeshEngine(ia, "Alice", ca, radio.sink("A"), { radio.now })
        val b = MeshEngine(ib, "Bob", cb, radio.sink("B"), { radio.now })
        val c = MeshEngine(ic, "Relais", cc, radio.sink("C"), { radio.now })
        val qrB = QrPayload.parse(QrPayload.create(ib, "Bob", radio.now).encode(), radio.now, LibsignalSignatures)!!
        val qrA = QrPayload.parse(QrPayload.create(ia, "Alice", radio.now).encode(), radio.now, LibsignalSignatures)!!
        a.addContact("bob", qrB); b.addContact("alice", qrA)
        val ch = Challenge.newChallenge()
        assertTrue(Challenge.verify(qrB.publicKey, ch, ia.publicKey, Challenge.respond(ib, ch, ia.publicKey), LibsignalSignatures))
        assertTrue(a.markVerified("bob")); assertTrue(b.markVerified("alice"))
        assertEquals(TrustLevel.VERIFIED, a.trust.level("bob"))
        assertTrue(a.sendText("bob", "trop tôt") is SendResult.NoSession)
        exchangeBundles(ca, cb)
        radio.connect(a, "A", "toC", c, "C", "toA"); radio.connect(c, "C", "toB", b, "B", "toC")
        assertTrue(a.sendText("bob", "salut Bob, via le relais") is SendResult.Queued)
        radio.run()
        assertEquals("salut Bob, via le relais", b.events.filterIsInstance<MeshEvent.Text>().single().text)
        assertTrue(c.events.isEmpty())
        assertEquals(0, a.pendingCount())
        assertTrue(a.events.any { it is MeshEvent.Delivered })
        assertTrue(b.sendText("alice", "bien reçu") is SendResult.Queued)
        radio.run()
        assertEquals("bien reçu", a.events.filterIsInstance<MeshEvent.Text>().single().text)
    }

    @Test fun bundleTextBuildsASessionAndRejectsGarbage() {
        val ia = LibsignalIdentity.generate(); val ib = LibsignalIdentity.generate()
        val a = LibsignalSessionCipher(ia); val b = LibsignalSessionCipher(ib)
        assertFalse(a.canEncrypt(ib.publicKey))
        assertTrue(a.acceptBundleText(b.bundleText()!!))
        assertTrue(a.canEncrypt(ib.publicKey))
        assertFalse(a.acceptBundleText("garbage"))
    }
}
