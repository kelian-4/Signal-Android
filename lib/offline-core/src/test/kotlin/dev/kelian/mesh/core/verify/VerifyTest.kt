package dev.kelian.mesh.core.verify

import dev.kelian.mesh.core.identity.Identity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VerifyTest {
    private val alice = Identity.generate(); private val bob = Identity.generate()

    @Test fun qrRoundTripAndSignature() {
        val qr = QrPayload.create(alice, "Alice", 1_000_000).encode()
        val p = QrPayload.parse(qr, 1_000_500)!!
        assertEquals("Alice", p.nickname); assertTrue(p.publicKey.contentEquals(alice.publicKey))
    }

    @Test fun qrRejectsTamperingExpiryAndGarbage() {
        val qr = QrPayload.create(alice, "Alice", 1_000_000).encode()
        assertNull(QrPayload.parse(qr, 1_000_000 + QrPayload.MAX_AGE_MS + 1))
        assertNull(QrPayload.parse(qr, 1_000_000 - 120_000))
        assertNull(QrPayload.parse("not base64 !!", 0)); assertNull(QrPayload.parse("", 0)); assertNull(QrPayload.parse("AAAA", 0))
        val forged = QrPayload(alice.publicKey, "Mallory", 1_000_000, QrPayload.create(alice, "Alice", 1_000_000).signature).encode()
        assertNull(QrPayload.parse(forged, 1_000_100))
        val stolen = QrPayload(bob.publicKey, "Alice", 1_000_000, QrPayload.create(alice, "Alice", 1_000_000).signature).encode()
        assertNull(QrPayload.parse(stolen, 1_000_100))
    }

    @Test fun challengeResponseProvesPossessionOfTheKey() {
        val ch = Challenge.newChallenge()
        val resp = Challenge.respond(alice, ch, bob.publicKey)
        assertTrue(Challenge.verify(alice.publicKey, ch, bob.publicKey, resp))
        assertFalse(Challenge.verify(alice.publicKey, Challenge.newChallenge(), bob.publicKey, resp))
        assertFalse(Challenge.verify(bob.publicKey, ch, bob.publicKey, resp))
        val mallory = Identity.generate()
        assertFalse(Challenge.verify(alice.publicKey, ch, bob.publicKey, Challenge.respond(mallory, ch, bob.publicKey)))
    }

    @Test fun securityCodeIsSymmetricAndKeySensitive() {
        val c1 = SecurityCode.compute(alice.publicKey, bob.publicKey)
        assertEquals(c1, SecurityCode.compute(bob.publicKey, alice.publicKey))
        assertEquals(12, c1.split(" ").size); assertTrue(c1.split(" ").all { it.length == 5 })
        assertTrue(c1 != SecurityCode.compute(alice.publicKey, Identity.generate().publicKey))
    }

    @Test fun everyoneStartsUnverifiedAndKeyChangeDropsTheBadge() {
        val book = ContactTrustBook()
        book.add("bob", bob.publicKey)
        assertEquals(TrustLevel.UNVERIFIED, book.level("bob"))
        assertFalse(book.markVerified("bob", alice.publicKey))
        assertTrue(book.markVerified("bob", bob.publicKey))
        assertEquals(TrustLevel.VERIFIED, book.level("bob"))
        assertNull(book.onKeySeen("bob", bob.publicKey))
        val newKey = Identity.generate().publicKey
        val alert = book.onKeySeen("bob", newKey)
        assertNotNull(alert); assertTrue(alert!!.wasVerified)
        assertEquals(TrustLevel.UNVERIFIED, book.level("bob"))
        assertNull(book.onKeySeen("bob", newKey))
        assertNull(book.onKeySeen("unknown", newKey))
    }

    @Test fun keyChangeOnUnverifiedContactAlertsWithoutBadge() {
        val book = ContactTrustBook(); book.add("bob", bob.publicKey)
        assertFalse(book.onKeySeen("bob", alice.publicKey)!!.wasVerified)
    }

    private class CurveLikeSigner(seed: Int) : dev.kelian.mesh.core.identity.IdentitySigner {
        override val publicKey = ByteArray(33) { (if (it == 0) 5 else seed + it).toByte() }
        override fun sign(message: ByteArray) = CurveLikeScheme.sig(publicKey, message)
    }
    private object CurveLikeScheme : dev.kelian.mesh.core.identity.SignatureVerifier {
        fun sig(pk: ByteArray, m: ByteArray) = java.security.MessageDigest.getInstance("SHA-512").digest(pk + m)
        override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray) = sig(publicKey, message).contentEquals(signature)
    }

    @Test fun otherSignatureSchemesAndKeyLengthsPlugIn() {
        val a = CurveLikeSigner(1); val b = CurveLikeSigner(50)
        val qr = QrPayload.create(a, "Awa", 5_000).encode()
        assertNull(QrPayload.parse(qr, 5_100))
        val p = QrPayload.parse(qr, 5_100, CurveLikeScheme)!!
        assertEquals(33, p.publicKey.size); assertEquals("Awa", p.nickname)
        val ch = Challenge.newChallenge()
        assertTrue(Challenge.verify(a.publicKey, ch, b.publicKey, Challenge.respond(a, ch, b.publicKey), CurveLikeScheme))
        assertFalse(Challenge.verify(b.publicKey, ch, b.publicKey, Challenge.respond(a, ch, b.publicKey), CurveLikeScheme))
        val bundle = dev.kelian.mesh.core.prekeys.PreKeyBundle.create(a, 3, ByteArray(33) { 1 }, listOf(7 to ByteArray(33) { 2 }), ByteArray(1600) { 9 })
        val back = dev.kelian.mesh.core.prekeys.PreKeyBundle.parse(bundle.encode(), CurveLikeScheme)!!
        assertEquals(1600, back.extra.size); assertEquals(33, back.identityKey.size)
        assertNull(dev.kelian.mesh.core.prekeys.PreKeyBundle.parse(bundle.encode()))
    }
}
