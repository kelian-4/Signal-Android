package dev.kelian.mesh.core.identity

import dev.kelian.mesh.core.protocol.hexToBytes
import dev.kelian.mesh.core.protocol.toHex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.SecureRandom

class IdentityTest {
    private fun fails(f: () -> Unit) = runCatching(f).isFailure

    @Test fun wordlistIsTheOfficialOne() {
        assertEquals(2048, Bip39.wordlist.size)
        assertEquals("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
            MessageDigest.getInstance("SHA-256").digest(javaClass.getResourceAsStream("/bip39-english.txt")!!.readBytes()).toHex())
    }

    @Test fun officialBip39Vectors() {
        assertEquals("abandon ".repeat(23) + "art", Bip39.encode(ByteArray(32)).joinToString(" "))
        assertEquals("zoo ".repeat(23) + "vote", Bip39.encode(ByteArray(32) { 0xFF.toByte() }).joinToString(" "))
        assertEquals("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            Bip39.encode(ByteArray(32) { 0x7F }).joinToString(" "))
    }

    @Test fun phraseRoundTripRandom() {
        val r = SecureRandom()
        repeat(50) {
            val e = ByteArray(32).also { r.nextBytes(it) }
            assertEquals(e.toHex(), Bip39.decode(Bip39.encode(e)).toHex())
        }
    }

    @Test fun badPhrasesAreRejected() {
        val w = Bip39.encode(ByteArray(32)).toMutableList()
        assertTrue(fails { Bip39.decode(w.dropLast(1)) })
        val badSum = w.toMutableList().also { it[23] = "abandon" }
        assertTrue(fails { Bip39.decode(badSum) })
        assertTrue(fails { Bip39.decode(w.toMutableList().also { it[0] = "notaword" }) })
        assertEquals(24, Bip39.parse("  ${w.joinToString("  ")}\n").size)
    }

    @Test fun sameSeedGivesSameIdentityAndPhraseRestoresIt() {
        val a = Identity.generate()
        val restored = Identity.fromPhrase(a.recoveryPhrase())
        assertEquals(a.publicKey.toHex(), restored.publicKey.toHex())
        assertEquals(32, a.publicKey.size)
        val msg = "salut".toByteArray()
        assertTrue(Ed25519.verify(a.publicKey, msg, restored.sign(msg)))
        assertTrue(Identity.generate().publicKey.toHex() != a.publicKey.toHex())
    }

    @Test fun signaturesVerifyOnlyForTheRightKeyAndMessage() {
        val a = Identity.generate(); val b = Identity.generate()
        val sig = a.sign("m".toByteArray())
        assertTrue(Ed25519.verify(a.publicKey, "m".toByteArray(), sig))
        assertFalse(Ed25519.verify(b.publicKey, "m".toByteArray(), sig))
        assertFalse(Ed25519.verify(a.publicKey, "x".toByteArray(), sig))
        assertFalse(Ed25519.verify(a.publicKey, "m".toByteArray(), ByteArray(10)))
        assertFalse(Ed25519.verify(ByteArray(5), "m".toByteArray(), sig))
    }

    @Test fun knownEd25519Rfc8032Vector() {
        val seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".hexToBytes()
        val id = Identity.fromSeed(seed)
        assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", id.publicKey.toHex())
        assertEquals("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            id.sign(ByteArray(0)).toHex())
    }
}
