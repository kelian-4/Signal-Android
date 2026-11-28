package dev.kelian.mesh.core.backup

import dev.kelian.mesh.core.identity.Bip39
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupTest {
    private val phrase = Bip39.encode(ByteArray(32) { it.toByte() })
    private val other = Bip39.encode(ByteArray(32) { (it + 1).toByte() })
    private val bundle = BackupBundle(
        listOf(BackupContact("c1", "Aïcha", ByteArray(32) { 7 }, true), BackupContact("c2", "Paul", ByteArray(32) { 8 }, false)),
        listOf(BackupMessage("0102030405060708", "c1", true, 1000, "Bonjour é 😀"), BackupMessage("0807060504030201", "c1", false, 2000, "")),
    )
    private val fast = 1000

    @Test fun roundTrip() {
        val enc = BackupCodec.encrypt(phrase, bundle, iterations = fast)
        val dec = BackupCodec.decrypt(phrase, enc, iterations = fast)
        assertEquals(2, dec.contacts.size); assertEquals("Aïcha", dec.contacts[0].nickname); assertTrue(dec.contacts[0].verified)
        assertEquals(2, dec.messages.size); assertEquals("Bonjour é 😀", dec.messages[0].text); assertFalse(dec.messages[1].outgoing)
    }

    @Test fun ciphertextHidesContentAndDiffersEachTime() {
        val a = BackupCodec.encrypt(phrase, bundle, iterations = fast); val b = BackupCodec.encrypt(phrase, bundle, iterations = fast)
        assertFalse(a.contentEquals(b))
        assertFalse(String(a, Charsets.ISO_8859_1).contains("Bonjour"))
    }

    @Test fun wrongPhraseTamperingAndGarbageAreRejected() {
        val enc = BackupCodec.encrypt(phrase, bundle, iterations = fast)
        fun rejected(f: () -> Unit) = try { f(); false } catch (e: BackupException) { true }
        assertTrue(rejected { BackupCodec.decrypt(other, enc, iterations = fast) })
        assertTrue(rejected { BackupCodec.decrypt(phrase, enc.copyOf().also { it[enc.size - 1] = (it[enc.size - 1] + 1).toByte() }, iterations = fast) })
        assertTrue(rejected { BackupCodec.decrypt(phrase, enc.copyOf().also { it[10] = (it[10] + 1).toByte() }, iterations = fast) })
        assertTrue(rejected { BackupCodec.decrypt(phrase, ByteArray(100), iterations = fast) })
        assertTrue(rejected { BackupCodec.decrypt(phrase, ByteArray(3), iterations = fast) })
    }

    @Test fun backupApiHasNoSessionState() {
        val names = BackupBundle::class.java.declaredFields.map { it.name.lowercase() }
        assertEquals(setOf("contacts", "messages"), names.toSet())
    }

    @Test fun defaultCostRoundTrip() {
        assertEquals(1, BackupCodec.decrypt(phrase, BackupCodec.encrypt(phrase, BackupBundle(emptyList(), listOf(BackupMessage("00", "c", true, 1, "x"))))).messages.size)
    }
}
