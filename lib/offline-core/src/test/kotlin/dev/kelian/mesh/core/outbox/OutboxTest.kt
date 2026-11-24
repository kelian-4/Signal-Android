package dev.kelian.mesh.core.outbox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class OutboxTest {
    private fun id(n: Int) = ByteArray(8) { n.toByte() }
    private val tag = ByteArray(8) { 9 }

    @Test fun survivesRestartUntilAcked() {
        val f = File.createTempFile("outbox", ".txt"); f.deleteOnExit()
        val a = Outbox(FileOutboxStore(f))
        assertTrue(a.enqueue(id(1), tag, "hello".toByteArray(), 100))
        assertTrue(a.enqueue(id(2), tag, ByteArray(0), 200))
        a.markAttempt("0101010101010101")
        val b = Outbox(FileOutboxStore(f)) // simulated app restart
        assertEquals(2, b.pending().size)
        assertEquals(1, b.pending()[0].attempts)
        assertEquals("hello", String(b.pending()[0].payload))
        assertTrue(b.ack(id(1)))
        assertFalse(b.ack(id(1)))
        assertEquals(1, Outbox(FileOutboxStore(f)).pending().size)
    }

    @Test fun duplicateEnqueueIgnoredAndOrderKept() {
        val o = Outbox(InMemoryOutboxStore())
        assertTrue(o.enqueue(id(1), tag, byteArrayOf(1), 0))
        assertFalse(o.enqueue(id(1), tag, byteArrayOf(2), 1))
        o.enqueue(id(3), tag, byteArrayOf(3), 2); o.enqueue(id(2), tag, byteArrayOf(4), 3)
        assertEquals(listOf("0101010101010101", "0303030303030303", "0202020202020202"), o.pending().map { it.msgIdHex })
    }

    @Test fun capacityIsEnforcedAndCorruptLinesSkipped() {
        val o = Outbox(InMemoryOutboxStore(), maxEntries = 2)
        assertTrue(o.enqueue(id(1), tag, byteArrayOf(), 0)); assertTrue(o.enqueue(id(2), tag, byteArrayOf(), 0))
        assertFalse(o.enqueue(id(3), tag, byteArrayOf(), 0))
        val f = File.createTempFile("outbox", ".txt"); f.deleteOnExit()
        f.writeText("garbage\n0101010101010101 0909090909090909 5 0 6869\nzz zz x y q")
        assertEquals(1, FileOutboxStore(f).load().size)
    }
}
