package dev.kelian.mesh.core.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class ProtocolVectorsTest {
    @Test
    fun sharedVectorsPass() {
        val failures = VectorRunner.runAll(javaClass.getResource("/vectors.json")!!.readText())
        assertTrue("Vector failures:\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun goldenTextFrame() {
        val f = Frame(TYPE_TEXT, "0102030405060708".hexToBytes(), 0, 1, "hello".toByteArray())
        assertEquals("010101020304050607080000" + "0001" + "68656c6c6f", f.encode().toHex())
    }

    @Test
    fun randomRoundTripShuffled() {
        val rnd = Random(1234)
        repeat(300) {
            val data = rnd.nextBytes(rnd.nextInt(0, 900))
            val id = rnd.nextBytes(8)
            val frames = fragment(data, rnd.nextInt(15, 260), id).shuffled(rnd)
            val r = Reassembler()
            var out: ByteArray? = null
            frames.forEachIndexed { i, f ->
                val res = r.accept(f.encode(), i.toLong())
                if (res is RxResult.Complete) out = res.payload
            }
            assertEquals(data.toHex(), out!!.toHex())
        }
    }

    @Test
    fun decodeNeverCrashesOnGarbage() {
        val rnd = Random(99)
        repeat(2000) { Frame.decode(rnd.nextBytes(rnd.nextInt(0, 40))) }
        assertNull(Frame.decode(ByteArray(0)))
    }
}
