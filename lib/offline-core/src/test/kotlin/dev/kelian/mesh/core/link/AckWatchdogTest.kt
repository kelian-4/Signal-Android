package dev.kelian.mesh.core.link

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AckWatchdogTest {
    @Test fun nothingHappensWhileAcksArrive() {
        val w = AckWatchdog(8000)
        w.onSent("a", 0); w.onAck("a")
        assertTrue(w.poll(60_000) is WatchdogAction.None)
    }

    @Test fun frozenPeerWith27UnackedMessagesTriggersOneReconnect() {
        val w = AckWatchdog(8000)
        for (i in 0 until 27) w.onSent("m$i", i * 100L)
        assertTrue(w.poll(5_000) is WatchdogAction.None)
        val a = w.poll(46_000)
        assertTrue(a is WatchdogAction.Reconnect && a.stale == 27 && a.attempt == 1)
        assertTrue(w.poll(46_100) is WatchdogAction.None) // timers restarted on the new link
        assertEquals(27, w.inFlight())
    }

    @Test fun givesUpAfterRepeatedFailuresAndAckResetsCounter() {
        val w = AckWatchdog(1000, maxRepairs = 2)
        w.onSent("x", 0)
        assertTrue(w.poll(1000) is WatchdogAction.Reconnect)
        assertTrue(w.poll(2000) is WatchdogAction.Reconnect)
        assertTrue(w.poll(3000) is WatchdogAction.GiveUp)
        w.onAck("x")
        w.onSent("y", 4000)
        assertTrue(w.poll(5000) is WatchdogAction.Reconnect)
    }

    @Test fun diagnosticsCsvLine() {
        assertEquals("10,disconnect,nominal,46000,133,-70,81,true", LinkDiagnostics(10, "disconnect", "nominal", 46000, 133, -70, 81, true).toCsv())
        assertEquals("1,scan,,,,,,", LinkDiagnostics(1, "scan", null, null, null, null, null, null).toCsv())
    }
}
