package dev.kelian.mesh.core.abuse

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AbusePolicyTest {
    private val txt = OutgoingContent("Salut, c'est Paul de la fac")
    private val day = 24L * 60 * 60 * 1000

    @Test fun unknownGetsExactlyOneTextRequest() {
        val p = AbusePolicy()
        assertEquals(Verdict.ALLOW, p.checkOutgoing("x", ContactStanding.UNKNOWN, txt, 0))
        p.recordSent("x", ContactStanding.UNKNOWN, 0)
        assertEquals(Verdict.REJECT_ALREADY_REQUESTED, p.checkOutgoing("x", ContactStanding.UNKNOWN, txt, 1))
        assertEquals(Verdict.ALLOW, p.checkOutgoing("x", ContactStanding.ACCEPTED, txt, 2))
        assertEquals(Verdict.ALLOW, p.checkOutgoing("x", ContactStanding.VERIFIED, OutgoingContent("https://a.cm", true), 2))
    }

    @Test fun noLinksNoAttachmentsToStrangers() {
        val p = AbusePolicy()
        for (t in listOf("viens ici https://evil.example/x", "www.promo.cm", "go to bit.ly/abc", "ftp://x", "gagne.com maintenant"))
            assertTrue(t, containsLink(t)).also { assertEquals(Verdict.REJECT_LINK, p.checkOutgoing("y", ContactStanding.UNKNOWN, OutgoingContent(t), 0)) }
        assertFalse(containsLink("Rendez-vous à 15h, salle B12. Merci!"))
        assertEquals(Verdict.REJECT_ATTACHMENT, p.checkOutgoing("y", ContactStanding.UNKNOWN, OutgoingContent("photo", true), 0))
    }

    @Test fun dailyLimitOnStrangersResetsAfterADay() {
        val p = AbusePolicy(dailyUnknownLimit = 3)
        for (i in 0 until 3) { assertEquals(Verdict.ALLOW, p.checkOutgoing("u$i", ContactStanding.UNKNOWN, txt, 10)); p.recordSent("u$i", ContactStanding.UNKNOWN, 10) }
        assertEquals(Verdict.REJECT_DAILY_LIMIT, p.checkOutgoing("u9", ContactStanding.UNKNOWN, txt, 20))
        assertEquals(Verdict.ALLOW, p.checkOutgoing("known", ContactStanding.VERIFIED, txt, 20))
        assertEquals(Verdict.ALLOW, p.checkOutgoing("u9", ContactStanding.UNKNOWN, txt, 10 + day))
    }

    @Test fun blockedPeersAreRefusedBothWays() {
        val p = AbusePolicy()
        assertEquals(Verdict.REJECT_BLOCKED, p.checkOutgoing("b", ContactStanding.BLOCKED, txt, 0))
        assertEquals(Verdict.REJECT_BLOCKED, p.checkIncoming("b", ContactStanding.BLOCKED, txt))
    }

    @Test fun incomingStrangerCanOnlySendOnePlainText() {
        val p = AbusePolicy()
        assertEquals(Verdict.REJECT_LINK, p.checkIncoming("s", ContactStanding.UNKNOWN, OutgoingContent("http://x.y")))
        assertEquals(Verdict.REJECT_ATTACHMENT, p.checkIncoming("s", ContactStanding.UNKNOWN, OutgoingContent("hi", true)))
        assertEquals(Verdict.ALLOW, p.checkIncoming("s", ContactStanding.UNKNOWN, txt))
        assertEquals(Verdict.REJECT_ALREADY_REQUESTED, p.checkIncoming("s", ContactStanding.UNKNOWN, txt))
        assertEquals(Verdict.ALLOW, p.checkIncoming("s", ContactStanding.ACCEPTED, txt))
    }

    @Test fun reportsStayLocal() {
        val p = AbusePolicy(); p.report("s", "spam")
        assertEquals(mapOf("s" to "spam"), p.reports())
    }
}
