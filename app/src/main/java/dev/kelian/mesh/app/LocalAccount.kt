package dev.kelian.mesh.app

import android.content.Context
import org.signal.core.models.ServiceId.ACI
import org.thoughtcrime.securesms.database.IdentityTable
import org.thoughtcrime.securesms.database.SignalDatabase
import org.thoughtcrime.securesms.dependencies.AppDependencies
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.recipients.Recipient
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

object LocalAccount {
    @JvmStatic
    fun ensure(context: Context) {
        val account = SignalStore.account
        val registration = SignalStore.registration
        if (account.isRegistered && registration.isRegistrationComplete && account.aci != null) {
            ensureUsername(context)
            return
        }

        val identity = MeshApp.identityOrCreate(context)
        val aci = ACI.from(aciFor(identity.publicKey))
        val pair = identity.identityKeyPair

        account.restoreAciIdentityKeyFromBackup(pair.publicKey.serialize(), pair.privateKey.serialize())
        if (account.registrationId == 0) account.registrationId = 1 + SecureRandom().nextInt(16380)
        account.setAci(aci)

        AppDependencies.resetProtocolStores()

        val recipients = SignalDatabase.recipients
        val selfId = Recipient.trustedPush(aci, null, null).id
        recipients.setProfileSharing(selfId, true)
        recipients.markRegisteredOrThrow(selfId, aci)
        AppDependencies.recipientCache.clearSelf()

        val store = AppDependencies.protocolStore.aci()
        store.identities().saveIdentityWithoutSideEffects(
            selfId, aci, store.identityKeyPair.publicKey, IdentityTable.VerifiedStatus.VERIFIED, true, System.currentTimeMillis(), true,
        )

        account.setRegistered(registered = true, isAciChanged = false)
        registration.hasPromptedPushRegistration = true
        account.isUnauthorizedReceived = false
        registration.markRegistrationComplete()
        ensureUsername(context)
    }

    private fun ensureUsername(context: Context) {
        if (SignalStore.account.username == null) {
            SignalStore.account.username = MeshApp.defaultNickname(MeshApp.identityOrCreate(context)) + ".01"
        }
    }

    internal fun aciFor(identityPublicKey: ByteArray): UUID {
        val h = MessageDigest.getInstance("SHA-256").digest("mesh-aci-v1".toByteArray() + identityPublicKey)
        h[6] = ((h[6].toInt() and 0x0F) or 0x40).toByte()
        h[8] = ((h[8].toInt() and 0x3F) or 0x80).toByte()
        var msb = 0L; var lsb = 0L
        for (i in 0 until 8) msb = (msb shl 8) or (h[i].toLong() and 0xFF)
        for (i in 8 until 16) lsb = (lsb shl 8) or (h[i].toLong() and 0xFF)
        return UUID(msb, lsb)
    }
}
