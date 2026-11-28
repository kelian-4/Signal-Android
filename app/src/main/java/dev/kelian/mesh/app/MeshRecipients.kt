package dev.kelian.mesh.app

import android.content.Context
import dev.kelian.mesh.core.protocol.toHex
import org.signal.core.models.ServiceId.ACI
import org.thoughtcrime.securesms.database.SignalDatabase
import org.thoughtcrime.securesms.profiles.ProfileName
import org.thoughtcrime.securesms.recipients.Recipient

object MeshRecipients {
    fun ensure(context: Context, publicKey: ByteArray, nickname: String): Recipient {
        val aci = ACI.from(LocalAccount.aciFor(publicKey))
        val recipient = Recipient.trustedPush(aci, null, null)
        val table = SignalDatabase.recipients
        table.markRegisteredOrThrow(recipient.id, aci)
        table.setProfileName(recipient.id, ProfileName.fromParts(nickname, ""))
        table.setProfileSharing(recipient.id, true)
        MeshContacts.put(context, publicKey.toHex(), nickname)
        return Recipient.resolved(recipient.id)
    }
}
