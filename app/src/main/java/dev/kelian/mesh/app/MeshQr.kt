package dev.kelian.mesh.app

import android.content.Context
import dev.kelian.mesh.core.protocol.toHex
import dev.kelian.mesh.core.verify.QrPayload
import dev.kelian.mesh.signal.LibsignalSignatures
import org.thoughtcrime.securesms.components.settings.app.usernamelinks.main.QrScanResult
import org.thoughtcrime.securesms.recipients.Recipient

object MeshQr {
    const val PREFIX = "mesh1:"

    fun isMeshLink(text: String): Boolean = text.startsWith(PREFIX)

    fun displayName(context: Context): String {
        val id = MeshApp.identityOrCreate(context)
        val name = Recipient.self().profileName.toString()
        return name.ifBlank { MeshApp.defaultNickname(id) }
    }

    fun myLink(context: Context): String {
        val id = MeshApp.identityOrCreate(context)
        return PREFIX + QrPayload.create(id, displayName(context), System.currentTimeMillis()).encode()
    }

    fun handleScan(context: Context, link: String): QrScanResult {
        val payload = QrPayload.parse(link.removePrefix(PREFIX), System.currentTimeMillis(), LibsignalSignatures) ?: return QrScanResult.InvalidData
        val own = MeshApp.identityOrCreate(context).publicKey
        if (payload.publicKey.contentEquals(own)) return QrScanResult.InvalidData
        val recipient = MeshRecipients.ensure(context, payload.publicKey, payload.nickname)
        val hex = payload.publicKey.toHex()
        MeshApp.ensureRuntime(context)?.post { engine ->
            engine.addContact(hex, payload)
            engine.requestBundle(hex)
        }
        return QrScanResult.Success(recipient)
    }
}
