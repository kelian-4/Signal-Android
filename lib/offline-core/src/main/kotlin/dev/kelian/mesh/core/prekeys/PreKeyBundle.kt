package dev.kelian.mesh.core.prekeys

import dev.kelian.mesh.core.identity.Ed25519
import dev.kelian.mesh.core.identity.IdentitySigner
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64

/**
 * Offline replacement for the server's prekey upload: a bundle shown as QR code or sent over close-range
 * BLE. The libsignal key material is carried as opaque bytes ([signedPreKey], [oneTimePreKeys]); the
 * identity key signs them, so a relay or an eavesdropper cannot swap them.
 */
class PreKeyBundle(
    val identityKey: ByteArray, val signedPreKeyId: Int, val signedPreKey: ByteArray,
    val oneTimePreKeys: List<Pair<Int, ByteArray>>, val signature: ByteArray,
) {
    fun encode(): String {
        val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
        o.writeByte(1); o.write(identityKey); o.writeInt(signedPreKeyId); o.writeShort(signedPreKey.size); o.write(signedPreKey)
        o.writeByte(oneTimePreKeys.size); for ((id, k) in oneTimePreKeys) { o.writeInt(id); o.writeShort(k.size); o.write(k) }
        o.write(signature)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bo.toByteArray())
    }

    companion object {
        const val MAX_ONE_TIME = 20
        private fun signedBytes(idKey: ByteArray, spkId: Int, spk: ByteArray, otks: List<Pair<Int, ByteArray>>): ByteArray {
            val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
            o.write("mesh-prekeys-v1".toByteArray()); o.write(idKey); o.writeInt(spkId); o.write(spk)
            for ((id, k) in otks) { o.writeInt(id); o.write(k) }
            return bo.toByteArray()
        }

        fun create(signer: IdentitySigner, spkId: Int, spk: ByteArray, otks: List<Pair<Int, ByteArray>>): PreKeyBundle {
            require(otks.size <= MAX_ONE_TIME)
            return PreKeyBundle(signer.publicKey, spkId, spk, otks, signer.sign(signedBytes(signer.publicKey, spkId, spk, otks)))
        }

        /** Null if malformed or if the signature does not match the embedded identity key. */
        fun parse(text: String): PreKeyBundle? = runCatching {
            val i = DataInputStream(ByteArrayInputStream(Base64.getUrlDecoder().decode(text)))
            if (i.readUnsignedByte() != 1) return null
            val idKey = ByteArray(32).also { i.readFully(it) }
            val spkId = i.readInt(); val spk = ByteArray(i.readUnsignedShort().also { if (it > 256) return null }).also { i.readFully(it) }
            val n = i.readUnsignedByte(); if (n > MAX_ONE_TIME) return null
            val otks = List(n) { val id = i.readInt(); id to ByteArray(i.readUnsignedShort().also { l -> if (l > 256) return null }).also { b -> i.readFully(b) } }
            val sig = ByteArray(64).also { i.readFully(it) }
            if (i.available() != 0) return null
            if (!Ed25519.verify(idKey, signedBytes(idKey, spkId, spk, otks), sig)) return null
            PreKeyBundle(idKey, spkId, spk, otks, sig)
        }.getOrNull()
    }
}
