package dev.kelian.mesh.core.prekeys

import dev.kelian.mesh.core.identity.Ed25519
import dev.kelian.mesh.core.identity.IdentitySigner
import dev.kelian.mesh.core.identity.SignatureVerifier
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
    /** Extra opaque key material covered by the signature (libsignal's post-quantum prekey and its own signature). */
    val extra: ByteArray = ByteArray(0),
) {
    fun encode(): String {
        val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
        o.writeByte(2); o.writeByte(identityKey.size); o.write(identityKey); o.writeInt(signedPreKeyId); o.writeShort(signedPreKey.size); o.write(signedPreKey)
        o.writeByte(oneTimePreKeys.size); for ((id, k) in oneTimePreKeys) { o.writeInt(id); o.writeShort(k.size); o.write(k) }
        o.writeShort(extra.size); o.write(extra); o.writeByte(signature.size); o.write(signature)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bo.toByteArray())
    }

    companion object {
        const val MAX_ONE_TIME = 20
        const val MAX_EXTRA = 4096
        private fun signedBytes(idKey: ByteArray, spkId: Int, spk: ByteArray, otks: List<Pair<Int, ByteArray>>, extra: ByteArray): ByteArray {
            val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
            o.write("mesh-prekeys-v2".toByteArray()); o.write(idKey); o.writeInt(spkId); o.write(spk)
            for ((id, k) in otks) { o.writeInt(id); o.write(k) }
            o.write(extra)
            return bo.toByteArray()
        }

        fun create(signer: IdentitySigner, spkId: Int, spk: ByteArray, otks: List<Pair<Int, ByteArray>>, extra: ByteArray = ByteArray(0)): PreKeyBundle {
            require(otks.size <= MAX_ONE_TIME && extra.size <= MAX_EXTRA)
            return PreKeyBundle(signer.publicKey, spkId, spk, otks, signer.sign(signedBytes(signer.publicKey, spkId, spk, otks, extra)), extra)
        }

        /** Null if malformed or if the signature does not match the embedded identity key. */
        fun parse(text: String, verifier: SignatureVerifier = Ed25519): PreKeyBundle? = runCatching {
            val i = DataInputStream(ByteArrayInputStream(Base64.getUrlDecoder().decode(text)))
            if (i.readUnsignedByte() != 2) return null
            val idLen = i.readUnsignedByte(); if (idLen !in 32..64) return null
            val idKey = ByteArray(idLen).also { i.readFully(it) }
            val spkId = i.readInt(); val spk = ByteArray(i.readUnsignedShort().also { if (it > 256) return null }).also { i.readFully(it) }
            val n = i.readUnsignedByte(); if (n > MAX_ONE_TIME) return null
            val otks = List(n) { val id = i.readInt(); id to ByteArray(i.readUnsignedShort().also { l -> if (l > 256) return null }).also { b -> i.readFully(b) } }
            val extra = ByteArray(i.readUnsignedShort().also { if (it > MAX_EXTRA) return null }).also { i.readFully(it) }
            val sigLen = i.readUnsignedByte(); if (sigLen !in 32..128) return null
            val sig = ByteArray(sigLen).also { i.readFully(it) }
            if (i.available() != 0) return null
            if (!verifier.verify(idKey, signedBytes(idKey, spkId, spk, otks, extra), sig)) return null
            PreKeyBundle(idKey, spkId, spk, otks, sig, extra)
        }.getOrNull()
    }
}
