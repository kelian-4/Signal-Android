package dev.kelian.mesh.core.verify

import dev.kelian.mesh.core.identity.Ed25519
import dev.kelian.mesh.core.identity.IdentitySigner
import dev.kelian.mesh.core.identity.SignatureVerifier
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Content of a contact QR code: identity key, nickname, timestamp, signature by that key. */
class QrPayload(val publicKey: ByteArray, val nickname: String, val timestampMs: Long, val signature: ByteArray) {
    fun encode(): String {
        val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
        o.writeByte(2); o.writeByte(publicKey.size); o.write(publicKey); o.writeUTF(nickname); o.writeLong(timestampMs); o.writeByte(signature.size); o.write(signature)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bo.toByteArray())
    }

    companion object {
        const val MAX_AGE_MS = 10L * 60 * 1000
        private fun signedBytes(pk: ByteArray, nick: String, ts: Long): ByteArray {
            val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
            o.write("mesh-qr-v1".toByteArray()); o.write(pk); o.writeUTF(nick); o.writeLong(ts)
            return bo.toByteArray()
        }

        fun create(signer: IdentitySigner, nickname: String, nowMs: Long) =
            QrPayload(signer.publicKey, nickname, nowMs, signer.sign(signedBytes(signer.publicKey, nickname, nowMs)))

        /** Returns null if malformed, badly signed, too old or from the future. */
        fun parse(text: String, nowMs: Long, verifier: SignatureVerifier = Ed25519): QrPayload? = runCatching {
            val i = DataInputStream(ByteArrayInputStream(Base64.getUrlDecoder().decode(text)))
            if (i.readUnsignedByte() != 2) return null
            val pkLen = i.readUnsignedByte(); if (pkLen !in 32..64) return null
            val pk = ByteArray(pkLen).also { i.readFully(it) }
            val nick = i.readUTF(); val ts = i.readLong()
            val sigLen = i.readUnsignedByte(); if (sigLen !in 32..128) return null
            val sig = ByteArray(sigLen).also { i.readFully(it) }
            if (i.available() != 0 || nick.length > 64) return null
            if (nowMs - ts > MAX_AGE_MS || ts - nowMs > 60_000) return null
            if (!verifier.verify(pk, signedBytes(pk, nick, ts), sig)) return null
            QrPayload(pk, nick, ts, sig)
        }.getOrNull()
    }
}

/** Challenge-response run right after the scan: proves the scanned phone holds the private key now. */
object Challenge {
    fun newChallenge(random: SecureRandom = SecureRandom()) = ByteArray(16).also { random.nextBytes(it) }

    private fun bytes(challenge: ByteArray, scannerPk: ByteArray, scannedPk: ByteArray) =
        "mesh-chal-v1".toByteArray() + challenge + scannerPk + scannedPk

    fun respond(signer: IdentitySigner, challenge: ByteArray, scannerPk: ByteArray) =
        signer.sign(bytes(challenge, scannerPk, signer.publicKey))

    fun verify(scannedPk: ByteArray, challenge: ByteArray, scannerPk: ByteArray, response: ByteArray, verifier: SignatureVerifier = Ed25519) =
        verifier.verify(scannedPk, bytes(challenge, scannerPk, scannedPk), response)
}

/** 60-digit safety number, identical on both phones, changes if either key changes. */
object SecurityCode {
    fun compute(pkA: ByteArray, pkB: ByteArray): String {
        val (x, y) = listOf(pkA, pkB).sortedWith { a, b -> java.util.Arrays.compareUnsigned(a, b) }
        val d = MessageDigest.getInstance("SHA-256").digest("mesh-code-v1".toByteArray() + x + y)
        val digits = (0 until 12).joinToString(" ") { g ->
            var v = 0L
            for (k in 0 until 4) v = (v shl 8) or (d[(g * 2 + k) % 32].toLong() and 0xFF)
            (v % 100000).toString().padStart(5, '0')
        }
        return digits
    }
}

enum class TrustLevel { UNVERIFIED, VERIFIED }

class KeyChangeAlert(val contactId: String, val previousKey: ByteArray, val newKey: ByteArray, val wasVerified: Boolean)

/** Trust state per contact. Everyone is UNVERIFIED until an in-person QR scan succeeds. */
class ContactTrustBook {
    private class Entry(var key: ByteArray, var level: TrustLevel)
    private val entries = HashMap<String, Entry>()

    fun add(contactId: String, key: ByteArray) { entries.putIfAbsent(contactId, Entry(key.copyOf(), TrustLevel.UNVERIFIED)) }
    fun level(contactId: String) = entries[contactId]?.level
    fun markVerified(contactId: String, key: ByteArray): Boolean {
        val e = entries[contactId] ?: return false
        if (!e.key.contentEquals(key)) return false
        e.level = TrustLevel.VERIFIED; return true
    }

    /** Call with the identity key authenticated in each session; a different key drops the badge and alerts. */
    fun onKeySeen(contactId: String, key: ByteArray): KeyChangeAlert? {
        val e = entries[contactId] ?: return null
        if (e.key.contentEquals(key)) return null
        val alert = KeyChangeAlert(contactId, e.key, key.copyOf(), e.level == TrustLevel.VERIFIED)
        e.key = key.copyOf(); e.level = TrustLevel.UNVERIFIED
        return alert
    }
}
