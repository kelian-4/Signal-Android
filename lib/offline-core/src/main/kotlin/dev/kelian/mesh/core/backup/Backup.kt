package dev.kelian.mesh.core.backup

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class BackupContact(val id: String, val nickname: String, val publicKey: ByteArray, val verified: Boolean)
class BackupMessage(val msgIdHex: String, val contactId: String, val outgoing: Boolean, val timestampMs: Long, val text: String)

class BackupBundle(val contacts: List<BackupContact>, val messages: List<BackupMessage>)

class BackupException(message: String) : Exception(message)

object BackupCodec {
    private val MAGIC = byteArrayOf('M'.code.toByte(), 'S'.code.toByte(), 'H'.code.toByte(), 'B'.code.toByte())
    private const val VERSION = 1
    const val DEFAULT_ITERATIONS = 200_000

    fun encrypt(phraseWords: List<String>, bundle: BackupBundle, random: SecureRandom = SecureRandom(), iterations: Int = DEFAULT_ITERATIONS): ByteArray {
        val salt = ByteArray(16).also { random.nextBytes(it) }
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val header = MAGIC + byteArrayOf(VERSION.toByte()) + salt + iv
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key(phraseWords, salt, iterations), GCMParameterSpec(128, iv))
        c.updateAAD(header)
        return header + c.doFinal(serialize(bundle))
    }

    fun decrypt(phraseWords: List<String>, data: ByteArray, iterations: Int = DEFAULT_ITERATIONS): BackupBundle {
        if (data.size < 33 + 16 || !data.copyOfRange(0, 4).contentEquals(MAGIC)) throw BackupException("not a backup file")
        if (data[4].toInt() != VERSION) throw BackupException("unsupported backup version")
        val salt = data.copyOfRange(5, 21); val iv = data.copyOfRange(21, 33)
        val plain = try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(phraseWords, salt, iterations), GCMParameterSpec(128, iv))
            c.updateAAD(data.copyOfRange(0, 33))
            c.doFinal(data, 33, data.size - 33)
        } catch (e: java.security.GeneralSecurityException) {
            throw BackupException("wrong recovery phrase or corrupted file")
        }
        return try { deserialize(plain) } catch (e: java.io.IOException) { throw BackupException("corrupted content") }
    }

    private fun key(words: List<String>, salt: ByteArray, iterations: Int): SecretKeySpec {
        val pwd = words.joinToString(" ") { it.trim().lowercase() }.toCharArray()
        val raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(PBEKeySpec(pwd, salt, iterations, 256)).encoded
        return SecretKeySpec(raw, "AES")
    }

    private fun serialize(b: BackupBundle): ByteArray {
        val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
        o.writeInt(b.contacts.size)
        for (c in b.contacts) { o.writeUTF(c.id); o.writeUTF(c.nickname); o.writeInt(c.publicKey.size); o.write(c.publicKey); o.writeBoolean(c.verified) }
        o.writeInt(b.messages.size)
        for (m in b.messages) { o.writeUTF(m.msgIdHex); o.writeUTF(m.contactId); o.writeBoolean(m.outgoing); o.writeLong(m.timestampMs); val t = m.text.toByteArray(Charsets.UTF_8); o.writeInt(t.size); o.write(t) }
        return bo.toByteArray()
    }

    private fun deserialize(d: ByteArray): BackupBundle {
        val i = DataInputStream(ByteArrayInputStream(d))
        val contacts = List(i.readInt().also { require(it in 0..1_000_000) }) {
            val id = i.readUTF(); val nick = i.readUTF(); val pk = ByteArray(i.readInt().also { require(it in 0..64) }).also { i.readFully(it) }
            BackupContact(id, nick, pk, i.readBoolean())
        }
        val msgs = List(i.readInt().also { require(it in 0..10_000_000) }) {
            val id = i.readUTF(); val cid = i.readUTF(); val out = i.readBoolean(); val ts = i.readLong()
            val t = ByteArray(i.readInt().also { require(it in 0..10_000_000) }).also { i.readFully(it) }
            BackupMessage(id, cid, out, ts, String(t, Charsets.UTF_8))
        }
        return BackupBundle(contacts, msgs)
    }
}
