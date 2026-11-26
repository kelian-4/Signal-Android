package dev.kelian.mesh.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Keeps the 32-byte identity seed on the phone only, encrypted with a key that never leaves the
 * Android Keystore. The seed is what the 24-word recovery phrase encodes.
 */
object SeedVault {
    private const val ALIAS = "mesh_identity_wrap"
    private const val FILE = "identity.bin"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    fun exists(ctx: Context): Boolean = File(ctx.filesDir, FILE).exists()

    fun save(ctx: Context, seed: ByteArray) {
        require(seed.size == 32)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val iv = c.iv
        val ct = c.doFinal(seed)
        File(ctx.filesDir, FILE).writeBytes(byteArrayOf(iv.size.toByte()) + iv + ct)
    }

    /** Null if there is no identity yet or the file cannot be decrypted. */
    fun load(ctx: Context): ByteArray? = try {
        val f = File(ctx.filesDir, FILE)
        if (!f.exists()) null else {
            val b = f.readBytes()
            val ivLen = b[0].toInt()
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b.copyOfRange(1, 1 + ivLen)))
            c.doFinal(b, 1 + ivLen, b.size - 1 - ivLen)
        }
    } catch (e: Exception) {
        null
    }

    fun delete(ctx: Context) { File(ctx.filesDir, FILE).delete() }
}
