package dev.kelian.mesh.core.identity

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.EdECPoint
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec

interface IdentitySigner {
    val publicKey: ByteArray
    fun sign(message: ByteArray): ByteArray
}

fun interface SignatureVerifier {
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}

object Ed25519 : SignatureVerifier {

    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = runCatching {
        if (publicKey.size != 32 || signature.size != 64) return false
        val s = Signature.getInstance("Ed25519")
        s.initVerify(toPublicKey(publicKey)); s.update(message); s.verify(signature)
    }.getOrDefault(false)

    internal fun toPublicKey(raw: ByteArray): PublicKey {
        val le = raw.copyOf()
        val xOdd = (le[31].toInt() and 0x80) != 0
        le[31] = (le[31].toInt() and 0x7F).toByte()
        val y = BigInteger(1, le.reversedArray())
        return KeyFactory.getInstance("Ed25519").generatePublic(EdECPublicKeySpec(NamedParameterSpec.ED25519, EdECPoint(xOdd, y)))
    }

    internal fun fromSeed(seed: ByteArray): KeyPair {
        require(seed.size == 32)
        val fixed = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) { System.arraycopy(seed, 0, bytes, 0, minOf(bytes.size, seed.size)) }
        }
        val g = KeyPairGenerator.getInstance("Ed25519")
        g.initialize(NamedParameterSpec.ED25519, fixed)
        return g.generateKeyPair()
    }
}

class Identity private constructor(val seed: ByteArray, private val pair: KeyPair) : IdentitySigner {
    override val publicKey: ByteArray = pair.public.encoded.let { it.copyOfRange(it.size - 32, it.size) }

    override fun sign(message: ByteArray): ByteArray {
        val s = Signature.getInstance("Ed25519")
        s.initSign(pair.private); s.update(message)
        return s.sign()
    }

    fun recoveryPhrase(): List<String> = Bip39.encode(seed)

    companion object {
        fun generate(random: SecureRandom = SecureRandom()): Identity = fromSeed(ByteArray(32).also { random.nextBytes(it) })
        fun fromSeed(seed: ByteArray): Identity = Identity(seed.copyOf(), Ed25519.fromSeed(seed))
        fun fromPhrase(words: List<String>): Identity = fromSeed(Bip39.decode(words))
    }
}
