package dev.kelian.mesh.signal

import dev.kelian.mesh.core.identity.Bip39
import dev.kelian.mesh.core.identity.IdentitySigner
import dev.kelian.mesh.core.identity.SignatureVerifier
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.protocol.ecc.ECPublicKey
import java.security.SecureRandom

/**
 * Device identity on libsignal's Curve25519 key (33-byte public key, XEd25519 signatures), the same
 * key type Signal sessions use. The 32-byte [seed] is what the 24-word phrase encodes; the key is
 * derived from it deterministically, so a restored phrase gives back the same public key.
 */
class LibsignalIdentity private constructor(val seed: ByteArray, internal val privateKey: ECPrivateKey) : IdentitySigner {
    override val publicKey: ByteArray = privateKey.getPublicKey().serialize()
    val identityKeyPair: IdentityKeyPair = IdentityKeyPair(IdentityKey(privateKey.getPublicKey()), privateKey)

    override fun sign(message: ByteArray): ByteArray = privateKey.calculateSignature(message)

    fun recoveryPhrase(): List<String> = Bip39.encode(seed)

    companion object {
        fun generate(random: SecureRandom = SecureRandom()): LibsignalIdentity = fromSeed(ByteArray(32).also { random.nextBytes(it) })
        fun fromSeed(seed: ByteArray): LibsignalIdentity {
            require(seed.size == 32)
            return LibsignalIdentity(seed.copyOf(), ECPrivateKey(seed))
        }
        fun fromPhrase(words: List<String>): LibsignalIdentity = fromSeed(Bip39.decode(words))
    }
}

/** Signature check for QR codes, challenges and prekey bundles when identities are libsignal keys. */
object LibsignalSignatures : SignatureVerifier {
    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        ECPublicKey(publicKey).verifySignature(message, signature)
    } catch (e: Exception) {
        false
    }
}
