package dev.kelian.mesh.signal

import dev.kelian.mesh.core.engine.SessionCipher
import dev.kelian.mesh.core.prekeys.PreKeyBundle
import dev.kelian.mesh.core.protocol.toHex
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle as SignalPreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.SecureRandom

/**
 * Double Ratchet sessions (libsignal, PQXDH) without any server: the prekey bundle that Signal would fetch
 * from its server is exchanged in person ([publishBundle] / [acceptPeerBundle], carried as QR or close-range BLE).
 * Peers are addressed by the hex of their identity public key, device 1. State is snapshotted to [stateFile].
 * Not thread-safe: call it from the radio thread only.
 */
class LibsignalSessionCipher(
    private val identity: LibsignalIdentity,
    private val stateFile: File? = null,
    private val random: SecureRandom = SecureRandom(),
) : SessionCipher {
    private val store = InMemorySignalProtocolStore(identity.identityKeyPair, REGISTRATION_ID)
    private val localAddress = SignalProtocolAddress(identity.publicKey.toHex(), DEVICE_ID)
    private val knownPeers = LinkedHashSet<String>()
    private val preKeyIds = LinkedHashSet<Int>()
    private val signedPreKeyIds = LinkedHashSet<Int>()
    private val kyberPreKeyIds = LinkedHashSet<Int>()

    init { restore() }

    private fun address(peerPk: ByteArray) = SignalProtocolAddress(peerPk.toHex(), DEVICE_ID)

    // ---------------------------------------------------------------- offline prekey exchange

    /** A fresh bundle to show to a contact: one one-time prekey, one signed prekey, one post-quantum prekey. */
    fun publishBundle(): PreKeyBundle {
        val priv = identity.identityKeyPair.privateKey
        val preKeyId = random.nextInt(0xFFFFFF) + 1
        val signedId = random.nextInt(0xFFFFFF) + 1
        val kyberId = random.nextInt(0xFFFFFF) + 1
        val pre = ECKeyPair.generate()
        val signed = ECKeyPair.generate()
        val signedSig = priv.calculateSignature(signed.publicKey.serialize())
        val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberSig = priv.calculateSignature(kyber.publicKey.serialize())
        val now = System.currentTimeMillis()
        store.storePreKey(preKeyId, PreKeyRecord(preKeyId, pre)); preKeyIds.add(preKeyId)
        store.storeSignedPreKey(signedId, SignedPreKeyRecord(signedId, now, signed, signedSig)); signedPreKeyIds.add(signedId)
        store.storeKyberPreKey(kyberId, KyberPreKeyRecord(kyberId, now, kyber, kyberSig)); kyberPreKeyIds.add(kyberId)
        persist()
        val extra = encodeExtra(signedSig, kyberId, kyber.publicKey.serialize(), kyberSig)
        return PreKeyBundle.create(identity, signedId, signed.publicKey.serialize(), listOf(preKeyId to pre.publicKey.serialize()), extra)
    }

    /**
     * Builds the session towards the bundle's owner. The bundle must come from
     * [PreKeyBundle.parse] with [LibsignalSignatures], so its signature is already checked.
     * Throws if libsignal refuses it (e.g. UntrustedIdentityException when the key changed).
     */
    fun acceptPeerBundle(bundle: PreKeyBundle) {
        require(bundle.oneTimePreKeys.isNotEmpty()) { "bundle has no one-time prekey" }
        val ex = decodeExtra(bundle.extra)
        val (preKeyId, preKey) = bundle.oneTimePreKeys.first()
        val remote = address(bundle.identityKey)
        val b = SignalPreKeyBundle(
            REGISTRATION_ID, DEVICE_ID, preKeyId, ECPublicKey(preKey),
            bundle.signedPreKeyId, ECPublicKey(bundle.signedPreKey), ex.signedPreKeySignature,
            IdentityKey(bundle.identityKey), ex.kyberId, KEMPublicKey(ex.kyberPublic), ex.kyberSignature,
        )
        SessionBuilder(store, remote, localAddress).process(b)
        knownPeers.add(bundle.identityKey.toHex())
        persist()
    }

    // ---------------------------------------------------------------- SessionCipher

    override fun canEncrypt(peerPk: ByteArray): Boolean = store.containsSession(address(peerPk))

    override fun encrypt(peerPk: ByteArray, plain: ByteArray): ByteArray {
        val remote = address(peerPk)
        val cipher = org.signal.libsignal.protocol.SessionCipher(store, localAddress, remote)
        val ct = cipher.encrypt(plain)
        knownPeers.add(peerPk.toHex())
        persist()
        return byteArrayOf(ct.type.toByte()) + ct.serialize()
    }

    override fun decrypt(peerPk: ByteArray, data: ByteArray): ByteArray? = try {
        if (data.size < 2) null else {
            val body = data.copyOfRange(1, data.size)
            val cipher = org.signal.libsignal.protocol.SessionCipher(store, localAddress, address(peerPk))
            val plain = when (data[0].toInt()) {
                CiphertextMessage.PREKEY_TYPE -> cipher.decrypt(PreKeySignalMessage(body))
                CiphertextMessage.WHISPER_TYPE -> cipher.decrypt(SignalMessage(body))
                else -> null
            }
            if (plain != null) { knownPeers.add(peerPk.toHex()); persist() }
            plain
        }
    } catch (e: Exception) {
        null
    }

    /** Contact requests are sealed (HPKE) to the recipient's identity key: only its owner can open them. */
    override fun seal(recipientPk: ByteArray, plain: ByteArray): ByteArray =
        ECPublicKey(recipientPk).seal(plain, REQUEST_INFO)

    override fun open(data: ByteArray): ByteArray? = try {
        identity.privateKey.open(data, REQUEST_INFO)
    } catch (e: Exception) {
        null
    }

    // ---------------------------------------------------------------- persistence (sessions survive a restart)

    private class Extra(val signedPreKeySignature: ByteArray, val kyberId: Int, val kyberPublic: ByteArray, val kyberSignature: ByteArray)

    private fun encodeExtra(spkSig: ByteArray, kyberId: Int, kyberPub: ByteArray, kyberSig: ByteArray): ByteArray {
        val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
        o.writeShort(spkSig.size); o.write(spkSig); o.writeInt(kyberId)
        o.writeShort(kyberPub.size); o.write(kyberPub); o.writeShort(kyberSig.size); o.write(kyberSig)
        return bo.toByteArray()
    }

    private fun decodeExtra(b: ByteArray): Extra {
        val i = DataInputStream(ByteArrayInputStream(b))
        val spk = ByteArray(i.readUnsignedShort()).also { i.readFully(it) }
        val kid = i.readInt()
        val kp = ByteArray(i.readUnsignedShort()).also { i.readFully(it) }
        val ks = ByteArray(i.readUnsignedShort()).also { i.readFully(it) }
        return Extra(spk, kid, kp, ks)
    }

    private fun persist() {
        val f = stateFile ?: return
        try {
            val bo = ByteArrayOutputStream(); val o = DataOutputStream(bo)
            o.writeInt(1)
            val sessions = knownPeers.filter { store.containsSession(address(it.hexToBytes())) }
            o.writeInt(sessions.size)
            for (p in sessions) {
                val a = address(p.hexToBytes())
                o.writeUTF(p)
                val s = store.loadSession(a).serialize(); o.writeInt(s.size); o.write(s)
                val idk = store.getIdentity(a)?.serialize() ?: ByteArray(0); o.writeInt(idk.size); o.write(idk)
            }
            val pre = preKeyIds.filter { store.containsPreKey(it) }
            o.writeInt(pre.size); for (id in pre) { val b = store.loadPreKey(id).serialize(); o.writeInt(id); o.writeInt(b.size); o.write(b) }
            val spk = signedPreKeyIds.filter { store.containsSignedPreKey(it) }
            o.writeInt(spk.size); for (id in spk) { val b = store.loadSignedPreKey(id).serialize(); o.writeInt(id); o.writeInt(b.size); o.write(b) }
            val kyb = kyberPreKeyIds.filter { store.containsKyberPreKey(it) }
            o.writeInt(kyb.size); for (id in kyb) { val b = store.loadKyberPreKey(id).serialize(); o.writeInt(id); o.writeInt(b.size); o.write(b) }
            val tmp = File(f.path + ".tmp")
            tmp.writeBytes(bo.toByteArray())
            if (!tmp.renameTo(f)) { f.delete(); tmp.renameTo(f) }
        } catch (e: Exception) {
            // best effort: a failed snapshot only means sessions are renegotiated after a restart
        }
    }

    private fun restore() {
        val f = stateFile ?: return
        if (!f.exists()) return
        try {
            val i = DataInputStream(ByteArrayInputStream(f.readBytes()))
            if (i.readInt() != 1) return
            repeat(i.readInt()) {
                val p = i.readUTF()
                val s = ByteArray(i.readInt()).also { i.readFully(it) }
                val idk = ByteArray(i.readInt()).also { i.readFully(it) }
                val a = address(p.hexToBytes())
                if (idk.isNotEmpty()) store.saveIdentity(a, IdentityKey(idk))
                store.storeSession(a, SessionRecord(s)); knownPeers.add(p)
            }
            repeat(i.readInt()) { val id = i.readInt(); val b = ByteArray(i.readInt()).also { i.readFully(it) }; store.storePreKey(id, PreKeyRecord(b)); preKeyIds.add(id) }
            repeat(i.readInt()) { val id = i.readInt(); val b = ByteArray(i.readInt()).also { i.readFully(it) }; store.storeSignedPreKey(id, SignedPreKeyRecord(b)); signedPreKeyIds.add(id) }
            repeat(i.readInt()) { val id = i.readInt(); val b = ByteArray(i.readInt()).also { i.readFully(it) }; store.storeKyberPreKey(id, KyberPreKeyRecord(b)); kyberPreKeyIds.add(id) }
        } catch (e: Exception) {
            // unreadable snapshot: start without sessions, they are renegotiated
        }
    }

    private fun String.hexToBytes(): ByteArray = ByteArray(length / 2) { ((this[2 * it].digitToInt(16) shl 4) or this[2 * it + 1].digitToInt(16)).toByte() }

    companion object {
        private const val REGISTRATION_ID = 1
        private const val DEVICE_ID = 1
        private const val REQUEST_INFO = "mesh-contact-request-v1"
    }
}
