package dev.kelian.mesh.app

import android.content.Context
import dev.kelian.mesh.ble.MeshHost
import dev.kelian.mesh.ble.MeshRuntime
import dev.kelian.mesh.core.protocol.hexToBytes
import dev.kelian.mesh.core.protocol.toHex
import dev.kelian.mesh.signal.LibsignalIdentity
import dev.kelian.mesh.signal.LibsignalSessionCipher
import java.io.File
import java.security.SecureRandom

object MeshApp {
    @Synchronized
    fun identityOrCreate(ctx: Context): LibsignalIdentity {
        SeedVault.load(ctx)?.let { return LibsignalIdentity.fromSeed(it) }
        val id = LibsignalIdentity.generate(SecureRandom())
        SeedVault.save(ctx, id.seed)
        return id
    }

    fun defaultNickname(id: LibsignalIdentity): String = "Mesh-" + id.publicKey.toHex().substring(2, 8)

    @Synchronized
    fun ensureRuntime(ctx: Context): MeshRuntime? {
        MeshHost.runtime?.let { return it }
        val app = ctx.applicationContext
        val id = identityOrCreate(app)
        val cipher = LibsignalSessionCipher(id, File(app.filesDir, "signal-state.bin"))
        val rt = MeshRuntime(app, id, defaultNickname(id), cipher, onEvent = { MeshBridge.handle(app, it) })
        MeshHost.runtime = rt
        val known = MeshContacts.all(app)
        rt.post { engine -> known.forEach { (hex, nick) -> engine.addContactKey(hex, hex.hexToBytes(), nick) } }
        return rt
    }
}
