package dev.kelian.mesh.app

import android.content.Context
import dev.kelian.mesh.ble.MeshHost
import dev.kelian.mesh.ble.MeshRuntime
import dev.kelian.mesh.core.protocol.toHex
import dev.kelian.mesh.signal.LibsignalIdentity
import dev.kelian.mesh.signal.LibsignalSessionCipher
import java.io.File
import java.security.SecureRandom

/** Process-wide access to the device identity and to the running mesh. */
object MeshApp {
    /** The identity of this phone: created silently on first use, restorable from its 24-word phrase. */
    @Synchronized
    fun identityOrCreate(ctx: Context): LibsignalIdentity {
        SeedVault.load(ctx)?.let { return LibsignalIdentity.fromSeed(it) }
        val id = LibsignalIdentity.generate(SecureRandom())
        SeedVault.save(ctx, id.seed)
        return id
    }

    /** Provisional display name until Signal's own profile screen sets one: "Mesh-" + start of the key. */
    fun defaultNickname(id: LibsignalIdentity): String = "Mesh-" + id.publicKey.toHex().substring(2, 8)

    /** Creates the runtime once; the foreground service starts and stops it. */
    @Synchronized
    fun ensureRuntime(ctx: Context): MeshRuntime? {
        MeshHost.runtime?.let { return it }
        val app = ctx.applicationContext
        val id = identityOrCreate(app)
        val cipher = LibsignalSessionCipher(id, File(app.filesDir, "signal-state.bin"))
        val rt = MeshRuntime(app, id, defaultNickname(id), cipher, onEvent = { /* mesh events are bridged to Signal's database in the next step */ })
        MeshHost.runtime = rt
        return rt
    }
}
