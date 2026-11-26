package dev.kelian.mesh.app

import android.content.Context
import dev.kelian.mesh.ble.MeshHost
import dev.kelian.mesh.ble.MeshRuntime
import dev.kelian.mesh.signal.LibsignalIdentity
import dev.kelian.mesh.signal.LibsignalSessionCipher
import java.io.File

/** Process-wide access to the identity and to the running mesh. */
object MeshApp {
    private const val PREFS = "mesh"
    private const val KEY_NICK = "nickname"

    fun nickname(ctx: Context): String? = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_NICK, null)

    fun hasIdentity(ctx: Context): Boolean = SeedVault.exists(ctx) && nickname(ctx) != null

    fun identity(ctx: Context): LibsignalIdentity? = SeedVault.load(ctx)?.let { LibsignalIdentity.fromSeed(it) }

    /** Stores a new identity (or a restored one). The previous one, if any, is replaced. */
    fun saveIdentity(ctx: Context, identity: LibsignalIdentity, nickname: String) {
        SeedVault.save(ctx, identity.seed)
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_NICK, nickname).apply()
        File(ctx.filesDir, "signal-state.bin").delete() // sessions belong to the previous identity
    }

    /** Creates the runtime once; the foreground service starts and stops it. */
    @Synchronized
    fun ensureRuntime(ctx: Context): MeshRuntime? {
        MeshHost.runtime?.let { return it }
        val app = ctx.applicationContext
        val id = identity(app) ?: return null
        val nick = nickname(app) ?: return null
        val cipher = LibsignalSessionCipher(id, File(app.filesDir, "signal-state.bin"))
        val rt = MeshRuntime(app, id, nick, cipher, onEvent = { /* UI wiring comes with the chat screens */ })
        MeshHost.runtime = rt
        return rt
    }
}
