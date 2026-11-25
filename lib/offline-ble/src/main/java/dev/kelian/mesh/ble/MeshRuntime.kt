package dev.kelian.mesh.ble

import android.content.Context
import dev.kelian.mesh.core.engine.LinkSink
import dev.kelian.mesh.core.engine.MeshEngine
import dev.kelian.mesh.core.engine.MeshEvent
import dev.kelian.mesh.core.engine.SessionCipher
import dev.kelian.mesh.core.identity.IdentitySigner
import dev.kelian.mesh.core.outbox.FileOutboxStore
import java.io.File

/**
 * Glues the pure-Kotlin [MeshEngine] to the BLE radio. The engine is not thread-safe, so every call
 * into it goes through [post], which runs on the radio thread. Events are handed to [onEvent] on that
 * same thread; the UI must hop to the main thread itself.
 */
class MeshRuntime(
    context: Context,
    identity: IdentitySigner,
    nickname: String,
    cipher: SessionCipher,
    private val onEvent: (MeshEvent) -> Unit,
    log: LinkLog = LinkLog.ANDROID,
) {
    private val appCtx = context.applicationContext
    val diagnostics = DiagnosticsRecorder(appCtx, File(appCtx.filesDir, "mesh-link-diag.csv"))

    private val listener = object : LinkListener {
        override fun onLinkUp(linkId: String, maxFrame: Int) { engine.onLinkUp(linkId, maxFrame); drain() }
        override fun onLinkDown(linkId: String) { engine.onLinkDown(linkId); drain() }
        override fun onFrame(linkId: String, frame: ByteArray) { engine.onFrame(linkId, frame); drain() }
        override fun wantsConnection(): Boolean = engine.wantsConnection()
        override fun onTick() { engine.tick(); drain() }
    }

    private val layer = BleLinkLayer(appCtx, listener, log, diagnostics)

    val engine: MeshEngine = MeshEngine(
        identity = identity,
        nickname = nickname,
        cipher = cipher,
        sink = object : LinkSink {
            override fun sendFrame(linkId: String, frame: ByteArray) { layer.send(linkId, frame) }
        },
        clock = { System.currentTimeMillis() },
        outboxStore = FileOutboxStore(File(appCtx.filesDir, "mesh-outbox.txt")),
    )

    val status: LayerStatus get() = layer.status

    fun start() { layer.start() }
    fun stop() { layer.stop() }

    /** Runs [block] with the engine on the radio thread, then delivers the events it produced. */
    fun post(block: (MeshEngine) -> Unit) {
        layer.post {
            block(engine)
            drain()
            if (engine.wantsConnection()) layer.connectNow()
        }
    }

    /** Called on the radio thread: dead links are cut so that the normal cycle re-establishes them. */
    private fun drain() {
        if (engine.events.isEmpty()) return
        val batch = engine.events.toList()
        engine.events.clear()
        for (e in batch) {
            if (e is MeshEvent.LinkRepair) {
                diagnostics.record("watchdog_repair_${e.stale}")
                layer.dropLink(e.linkId)
            }
            onEvent(e)
        }
    }
}

/** Process-wide holder: the application sets the runtime once the identity exists; the service runs it. */
object MeshHost {
    @Volatile var runtime: MeshRuntime? = null
    @Volatile var notificationTitle: String = "Messagerie hors ligne active"
    @Volatile var notificationText: String = "Recherche d'appareils proches"
}
