package dev.kelian.mesh.ble

import android.content.Context
import dev.kelian.mesh.core.engine.LinkSink
import dev.kelian.mesh.core.engine.MeshEngine
import dev.kelian.mesh.core.engine.MeshEvent
import dev.kelian.mesh.core.engine.SessionCipher
import dev.kelian.mesh.core.identity.IdentitySigner
import dev.kelian.mesh.core.outbox.FileOutboxStore
import java.io.File

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

    fun post(block: (MeshEngine) -> Unit) {
        layer.post {
            block(engine)
            drain()
            if (engine.wantsConnection()) layer.connectNow()
        }
    }

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

object MeshHost {
    @Volatile var runtime: MeshRuntime? = null
    @Volatile var notificationTitle: String = "Messagerie hors ligne active"
    @Volatile var notificationText: String = "Recherche d'appareils proches"
}
