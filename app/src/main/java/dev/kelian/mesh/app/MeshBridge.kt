package dev.kelian.mesh.app

import android.content.Context
import dev.kelian.mesh.core.engine.MeshEvent
import java.util.concurrent.Executors

object MeshBridge {
    private val executor = Executors.newSingleThreadExecutor()

    fun handle(context: Context, event: MeshEvent) {
        when (event) {
            is MeshEvent.ContactAppeared -> executor.execute { MeshRecipients.ensure(context, event.publicKey, event.nickname) }
            else -> Unit
        }
    }
}
