package dev.kelian.mesh.ble

import android.os.Handler

/**
 * Serializes GATT operations: Android allows only one outstanding operation per connection.
 * Must be used from the engine handler thread only.
 */
class OpQueue(
    private val handler: Handler,
    private val log: (String) -> Unit,
    private val onTimeout: () -> Unit,
    private val timeoutMs: Long = 10_000,
) {
    private class Op(val name: String, val timeoutMs: Long?, val run: () -> Boolean, val onDone: ((Boolean) -> Unit)?)

    private val queue = ArrayDeque<Op>()
    private var current: Op? = null
    private val timeoutRunnable = Runnable {
        log("operation timed out: ${current?.name}")
        current = null
        queue.clear()
        onTimeout()
    }

    /** [timeoutMs] overrides the default timeout for this operation only (e.g. a slow MTU exchange). */
    fun enqueue(name: String, onDone: ((Boolean) -> Unit)? = null, timeoutMs: Long? = null, run: () -> Boolean) {
        queue.addLast(Op(name, timeoutMs, run, onDone))
        pump()
    }

    /** Call when the callback of the current operation arrived. */
    fun done(success: Boolean = true) {
        handler.removeCallbacks(timeoutRunnable)
        val op = current
        current = null
        op?.onDone?.invoke(success)
        pump()
    }

    fun clear() {
        handler.removeCallbacks(timeoutRunnable)
        queue.clear()
        current = null
    }

    private fun pump() {
        if (current != null) return
        val op = queue.removeFirstOrNull() ?: return
        current = op
        val ok = try {
            op.run()
        } catch (e: Exception) {
            log("operation '${op.name}' threw ${e.javaClass.simpleName}: ${e.message}")
            false
        }
        if (ok) {
            handler.postDelayed(timeoutRunnable, op.timeoutMs ?: timeoutMs)
        } else {
            log("operation '${op.name}' rejected by the stack")
            current = null
            op.onDone?.invoke(false)
            pump()
        }
    }
}
