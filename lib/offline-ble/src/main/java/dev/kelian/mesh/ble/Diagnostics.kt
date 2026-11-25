package dev.kelian.mesh.ble

import android.app.KeyguardManager
import android.content.Context
import android.os.BatteryManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import dev.kelian.mesh.core.link.LinkDiagnostics
import java.io.File

/**
 * Records one CSV line per link event with the phone state around it (thermal, main-thread stall,
 * disconnect code, RSSI, battery, screen lock), to explain stalls like the 46 s freeze seen in the field.
 * The file stays on the phone; nothing is sent anywhere.
 */
class DiagnosticsRecorder(private val ctx: Context, file: File?) {
    private val out = file
    private val ring = ArrayDeque<String>()
    @Volatile private var mainBlockMs = 0L
    private val main = Handler(Looper.getMainLooper())

    private val probe = object : Runnable {
        var expected = 0L
        override fun run() {
            val now = SystemClock.uptimeMillis()
            if (expected != 0L) mainBlockMs = maxOf(0L, now - expected)
            expected = now + PROBE_MS
            main.postDelayed(this, PROBE_MS)
        }
    }

    fun start() { main.post(probe) }
    fun stop() { main.removeCallbacks(probe) }

    private fun thermal(): String? {
        if (Build.VERSION.SDK_INT < 29) return null
        val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return null
        return pm.currentThermalStatus.toString()
    }

    private fun battery(): Int? =
        (ctx.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager)?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)

    private fun locked(): Boolean? = (ctx.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)?.isKeyguardLocked

    @Synchronized
    fun record(event: String, disconnectCode: Int? = null, rssi: Int? = null) {
        val line = LinkDiagnostics(System.currentTimeMillis(), event, thermal(), mainBlockMs, disconnectCode, rssi, battery(), locked()).toCsv()
        ring.addLast(line)
        while (ring.size > MAX_LINES) ring.removeFirst()
        try {
            val f = out ?: return
            if (f.length() > MAX_BYTES) f.writeText(ring.joinToString("\n") + "\n")
            f.appendText(line + "\n")
        } catch (_: Exception) {
        }
    }

    @Synchronized
    fun tail(): List<String> = ring.toList()

    companion object {
        const val HEADER = "t_ms,event,thermal,main_block_ms,disconnect_code,rssi,battery_pct,screen_locked"
        private const val PROBE_MS = 1000L
        private const val MAX_LINES = 2000
        private const val MAX_BYTES = 2L * 1024 * 1024
    }
}
