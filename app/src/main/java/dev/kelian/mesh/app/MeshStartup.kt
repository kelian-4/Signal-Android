package dev.kelian.mesh.app

import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.content.Intent
import dev.kelian.mesh.ble.BatteryOptimization
import dev.kelian.mesh.ble.BleForegroundService
import dev.kelian.mesh.ble.BlePermissions
import org.signal.core.ui.permissions.Permissions

object MeshStartup {
    private const val PREFS = "mesh_startup"
    private const val KEY_BATTERY_ASKED = "battery_asked"
    private var started = false

    @JvmStatic
    fun begin(activity: Activity) {
        MeshApp.ensureRuntime(activity)
        if (BlePermissions.bluetoothMissing(activity).isEmpty()) {
            launch(activity)
            return
        }
        Permissions.with(activity)
            .request(*BlePermissions.required())
            .ifNecessary()
            .withPermanentDenialDialog("Le Bluetooth est nécessaire pour envoyer et recevoir des messages sans internet.")
            .onAnyResult {
                if (BlePermissions.bluetoothMissing(activity).isEmpty()) launch(activity)
            }
            .execute()
    }

    private fun launch(activity: Activity) {
        if (started) return
        started = true
        val adapter = BluetoothAdapter.getDefaultAdapter()
        if (adapter != null && !adapter.isEnabled) {
            activity.startActivity(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
        }
        BleForegroundService.start(activity)
        val prefs = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!BatteryOptimization.isExempt(activity) && !prefs.getBoolean(KEY_BATTERY_ASKED, false)) {
            prefs.edit().putBoolean(KEY_BATTERY_ASKED, true).apply()
            activity.startActivity(BatteryOptimization.requestIntent(activity))
        }
    }
}
