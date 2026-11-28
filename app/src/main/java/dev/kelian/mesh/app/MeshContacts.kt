package dev.kelian.mesh.app

import android.content.Context

object MeshContacts {
    private const val PREFS = "mesh_contacts"

    fun put(context: Context, publicKeyHex: String, nickname: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(publicKeyHex, nickname).apply()
    }

    fun all(context: Context): Map<String, String> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).all.mapNotNull { (k, v) -> (v as? String)?.let { k to it } }.toMap()
}
