package dev.kelian.mesh.app

/**
 * This fork has no server. While [NETWORK_DISABLED] is true the app always reports "no network", so
 * Signal's network jobs wait instead of failing in a loop and its websockets never try to connect.
 */
object MeshOffline {
    const val NETWORK_DISABLED: Boolean = true
}
