package dev.kelian.mesh.core.protocol

const val MAX_CLIENT_LINKS = 2
const val IDLE_DISCONNECT_MS = 20_000L

fun shouldConnect(
    pending: Boolean,
    readyLinks: Int,
    clientLinks: Int,
    nowMs: Long,
    nextConnectAtMs: Long,
    ignoreUntilMs: Long,
    inboundFromPeer: Boolean = false,
): Boolean =
    pending && readyLinks == 0 && clientLinks < MAX_CLIENT_LINKS && nowMs >= nextConnectAtMs &&
        nowMs >= ignoreUntilMs && !inboundFromPeer

fun shouldDropIdle(ready: Boolean, pending: Boolean, nowMs: Long, lastActivityMs: Long): Boolean =
    ready && !pending && nowMs - lastActivityMs >= IDLE_DISCONNECT_MS

const val MESH_MAX_CLIENT_LINKS = 3

fun shouldConnectMesh(
    wantsConnection: Boolean,
    clientLinks: Int,
    nowMs: Long,
    nextConnectAtMs: Long,
    ignoreUntilMs: Long,
    alreadyLinkedWithPeer: Boolean,
): Boolean =
    wantsConnection && clientLinks < MESH_MAX_CLIENT_LINKS && nowMs >= nextConnectAtMs &&
        nowMs >= ignoreUntilMs && !alreadyLinkedWithPeer
