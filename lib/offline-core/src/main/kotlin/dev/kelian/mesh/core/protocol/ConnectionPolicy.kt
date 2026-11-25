package dev.kelian.mesh.core.protocol

const val MAX_CLIENT_LINKS = 2
const val IDLE_DISCONNECT_MS = 20_000L

/**
 * Connect on demand: devices are always detected (scan), but we only open a connection when a message
 * waits for delivery and no link is ready yet. This keeps users from ending up with many connections.
 */
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

/** An outgoing link is dropped when nothing is pending and it carried no traffic for [IDLE_DISCONNECT_MS]. */
fun shouldDropIdle(ready: Boolean, pending: Boolean, nowMs: Long, lastActivityMs: Long): Boolean =
    ready && !pending && nowMs - lastActivityMs >= IDLE_DISCONNECT_MS

const val MESH_MAX_CLIENT_LINKS = 3

/**
 * Mesh variant: a relay phone may already hold a link (from the sender) and still has to open another
 * one towards the next hop, so ready links do not block a new connection. Still on demand only.
 */
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
