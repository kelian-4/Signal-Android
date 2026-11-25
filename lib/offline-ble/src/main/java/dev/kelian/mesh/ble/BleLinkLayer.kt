package dev.kelian.mesh.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelUuid
import dev.kelian.mesh.core.protocol.IDLE_DISCONNECT_MS
import dev.kelian.mesh.core.protocol.shouldConnectMesh
import dev.kelian.mesh.core.protocol.toHex
import java.security.SecureRandom

/** Events from the radio, all delivered on the layer's handler thread (see [BleLinkLayer.post]). */
interface LinkListener {
    /** A link is usable. [maxFrame] = largest frame (ATT payload) the link accepts. */
    fun onLinkUp(linkId: String, maxFrame: Int)
    fun onLinkDown(linkId: String)
    fun onFrame(linkId: String, frame: ByteArray)

    /** True while something waits to be sent or relayed: only then may we open connections. */
    fun wantsConnection(): Boolean

    /** Called every ~2 s on the layer thread (watchdogs, housekeeping). */
    fun onTick()
}

data class LayerStatus(
    val running: Boolean = false,
    val btEnabled: Boolean = false,
    val advertising: Boolean = false,
    val scanning: Boolean = false,
    val serverReady: Boolean = false,
    val readyLinks: Int = 0,
    val peersSeen: Int = 0,
)

/**
 * BLE link layer: every phone is GATT peripheral (advertise + server) and GATT central (scan + client)
 * at once. It only moves frames: fragmentation, ACKs, relay and messages live in the core.
 * All state is touched on one handler thread; Bluetooth callbacks copy their arguments and post to it.
 *
 * Privacy: the advertisement carries only the service UUID. The INFO characteristic holds a random id
 * regenerated at every start, used to recognise ourselves; no stable identifier is ever exposed.
 */
@SuppressLint("MissingPermission")
@Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
class BleLinkLayer(
    private val ctx: Context,
    private val listener: LinkListener,
    private val log: LinkLog = LinkLog.ANDROID,
    private val diag: DiagnosticsRecorder? = null,
) {
    private val thread = HandlerThread("mesh-ble").also { it.start() }
    private val h = Handler(thread.looper)
    private val manager = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val rnd = SecureRandom()
    private val ephemeralId: ByteArray = ByteArray(8).also { rnd.nextBytes(it) }

    @Volatile var status = LayerStatus()
        private set

    private var started = false
    private var server: BluetoothGattServer? = null
    private var txChar: BluetoothGattCharacteristic? = null
    private var serverReady = false
    private var advertising = false
    private var scanning = false
    private var receiverRegistered = false

    private val clientLinks = HashMap<String, ClientLink>()
    private val serverLinks = HashMap<String, ServerLink>()
    private val lastSeen = HashMap<String, Long>()
    private val rssis = HashMap<String, Int>()
    private val devices = HashMap<String, BluetoothDevice>()
    private val attempts = HashMap<String, Int>()
    private val nextConnectAt = HashMap<String, Long>()
    private val ignoreUntil = HashMap<String, Long>()
    private var lastScanStart = 0L

    /** Runs [block] on the layer thread: the only thread allowed to touch the core engine. */
    fun post(block: () -> Unit) { h.post(block) }

    // ---------------------------------------------------------------- lifecycle

    fun start() {
        h.post {
            if (started) return@post
            started = true
            log.i("engine", "starting")
            diag?.start(); diag?.record("start")
            registerStateReceiver()
            if (adapterEnabled()) bringUp() else log.w("engine", "Bluetooth is off, waiting for it to be enabled")
            publish()
            h.postDelayed(housekeeping, TICK_MS)
        }
    }

    fun stop() {
        h.post {
            if (!started) return@post
            started = false
            log.i("engine", "stopping")
            h.removeCallbacks(housekeeping)
            tearDown()
            unregisterStateReceiver()
            diag?.record("stop"); diag?.stop()
            status = LayerStatus()
            thread.quitSafely()
        }
    }

    private fun adapterEnabled(): Boolean = manager.adapter?.isEnabled == true

    private fun bringUp() {
        openServer()
        startScan()
    }

    private fun tearDown() {
        stopAdvertising()
        stopScan()
        for (l in clientLinks.values.toList()) {
            l.ops.clear()
            announceDown(l)
            try { l.gatt?.disconnect() } catch (_: Exception) {}
            try { l.gatt?.close() } catch (_: Exception) {}
            l.closed = true
        }
        clientLinks.clear()
        for (l in serverLinks.values.toList()) { l.ops.clear(); announceDown(l) }
        serverLinks.clear()
        try { server?.close() } catch (_: Exception) {}
        server = null
        txChar = null
        serverReady = false
    }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            val st = i.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
            h.post {
                if (!started) return@post
                log.i("engine", "Bluetooth adapter state=$st")
                diag?.record("adapter_state_$st")
                if (st == BluetoothAdapter.STATE_ON) {
                    tearDown()
                    bringUp()
                } else if (st == BluetoothAdapter.STATE_TURNING_OFF || st == BluetoothAdapter.STATE_OFF) {
                    tearDown()
                }
                publish()
            }
        }
    }

    private fun registerStateReceiver() {
        if (receiverRegistered) return
        val f = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) ctx.registerReceiver(stateReceiver, f, Context.RECEIVER_NOT_EXPORTED)
        else ctx.registerReceiver(stateReceiver, f)
        receiverRegistered = true
    }

    private fun unregisterStateReceiver() {
        if (!receiverRegistered) return
        try { ctx.unregisterReceiver(stateReceiver) } catch (_: Exception) {}
        receiverRegistered = false
    }

    // ---------------------------------------------------------------- public link API

    /** Sends one frame on a link (ids come from [LinkListener.onLinkUp]). Safe from any thread. */
    fun send(linkId: String, frame: ByteArray, onDone: ((Boolean) -> Unit)? = null) {
        h.post {
            val l = findLink(linkId)
            if (l == null || !l.ready) onDone?.invoke(false) else l.write(frame, onDone)
        }
    }

    /** Cuts a link that stopped answering; it is re-established by the normal scan/connect cycle. */
    fun dropLink(linkId: String) {
        h.post {
            when (val l = findLink(linkId)) {
                is ClientLink -> dropClient(l, "watchdog")
                is ServerLink -> try { server?.cancelConnection(l.device) } catch (_: Exception) {}
                else -> {}
            }
            // Fresh scan: gives the stack a clean start after a stall.
            if (started && adapterEnabled()) { stopScan(); startScan() }
        }
    }

    private fun findLink(id: String): Link? =
        if (id.startsWith("cli:")) clientLinks[id.removePrefix("cli:")] else if (id.startsWith("srv:")) serverLinks[id.removePrefix("srv:")] else null

    // ---------------------------------------------------------------- GATT server (peripheral role)

    private fun openServer() {
        val srv = manager.openGattServer(ctx, serverCb)
        if (srv == null) {
            log.e("gatt-s", "openGattServer returned null")
            return
        }
        server = srv
        val svc = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val rx = BluetoothGattCharacteristic(RX_UUID, BluetoothGattCharacteristic.PROPERTY_WRITE, BluetoothGattCharacteristic.PERMISSION_WRITE)
        val tx = BluetoothGattCharacteristic(TX_UUID, BluetoothGattCharacteristic.PROPERTY_NOTIFY, BluetoothGattCharacteristic.PERMISSION_READ)
        tx.addDescriptor(
            BluetoothGattDescriptor(CCCD_UUID, BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE),
        )
        val info = BluetoothGattCharacteristic(INFO_UUID, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ)
        svc.addCharacteristic(rx)
        svc.addCharacteristic(tx)
        svc.addCharacteristic(info)
        txChar = tx
        log.i("gatt-s", "addService requested ok=${srv.addService(svc)}")
    }

    private fun infoValue(): ByteArray = byteArrayOf(1) + ephemeralId

    private val serverCb = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            h.post {
                log.i("gatt-s", "service added status=$status")
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    serverReady = true
                    startAdvertising()
                }
                publish()
            }
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            val addr = device.address
            h.post {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    serverLinks.remove(addr)?.let { it.ops.clear(); announceDown(it) }
                    serverLinks[addr] = ServerLink(device)
                    touch(addr, null)
                    log.i("gatt-s", "central connected status=$status")
                    diag?.record("srv_connected", status)
                } else {
                    serverLinks.remove(addr)?.let { it.ops.clear(); announceDown(it) }
                    log.i("gatt-s", "central disconnected status=$status")
                    diag?.record("srv_disconnected", status)
                }
                publish()
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            val addr = device.address
            h.post {
                serverLinks[addr]?.mtu = mtu
                log.i("gatt-s", "MTU changed to $mtu")
            }
        }

        override fun onCharacteristicReadRequest(device: BluetoothDevice, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic) {
            val value = if (characteristic.uuid == INFO_UUID) infoValue() else null
            if (value == null || offset > value.size) {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
            } else {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value.copyOfRange(offset, value.size))
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?,
        ) {
            val copy = value?.copyOf()
            val isRx = characteristic.uuid == RX_UUID
            if (responseNeeded) {
                server?.sendResponse(device, requestId, if (isRx) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_WRITE_NOT_PERMITTED, offset, null)
            }
            if (!isRx || copy == null) return
            val addr = device.address
            h.post {
                val link = serverLinks[addr] ?: ServerLink(device).also { serverLinks[addr] = it }
                incoming(copy, link)
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?,
        ) {
            val copy = value?.copyOf()
            val isCccd = descriptor.uuid == CCCD_UUID
            if (responseNeeded) {
                server?.sendResponse(device, requestId, if (isCccd) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_WRITE_NOT_PERMITTED, offset, null)
            }
            if (!isCccd || copy == null) return
            val addr = device.address
            h.post {
                val link = serverLinks[addr] ?: ServerLink(device).also { serverLinks[addr] = it }
                link.subscribed = copy.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                log.i("gatt-s", "notifications ${if (link.subscribed) "enabled" else "disabled"}")
                if (link.subscribed) announceUp(link) else announceDown(link)
                publish()
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            val addr = device.address
            h.post {
                if (status != BluetoothGatt.GATT_SUCCESS) log.w("gatt-s", "notification failed status=$status")
                serverLinks[addr]?.ops?.done(status == BluetoothGatt.GATT_SUCCESS)
            }
        }
    }

    // ---------------------------------------------------------------- advertising

    private val advCb = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            h.post { advertising = true; log.i("adv", "advertising started"); publish() }
        }

        override fun onStartFailure(errorCode: Int) {
            h.post {
                advertising = false
                log.e("adv", "advertising failed code=$errorCode")
                if (errorCode != ADVERTISE_FAILED_ALREADY_STARTED) {
                    h.postDelayed({ if (started && adapterEnabled() && serverReady && !advertising) startAdvertising() }, 5000)
                } else {
                    advertising = true
                }
                publish()
            }
        }
    }

    private fun startAdvertising() {
        val adv = manager.adapter?.bluetoothLeAdvertiser
        if (adv == null) {
            log.e("adv", "BLE advertising not supported on this device")
            return
        }
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        // Only the service UUID goes into the advertisement (iOS background limitation, and no stable id).
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()
        try {
            adv.startAdvertising(settings, data, advCb)
        } catch (e: Exception) {
            log.e("adv", "startAdvertising threw ${e.javaClass.simpleName}")
        }
    }

    private fun stopAdvertising() {
        try { manager.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advCb) } catch (_: Exception) {}
        advertising = false
    }

    // ---------------------------------------------------------------- scanning (central role)

    private val scanCb = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val dev = result.device
            val rssi = result.rssi
            h.post { onScanned(dev, rssi) }
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            val copy = results.map { it.device to it.rssi }
            h.post { copy.forEach { onScanned(it.first, it.second) } }
        }

        override fun onScanFailed(errorCode: Int) {
            h.post {
                scanning = false
                log.e("scan", "scan failed code=$errorCode")
                if (errorCode != SCAN_FAILED_ALREADY_STARTED) {
                    h.postDelayed({ if (started && adapterEnabled() && !scanning) startScan() }, 10_000)
                } else {
                    scanning = true
                }
                publish()
            }
        }
    }

    private fun startScan() {
        val scanner = manager.adapter?.bluetoothLeScanner
        if (scanner == null) {
            log.e("scan", "BLE scanner unavailable")
            return
        }
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        try {
            scanner.startScan(listOf(filter), settings, scanCb)
            scanning = true
            lastScanStart = System.currentTimeMillis()
            log.i("scan", "scan started (filtered on service UUID)")
        } catch (e: Exception) {
            log.e("scan", "startScan threw ${e.javaClass.simpleName}")
        }
        publish()
    }

    private fun stopScan() {
        try { manager.adapter?.bluetoothLeScanner?.stopScan(scanCb) } catch (_: Exception) {}
        scanning = false
    }

    private fun onScanned(dev: BluetoothDevice, rssi: Int) {
        if (!started) return
        val addr = dev.address
        devices[addr] = dev
        touch(addr, rssi)
        maybeConnect(dev)
    }

    private fun touch(addr: String, rssi: Int?) {
        if (rssi != null) rssis[addr] = rssi
        lastSeen[addr] = System.currentTimeMillis()
    }

    // ---------------------------------------------------------------- links

    private abstract inner class Link(val key: String) {
        var mtu = 23
        var lastActivityMs = System.currentTimeMillis()
        var announced = false
        val ops = OpQueue(h, { log.w("gatt", it) }, { onLinkTimeout(this) })
        abstract val ready: Boolean
        abstract val id: String
        fun maxFrame(): Int = mtu - 3
        abstract fun write(frame: ByteArray, onDone: ((Boolean) -> Unit)? = null)
    }

    private inner class ServerLink(val device: BluetoothDevice) : Link(device.address) {
        var subscribed = false
        override val ready: Boolean get() = subscribed
        override val id: String get() = "srv:${device.address}"

        override fun write(frame: ByteArray, onDone: ((Boolean) -> Unit)?) {
            lastActivityMs = System.currentTimeMillis()
            ops.enqueue("notify", onDone) {
                val tx = txChar
                val srv = server
                if (tx == null || srv == null) false else notifyChar(srv, device, tx, frame)
            }
        }
    }

    private inner class ClientLink(val device: BluetoothDevice) : Link(device.address) {
        var gatt: BluetoothGatt? = null
        var rx: BluetoothGattCharacteristic? = null
        var tx: BluetoothGattCharacteristic? = null
        var info: BluetoothGattCharacteristic? = null
        var ready0 = false
        var everReady = false
        var closed = false
        override val ready: Boolean get() = ready0 && !closed
        override val id: String get() = "cli:${device.address}"

        override fun write(frame: ByteArray, onDone: ((Boolean) -> Unit)?) {
            lastActivityMs = System.currentTimeMillis()
            ops.enqueue("write", onDone) {
                val g = gatt
                val c = rx
                if (g == null || c == null) false else writeChar(g, c, frame)
            }
        }

        val cb = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                h.post { onClientState(this@ClientLink, g, status, newState) }
            }

            override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
                h.post { onClientMtu(this@ClientLink, g, mtu, status) }
            }

            override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                h.post { onClientServices(this@ClientLink, g, status) }
            }

            override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
                val v = c.value?.copyOf()
                val u = c.uuid
                h.post { onClientRead(this@ClientLink, u, v, status) }
            }

            override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
                val v = value.copyOf()
                val u = c.uuid
                h.post { onClientRead(this@ClientLink, u, v, status) }
            }

            override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
                h.post {
                    if (status != BluetoothGatt.GATT_SUCCESS) log.w("gatt-c", "write failed status=$status")
                    ops.done(status == BluetoothGatt.GATT_SUCCESS)
                }
            }

            override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) {
                val isCccd = d.uuid == CCCD_UUID
                h.post { onClientDescriptorWrite(this@ClientLink, isCccd, status) }
            }

            override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
                val v = c.value?.copyOf() ?: return
                h.post { incoming(v, this@ClientLink) }
            }

            override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) {
                val v = value.copyOf()
                h.post { incoming(v, this@ClientLink) }
            }
        }
    }

    private fun announceUp(link: Link) {
        if (link.announced || !link.ready) return
        link.announced = true
        log.i("link", "up ${link.id.take(4)} maxFrame=${link.maxFrame()}")
        diag?.record("link_up", rssi = rssis[link.key])
        listener.onLinkUp(link.id, link.maxFrame())
    }

    private fun announceDown(link: Link) {
        if (!link.announced) return
        link.announced = false
        log.i("link", "down ${link.id.take(4)}")
        diag?.record("link_down")
        listener.onLinkDown(link.id)
    }

    private fun incoming(bytes: ByteArray, link: Link) {
        link.lastActivityMs = System.currentTimeMillis()
        if (!link.announced) announceUp(link)
        listener.onFrame(link.id, bytes)
    }

    private fun onLinkTimeout(link: Link) {
        log.w("gatt", "${link.id.take(4)}: link timed out, dropping")
        diag?.record("op_timeout")
        when (link) {
            is ClientLink -> dropClient(link, "operation timeout")
            is ServerLink -> try { server?.cancelConnection(link.device) } catch (_: Exception) {}
        }
    }

    // ---- low level helpers (API 33 introduced value-carrying overloads)

    private fun writeChar(g: BluetoothGatt, c: BluetoothGattCharacteristic, v: ByteArray): Boolean {
        return if (Build.VERSION.SDK_INT >= 33) {
            g.writeCharacteristic(c, v, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == BluetoothStatusCodes.SUCCESS
        } else {
            c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            c.value = v
            g.writeCharacteristic(c)
        }
    }

    private fun writeDescriptor(g: BluetoothGatt, d: BluetoothGattDescriptor, v: ByteArray): Boolean {
        return if (Build.VERSION.SDK_INT >= 33) {
            g.writeDescriptor(d, v) == BluetoothStatusCodes.SUCCESS
        } else {
            d.value = v
            g.writeDescriptor(d)
        }
    }

    private fun notifyChar(srv: BluetoothGattServer, dev: BluetoothDevice, c: BluetoothGattCharacteristic, v: ByteArray): Boolean {
        return if (Build.VERSION.SDK_INT >= 33) {
            srv.notifyCharacteristicChanged(dev, c, false, v) == BluetoothStatusCodes.SUCCESS
        } else {
            c.value = v
            srv.notifyCharacteristicChanged(dev, c, false)
        }
    }

    // ---- client connection state machine: connect -> MTU -> discover -> read INFO -> subscribe TX -> ready

    private fun maybeConnect(dev: BluetoothDevice) {
        if (!started || !adapterEnabled()) return
        val addr = dev.address
        val now = System.currentTimeMillis()
        if (clientLinks.containsKey(addr)) return
        // On demand: detection alone never opens a connection; only queued or relayable data does.
        if (!shouldConnectMesh(
                listener.wantsConnection(), clientLinks.size, now,
                nextConnectAt[addr] ?: 0L, ignoreUntil[addr] ?: 0L,
                serverLinks[addr]?.ready == true,
            )
        ) return
        val link = ClientLink(dev)
        clientLinks[addr] = link
        log.i("gatt-c", "connecting (attempt ${(attempts[addr] ?: 0) + 1})")
        val g = try {
            dev.connectGatt(ctx, false, link.cb, BluetoothDevice.TRANSPORT_LE)
        } catch (e: Exception) {
            log.e("gatt-c", "connectGatt threw ${e.javaClass.simpleName}")
            null
        }
        if (g == null) {
            clientLinks.remove(addr)
            return
        }
        link.gatt = g
        h.postDelayed({
            if (clientLinks[addr] === link && !link.ready) dropClient(link, "not ready after 40 s")
        }, 40_000)
        publish()
    }

    private fun onClientState(link: ClientLink, g: BluetoothGatt, status: Int, newState: Int) {
        if (link.closed) return
        if (newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) {
            val inboundMtu = serverLinks[link.key]?.mtu ?: 23
            if (inboundMtu > 23) {
                // The ATT MTU is per connection and was already negotiated by the inbound link: asking
                // again is useless and its callback may never come (it cut a working link once).
                link.mtu = minOf(inboundMtu, REQUESTED_MTU)
                link.ops.enqueue("discoverServices") { g.discoverServices() }
            } else {
                link.ops.enqueue("requestMtu", timeoutMs = 20_000) { g.requestMtu(REQUESTED_MTU) }
            }
        } else {
            if (status == 133) log.w("gatt-c", "GATT error 133, will retry with backoff")
            log.i("gatt-c", "disconnected status=$status newState=$newState")
            diag?.record("cli_disconnected", status, rssis[link.key])
            closeClient(link)
        }
    }

    private fun onClientMtu(link: ClientLink, g: BluetoothGatt, mtu: Int, status: Int) {
        if (link.closed) return
        if (status == BluetoothGatt.GATT_SUCCESS) link.mtu = mtu
        log.i("gatt-c", "MTU=$mtu status=$status (max frame ${link.maxFrame()} bytes)")
        link.ops.done()
        link.ops.enqueue("discoverServices") { g.discoverServices() }
    }

    private fun onClientServices(link: ClientLink, g: BluetoothGatt, status: Int) {
        if (link.closed) return
        link.ops.done()
        val svc = g.getService(SERVICE_UUID)
        if (status != BluetoothGatt.GATT_SUCCESS || svc == null) {
            log.w("gatt-c", "service discovery failed status=$status")
            ignoreUntil[link.key] = System.currentTimeMillis() + 60_000
            dropClient(link, "no usable service")
            return
        }
        link.rx = svc.getCharacteristic(RX_UUID)
        link.tx = svc.getCharacteristic(TX_UUID)
        link.info = svc.getCharacteristic(INFO_UUID)
        if (link.rx == null || link.tx == null || link.info == null) {
            ignoreUntil[link.key] = System.currentTimeMillis() + 60_000
            dropClient(link, "characteristics missing")
            return
        }
        link.ops.enqueue("readInfo") { g.readCharacteristic(link.info) }
        link.ops.enqueue("enableNotify") {
            val tx = link.tx
            val cccd = tx?.getDescriptor(CCCD_UUID)
            if (tx == null || cccd == null) false
            else g.setCharacteristicNotification(tx, true) && writeDescriptor(g, cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
        }
    }

    private fun onClientRead(link: ClientLink, uuid: java.util.UUID, value: ByteArray?, status: Int) {
        if (link.closed) return
        link.ops.done(status == BluetoothGatt.GATT_SUCCESS)
        if (uuid != INFO_UUID) return
        if (status != BluetoothGatt.GATT_SUCCESS || value == null || value.size < 9 || value[0].toInt() != 1) {
            log.w("gatt-c", "bad INFO read status=$status")
            return
        }
        if (value.copyOfRange(1, 9).contentEquals(ephemeralId)) {
            log.w("gatt-c", "that link is ourselves, ignoring it for 10 min")
            ignoreUntil[link.key] = System.currentTimeMillis() + 10 * 60_000
            dropClient(link, "self")
        }
    }

    private fun onClientDescriptorWrite(link: ClientLink, isCccd: Boolean, status: Int) {
        if (link.closed) return
        link.ops.done(status == BluetoothGatt.GATT_SUCCESS)
        if (!isCccd) return
        if (status != BluetoothGatt.GATT_SUCCESS) {
            log.w("gatt-c", "enabling notifications failed status=$status")
            dropClient(link, "subscribe failed")
            return
        }
        link.ready0 = true
        link.everReady = true
        attempts.remove(link.key)
        announceUp(link)
        publish()
    }

    private fun dropClient(link: ClientLink, reason: String) {
        if (link.closed) return
        log.i("gatt-c", "dropping link: $reason")
        try { link.gatt?.disconnect() } catch (_: Exception) {}
        // The disconnect callback normally closes the link; make sure it happens.
        h.postDelayed({ closeClient(link) }, 2000)
    }

    private fun closeClient(link: ClientLink) {
        if (link.closed) return
        link.closed = true
        announceDown(link)
        link.ready0 = false
        link.ops.clear()
        try { link.gatt?.close() } catch (_: Exception) {}
        if (clientLinks[link.key] === link) clientLinks.remove(link.key)
        val addr = link.key
        val now = System.currentTimeMillis()
        val delay: Long
        if (link.everReady) {
            attempts.remove(addr)
            delay = 3000
        } else {
            val n = (attempts[addr] ?: 0) + 1
            attempts[addr] = n
            delay = minOf(30_000L, 1000L shl minOf(n, 5)) + rnd.nextInt(500)
            log.i("gatt-c", "backoff $delay ms before retrying (failure $n)")
        }
        nextConnectAt[addr] = now + delay
        h.postDelayed({
            val dev = devices[addr]
            val seen = lastSeen[addr] ?: 0L
            if (dev != null && started && System.currentTimeMillis() - seen < 60_000) maybeConnect(dev)
        }, delay + 200)
        publish()
    }

    /** Called when data became pending: try the peers detected recently (the policy decides). */
    fun connectNow() {
        h.post {
            val now = System.currentTimeMillis()
            for ((addr, dev) in devices.entries.toList()) if (now - (lastSeen[addr] ?: 0L) < 30_000) maybeConnect(dev)
        }
    }

    // ---------------------------------------------------------------- housekeeping

    private val housekeeping = object : Runnable {
        override fun run() {
            if (!started) return
            val now = System.currentTimeMillis()
            publish()
            listener.onTick()
            val wants = listener.wantsConnection()
            for (l in clientLinks.values.toList()) {
                if (l.ready && !wants && now - l.lastActivityMs >= IDLE_DISCONNECT_MS) {
                    log.i("gatt-c", "idle with nothing pending, disconnecting")
                    dropClient(l, "idle")
                }
            }
            if (wants) connectNow()
            if (scanning && now - lastScanStart > 10 * 60_000) {
                log.i("scan", "periodic scan restart")
                stopScan()
                startScan()
            }
            h.postDelayed(this, TICK_MS)
        }
    }

    private fun publish() {
        val now = System.currentTimeMillis()
        lastSeen.entries.removeAll { (addr, t) -> now - t > 30_000 && !clientLinks.containsKey(addr) && !serverLinks.containsKey(addr) }
        status = LayerStatus(
            running = started,
            btEnabled = adapterEnabled(),
            advertising = advertising,
            scanning = scanning,
            serverReady = serverReady,
            readyLinks = clientLinks.values.count { it.ready } + serverLinks.values.count { it.ready },
            peersSeen = lastSeen.size,
        )
    }

    companion object {
        private const val TICK_MS = 2000L
    }
}
