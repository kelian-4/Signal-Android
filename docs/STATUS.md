# Status of the offline fork (Android)

## Done and verified (unit tests, run locally with `lib/offline-core/tools/run-local.sh`)
`lib/offline-core` (pure Kotlin/JVM, 43 tests): frames, fragmentation, reassembly and de-duplication
(shared `vectors.json` from the lab repo), connection policy, BLE relay with TTL + bounded dedup cache
(simulated nodes), persisted outbox, ACK watchdog, link diagnostics, device identity, 24-word BIP-39
phrase, encrypted backup (no session state), signed QR + challenge-response + security code, trust
levels with key-change alert, anti-abuse rules.

## Done and compiled (CI), not run on a phone
`lib/offline-ble` (Android library): BLE link layer ported from the field-tested lab engine (GATT server +
client, serialized operations, error 133 backoff, MTU reuse, on-demand mesh connection policy, ephemeral
INFO id, watchdog-driven link repair), foreground service (connectedDevice), battery-exemption helper,
permission list, per-event diagnostics CSV, and `MeshRuntime` gluing the core engine to the radio.

## NOT done (nothing below was changed in the app yet)
- Rename of the app (applicationId, name, icon), removal of server-dependent features, removal of the
  INTERNET permission, offline profile start (scope A). No removal is recorded yet in `docs/REMOVED.md`
  because none was made.
- Wiring of `MeshRuntime` into the Signal app (identity storage, start/stop, permission screens).
- libsignal sessions and offline prekey exchange; wiring of identity/backup/verification into the Signal UI.
- Contact-request screens.

## Not verifiable without a phone
Everything Bluetooth, battery, background behaviour, relay across 3 real phones.
