# Status of the offline fork (Android)

## Done and verified (unit tests, run locally with `lib/offline-core/tools/run-local.sh`)
`lib/offline-core` (pure Kotlin/JVM, 43 tests): frames, fragmentation, reassembly and de-duplication
(shared `vectors.json` from the lab repo), connection policy, BLE relay with TTL + bounded dedup cache
(simulated nodes), persisted outbox, ACK watchdog, link diagnostics, device identity, 24-word BIP-39
phrase, encrypted backup (no session state), signed QR + challenge-response + security code, trust
levels with key-change alert, anti-abuse rules.

## NOT done (nothing below was changed in the app yet)
- Rename of the app (applicationId, name, icon), removal of server-dependent features, removal of the
  INTERNET permission, offline profile start (scope A). No removal is recorded yet in `docs/REMOVED.md`
  because none was made.
- Android BLE transport (GATT, foreground service, battery exemption, error 133 retry) wired to the UI.
- libsignal sessions and offline prekey exchange; wiring of identity/backup/verification into the Signal UI.
- Contact-request screens.

## Not verifiable without a phone
Everything Bluetooth, battery, background behaviour, relay across 3 real phones.
