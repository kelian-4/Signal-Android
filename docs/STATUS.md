# Status of the offline fork (Android)

Legend: **tested** = unit tests pass (local + CI) · **compiled** = builds in CI, never run · **not done**.

## Tested (unit tests, CI and `lib/offline-core/tools/run-local.sh`)
- `lib/offline-core` (56 tests, pure Kotlin): frames, fragmentation, reassembly, dedup (shared `vectors.json`),
  connection policies (lab + mesh), relay with TTL / bounded cache / store-and-forward, persisted outbox,
  ACK watchdog, link diagnostics, BIP-39 24-word phrase, encrypted backup (no session state), signed QR,
  challenge-response, security code, trust levels + key-change alert, anti-abuse rules, `MeshEngine`
  end-to-end in simulation, pluggable signature scheme.
- `lib/offline-signal` (libsignal 0.108, real native library): identity restorable from the phrase,
  offline prekey bundle (~2.5 k chars, fits one QR), Double Ratchet sessions that survive a restart,
  HPKE-sealed contact requests, full text exchange through a relay that cannot read it.

## Compiled only (never run on a phone)
- `lib/offline-ble`: BLE link layer ported from the field-tested lab engine, foreground service,
  battery-exemption helper, permission list, diagnostics CSV, `MeshRuntime`.
- Launcher screen `MeshMainActivity` (plain Android views): identity creation with a nickname, 24-word recovery
  phrase display, restore from a phrase, seed encrypted with an Android Keystore key, Bluetooth permission
  request, battery-exemption request, start/stop of the foreground BLE service, live link status. The
  `RoutingActivity` launcher alias now points to it instead of Signal's `MainActivity`.
- The whole app builds (`:Signal-Android:assemblePlayProdDebug`) with: new applicationId
  `app.messagerie.mesh`, name "Mesh", neutral icon, INTERNET permission removed.

## Not done
- Signal's own code still runs at startup (`ApplicationContext`) and its server-dependent features are not
  removed (see `docs/REMOVED.md`): how the app behaves at launch without INTERNET is untested.
- Mesh screens still missing: QR display/scan with the signed QR and prekey bundle, chat, verification badge,
  key-change alert, backup export/import, contact requests. `MeshRuntime` events are not consumed yet, so
  no message can be sent from the UI. Signal's conversation UI does not use the mesh transport.
- Signal's alternative launcher icons and other Signal branding assets are still present.
- Everything radio-related on real phones: see `docs/HARDWARE_TESTS.md`.

## Known risks
- QR of ~2.5 k characters is dense: scanning reliability on cheap phone cameras is untested
  (fallback: send the bundle over close-range BLE after scanning the compact signed QR).
- Removing server code from ~6,900 Signal source files can only be validated by build + a real phone.
