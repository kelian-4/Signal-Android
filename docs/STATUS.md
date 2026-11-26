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
- The whole app builds (`:Signal-Android:assemblePlayProdDebug`) with: new applicationId
  `app.messagerie.mesh`, name "Mesh", neutral icon, INTERNET permission removed.

## Not done
- Starting the app offline with a local profile: the Signal registration flow is still there and cannot
  work without a server (and without the INTERNET permission). Server-dependent features are not removed
  yet (see `docs/REMOVED.md`).
- `MeshRuntime` / `LibsignalSessionCipher` are not wired into the Signal UI: no screens for identity
  creation, QR display/scan, verification badge, key-change alert, recovery phrase, backup export/import,
  contact requests; the Signal message pipeline does not use the mesh transport yet.
- Signal's alternative launcher icons and other Signal branding assets are still present.
- Everything radio-related on real phones: see `docs/HARDWARE_TESTS.md`.

## Known risks
- QR of ~2.5 k characters is dense: scanning reliability on cheap phone cameras is untested
  (fallback: send the bundle over close-range BLE after scanning the compact signed QR).
- Removing server code from ~6,900 Signal source files can only be validated by build + a real phone.
