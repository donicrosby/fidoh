# Testing fidoh — pyramid, CI contract, and hardware runbook

Governing spec: `openspec/changes/testing-strategy/specs/testing-strategy/spec.md`.

All device-procedure descriptions below are **constructed guidance** (written
from the CTAP2.1 spec and Yubico's public developer documentation, not
captured from a test run). Expected typed outcomes are normative (from the
ceremony spec's error taxonomy); LED/touch cues are indicative and may vary
by firmware.

## The pyramid

| Tier | What | Environment | When it runs |
|---|---|---|---|
| T1 unit | Pure CBOR/model logic (core-model): canonical encoding, strict decode, wire structures, status table | none | default `cargo test`, every CI commit |
| T2 soft-token integration | Full ceremony against `transport-soft` via the shared `Transport`/`Device` traits | no hardware, no root, no udev | default `cargo test`, every CI commit — **the CI contract** |
| T3 hardware | Same ceremonies against physical authenticators | the device under test + a human | manual only, behind a gate |

T2 is the only tier that must be green in default CI. Because the soft token
implements the same traits as the hardware transports, T2 exercises the real
client code paths — CBOR, error mapping, timeouts, keepalive handling —
unchanged.

## CI contract (T2 mandatory matrix)

The following scenarios MUST each have a passing T2 test. See the spec's
mandatory-matrix requirement for the normative table; summary:

- **M1** keepalive-then-success — knob (b) emits UP_NEEDED keepalives before
  a successful response; ceremony succeeds without resetting the deadline.
- **M2** delay-beyond-deadline — knob (c); expect typed `Error::Timeout`
  naming the expired phase (test terminates within deadline + 60 s worst case).
- **M3–M13** status injection — knob (a) with 0x2E, 0x22 → `NoCredentials`;
  0x2F → `UserActionTimeout`; 0x2D → `UserCancelled`; 0x27, 0x3B, 0x33, 0x34,
  0x36, 0x37, 0x3C → `UpRejected` (CTAP2.1 §8.2 + ceremony status mapping).
- **M14** wrong-credential-id — knob (d) + caller allowList →
  `Error::CredentialMismatch`.
- **M15** multi-assertion drain — ≥3 resident credentials, no allowList →
  getNextAssertion (CTAP2.1 §6.3) issued `numberOfCredentials − 1` times.
- **M16** AmbiguousDevice — two soft tokens, default `Fail` policy →
  `Error::AmbiguousDevice` with both descriptors; `connect` never called.
- **M17** NoDevice — zero transports → `Error::NoDevice` with diagnostics.

## Other CI gates

- **MSRV**: build + full T1/T2 test on exactly Rust **1.75** (workspace
  `rust-version = "1.75"`, async-core OQ-1) and on **stable**.
- **Clippy**: zero warnings (warnings denied), all workspace crates.
- **fmt**: `cargo fmt --check`.
- **Fuzz smoke**: time-boxed coverage-guided run of the CBOR decoder target
  over a committed seed corpus; any panic/abort fails CI. Longer campaigns
  run outside CI. Rationale: the decoder parses attacker-controlled bytes
  from a USB/NFC device.

## Conformance vectors

Two labeled sources only (cleanroom rules; config.yaml docs rule):

- **spec-derived** — transcribed from the CTAP2 spec's own examples
  (CTAP2.1 §6) where they exist; ground truth for canonical CBOR.
- **constructed** — generated from `transport-soft` snapshots under the
  deterministic seeded RNG (see docs/transport-soft.md §Conformance vectors);
  committed under `fixtures/`; CI regenerates and asserts byte-identical
  output.

Never commit blobs captured from third-party authenticators.

## Hardware test runbook (T3)

### Enabling

T3 tests are gated (cargo feature `hardware-tests` or env
`FIDOH_HARDWARE_TESTS=1` — design OQ-1) and **never run by default**. Run one
matrix row at a time with the matching device attached. All touch waits are
bounded by the ceremony deadline (default 30 s budget, per async-core); a row
that does not produce its expected outcome within the deadline FAILS — it
does not hang.

### Matrix

Device classes × behaviors: {pre-5.8 YubiKey HID, 5.8+ YubiKey HID, 5.8+
YubiKey CCID, NFC via PC/SC} × {UP-required, wrong-allowCredential}.

### Row H1: pre-5.8 YubiKey over CTAPHID — UP-required getAssertion

- **Setup**: insert a pre-5.8 YubiKey (HID interface; hidraw on Linux, udev
  rule or permissions per your distro). Mint/prepare a credential for the
  test rpId out of band. Run the getAssertion test with `up` required and no
  allowList.
- **Expected typed outcome**: ceremony returns a raw assertion with flags
  bit 0 (UP) set; deadline never exceeded.
- **Cues**: key LED blinks steadily requesting touch; touching the contact
  completes the ceremony. Withholding touch until the 30 s deadline must
  produce `Error::Timeout` naming the user-presence phase.

### Row H2: pre-5.8 YubiKey over CTAPHID — wrong-allowCredential

- **Setup**: as H1, but pass an allowList containing only a credential ID
  not on the key.
- **Expected typed outcome**: `Error::NoCredentials` (0x2E
  CTAP2_ERR_NO_CREDENTIALS, CTAP2.1 §8.2), fail-fast, **no touch requested**.
- **Cues**: LED does not blink; no user interaction occurs.

### Row H3: 5.8+ YubiKey over CTAPHID — UP-required getAssertion

- **Setup**: as H1 with a firmware ≥ 5.8 YubiKey on the USB HID interface.
- **Expected typed outcome**: as H1 — assertion with UP flag set.
- **Cues**: as H1 (steady blink → touch → success).

### Row H4: 5.8+ YubiKey over CTAPHID — wrong-allowCredential

- **Setup**: as H2 with the 5.8+ key on HID.
- **Expected typed outcome**: as H2 — `Error::NoCredentials`, fail-fast.
- **Cues**: as H2 — no blink, no touch.

### Row H5: 5.8+ YubiKey over USB CCID (FIDO-over-CCID) — UP-required

- **Setup**: firmware ≥ 5.8 YubiKey with the CCID interface enabled; pcscd
  running. The PC/SC transport selects the FIDO applet and runs the same
  APDU-layer ceremony (CTAP 2.x over ISO 7816 APDUs per Yubico's public
  docs for fw 5.8+).
- **Expected typed outcome**: assertion with UP flag set; same typed result
  as the HID rows (unified APDU layer, transport-pcsc spec).
- **Cues**: LED blink/touch behavior as on HID; NFC field not involved.

### Row H6: 5.8+ YubiKey over USB CCID — wrong-allowCredential

- **Setup**: as H5, with a non-matching allowList.
- **Expected typed outcome**: `Error::NoCredentials`.
- **Cues**: no touch requested.

### Row H7: NFC via PC/SC — UP-required

- **Setup**: NFC reader on PC/SC (SHARED mode for T=CL per transport-pcsc
  spec); YubiKey held against the reader. ISO 14443 / CTAP2.1 §11.3 framing;
  expect WTX time extensions during the touch wait (transport-pcsc spec).
- **Expected typed outcome**: assertion with UP flag set; WTX extensions
  consumed as progress, not errors, within the single ceremony budget.
- **Cues**: hold the key on the reader for the whole ceremony; touch when
  the key's LED blinks. Removing the key mid-ceremony must surface a typed
  transport error, not a hang.

### Row H8: NFC via PC/SC — wrong-allowCredential

- **Setup**: as H7, with a non-matching allowList.
- **Expected typed outcome**: `Error::NoCredentials`.
- **Cues**: no touch requested; key may be removed once the error returns.

### Cross-row invariants

- Every row's expected error is one of the ten typed ceremony variants —
  never a string, untyped error, or panic.
- Every touch wait is bounded by the named ceremony deadline; a withheld
  touch produces `Error::Timeout`, distinct from the authenticator-side
  `Error::UserActionTimeout` (0x2F) if the key itself times out first.
- After any row — success or failure — the device must remain usable for a
  subsequent ceremony (async-core cancellation contract).
