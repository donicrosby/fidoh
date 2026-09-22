# transport-pcsc — PC/SC APDU transport (FIDO over CCID + NFC)

## Why

async-core names `fidoh-transport-pcsc` (FIDO-over-CCID and NFC per
CTAP2.1 §11) and config.yaml scopes "PC/SC in both flavors sharing
one APDU layer" — but nothing specifies that layer: reader sharing,
FIDO applet selection (CTAP2.1 §11.3.3), command framing (§11.3.5),
NFC field/WTX handling (ISO 14443-4), and mapping PC/SC codes and
ISO 7816 status words onto the typed error taxonomy. Without this
spec the PC/SC crate would invent all of it, violating the stack
invariants (bounded waits, typed errors, collect-never-short-circuit
discovery).

## What Changes

- New spec capability `transport-pcsc`: ONE ISO 7816-4 APDU engine
  serving BOTH USB CCID (CTAP 2.x over ISO 7816 APDUs via the PC/SC
  stack; Yubico documents this for YubiKey fw ≥ 5.8 — citation in
  docs/transport-pcsc.md) and NFC (ISO 14443 T=CL; CTAP2.1 §11.3
  SELECT AID + CTAP APDUs).
- Readers enumerated via the PC/SC resource manager
  (`SCardListReaders`, PC/SC Part 3) with card-present detection;
  SHARED `SCardConnect` default on both NFC and CCID/USB; exclusive
  is explicit caller opt-in only.
- Applet selection with AID `A0000006472F0001` (verified against
  CTAP2.1 §11.3.3); `6A82` / `6985` / `6283` → TYPED
  enumerate-and-skip (per-device negative result, NOT a discovery
  failure — ceremony's collect-never-short-circuit rule); `9000` →
  candidate, CTAP2 capability settled by the mandatory getInfo probe
  (ceremony D3).
- Framing per CTAP2.1 §11.3.5: CLA 0x80, INS 0x10, P1 0x00, P2 0x00,
  CTAP command byte || CBOR, Le; extended length preferred, short-APDU
  chaining (§11.3.6) fallback; `61xx` → GET RESPONSE (INS 0xC0),
  `6Cxx` → Le retry, `9100` → NFCCTAP_GETRESPONSE loop (§11.3.7.2).
- NFC: field loss = typed terminal `Transport(removed)`; presence
  polls sliced ≤ 1 s via `Sleep` (async-core); ISO 14443-4 §7.3 WTX
  is progress, never a deadline extension; NFC presence per CTAP2.1
  §5 (tap establishes presence, 120 s window) — no HID-style
  indefinite touch wait.
- Timeouts (async-core D4): every exchange, connect retry, chaining
  hop, GETRESPONSE iteration, and poll slice consumes the remaining
  budget; exhaustion is typed `Timeout` naming the phase; unbounded
  waits are spec violations.
- Error mapping: PC/SC codes (no readers, no card, removed, sharing
  violation, protocol mismatch, reset, timeout, reader failures) and
  ISO 7816 SW (6A82, 6985, 6283, 61xx, 6Cxx, 6986/6D00, remaining
  6xxx) onto the typed async-core/ceremony taxonomy; CTAP status
  bytes stay with core-model's §8.2 table.
- `docs/transport-pcsc.md`: pcscd/CCID requirements, shared-vs-
  exclusive rationale, fw-5.8+ FIDO-over-CCID note with Yubico doc
  URL, constructed SELECT + getInfo APDU trace.

## Impact

- Affected specs: `transport-pcsc` (new capability).
- Affected code: none — documents only (Phase C, spec-authoring).
- Depends on: `async-core` (traits, D3 spawn_blocking policy, D4
  single budget, 1 s NFC poll slice), `core-model` (§8.2 status
  space), `ceremony` (D2 discovery, D3 probe, D7 taxonomy),
  `transport-soft` (trait parity). Parallel `transport-hid` shares
  only the async-core traits.
- Downstream: the implementation change-set for
  `fidoh-transport-pcsc` consumes this spec.

## Non-goals

- CTAP1/U2F fallback signaling and the §10 encapsulated CTAP2-in-U2F
  APDU form (project non-goal; design OQ-2).
- Secure channel protocols (SCP11b — Yubico-documented NFC-only).
- NFC reader/PCD emulation, peer-to-peer, ISO 14443-3 antenna-level
  handling: fidoh sits on the PC/SC resource manager, never on raw
  NFC hardware.
- Vendor-specific behaviors beyond CTAP2.1 §11 and ISO
  7816-4/14443-4 (cleanroom: live probes or open questions only).
- Bluetooth/BLE transport (separate capability).
