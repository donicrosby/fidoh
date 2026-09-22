# Proposal: transport-hid — CTAPHID USB HID transport

## Why

fidoh's v1 scope includes USB HID via CTAPHID (config.yaml, "Transports
in scope"). The async-core change defines the `Transport`/`Device`
traits and the single-budget timeout model every transport must
implement; the ceremony change drives getInfo + getAssertion over them.
This change specifies the CTAPHID wire and channel behavior
(CTAP2.1 §11.2) so `fidoh-transport-hid` can be implemented from the
spec alone, and so the soft token can emulate the same observable
behavior in CI.

## What changes

- New spec capability `transport-hid` covering:
  - CTAPHID framing: 64-byte init packets (4-byte CID, CMD with bit 7
    set, 2-byte BCNT, 57-byte payload) and continuation packets
    (4-byte CID, SEQ 0x00..0x7F, 59-byte payload); 7609-byte maximum
    message payload (CTAP2.1 §11.2.4).
  - Channel management: broadcast CID 0xFFFFFFFF, CTAPHID_INIT (0x06)
    with 8-byte nonce, INIT response layout (nonce, channel ID,
    protocol version 2, device version, capabilities byte: WINK 0x01,
    CBOR 0x04, NMSG 0x08) (CTAP2.1 §11.2.3, §11.2.9.1.3).
  - Keepalive semantics: CTAPHID_KEEPALIVE (0x3B) statuses PROCESSING
    0x01 / UPNEEDED 0x02 surfaced to the caller as progress signals;
    every keepalive wait bounded by the remaining ceremony budget with
    typed `Timeout` on expiry (async-core D4); CTAPHID_CANCEL (0x11)
    sent when the caller cancels mid-transaction (CTAP2.1 §11.2.5.3,
    §11.2.9.1.5).
  - Error handling: CTAPHID_ERROR (0x3F) codes 0x01–0x06, 0x0A, 0x0B,
    0x7F mapped to typed errors; bounded busy-retry (CTAP2.1
    §11.2.9.1.6).
  - Reassembly rules: SEQ ordering, invalid-SEQ abort, foreign-CID
    packets ignored, spurious continuation ignored, budget-bounded
    inter-packet wait (CTAP2.1 §11.2.4, §11.2.5.4, §11.2.5.2).
  - v1 decision: CTAPHID_LOCK (0x04) is not used (CTAP2.1 §11.2.6
    optional; channel allocation suffices).
  - Wink (CTAPHID_WINK 0x08) gated on the CAPABILITY_WINK bit
    (CTAP2.1 §11.2.9.1.3, §11.2.9.2.1).
  - Linux enumeration: hidraw devices filtered by FIDO usage page
    0xF1D0 / usage 0x01 from the report descriptor; no VID/PID filter
    (CTAP2.1 §11.2.8.2).
- `docs/transport-hid.md`: packet layout diagrams, a worked INIT
  channel-allocation example (labeled constructed), udev permission
  recipes (uaccess tag, group rule), and open-failure diagnostics.

## Non-goals

- CTAPHID_MSG / CTAP1 ("U2F") message exchange (v1 is CTAP2 CBOR only;
  NMSG-capable devices remain usable).
- CTAPHID_PING (debug helper), vendor-specific commands 0x40–0x7F.
- CTAPHID_LOCK usage (v1 decision: not sent).
- Non-Linux platforms (macOS/Windows IO backends are later work).
- PC/SC and NFC transports (separate change, CTAP2.1 §11.3).

## Impact

- New spec: `openspec/changes/transport-hid/specs/transport-hid/`
  (delta; folds into `openspec/specs/transport-hid/` on archive).
- New doc: `docs/transport-hid.md`.
- Depends on: async-core (traits, D3 blocking policy, D4 single
  budget, `DEFAULT_WAIT_SLICE`), core-model (status-code space),
  ceremony (progress-signal consumption, typed taxonomy),
  transport-soft (CI parity knob for keepalive sequences).
- Enables: Phase D implementation of `fidoh-transport-hid` (crate
  per async-core D2 crate graph).
