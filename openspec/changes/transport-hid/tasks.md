# Tasks: transport-hid

Spec/doc-authoring tasks only (Phase C). No implementation tasks —
those arrive in a later change set per config.yaml rules.

- [x] 1. Verify all CTAPHID constants against the FIDO CTAP 2.1 spec text (downloaded from fidoalliance.org) and record the §8.1→§11.2 numbering correction: framing sizes, 7609-byte maximum, INIT BCNT 8/17, capabilities bits, error codes, keepalive statuses, 100 ms keepalive cadence, FIDO usage 0xF1D0/0x01.
- [x] 2. Author `openspec/changes/transport-hid/proposal.md` with Why, What changes, Non-goals, Impact (<500 words).
- [x] 3. Author `openspec/changes/transport-hid/design.md`: Phase C statement, decisions D1–D7 with exact spec-section citations, blocking-wait table (every wait named with its timeout bound), alternatives considered, open questions.
- [x] 4. Author spec requirement "CTAPHID framing over 64-byte HID reports" (init 7-byte header / 57-byte payload, continuation 5-byte header / 59-byte payload, SEQ ascending, 7609-byte ceiling) with scenarios (CTAP2.1 §11.2.4).
- [x] 5. Author spec requirement "Channel allocation via CTAPHID_INIT on the broadcast CID" (0xFFFFFFFF, 8-byte nonce match, response layout, reserved CIDs, capabilities byte) with scenarios (CTAP2.1 §11.2.3, §11.2.9.1.3).
- [x] 6. Author spec requirement "Capability-gated commands" (WINK on 0x01, CBOR on 0x04, NMSG 0x08 recorded) with scenarios (CTAP2.1 §11.2.9.1.3, §11.2.9.2.1).
- [x] 7. Author spec requirement "CTAPHID_CANCEL on caller cancellation" (send 0x11 mid-transaction, no reply expected, KEEPALIVE_CANCEL surfaced as UserCancelled via ceremony) with scenarios (CTAP2.1 §11.2.5.3, §11.2.9.1.5).
- [x] 8. Author spec requirement "CTAPHID_ERROR mapping" (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0B, 0x7F typed; bounded busy-retry) with scenarios (CTAP2.1 §11.2.9.1.6).
- [x] 9. Author spec requirement "CTAPHID_KEEPALIVE surfaced as progress signals with budget-bounded waits" (statuses 0x01/0x02 as progress; every wait bounded by remaining ceremony budget per async-core D4; typed `Timeout` on expiry; unbounded wait = spec violation; `DEFAULT_WAIT_SLICE` re-slicing) with scenarios (CTAP2.1 §11.2.9.1.7).
- [x] 10. Author spec requirement "Message reassembly and packet ordering rules" (SEQ expectation, invalid-SEQ typed abort, foreign-CID ignored, spurious continuation ignored, budget-bounded inter-packet gap) with scenarios (CTAP2.1 §11.2.4, §11.2.5.2–§11.2.5.4).
- [x] 11. Author spec requirement "Channel lock (CTAPHID_LOCK) is not used in v1" with scenarios, and the design.md Alternatives justification (CTAP2.1 §11.2.6).
- [x] 12. Author spec requirement "Linux hidraw enumeration filtered by FIDO usage page and usage" (report_descriptor sysfs attribute, usage page 0xF1D0 / usage 0x01, no VID/PID filter, budget-bounded, per-node failures as diagnostics) with scenarios (CTAP2.1 §11.2.8.2; kernel hidraw doc).
- [x] 13. Author `docs/transport-hid.md`: packet layout diagrams, worked INIT allocation walk-through labeled constructed, keepalive/cancel lifecycle, udev permission recipes (uaccess tag vs group rule), open-failure diagnostics with remediation text, hidraw blocking-I/O note (async-core D3 / fidoh-tokio spawn_blocking).
- [x] 14. Verify every requirement has ≥1 scenario, every scenario involving a wait names its timeout bound, and every protocol claim cites an exact spec section; run `openspec validate transport-hid --strict` until clean.
