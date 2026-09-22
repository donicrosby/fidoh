# spec-review.md — Task 10 cross-check audit

Audit date: 2026-09-22. Scope: all 8 changes under `openspec/changes/`
(async-core, core-model, transport-soft, ceremony, transport-hid,
transport-pcsc, error-diagnostics, testing-strategy) plus `docs/`.
Auditor: automated cross-check agent. Method: read-only audit plus
consistency-only micro-fixes; substantive gaps are recorded as findings,
not silently fixed. Nothing in this audit is committed.

## 1. Validation results

`openspec validate <change> --strict` for every change:

| Change | Result |
|---|---|
| async-core | ✅ valid |
| ceremony | ✅ valid |
| core-model | ✅ valid |
| error-diagnostics | ✅ valid |
| testing-strategy | ✅ valid |
| transport-hid | ✅ valid |
| transport-pcsc | ✅ valid |
| transport-soft | ✅ valid |

8/8 green under `--strict`.

## 2. Requirement → scenario coverage

Every `### Requirement` in every spec has ≥ 1 `#### Scenario`
(verified by splitting each spec on requirement headers and checking
each block for a scenario header):

| Change | Requirements | Scenarios |
|---|---|---|
| async-core | 8 | 18 |
| ceremony | 8 | 15 |
| core-model | 10 | 24 |
| error-diagnostics | 6 | 13 |
| testing-strategy | 6 | 13 |
| transport-hid | 9 | 27 |
| transport-pcsc | 7 | 27 |
| transport-soft | 10 | 22 |
| **Total** | **64** | **159** |

No requirement is missing a scenario. Config rule "every requirement
MUST have at least one scenario" holds everywhere.

## 3. Wait-timeout audit

155 lines of wait/blocking language (wait, block, poll, loop, keepalive,
until, deadline, sleep) across all specs were reviewed. Every blocking
wait names a bound: the caller's ceremony budget (async-core D4 single
budget), the `DEFAULT_WAIT_SLICE` per-wait slice (30 s crate-public
const, caller-overridable), an explicit duration (e.g. 50 ms keepalive
spacing, ≤ 1 s NFC presence-poll slice, deadline + 60 s soft-token hard
cap), or is a deliberately non-waiting path (e.g. CTAPHID_CANCEL with no
expected reply, CTAP2.1 §11.2.9.1.5).

| Wait | Change / location | Bound |
|---|---|---|
| Device connect / all `Device` ops | async-core spec (deadline-driven ops, keepalive progress) | caller deadline; typed `Timeout` on expiry |
| Blocking-pool worker thread exit | async-core spec (drop/abort path) | current `Sleep` slice (`DEFAULT_WAIT_SLICE`) |
| Every internal ceremony wait | async-core spec (Sleep as sole waiting mechanism; single budget) | remaining ceremony budget via `Sleep` factory |
| Keepalive / user-presence wait in ceremony | ceremony spec (§6.2 single-budget keepalive loop) | remaining budget; `Timeout` naming the phase |
| Soft-token UP/UV poke wait | transport-soft spec (UP/UV behavior modes) | caller ceremony deadline only |
| Soft-token delayed response | transport-soft spec (error-injection knob c) | deadline + 60 s hard cap |
| Channel allocation (INIT write/read) | transport-hid spec | remaining budget (design wait table: `DEFAULT_WAIT_SLICE` slices) |
| Command exchange (CBOR write/read) | transport-hid spec | remaining budget |
| Keepalive wait (processing/up-needed) | transport-hid spec | remaining budget; re-sliced at `DEFAULT_WAIT_SLICE` for drop responsiveness |
| Inter-packet reassembly gap | transport-hid spec | remaining budget; `Timeout{reassembly}` then INIT resync |
| Wink request/response | transport-hid spec | remaining budget; `Timeout{wink}` |
| CTAPHID_CANCEL send | transport-hid spec | no wait — spec SHALL NOT expect a reply (§11.2.9.1.5) |
| CTAPHID_LOCK arbitration | transport-hid spec | not used in v1; any lock-related wait bounded by remaining budget |
| GET RESPONSE / 0x9100 NFCCTAP_GETRESPONSE loop | transport-pcsc spec | each iteration bounded; loop under the timeout requirement |
| NFC presence poll | transport-pcsc spec | per-poll slice ≤ 1 s via `Sleep`; bounded by remaining budget |
| WTX extension chain | transport-pcsc spec | never extends deadline; expiry at remaining budget |
| Shared-mode connect retry loop | transport-pcsc spec | remaining budget; blocking pool thread exits within current slice |
| Hardware-test touch waits | testing-strategy spec | caller-supplied ceremony deadline |
| CI matrix waits (M1, M2) | testing-strategy spec | single budget; no wait beyond deadline + 60 s |

**Unbounded waits found: none.** The invariant "every device wait has a
caller-visible timeout" is satisfied across all 8 changes.

## 4. Cross-reference audit

**docs/ linkage.** All 5 docs link to at least one spec or change:
docs/errors.md → ceremony + error-diagnostics specs (and the two
transport docs); docs/testing.md → testing-strategy spec;
docs/transport-hid.md, docs/transport-pcsc.md, docs/transport-soft.md →
their governing specs.

**Cross-change references resolve.** Spot-verified:

- async-core traits (`Transport`, `Device`, `Ceremony`, `Sleep`,
  selection policy `First | Select(fn) | Fail`) are referenced by
  ceremony, transports, and docs with consistent spelling.
- Ceremony error taxonomy: the ten variants (`NoDevice`,
  `AmbiguousDevice`, `UserActionTimeout`, `UserCancelled`,
  `NoCredentials`, `UpRejected`, `CredentialMismatch`, `Timeout`,
  `Transport`, `Ctap`) are spelled identically in ceremony spec/design,
  error-diagnostics spec, and docs/errors.md.
- core-model status codes: every code used in the testing-strategy M3–M13
  matrix (0x2E, 0x22, 0x2F, 0x2D, 0x27, 0x3B, 0x33, 0x34, 0x36, 0x37,
  0x3C) is present in the core-model §8.2 status table, and the
  testing-strategy mappings agree with the ceremony mapping (0x22 →
  `NoCredentials`, 0x3B → `UpRejected`, etc.).
- transport-soft knobs: behavior-mode names (`auto-approve`,
  `always-fail`, `require-explicit-poke`) and knob (a)–(d) semantics are
  consistent between transport-soft spec, testing-strategy matrix, and
  docs/transport-soft.md.
- `DEFAULT_WAIT_SLICE` (30 s, crate-public, caller-overridable):
  consistent across async-core design, transport-hid spec/design,
  error-diagnostics design, docs/transport-hid.md. Note: it is a
  transport-hid crate const (async-core's caller-overridable slice,
  OQ-2); pcsc uses the NFC presence-poll slice (≤ 1 s) instead.
- `FIDOH_HARDWARE_TESTS=1` env gate: consistent between
  testing-strategy design OQ-1 (RESOLVED 2026-09-22) and
  docs/testing.md.
- Test scenario IDs M1–M17 match between testing-strategy spec and
  docs/testing.md (docs cover M1–M3, M13–M17 individually and M3–M13 as
  the status-injection family).
- docs/transport-soft.md marks its Rust snippets "constructed examples —
  API names illustrative", which covers the snake_case knob spellings
  there vs the kebab-case behavioral names in the spec. Not a defect.
- docs/testing.md's internal reference to `docs/transport-soft.md
  §Conformance vectors` resolves (the section exists in
  docs/transport-soft.md).

**Cross-reference fixes made:** none required — no stale or broken
cross-references were found.

### Cosmetic consistency notes (not fixed; informational)

- The CTAPHID keepalive status byte is written `0x3B` in the
  transport-hid spec, docs/transport-hid.md, and the transport-hid
  design constant list (spec §11.2.9.1.7 value), but `0xBB` in
  async-core spec:52 and async-core design:17 (§8.1.5.1-style notation),
  and `0x8B` in transport-soft design open question 2 (§11.3-style
  notation). All three refer to the same CTAPHID keepalive code point;
  the variation tracks different spec-section notations (0x80|CMD
  vs raw CMD vs host-INIT bit). Meaning is unambiguous in context, but
  implementers should note the synonymy — see Finding F-3.
- Keepalive status naming varies across files (`STATUS_UPNEEDED`,
  `UPNEEDED`, `UP_NEEDED`, `up-needed`). All refer to CTAP2.1
  §11.2.9.1.7 status 0x02. `STATUS_UPNEEDED` dominates in the
  transport-hid spec; the others appear in ceremony/soft/testing prose.
  Cosmetic only.

## 5. Dangling open questions

| Change | OQ | Status | Owner |
|---|---|---|---|
| async-core | OQ-1 MSRV pin | RESOLVED 2026-09-22 (Rust 1.75) | — |
| async-core | OQ-2 per-wait slice | RESOLVED 2026-09-22 (`DEFAULT_WAIT_SLICE` 30 s, overridable) | — |
| async-core | OQ-3 `Device::close` best-effort | RESOLVED 2026-09-22 | — |
| ceremony | OQ-1 in-ceremony retry | RESOLVED 2026-09-22 (no retry) | — |
| ceremony | OQ-2 getInfo probe policy | RESOLVED 2026-09-22 (always probe) | — |
| ceremony | OQ-3 CredentialMismatch early check | RESOLVED 2026-09-22 (keep) | — |
| core-model | Q1 preferred-float handling | **open** — not load-bearing for v1 (no in-scope message uses floats) | owner-review |
| core-model | Q2 strict-vs-tolerant decode fallback | **open** — default (typed `NonCanonicalEncoding`) spec'd; conscious decision at implementation | owner-review |
| core-model | Q3 `certifications` value schema | **open** — modeled as opaque map; §7.3 deferred to later change | owner-review |
| error-diagnostics | OQ-1 AmbiguousDevice remediation hint | RESOLVED 2026-09-22 (carries hint) | — |
| error-diagnostics | OQ-2 credential-id truncation length | **open** — presentation detail; "truncated, never full" spec'd | owner-review |
| testing-strategy | OQ-1 hardware-test gate | RESOLVED 2026-09-22 (`FIDOH_HARDWARE_TESTS=1`) | — |
| testing-strategy | OQ-2 fuzz smoke duration | RESOLVED 2026-09-22 (60–120 s) | — |
| testing-strategy | OQ-3 T2 matrix enforcement | RESOLVED 2026-09-22 (M1–M17 names, review-enforced) | — |
| transport-hid | OQ-1 transaction-timeout numeric value | **open** — spec publishes no duration; budget bound already satisfies the invariant | hardware-probe |
| transport-hid | OQ-2 real keepalive cadence | **open** — probe item, non-blocking; no timeout derived from it | hardware-probe |
| transport-hid | OQ-3 hidraw CANCEL write path (SET_REPORT) | **open** — verify on live hardware; v1 treats write failure as swallowable best-effort | hardware-probe |
| transport-hid | OQ-4 report-descriptor parsing vs `fido_id` | **open** — implementation-phase decision (D7 alternative recorded) | owner-review |
| transport-pcsc | OQ-1 NFC touch-and-hold vs re-present | **open** — §5-grounded behavior spec'd; extensions need live probe | hardware-probe |
| transport-pcsc | OQ-2 CTAP1/U2F interop frame | **open** — future CTAP1-interop change; non-blocking for v1 | owner-review |
| transport-pcsc | OQ-3 reader-driver WTX/timing variance | **open** — observable contract spec'd; driver internals need probing | hardware-probe |
| transport-soft | OQ-1 phase letter | RESOLVED 2026-09-22 (Phase B) | — |
| transport-soft | OQ-2 keepalive framing (0x8B vs APDU) | **open** — spec keeps it abstract; answered per-transport by transport-hid/pcsc | owner-review (effectively discharged; close at implementation) |
| transport-soft | OQ-3 snapshot format (JSON vs CBOR) | **open** — version field spec'd; serde format at implementation | owner-review |

Open OQs: 13. Every open OQ has a clear owner (owner-review or
hardware-probe) and none is load-bearing for v1: each records the
spec'd default or interim behavior explicitly.

## 6. Cleanroom audit

- **Forbidden sourcing:** grep across all changes, docs, and README for
  existing-library citations (libfido2, webauthn-rs,
  webauthn-authenticator-rs, fido-hid-rs, solokeys, third-party repos)
  found exactly one mention: error-diagnostics design A1 cites
  "libfido2's `FIDO_ERR_*` integers" in an *alternatives-rejected*
  comparison — a capability-level API-shape reference (explicitly
  allowed, evidence class 4), not a protocol-behavior claim. No source
  code of any existing library is cited anywhere. PASS.
- **Standards citations:** the four protocol-heavy specs carry 66, 43,
  35, and 12 `§` citations respectively (CTAP2.1, ISO 7816-4,
  ISO 14443-4, WebAuthn L2, PC/SC workgroup Part 3). transport-hid
  design states its numeric constants were verified against the spec
  text. docs/transport-pcsc.md's Yubico claims cite the public YubiKey
  Technical Manual (allowed class 2, documents not source). Worked
  examples in docs are labeled constructed-vs-captured per config.
  PASS.
- **Uncited requirement:** transport-soft "Credential store" requirement
  carries no standards citation. It is harness plumbing (test-fixture
  snapshotting), not a protocol claim, so the citation rule does not
  strictly apply — but see Finding F-2.

## 7. Findings requiring owner review

1. **F-1 (severity: low, advisory) — transport-pcsc cites "CTAP2.0 §10.3"
   for the U2F encapsulation frame.** All other citations target CTAP2.1.
   Verify that CTAP2.0 §10.3 (not a CTAP2.1 section) is the intended and
   correct reference for the INS 0x10 + 0x01-prefix encapsulated form,
   and confirm the section number against the published CTAP2.0 text.
   (transport-pcsc design A5 and OQ-2; non-blocking since the feature is
   rejected for v1.)
2. **F-2 (severity: low, advisory) — transport-soft "Credential store"
   requirement has no standards citation.** Defensible as harness
   plumbing (config rule targets protocol claims), but a one-line
   note ("harness-internal; no protocol surface") would make the
   exemption explicit. Left for owner decision rather than edited in.
3. **F-3 (severity: low, cosmetic) — keepalive byte-value notation varies
   (0x3B vs 0xBB vs 0x8B) across changes** (§4 cosmetic notes). No
   contradiction of substance, but a single canonical notation with
   parenthetical synonyms would reduce implementer confusion.
4. **F-4 (severity: none-blocking, confirmation) — 13 open OQs remain,
   all owned and non-load-bearing** (§5). Owner should confirm that
   deferring core-model Q1–Q3, error-diagnostics OQ-2, transport-hid
   OQ-1–4, transport-pcsc OQ-1–3, and transport-soft OQ-2/3 into the
   implementation phase is intended; each already records its interim
   spec'd behavior.

No finding is severity high or medium; none blocks implementation.

## 8. Verdict

**READY-FOR-IMPLEMENTATION.**

All 8 changes validate `--strict`; 64/64 requirements have scenarios
(159 total); zero unbounded waits; all cross-references resolve with
consistent naming; all open questions are owned and non-load-bearing;
cleanroom rules hold with no forbidden sourcing and no ungrounded
protocol claims beyond the advisory findings above. Blockers: none.
The four findings are advisory/cosmetic and can be addressed during or
after implementation begins.
