# Design: transport-pcsc

**Phase: C** (transports; spec-authoring only — no code in this
change, implementation tasks arrive in a later change set per
config.yaml rules). Depends on Phase-A contracts (async-core D3/D4,
core-model §8.2 table) and the Phase-B ceremony spec (discovery D2,
probe D3, taxonomy D7).

## Context

CTAP2.1 §11.3 defines a single ISO 7816 APDU binding for "ISO7816,
ISO14443 and Near Field Communication": the same SELECT AID
(§11.3.3), the same CTAP command frame (§11.3.5.1: CLA 0x80, INS
0x10, P1 0x00, P2 0x00), the same response shape (§11.3.5.2: CTAP
status byte || data with SW 9000), and the same fragmentation rules
(§11.3.6). A USB CCID reader presents the key as a standard ISO 7816
card to the PC/SC resource manager; an NFC reader presents the same
APDU surface over T=CL (ISO 14443-4 block protocol, which the
reader/driver layer terminates). fidoh sees `SCardTransmit` in both
cases. That is the technical core of the unification decision below;
the stack invariants (single budget D4, blocking-syscall policy D3,
typed errors) then shape everything else.

Grounding note: the brief's section numbers ("§11.2.1 applet
selection, §11.2.2 command APDU") were verified against the CTAP2.1
Proposed Standard text and corrected — applet selection is §11.3.3
(AID = rid 0xA000000647 + pix 0x2F0001), command framing is §11.3.5,
NFCCTAP_MSG/GETRESPONSE are §11.3.7.1/2.

## Decisions

### D1: One unified APDU transport, not separate CCID and NFC change-sets

**Decision: `fidoh-transport-pcsc` is ONE capability with ONE APDU
engine covering FIDO-over-CCID and NFC.**

Rationale:
- CTAP2.1 §11.3 defines the protocol once for both media; the
  standard has no CCID-specific or NFC-specific CTAP framing. A split
  would duplicate SELECT, framing, chaining, and status-word logic in
  two specs that must be kept identical by discipline.
- At the fidoh level the difference between the interfaces is
  bounded and enumerable: NFC adds field-presence handling, T=CL
  block-layer behavior (WTX, §11.3.7.2 9100 status updates), and the
  §5 tap-presence semantics. All of these are named NFC behaviors
  layered UNDER the same APDU operations, not a second engine.
- config.yaml already scopes "PC/SC in both flavors sharing one APDU
  layer" — the change-set structure follows the spec surface.
- Operationally one crate/feature (`pcsc`) keeps the dependency story
  simple (async-core crate graph: `fidoh-transport-pcsc` depends only
  on `fidoh-core`).

The Yubico fw-5.8 CCID support note (developer docs: CTAP 2.x carried
as ISO 7816 APDUs over the USB CCID interface through the OS smart
card stack; URL cited in docs/transport-pcsc.md) confirms the CCID
side rides the identical PC/SC path — no vendor-specific framing is
spec'd.

### D2: Reader enumeration + shared-mode connect (NFC AND CCID), exclusive as opt-in

Enumeration is `SCardListReaders` (PC/SC Core Specification Part 3);
card-present detection uses the reader state
(`SCARD_STATE_PRESENT`, `SCARD_STATE_MUTE` excluded) at connect time.
Connect sharing:

- **NFC → SHARED (spec-mandated).** Contactless readers are
  effectively single-field resources; an exclusive hold would lock
  every other host/process out of the reader for a whole
  touch-waiting ceremony, for zero benefit (the field gives us
  exclusivity against other PCDs anyway — ISO 14443 is a
  point-to-point field).
- **CCID/USB → SHARED by default (decision + justification).** A
  YubiKey is a composite device exposing several applets (FIDO, PIV,
  OATH, OpenPGP) through the same PC/SC reader abstraction; other
  PC/SC clients legitimately talk to other applets concurrently.
  Exclusive mode would block them for the ceremony's duration —
  potentially minutes if a touch is pending. The PC/SC resource
  manager already serializes transactions per reader (Part 3:
  SCardBeginTransaction/SCardTransmit are atomic per connection), so
  fidoh gains nothing from exclusivity that it does not already get.
  FIDO-over-CCID sessions are short APDU request/response pairs with
  the long waits happening inside ONE getAssertion exchange; if a
  concurrent client steals a transaction in between, the typed
  `reset`/`sharing` errors surface and the caller re-runs — honest
  failure beats silent lockout.
- **Exclusive stays available** as an explicit caller opt-in for
  environments that need it (e.g. benchmarking, hostile-concurrency
  tests). The transport never escalates shared→exclusive on its own;
  a sharing violation triggers a bounded retry, then a typed error.

Card-present detection is connect-time and exchange-time: a card that
vanishes mid-operation maps to the typed `removed` cause (error
table), never to a silent retry loop.

### D3: Applet selection semantics and enumerate-and-skip

SELECT uses the CTAP2.1 §11.3.3 AID `A0000006472F0001` (rid
`0xA000000647`, pix `0x2F0001` — byte-verified against the spec
text). Response handling is deliberately asymmetric:

- `9000` → candidate. The version string (`U2F_V2` when both CTAP1
  and CTAP2 are implemented, per §11.3.3) does NOT decide CTAP2
  capability; §11.3.3 itself says CTAP2-aware clients then issue
  authenticatorGetInfo. ceremony D3 already makes getInfo mandatory
  per ceremony, so capability gating rides that probe — the transport
  does not need its own CTAP2-detection round trip.
- `6A82` (file not found, ISO 7816-4; the applet is absent on this
  interface) → **typed skip**: a per-device negative result that
  discovery records and continues past. This is the task's
  "enumerate-and-skip" policy and it directly implements ceremony's
  collect-never-short-circuit rule (D2): one reader lacking the FIDO
  applet (a PIV-only card, a transit card, a YubiKey whose FIDO
  applet is disabled) must not fail discovery or mask candidates on
  other readers/transport.
- `6985` (conditions of use not satisfied) and `6283` (selected file
  invalidated — applet present but unusable this power cycle) →
  typed skips with qualifiers, same skip path.
- Everything else → typed `Transport` errors with the raw SW attached
  (error table); the transport refuses to guess semantics that
  ISO 7816-4 leaves open.

Why skip-on-SELECT-failure over probe-everything: ceremony D3 already
rejected auto-probing every candidate during discovery (its A4 —
device traffic multiplication); SELECT is the minimum traffic needed
to classify a reader at all (§11.3.3: "A client SHALL send a Select
to the authenticator before any other command"), so classify-then-skip
is the cheapest spec-clean policy.

### D4: Command framing and response assembly

Transmit path (per §11.3.5.1, §11.3.6, §11.3.7.1):

- CLA 0x80, INS 0x10 (NFCCTAP_MSG), P1 0x00 | 0x80-bit set (client
  supports NFCCTAP_GETRESPONSE — §11.3.7.1 makes status updates legal
  only when the client declares this), P2 0x00, Lc, CTAP command byte
  || canonical CBOR (core-model), Le.
- Extended-length encoding preferred when command data > 255 bytes or
  a large response is expected (§11.3.5: authenticators MUST support
  short AND extended length); short-form chaining (CLA 0x90 per
  §11.3.6) is the fallback, not the default, because chaining
  multiplies round trips and each extra APDU is another timeout
  surface.

Receive path (per §11.3.5.2, §11.3.7.2, ISO 7816-4):

- SW 9000 → data = CTAP status byte || response CBOR; status byte
  mapping is core-model's (§8.2), never re-interpreted here.
- SW 9100 (status update) → immediate NFCCTAP_GETRESPONSE (INS 0x11,
  P1=P2=0x00, §11.3.7.2), loop while 9100 recurs — this is the NFC
  analogue of HID keepalives and the seam where transport-soft's
  abstract keepalive knob materializes on this transport
  (transport-soft design OQ-2 deferred per-transport framing here).
- SW 61xx → GET RESPONSE (INS 0xC0) hops until complete (ISO 7816-4);
  SW 6Cxx → single retry with the corrected Le.
- Everything else → the error table.

### D5: NFC field, WTX, and presence semantics

- **Field loss = terminal typed error.** A ceremony cannot continue
  across a lost field; `Transport(removed)` is returned within one
  presence-poll slice (≤ 1 s, per async-core's resolved blocking
  policy) of the removal. No reconnect-and-continue inside a
  ceremony: the §5 presence model (below) makes a resumed session a
  NEW presence event, so silent continuation would fabricate presence
  evidence.
- **WTX (ISO 14443-4 §7.3): progress, never deadline extension.** The
  reader answers S(WTX) with S(WTX) (temporary FWT = FWT × WTXM, ≤
  FWT_MAX); the transport treats this as "the card is slow," keeps
  waiting, and the wait still expires at the remaining ceremony
  budget. An unbounded WTX chain therefore ends as typed `Timeout`,
  which keeps the stack invariant intact despite a protocol layer
  fidoh does not itself drive.
- **Presence per CTAP2.1 §5.** NFC presence is the tap: field entry
  powers the key, sets the NFC userPresent flag, and starts a 120 s
  maximum window (§5, Terminology "user gesture"). Consequently this
  transport has NO indefinite touch wait: the wait is bounded by the
  remaining budget, and the authenticator's own §5 window produces
  the typed 0x2F path (core-model mapping) when it expires. This is
  the concrete NFC answer to transport-soft design OQ-2's "NFC APDU
  time extension" alternative.

### D6: Timeout architecture (async-core D4 applied)

One budget, remainder handed hop to hop: enumerate → connect (incl.
bounded sharing retries) → SELECT → getInfo probe (ceremony D3) →
getAssertion (+ chaining/GETRESPONSE hops). Each hop's deadline is
the budget's remainder; expiry anywhere is `Timeout` naming that
phase. Blocking PC/SC calls run via `fidoh-tokio`'s spawn_blocking
wrapper (async-core D3 — PC/SC has no fd-readiness API, so the
wrapping decision is reused verbatim); each blocking wait carries a
deadline-driven abort path so a dropped future's thread exits within
its slice. Internal slices: NFC presence polls ≤ 1 s
(async-core resolved decision); APDU waits ≤ remaining budget; no
other fixed timeouts exist in the transport. `SCARD_E_TIMEOUT` from
the resource manager maps to `Timeout` naming the phase in flight —
it never spawns an internal retry loop, because retries interact with
the budget (ceremony OQ-1 resolved: no implicit retries).

## Blocking waits and their timeout bounds

| Wait | Bound | Notes |
|---|---|---|
| `SCardListReaders` enumeration | remaining ceremony budget | resource-manager call on the blocking pool |
| `SCardConnect` incl. shared-mode retry | remaining ceremony budget | retry loop has no private backoff timer |
| SELECT applet (§11.3.3) | remaining ceremony budget | first APDU; skip decisions are immediate on its SW |
| CTAP command exchange (getInfo, getAssertion) | remaining ceremony budget | incl. extended-length or chained request |
| Response chaining: 61xx GET RESPONSE hops | remaining ceremony budget (each hop) | ISO 7816-4 §61xx procedure |
| 9100 → NFCCTAP_GETRESPONSE loop | remaining ceremony budget (each iteration) | CTAP2.1 §11.3.5.2/§11.3.7.2 |
| NFC presence polling between exchanges | per-slice ≤ 1 s, loop ≤ remaining budget | async-core resolved slice; removal surfaces ≤ 1 slice |
| ISO 14443-4 WTX chain (reader-driven) | transport wait still ≤ remaining budget | S(WTX) handshake is below fidoh; never extends the deadline |

No wait is unbounded. An unbounded wait is a spec violation (stack
invariant).

## Alternatives Considered

### A1: Separate `transport-nfc` change-set alongside a CCID-only `transport-pcsc` — rejected

Splitting by medium would fork the §11.3 protocol implementation into
two specs and two crates with identical SELECT/framing/chaining text,
guaranteeing drift (the openspec skill's delegation rule: siblings
should cite, not duplicate). The genuinely NFC-only behaviors are
small, enumerable, and spec'd as named NFC requirements inside the
one capability. Revisit only if a future NFC-only stack (e.g. Android
HCE-style, non-PC/SC) forces a different OS boundary — then the
shared engine should become a core-owned APDU codec, still one
protocol.

### A2: Exclusive SCardConnect everywhere (or everywhere-except-NFC) — rejected for CCID

Exclusive mode on a composite-protocol key freezes PIV/OATH/OpenPGP
clients for the ceremony's whole duration (a touch wait can be tens of
seconds) and buys nothing: the resource manager already serializes
transactions per connection (PC/SC Part 3), and FIDO exchanges are
short. NFC must be shared regardless (field readers are shared
infrastructure). Exclusive remains an explicit opt-in for callers who
want hard exclusion. See D2 for the CCID justification.

### A3: Probe getInfo on every reader during discovery to decide CTAP2 capability — rejected

Ceremony A4 already rejected candidate-probing (traffic
multiplication, authenticator-side side effects). The §11.3.3 SELECT
version string is insufficient anyway (`U2F_V2` is mandated when both
protocols exist), so the probe would be per-reader getInfo — exactly
the pattern ceremony D3 confines to post-selection. The transport
classifies with SELECT only; getInfo (capability truth) runs once,
post-selection, per ceremony D3.

### A4: Treat 6A82 on SELECT as a transport error — rejected

It would abort or pollute discovery for a perfectly healthy
non-FIDO reader, breaking ceremony D2's collect-never-short-circuit
rule. A typed skip preserves the distinction "this device answered,
it just is not FIDO on this interface" from "the transport could not
even talk to the reader."

### A5: Follow CTAP2.0 §8.2.6.1's encapsulated NFC CTAP2 form (NFCCTAP_MSG, INS 0x10) on CCID — rejected for v1

That path (CTAP2.0 §8.2.6.1 NFCCTAP_MSG, INS 0x10) exists for CTAP2
signaling on NFC interfaces where the FIDO applet is reached behind
U2F visibility; it is specified for NFC, not CCID. v1 requires CTAP2
capability and gates on the §6.4 probe (ceremony), and the plain
§11.3.5 frame is the spec'd form for CTAP2-over-APDU. Adding the encapsulated form would
double the framing surface for a fallback fidoh does not do. Open
question OQ-2 records it for a future CTAP1-interop change.

## Open Questions

- **OQ-1 — touch-and-hold vs re-present on NFC.** CTAP2.1 §5 defines
  tap-establishes-presence with a 120 s maximum window and
  re-insertion after expiry; §11 defines no mechanism by which the
  platform requests or observes a touch-and-hold (no keepalive
  channel exists on T=CL — the 9100 status-update loop signals
  processing, not UP). The spec therefore models the §5 window
  behavior only. If live hardware shows vendors extending presence
  while the card stays in field (device-specific), that is a live
  probe (cleanroom evidence class 3), not spec text. *Status: open;
  §5-grounded behavior is spec'd in the meantime.*
- **OQ-2 — CTAP1/U2F interop frame (CTAP2.0 §8.2.6.1 NFCCTAP_MSG).**
  Whether a later change adds the INS 0x10 encapsulated NFC form
  to talk to devices whose FIDO applet answers
  U2F-only APDUs on some interfaces. v1 gates on the §6.4 probe and
  does not implement CTAP1 fallback (ceremony non-goal); the
  encapsulated frame would be the natural extension point. *Status:
  open; non-blocking for v1.*
- **OQ-3 — reader-driver variance in WTX and timing behavior.**
  ISO 14443-4 §7.3 WTX handling sits in the reader/CCID driver layer
  below PC/SC; some drivers may surface slow cards as long APDU waits
  without WTX visibility. The spec pins only the observable contract
  (progress, never deadline extension). If implementation probing
  finds drivers that exceed the budget without surfacing cancellable
  states, the D6 abort path may need a driver-level note. *Status:
  open; observable contract is spec'd, driver internals are not.*

## Implementation crystallization (2026-09-23, from the first implementation)

Decisions made design-silently while implementing against this spec,
now binding for v1:

1. **Zero-runtime-deps resolution**: exactly one external binding —
   `pcsc 2.9` — behind the `Library` trait (Send+Sync) and a feature
   gate; the pure APDU/framing layer never touches it. MSRV 1.75 held
   (`split_last_chunk` is 1.77; used `split_at`).
2. **Typed skips** ride `Error::Transport` with a stable detail marker
   (`skip <reader>: not-fido …`); `Transport::enumerate` gains no skip
   channel in v1. Revisit the trait signature in the
   error-diagnostics change, which owns diagnostic surfacing.
3. **Sharing-retry detection** is via a typed detail marker after
   `PcscError → Error` conversion; sharing retry never escalates.
4. **SELECT at connect** (§11.3.3, the channel-open hop);
   `open_channel` re-asserts the logical channel without re-SELECT
   (traffic discipline per A3).
5. **Runaway guard**: 61xx GET RESPONSE chains and 9100 poll loops
   cap at 64 hops, belt-and-braces with the caller budget.
6. **NFC reader identification is caller-declared metadata**
   (`with_nfc_readers`) — PC/SC exposes no standard contactless
   attribute; the APDU layer never branches on it.

Ambiguities met in the spec text, resolved as follows (patch-back to
spec wording next revision pass):

a. pcsclite returns Ok(empty) — not SCARD_E_NO_READERS_AVAILABLE —
   when pcscd runs with zero readers; the `no-readers` skip fires only
   on stacks that surface the code. Harmless divergence, documented.
b. §11.3.3 `9000` with no version data (non-conformant) is tolerated
   as `Selected { version: None }`; capability settles at getInfo.
c. Concurrent `connect`s to one reader are permitted (independent
   connections); the spec neither rules them in nor out.
d. `9100` on the initial command vs inside the status-update loop is
   treated uniformly — one loop.

Live-hardware re-verification queue (OQ-1/OQ-3 evidence class 3):
fw≥5.8 YubiKey over CCID (SELECT/getInfo), same over NFC T=CL, live
9100 loop (slow getAssertion), WTX under a real contactless driver,
sharing-violation retry timing against a concurrent PIV/OATH client.
