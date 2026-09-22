# Design: transport-hid

**Phase: C** (hardware transports — spec/document authoring only, no
code in this change; implementation tasks arrive in a later change set
per config.yaml rules).

## Context

CTAPHID (CTAP2.1 §11.2) is the USB HID framing that carries CTAP2 CBOR
commands. It is a multi-channel, transaction-atomic, keepalive-driven
protocol whose semantics interact directly with the async-core
decisions: D3 (blocking syscalls wrapped by `fidoh-tokio`
`spawn_blocking`), D4 (single ceremony budget, typed `Timeout` naming
the expired phase), and the resolved 30 s tunable `DEFAULT_WAIT_SLICE`
per blocking-read slice. The keepalive loop is the point where the two
meet: the device emits CTAPHID_KEEPALIVE (at least every 100 ms per
§11.2.9.1.7) while the host blocks reading packets, and the host MUST
both surface the up-needed signal to the caller and stay responsive to
caller cancellation. Evidence base for this change: the FIDO CTAP 2.1
specification text (fidoalliance.org, Principal Specification
v2.1 PS-20210615, §11.2), the Linux kernel hidraw documentation
(Documentation/hid/hidraw.rst), and the kernel/sysfs interfaces hidraw
exposes (report_descriptor bin attribute, id/{bustype,vendor,product,
version} attributes — Linux drivers/hid/hid-core.c). Per config.yaml
cleanroom rules, no existing CTAPHID client implementation was
consulted.

**Citation correction (verified against the spec text):** the task
brief cited "CTAP2.1 §8.1" for the USB HID transport. In the published
CTAP 2.1 document, §8 is "Message Encoding" (§8.1 Command Codes) and
the USB HID transport is **§11.2**, with subsections §11.2.1–§11.2.9
(§8.1 numbering belongs to CTAP 2.0). All citations in this change use
the verified CTAP 2.1 §11.2.x numbering.

**Numeric constants verified against the spec text** (not from
memory): max message payload 7609 bytes (§11.2.4: 64 − 7 + 128 ×
(64 − 5)); INIT BCNT 8 request / 17 response; capabilities WINK 0x01,
CBOR 0x04, NMSG 0x08; error codes 0x01 0x02 0x03 0x04 0x05 0x06 0x0A
0x0B 0x7F; keepalive statuses PROCESSING 0x01, UPNEEDED 0x02; keepalive
SHOULD be sent at least every 100 ms; endpoint bInterval 5 ms in the
reference descriptors (§11.2.8.1); FIDO usage page 0xF1D0, CTAPHID
usage 0x01 (§11.2.8.2); LOCK time 0..10 seconds (§11.2.9.2.2).

## Decisions

### D1 — Framing is a strict encode / strict decode pair

Encode: build init + continuation packets exactly per §11.2.4 (CID,
CMD|0x80, BCNT big-endian, SEQ ascending from 0x00, zero padding to 64
bytes). Decode: parse symmetrically; enforce SEQ expectation, BCNT
plausibility (message length against remaining payload), and the
7609-byte ceiling with typed errors. Message length > 7609 fails
before any packet is written (no partial transaction debris).

*Alternative:* tolerate BCNT/payload inconsistencies and truncate.
Rejected — §11.2.9.1.6 defines ERR_INVALID_LEN precisely so malformed
lengths surface; silently truncating invites protocol desync, and the
stack invariant requires typed errors over silent coercion.

### D2 — Channel allocation: INIT with nonce on broadcast CID, once per connection

Per §11.2.9.1.3: INIT on 0xFFFFFFFF with a host-generated 8-byte
nonce; the response's echoed nonce guards against stale/mismatched
responses (two hosts allocating concurrently is the classic case); the
returned channel ID is stored per connection. Channel 0 and
0xFFFFFFFF are reserved (§11.2.3) — receiving either as an allocation
result is a typed error. INIT on an already-allocated CID is used only
as the §11.2.5.3 abort-and-resynchronize escape hatch. INIT hops are
budget-bounded (async-core D4), not fixed-timeout.

*Alternative:* reuse one channel across `connect` calls or skip INIT
when a channel "seems" allocated. Rejected — §11.2.9.1.3 makes INIT
the allocation and resync mechanism; guessing channel state across
processes is exactly what the nonce handshake exists to avoid.

### D3 — Keepalive loop: progress signal out, single budget in, slice per read

This is the load-bearing decision (task brief: "the critical
requirement"):

1. **Surface, never swallow.** Every STATUS_UPNEEDED (0x02) keepalive
   is delivered to the caller as a progress signal (async-core Device
   requirement; ceremony consumes them as progress, not errors).
   STATUS_PROCESSING (0x01) is surfaced with status `processing`.
   A keepalive is not a response (§11.2.9.1.7) and never ends the
   transaction.
2. **Bound every wait.** The keepalive wait is a `Sleep`-driven loop:
   blocking hidraw read (D3 of async-core) sliced at
   `DEFAULT_WAIT_SLICE` (30 s crate-public const, caller-overridable),
   each slice checked against the remaining ceremony budget. There is
   no wait that is not bounded by the caller's budget; the 30 s slice
   bounds drop-detection latency only, never the total wait.
3. **Terminate typed.** Budget exhaustion ends the loop with
   `Error::Timeout` naming the user-presence phase (async-core D4;
   "an unbounded wait is a spec violation" — async-core Sleep
   requirement). The authenticator's own user-action timeout (§5
   Terminology: MUST be at least 10 s, duration authenticator-chosen)
   typically fires first on real hardware and arrives as a CTAP status,
   which ceremony maps distinctly from budget `Timeout`.
4. **Cancel on the way out.** Caller cancellation (drop or explicit)
   while the loop is in flight sends CTAPHID_CANCEL (0x11, BCNT 0) on
   the transaction's channel (§11.2.5.3, §11.2.9.1.5), never waits for
   a reply to the cancel, and lets the pending request terminate with
   CTAP2_ERR_KEEPALIVE_CANCEL (surfaced as `Error::UserCancelled` by
   the ceremony taxonomy). If the budget is already exhausted at
   cancel time, the send is best-effort and its failure is swallowable
   (async-core OQ-3 mandatory-best-effort semantics).

*Alternative:* interpret keepalives inside `fidoh-core` with no
transport-level signal. Rejected — HID is not the only transport with
progress (NFC has its own affordances), and the async-core Device
requirement already fixes the surface: transport-internal handling,
caller-visible progress.

### D4 — Reassembly: strict ordering, ignore foreign traffic, budget-bounded gaps

SEQ expectation per §11.2.4 (0x00 ascending); mismatch → typed
invalid-sequence error (§11.2.9.1.6 ERR_INVALID_SEQ), then INIT-on-
allocated-CID resync (§11.2.5.3). Packets on other CIDs are ignored —
they are other clients' traffic on the shared HID device (§11.2.3) and
a host sees the device's full report stream. Spurious continuation
packets with no message in progress are ignored (§11.2.5.4 device-side
rule adopted host-side for symmetry). The gap between packets of one
message is bounded only by the remaining ceremony budget; §11.2.5.2
defines the transaction timeout concept but fixes no numeric value, so
no number is invented here (OQ-1 below).

### D5 — CTAPHID_LOCK is not used in v1

§11.2.6 makes channel locking optional and explicitly not a concern
for "general CTAP HID applications": the device already enforces
transaction atomicity per channel (§11.2.5.1 — the channel that wins
the first init packet holds the device until the response completes or
the transaction aborts, and other channels get ERR_CHANNEL_BUSY),
which is exactly the serialization fidoh needs for one ceremony at a
time on one channel. Lock adds a stateful exclusive mode with a 10 s
maximum hold (§11.2.9.2.2) that v1's single-ceremony-per-channel model
never requires. Consequently ERR_LOCK_REQUIRED (0x0A) is modeled but
unexpected; it surfaces typed, no retry.

*Alternatives:*
- *Lock around every transaction.* Rejected — redundant with §11.2.5.1
  device-side atomicity; adds lock maintenance (10 s refresh loop) as
  a failure mode with no v1 benefit.
- *Lock to protect multi-channel future use.* Rejected for v1 —
  speculative; the spec allows adding it later without wire
  incompatibility since it is an optional command.

### D6 — Wink is capability-gated and best-effort by nature

CTAPHID_WINK (0x08) is sent only when the INIT capabilities byte has
CAPABILITY_WINK (0x01) set (§11.2.9.1.3 table); otherwise a typed
unsupported-operation error returns before any device write. Wink
completion is bounded by the remaining ceremony budget like every hop.
CBOR support (CAPABILITY_CBOR 0x04) is checked before issuing
CTAPHID_CBOR; a device without it cannot serve CTAP2 and errors typed
at connect time. NMSG (0x08) is recorded as metadata only — it
describes absence of CTAPHID_MSG, which v1 never uses.

### D7 — Linux enumeration: hidraw + report-descriptor usage match, no VID/PID filter

Enumerate hidraw nodes (kernel hidraw doc: udev creates `/dev/hidraw*`
nodes; applications should use libudev or equivalent sysfs walking to
locate them), read each device's `report_descriptor` sysfs attribute
(bin attribute the kernel exposes for HID devices), and match the
FIDO usage page 0xF1D0 / usage 0x01 per §11.2.8.2. No VID/PID list —
§11.2.8.2 conditions candidacy on the usage pair alone, and a static
VID/PID filter would exclude vendors it predates. A failed descriptor
read on one node is recorded as a diagnostic and skips that node;
per the ceremony change, one device's discovery failure never aborts
discovery. Enumeration is bounded by the remaining ceremony budget
(async-core D4).

*Alternative:* parse the kernel's `fido_id` uevent
(`ID_SECURITY_TOKEN`) set by systemd's shipped udev rules instead of
parsing descriptors ourselves. Deferred — relying on systemd's rules
couples the crate to a specific udev configuration that may be absent
(minimal containers); a small usage-page parser over the report
descriptor is self-contained and spec-derived. Revisit if descriptor
parsing proves error-prone on real hardware (open question OQ-4).

## Blocking waits and timeout bounds

Config rule: "Every blocking wait named in design must name its
timeout bound." All bounds are the remaining ceremony budget (async-core
D4); the slice column bounds only drop-cancellation latency.

| # | Blocking wait | Bound | Slice | Expiry behavior |
|---|---|---|---|---|
| 1 | Channel allocation: INIT write + response read | remaining budget | `DEFAULT_WAIT_SLICE` (30 s default) | `Timeout{channel-allocation}` |
| 2 | Command exchange: CTAPHID_CBOR write + response read | remaining budget | `DEFAULT_WAIT_SLICE` | `Timeout{command}` |
| 3 | Keepalive wait (processing / up-needed) | remaining budget | `DEFAULT_WAIT_SLICE` | `Timeout{user-presence}` (or `{processing}`) |
| 4 | Inter-packet gap during reassembly | remaining budget | `DEFAULT_WAIT_SLICE` | `Timeout{reassembly}` then INIT resync |
| 5 | Busy-retry (ERR_CHANNEL_BUSY) delay + re-issue | remaining budget | retry delay `Sleep`-driven, short | `Timeout{busy-retry}` |
| 6 | Wink request/response | remaining budget | `DEFAULT_WAIT_SLICE` | `Timeout{wink}` |
| 7 | CTAPHID_CANCEL send | none new — best-effort within already-remaining budget; skipped if budget exhausted | n/a (single write) | error swallowed (async-core OQ-3) |
| 8 | Enumerate (sysfs scan + descriptor reads) | remaining budget | n/a (non-blocking file reads) | `Timeout{enumeration}` |

No wait in this design uses `std::thread::sleep` or an unbounded
blocking read without a deadline-driven abort path (async-core D4).

## Alternatives considered

- **A1 — Use CTAPHID_LOCK for transaction exclusivity (D5).** Rejected:
  §11.2.5.1 device-side atomicity + channel arbitration already give
  one-transaction-at-a-time semantics; lock adds a 10 s-refresh
  stateful mode v1 never needs. Spec'd as "SHALL NOT send" so the
  implementation cannot drift into using it.
- **A2 — Per-hop fixed timeouts (e.g. 150 ms INIT, 5 s response).**
  Rejected (async-core A2 applies): §11.2.5.2 fixes no numbers, and
  human-paced hops (user presence) cannot share a table with
  machine-speed hops without spurious failures. Single budget, phases
  named in `Timeout`.
- **A3 — Interpret keepalives as transport-internal only.** Rejected —
  the task brief and async-core both require up-needed to surface as a
  caller-visible progress signal; hiding it would also break the
  ceremony change's keepalive-progress requirement and CI knob (b).
- **A4 — Async-io readiness-based hidraw I/O.** Rejected for v1 by
  async-core D3 (uniform blocking-first policy; PC/SC has no fd
  readiness API anyway). This change inherits that verdict; hidraw
  `read()` blocks by default (kernel hidraw doc) and the slice +
  `spawn_blocking` model bounds it.
- **A5 — Rely on systemd udev `ID_SECURITY_TOKEN` tagging for device
  discovery (D7).** Deferred: self-contained report-descriptor parsing
  is spec-grounded and works without systemd; revisit after live
  hardware probes.

## Open questions

- **OQ-1 — Numeric transaction-timeout value (§11.2.5.2).** The spec
  defines the concept ("A transaction has to be completed within a
  specified period of time") but publishes no duration. Our reassembly
  gap and transaction waits are therefore bounded solely by the
  ceremony budget; we do not invent a device-side number. If live
  probes (allowed evidence class 3) show devices releasing channels on
  their own schedule, record the observed bound as a documented
  default here. *Status: open; not load-bearing — the budget bound
  already satisfies the timeout invariant.*
- **OQ-2 — Real keepalive cadence.** §11.2.9.1.7 says keepalives
  SHOULD arrive at least every 100 ms; nothing constrains a device
  that sends them less often. The wait loop does not depend on
  keepalive arrival (each read slice stands alone), so no timeout is
  derived from the 100 ms figure; it is recorded only as expected
  device behavior. *Status: open as a probe item, non-blocking.*
- **OQ-3 — hidraw write path for CTAPHID_CANCEL during an IN-flight
  transaction.** The kernel hidraw doc documents `write()` as
  delivering via the INTERRUPT OUT endpoint or a control
  (SET_REPORT) transfer when no OUT endpoint exists. Whether every
  FIDO device accepts OUT reports via SET_REPORT while a transaction
  is pending is device-behavior territory not fixed by the CTAP spec.
  v1: send CANCEL the same way as any packet and treat write failure
  as the swallowable best-effort case (async-core OQ-3). *Status:
  open; verify on live hardware.*
- **OQ-4 — Report-descriptor usage extraction vs. `fido_id`.** See
  D7 alternative: implement the minimal usage-page/usage parser now,
  consider consuming systemd's tagging later. *Status: open,
  implementation-phase decision.*
