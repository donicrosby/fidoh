# ceremony — Design

## Phase

Phase B (specification / spec-authoring, building on Phase-A contracts).
This change produces documents only; implementation tasks arrive in
later change-sets per the repo's tasks rules. It depends on Phase-A
specs: async-core (traits, D4 single-budget timeout model, resolved
decisions), core-model (wire structures and the CTAP2.1 §8.2 status
table), and transport-soft (CI harness knobs).

## Context

The library is RP-agnostic: it takes a caller-supplied `clientDataHash`
and returns a raw assertion (project rule; WebAuthn L2 §6.5 is the RP's
responsibility). CTAP2.1 §6.2 defines authenticatorGetAssertion as a
single command/response exchange, but the observable ceremony is wider:
the platform must find an authenticator, pick exactly one, optionally
probe capabilities with authenticatorGetInfo (CTAP2.1 §6.4), survive the
user-presence wait (keepalive signaling per CTAP2.1 §11.2.9.1.7 for HID;
the §6.2 exchange itself is transport-neutral), interpret status codes
per the CTAP2.1 §8.2 table, and — when the authenticator found several
matching credentials — drain the remaining assertions via
authenticatorGetNextAssertion (CTAP2.1 §6.3).

All of this must respect the stack invariants: every wait bounded by a
caller-visible deadline; explicit, deterministic device selection;
typed errors everywhere; and the async-core D4 rule of ONE ceremony
budget whose remainder is handed hop to hop.

## Decisions

### D1: Two-stage entry — discover, then run

The ceremony entry point decomposes into two stages:

1. **Discovery + selection** over all registered transports, producing
   exactly one connected `Device` (or a typed error).
2. **Exchange** per CTAP2.1 §6.2 (with optional §6.4 probe and §6.3
   multi-assertion drain) on that device.

The two stages share ONE caller-supplied deadline budget (async-core
D4). The budget is consumed in order: discovery, connect, optional
getInfo probe, getAssertion hop(s). Each hop receives only the
remaining budget; there are no independent per-hop timeouts.

```rust
// Sketch — normative behavior lives in specs/ceremony/spec.md
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub user_verification: UvPolicy,        // Discouraged | Preferred  (see D4)
    pub deadline: Duration,                 // single total budget
    pub selection: SelectionPolicy,         // default Fail
    pub probe_info: ProbePolicy,            // default IfNeeded (see D3)
    // pin_uv_auth_param / pin_uv_auth_protocol: opaque, caller-supplied
    // (core-model shapes); token acquisition is out of scope.
}

pub enum SelectionPolicy { First, Select(/* fn over descriptors */), Fail }
```

### D2: Discovery collects; it never short-circuits

Every registered transport is enumerated. A transport whose
`enumerate` fails contributes its typed error to an error list; it does
NOT abort discovery and MUST NOT hide candidates found on other
transports. Outcomes:

- ≥1 candidate → proceed to selection (per-transport errors, if any,
  are attached to the outcome as diagnostics, not failures).
- 0 candidates and ≥1 transport error → `Error::NoDevice` carrying the
  per-transport discovery errors (transport kind + typed cause).
- 0 candidates and 0 transport errors → `Error::NoDevice` with an empty
  error list.

Timeout bound: the whole discovery phase is bounded by the remaining
ceremony budget; each transport's enumerate call receives the remaining
budget (transports may be enumerated concurrently, but concurrency is
an implementation detail — the observable bound is the budget).

### D3: Candidate descriptors and the optional getInfo probe

Each candidate is described by a `CandidateDescriptor`:
transport kind (hid / pcsc / soft), the transport's device identifier
(path/handle), human-readable metadata from `DeviceInfo` (async-core),
and an optional AAGUID. The AAGUID is present only when a getInfo probe
(CTAP2.1 §6.4) ran against that candidate.

Probe policy (RESOLVED OQ-2, 2026-09-22, owner decision): the ceremony
MUST run authenticatorGetInfo (CTAP2.1 §6.4) on the selected device
before building the getAssertion request, on every ceremony. The
capabilities response drives request construction (options, uv
capability, pinUvAuthToken availability) and is included in the
ceremony outcome. During *discovery*, candidates are NOT probed (to
avoid multiplying device traffic across candidates); the probe happens
exactly once, after selection, on the connected device.

Timeout bound: the probe runs under the remaining ceremony budget; a
probe failure fails the ceremony with a typed error (the request cannot
be constructed safely without capability data).

### D4: User-verification policy

```rust
pub enum UvPolicy { Discouraged, Preferred }
```

- `Discouraged` (default): the request omits `options.uv` (CTAP2.1 §6.2
  default false) and carries no pinUvAuthParam.
- `Preferred`: v1 cannot acquire a pinUvAuthToken (clientPIN is a
  project non-goal). If the caller already holds one, the ceremony sends
  caller-supplied `pinUvAuthParam`/`pinUvAuthProtocol` (core-model wire
  shapes). If no token is supplied, `Preferred` degrades to
  `Discouraged` and the outcome is reported in the returned assertion
  metadata — never a silent fallback. PIN/UV auth failures from the
  authenticator (0x33 PIN_AUTH_INVALID, 0x34 PIN_AUTH_BLOCKED, 0x36
  PUAT_REQUIRED, 0x37 PIN_POLICY_VIOLATION, 0x3C UV_BLOCKED per the
  core-model CTAP2.1 §8.2 table) map to the typed `Error::UpRejected`.

The mutual-exclusion rule (never `options.uv` together with
`pinUvAuthParam`, CTAP2.1 §6.2) is enforced by core-model at encode
time; the ceremony never constructs a violating request.

### D5: Keepalive / user-presence wait loop

During the getAssertion hop the authenticator may signal "waiting for
user presence" (CTAPHID KEEPALIVE/UPNEEDED per CTAP2.1 §11.2.9.1.7; the
soft transport models the same via its keepalive-sequence knob).
Per async-core, transports surface keepalives as progress signals, not
errors. The ceremony:

- consumes keepalive progress signals without resetting the deadline;
- bounds the ENTIRE wait by the single remaining budget (D4 of
  async-core — each hop consumes the remainder; there is no separate
  "user presence timeout");
- maps an authenticator-side user-action timeout (status 0x2F
  CTAP2_ERR_USER_ACTION_TIMEOUT) to typed `Error::UserActionTimeout`;
- maps an authenticator-side keepalive cancel (status 0x2D
  CTAP2_ERR_KEEPALIVE_CANCEL) to typed `Error::UserCancelled`;
- maps caller-side budget expiry to typed `Error::Timeout` naming the
  user-presence phase (async-core requirement).

Timeout bound: remaining ceremony budget. This is the ONLY timeout for
the wait loop.

### D6: Multi-assertion drain per CTAP2.1 §6.3

When the getAssertion response carries `numberOfCredentials > 1`
(core-model response member 0x05), the ceremony MUST issue
authenticatorGetNextAssertion (CTAP2.1 §6.3) exactly
`numberOfCredentials - 1` times, collecting every assertion. Each
getNextAssertion hop is bounded by the remaining budget. Status 0x30
CTAP2_ERR_NOT_ALLOWED (continuation not allowed) surfaces as
`Error::Ctap(0x30)` — the ceremony does not retry it. The ceremony
returns the full ordered list of raw assertions; the first element is
the §6.2 response, followed by §6.3 responses in arrival order.

### D7: Error taxonomy (ceremony layer)

| Variant | Meaning | Primary sources (CTAP2.1 §8.2 via core-model) |
|---|---|---|
| `NoDevice` | Zero candidates; carries per-transport discovery errors | discovery phase |
| `AmbiguousDevice` | >1 candidate under `Fail`; carries every `CandidateDescriptor` | selection phase |
| `UserActionTimeout` | Authenticator-side UP wait expired | 0x2F CTAP2_ERR_USER_ACTION_TIMEOUT |
| `UserCancelled` | Pending keepalive cancelled (user or platform) | 0x2D CTAP2_ERR_KEEPALIVE_CANCEL |
| `NoCredentials` | No credential on the authenticator matches | 0x2E CTAP2_ERR_NO_CREDENTIALS; 0x22 CTAP2_ERR_INVALID_CREDENTIAL |
| `UpRejected` | UP/UV refused, incl. pinUvAuthToken-related codes | 0x27 CTAP2_ERR_OPERATION_DENIED; 0x3B CTAP2_ERR_UP_REQUIRED; 0x33/0x34/0x36/0x37/0x3C |
| `Timeout` | Caller budget expired; names the ceremony phase | deadline (async-core D4) |
| `Transport` | I/O or framing failure on the transport | transport layer |
| `Ctap(status)` | Any other authenticator status, carrying the typed core-model status | all remaining codes |
| `CredentialMismatch` | Returned credential id not in the caller's allow list | ceremony-side verification (OQ-3) |

Mapping precedence: exact typed variants above take priority over the
`Ctap(status)` catch-all; `Timeout` and `Transport` originate below the
status-code layer.

### D8: Wire-shape rules delegated to core-model

The ceremony layer does not re-derive wire rules. It relies on
core-model for: canonical CBOR encoding (CTAP2.1 §8), the getAssertion
request/response structures (CTAP2.1 §6.2), the empty-allowList
omission rule ("A platform MUST NOT send an empty allowList"), the
uv/pinUvAuthParam mutual exclusion, and the status-code space
(CTAP2.1 §8.2). The ceremony passes `allowCredentials: Some(list)` only
when the list is non-empty; `None` and `Some([])` both omit key 0x03.

## Blocking waits and their timeout bounds

| Wait | Bound |
|---|---|
| Transport enumeration (per transport) | remaining ceremony budget |
| Device connect / channel open (CTAPHID INIT per CTAP2.1 §11.2.9.1.3; APDU SELECT per CTAP2.1 §11) | remaining ceremony budget |
| Optional getInfo probe (per candidate) | remaining ceremony budget |
| getAssertion response wait, including keepalive/UPNEEDED loop | remaining ceremony budget |
| Each authenticatorGetNextAssertion hop | remaining ceremony budget |
| Transport-internal wait slices (CTAPHID read re-slice 30 s default; NFC poll 1 s) | per async-core resolved decisions; always ≤ remaining budget |

No wait in this design is unbounded. An unbounded wait is a spec
violation (stack invariant).

## Alternatives Considered

### A1: Fail-fast discovery (first transport error aborts) — rejected

Aborting the whole ceremony because, e.g., no PC/SC reader daemon is
running would hide a perfectly good HID key sitting on the desk. The
collect-and-report model keeps failure local to the failing transport
and preserves candidates elsewhere. Cost: `NoDevice` must carry a list
of per-transport errors instead of a single cause — accepted, because
diagnosing "why did you see no devices?" REQUIRES the per-transport
causes.

### A2: Implicit first-device selection as the default — rejected

Silently picking the first enumerated authenticator violates the stack
invariant "Never silently pick among multiple candidate
authenticators". `Fail` is the default; `First` exists for scripted
single-device environments and must be chosen explicitly.

### A3: Per-phase timeouts (discovery budget, probe budget, UP budget) — rejected

Already rejected for the transport layer in async-core A2; the same
rationale applies doubly at ceremony level: the only duration a user
reasons about is "the whole sign-in may take up to N seconds".
Combinatorial timeout knobs would invite misconfiguration and spurious
failures. One budget, remainder passed hop to hop (async-core D4).

### A4: Auto-probing getInfo on every candidate during discovery — rejected

Probing multiplies device traffic, adds waits to discovery, and can
itself trigger authenticator-side behavior. Default `IfNeeded` probes
only when capability data is actually consumed; `Always` remains
available for callers that want AAGUIDs in ambiguity reports.

### A5: Ceremony-level retry of retriable statuses (0x06 CHANNEL_BUSY, 0x3F UV_INVALID) — deferred

CTAP2.1 §8.2 marks 0x06 CHANNEL_BUSY as "client SHOULD retry after a
short delay" and 0x3F UV_INVALID as "platform SHOULD retry". v1 maps
them to `Ctap(status)` and lets the caller re-run the ceremony, because
a retry policy interacts with the single budget (how much of the
remainder may a retry consume?) and with UV attempt counters in ways
that deserve their own change-set. Flagged as open question OQ-1.

## Open Questions

- ~~OQ-1~~ RESOLVED 2026-09-22 (owner decision): **no in-ceremony retry.**
  Retriable statuses (0x06 CHANNEL_BUSY, 0x3F UV_INVALID) are surfaced
  typed immediately as `Ctap(status)`; the caller re-runs the ceremony if
  it wants to retry. Retry/backoff policy — if ever added — must live in
  the caller or a dedicated change-set, never implicit in the ceremony.
- ~~OQ-2~~ RESOLVED 2026-09-22 (owner decision): **always probe getInfo
  first.** The ceremony MUST run authenticatorGetInfo before building the
  getAssertion request, on every ceremony, regardless of UvPolicy. The
  capabilities response drives request construction (options, uv
  capability, pinUvAuthToken availability per CTAP2.1 §6.4) and is
  included in the ceremony outcome so callers can reason about
  capability. The "optional probe" phrasing in the spec is superseded:
  probe is mandatory.
- ~~OQ-3~~ RESOLVED 2026-09-22 (owner decision): **keep the
  wrong-credential-id check, bail early.** `CredentialMismatch` is a
  first-class typed error. Wherever the library can know the credential is
  wrong for this authenticator before or early in the ceremony, it MUST
  fail fast rather than waste the user's touch: (a) the credential-id
  check against the caller's allow list on the returned assertion stays;
  (b) the error message SHOULD identify the mismatch (returned id vs
  allowed ids, truncated safely); (c) it remains documented here as a
  library-safety rule, not a CTAP2 protocol requirement.
- ~~OQ-4~~ RESOLVED 2026-09-23 (implementation crystallization): **§6.3
  continuation seam is a caller-agnostic `Drain` hook, not a `CtapCommand`
  variant, in v1.** `CtapCommand` (async-core) has no
  `GetNextAssertion` variant and stays that way: the ceremony's drain is
  expressed as a `Drain` continuation hook over the device event stream,
  bounded by the remaining budget (`Timeout(GetNextAssertion)` on
  expiry), preserving the spec's observable contract (ordered list,
  §6.2 response first, 0x30 surfaced as `Ctap(0x30)` un-retried). Each
  transport implements the hook against its own wire (transport-hid:
  CTAP command 0x08 per CTAP2.1 §6.3). Codified in
  docs; revisit only if a transport needs first-class command framing.
- ~~OQ-5~~ RESOLVED 2026-09-23 (implementation crystallization):
  **Budget-expiry phase naming during the §6.2 hop reflects
  user-interaction progress, not the underlying command.** Expiry before
  any keepalive has flowed names `GetAssertion`; expiry after UP_NEEDED
  (or a keepalive) has flowed names `UserPresence`. Rationale: the name
  tells the caller where the user was in the ceremony, which is the
  actionable information; the device contract beneath names command
  phases and is not user-visible here.
- ~~OQ-6~~ RESOLVED 2026-09-23 (implementation crystallization):
  **`DiscoveryDiagnostic.kind` may be approximate in v1; the typed
  cause is authoritative.** The `Transport` trait does not expose its
  kind, so the diagnostic's `kind` field defaults to `Soft` for
  transports that do not self-report; callers needing the true layer
  read the cause's `TransportError.kind`. Revisit (trait method) when
  transport-hid/pcsc land if diagnostics prove load-bearing.
- ~~OQ-7~~ RESOLVED 2026-09-23 (implementation crystallization):
  **Unsupported pinUvAuthProtocolVersion (§6.5.5) surfaces as
  `Error::Transport` with a §6.5.5-citing detail; the taxonomy stays
  closed at 10 variants.** It is a pre-exchange capability mismatch
  discovered at the mandatory probe, not a transport fault; a dedicated
  variant would break the closed "every failure path is typed"
  enumeration for a condition callers can already match via detail.
- KNOWN HARNESS LIMIT (transport-soft, found 2026-09-23): `uv_mode:
  always-fail` couples capability advertisement with behavior — it both
  clears advertised `uv` and rejects getAssertion even without
  `options.uv`, so "uv-incapable but UP-only succeeds" is not
  modelable. The wire-degradation path (`Preferred` → `Discouraged`
  with reported `uv_effective`) is asserted via the happy path until
  the soft token splits advertisement from behavior (follow-up change,
  not a ceremony blocker).
