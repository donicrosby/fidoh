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
user-presence wait (keepalive signaling per CTAP2.1 §8.1.5.1 for HID;
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

Probing every candidate during discovery would multiply device traffic
and wait time, so the probe policy is:

- `ProbePolicy::IfNeeded` (default) — probe only when the caller's
  request needs capability data (e.g. a non-default UV policy check) or
  when the caller asks for AAGUIDs in the `AmbiguousDevice` report.
- `ProbePolicy::Always` / `Never` — explicit overrides.

Timeout bound: each probe runs under the remaining ceremony budget; a
probe failure does not fail the ceremony — the candidate proceeds with
AAGUID absent.

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
user presence" (CTAPHID KEEPALIVE/UPNEEDED per CTAP2.1 §8.1.5.1; the
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
| Device connect / channel open (CTAPHID INIT per CTAP2.1 §8.1.4; APDU SELECT per CTAP2.1 §11) | remaining ceremony budget |
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

- OQ-1: Should the ceremony retry retriable statuses (0x06
  CHANNEL_BUSY, 0x3F UV_INVALID per CTAP2.1 §8.2 SHOULD-retry language)
  within the remaining budget, and if so with what backoff driven by
  `Sleep`? Groundable in CTAP2.1 §8.2, but the POLICY (retry count,
  backoff shape) is a design choice, not a spec fact. Deferred to a
  later change-set; v1 behavior is "surface as `Ctap(status)`, caller
  re-runs".
- OQ-2: When `UvPolicy::Preferred` is requested without a
  caller-supplied pinUvAuthToken, should the ceremony probe getInfo
  unconditionally to check the `uv`/`pinUvAuthToken` options
  (CTAP2.1 §6.4) and report capability in the outcome, or is the
  current degrade-with-report behavior sufficient? The option semantics
  are grounded (CTAP2.1 §6.4); the UX trade-off is not. Deferred.
- OQ-3: The wrong-credential-id check (reject an assertion whose
  credential id is outside the caller's allow list) is a deliberate
  library-safety rule; it is motivated by WebAuthn's assertion contract
  but is not a verbatim MUST in CTAP2.1 §6.2 as a client-side step.
  Recorded here per the cleanroom rule rather than presented as a
  protocol requirement. The `CredentialMismatch` variant stays in the
  taxonomy; if owner review judges the check overreach, the variant is
  removed and knob (d) scenarios are re-scoped to signature-fidelity
  checks by the caller.
