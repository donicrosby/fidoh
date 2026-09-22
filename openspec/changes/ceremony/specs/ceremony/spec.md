# ceremony Specification

Orchestration of the authenticatorGetAssertion ceremony: transport
discovery, deterministic device selection, the CTAP2.1 §6.2 exchange,
multi-assertion draining per CTAP2.1 §6.3, and the ceremony-layer error
taxonomy. Built on async-core's `Transport`/`Device`/`Ceremony`/`Sleep`
traits and single-budget timeout model (async-core D4), and on
core-model's wire structures and CTAP2.1 §8.2 status table. The library
is RP-agnostic: the caller supplies `clientDataHash` and consumes the
raw assertion; clientDataJSON construction and origin semantics are the
caller's responsibility (WebAuthn L2 §6.5).

## ADDED Requirements

### Requirement: Transport discovery collects candidates across all transports

The ceremony SHALL enumerate every registered transport and every
device on each, collecting all candidates into a single pool. A
discovery failure on one transport MUST NOT hide candidates found on
any other transport and MUST NOT abort discovery. Per-transport
discovery errors SHALL be collected; if zero candidates result, the
ceremony SHALL return a typed `Error::NoDevice` carrying every
per-transport discovery error (transport kind plus typed cause). If
candidates exist alongside transport errors, the errors SHALL be
attached to the outcome as diagnostics, not treated as failures. The
entire discovery phase SHALL be bounded by the remaining ceremony
budget (async-core D4); on expiry the ceremony SHALL return
`Error::Timeout` naming the discovery phase.

#### Scenario: One transport fails, another yields a candidate

- **WHEN** the PC/SC transport's enumeration fails (e.g. no reader
  daemon) and the soft transport enumerates one candidate
- **THEN** discovery returns the soft-transport candidate, the PC/SC
  error is attached as a diagnostic, and the ceremony proceeds
- **AND** the whole discovery phase is bounded by the remaining
  ceremony budget; on expiry the ceremony returns `Error::Timeout`
  naming the discovery phase

#### Scenario: All transports fail or yield nothing

- **WHEN** every registered transport either errors during enumeration
  or returns zero devices
- **THEN** the ceremony returns typed `Error::NoDevice` carrying each
  transport's kind and typed discovery error (empty list if all
  transports enumerated cleanly but found nothing)

### Requirement: Deterministic device selection

The ceremony SHALL select the device to use via an explicit
caller-supplied policy `First | Select(fn) | Fail`, defaulting to
`Fail` (stack invariant: never silently pick among multiple candidate
authenticators). When the candidate pool contains more than one
candidate and the policy is `Fail`, the ceremony SHALL return typed
`Error::AmbiguousDevice` carrying a `CandidateDescriptor` per candidate
containing: transport kind, the transport's device identifier
(path/handle), human-readable metadata, and the AAGUID when a getInfo
probe (CTAP2.1 §6.4) ran against that candidate. Under `First`, the
first enumerated candidate in deterministic transport order SHALL be
used. Under `Select(fn)`, the caller's function SHALL choose from the
descriptor list. Selection SHALL consume no device traffic beyond an
optional probe; `connect` SHALL be invoked exactly once, for the
selected candidate only, and SHALL be bounded by the remaining ceremony
budget.

#### Scenario: Multiple candidates under default Fail policy

- **WHEN** discovery yields two candidates and the selection policy is
  the default `Fail`
- **THEN** the ceremony returns typed `Error::AmbiguousDevice` listing
  both candidates' descriptors (transport kind, device path/handle,
  AAGUID if probed), and `connect` is never called

#### Scenario: Explicit First policy selects deterministically

- **WHEN** discovery yields two candidates and the policy is `First`
- **THEN** the ceremony connects to the first enumerated candidate in
  deterministic transport order, within the remaining ceremony budget,
  and proceeds with the exchange

### Requirement: Ceremony inputs and RP-agnostic boundary

The ceremony SHALL accept: `rpId` (string); `clientDataHash`
(caller-supplied; the library SHALL NOT construct `clientDataJSON` or
apply origin semantics — WebAuthn L2 §6.5 is the RP's responsibility);
optional `allowCredentials`; a user-verification policy; and a single
deadline budget. When `allowCredentials` is absent OR empty, the
allowList key (0x03) SHALL be omitted from the encoded request
(CTAP2.1 §6.2: "A platform MUST NOT send an empty allowList"; wire
enforcement delegated to core-model). Extensions are out of scope for
v1: the ceremony SHALL NOT send `appid`, `hmac-secret`, or any other
CTAP2.1 §12 extension, and the extensions parameter (0x04) SHALL be
absent from the request. Caller-supplied `pinUvAuthParam` /
`pinUvAuthProtocol` (core-model wire shapes) MAY be passed through when
the caller already holds a pinUvAuthToken; acquiring one is out of
scope (project non-goal).

#### Scenario: Minimal ceremony input

- **WHEN** the caller runs the ceremony with only `rpId`, a 32-byte
  `clientDataHash`, and a deadline budget against the soft transport
- **THEN** the getAssertion request on the wire contains keys 0x01 and
  0x02 only (CTAP2.1 §6.2), with no extensions member (0x04), and the
  ceremony completes within the budget

#### Scenario: Empty allowCredentials omitted on the wire

- **WHEN** the caller passes an empty `allowCredentials` list
- **THEN** the encoded getAssertion request omits key 0x03 entirely
  (CTAP2.1 §6.2), identically to passing no allowCredentials

### Requirement: Ceremony sequence per CTAP2.1 §6.2 with single-budget keepalive loop

The ceremony SHALL execute in order: (1) a mandatory
authenticatorGetInfo probe (CTAP2.1 §6.4) — always run, every ceremony;
the capabilities response SHALL drive request construction (options,
uv capability, pinUvAuthToken availability) and SHALL be included in
the ceremony outcome; (2) send authenticatorGetAssertion (CTAP2.1 §6.2); (3) consume
keepalive / user-presence progress signals surfaced by the transport
(CTAPHID KEEPALIVE UPNEEDED per CTAP2.1 §8.1.5.1; surfaced as progress,
not errors, per async-core) until a terminal response arrives. The
entire sequence — probe, exchange, and every keepalive wait — SHALL be
bounded by the SINGLE caller-supplied budget: each hop consumes only
the remaining budget (async-core D4), there are no independent per-hop
or per-wait timeouts, and budget expiry at any hop SHALL return
`Error::Timeout` naming the expired phase. On success the ceremony
SHALL return the raw assertion: credential, authenticatorData,
signature, userHandle, and numberOfCredentials (default 1), as modeled
by core-model (CTAP2.1 §6.2 response).

#### Scenario: Keepalive-then-success within budget (CI: transport-soft keepalive knob)

- **WHEN** the soft token is configured (error-injection knob (b)) to
  emit three UP_NEEDED keepalive events at 50 ms spacing before a
  successful getAssertion response, and the ceremony runs with a
  sufficient budget
- **THEN** the ceremony consumes the keepalives as progress signals
  without resetting the deadline, returns the raw assertion, and every
  wait is bounded by the single remaining budget

#### Scenario: Budget expires during user-presence wait (CI: transport-soft require-explicit-poke)

- **WHEN** the soft token is in `require-explicit-poke` UP mode, no
  poke arrives, and the ceremony budget expires mid-wait
- **THEN** the ceremony returns `Error::Timeout` naming the
  user-presence phase, and the device remains usable for a subsequent
  ceremony (async-core cancellation contract)

### Requirement: Typed status-code handling

The ceremony SHALL map authenticator status codes (core-model's
CTAP2.1 §8.2 table) to typed ceremony errors as follows: 0x2E
CTAP2_ERR_NO_CREDENTIALS and 0x22 CTAP2_ERR_INVALID_CREDENTIAL →
`Error::NoCredentials`; 0x2F CTAP2_ERR_USER_ACTION_TIMEOUT →
`Error::UserActionTimeout`; 0x2D CTAP2_ERR_KEEPALIVE_CANCEL →
`Error::UserCancelled`; 0x27 CTAP2_ERR_OPERATION_DENIED, 0x3B
CTAP2_ERR_UP_REQUIRED, and the pinUvAuthToken-related codes 0x33
CTAP2_ERR_PIN_AUTH_INVALID, 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED, 0x36
CTAP2_ERR_PUAT_REQUIRED, 0x37 CTAP2_ERR_PIN_POLICY_VIOLATION, 0x3C
CTAP2_ERR_UV_BLOCKED → `Error::UpRejected`; every other status →
`Error::Ctap(status)` carrying the typed core-model status value.
Transport I/O or framing failures SHALL surface as
`Error::Transport(io)`. No status byte SHALL reach the caller as an
untyped error.

#### Scenario: No matching credential maps to NoCredentials (CI: transport-soft status knob)

- **WHEN** the soft token returns 0x2E CTAP2_ERR_NO_CREDENTIALS for a
  getAssertion whose allowList matches nothing (knob (a) or an
  unmatched store)
- **THEN** the ceremony returns typed `Error::NoCredentials`, and no
  retry is attempted

#### Scenario: User-action timeout maps distinctly from budget timeout (CI: transport-soft status knob)

- **WHEN** the soft token is configured (knob (a)) to return 0x2F
  CTAP2_ERR_USER_ACTION_TIMEOUT for the next getAssertion
- **THEN** the ceremony returns `Error::UserActionTimeout` (authenticator-side
  timeout), distinguishable from `Error::Timeout` (caller budget expiry)

#### Scenario: Keepalive cancel maps to UserCancelled (CI: transport-soft status knob)

- **WHEN** the soft token is configured (knob (a)) to return 0x2D
  CTAP2_ERR_KEEPALIVE_CANCEL for the next getAssertion
- **THEN** the ceremony returns typed `Error::UserCancelled`

### Requirement: Multi-assertion drain via authenticatorGetNextAssertion

When the getAssertion response carries `numberOfCredentials > 1`
(core-model response member 0x05, CTAP2.1 §6.2), the ceremony SHALL
issue authenticatorGetNextAssertion (CTAP2.1 §6.3) exactly
`numberOfCredentials − 1` additional times and SHALL return all
assertions as an ordered list: the §6.2 response first, followed by the
§6.3 responses in arrival order. Each getNextAssertion hop SHALL be
bounded by the remaining ceremony budget. Status 0x30
CTAP2_ERR_NOT_ALLOWED on a continuation SHALL surface as
`Error::Ctap(0x30)` without retry.

#### Scenario: Three credentials drained in order

- **WHEN** the getAssertion response reports `numberOfCredentials = 3`
  and a sufficient budget remains
- **THEN** the ceremony issues authenticatorGetNextAssertion twice
  (CTAP2.1 §6.3), returns a list of three raw assertions in order, and
  every hop is bounded by the single remaining budget (expiry returns
  `Error::Timeout` naming the getNextAssertion phase)

#### Scenario: Continuation refused surfaces typed

- **WHEN** a getNextAssertion hop returns 0x30 CTAP2_ERR_NOT_ALLOWED
- **THEN** the ceremony returns `Error::Ctap` carrying the typed 0x30
  status and does not retry

### Requirement: Ceremony error taxonomy

The ceremony layer SHALL expose exactly these typed error variants:
`NoDevice` (carrying per-transport discovery errors),
`AmbiguousDevice` (carrying every candidate descriptor),
`UserActionTimeout`, `UserCancelled`, `NoCredentials`, `UpRejected`,
`Timeout` (carrying the expired ceremony phase), `Transport(io)`,
`Ctap(status)` carrying the typed core-model status, and
`CredentialMismatch` (returned credential id not in the caller's
allow list). All variants SHALL
be distinct typed values; no ceremony failure SHALL surface as a
string, an untyped error, or a panic (stack invariant).

#### Scenario: Every failure path is typed

- **WHEN** a ceremony fails at any phase (discovery, selection,
  exchange, drain)
- **THEN** the error is exactly one of the ten typed variants, with
  `Timeout` naming the expired phase and `Ctap` carrying the typed
  core-model status value

### Requirement: Returned assertion fidelity and credential verification

The ceremony SHALL return the raw assertion fields exactly as decoded
by core-model: credential (PublicKeyCredentialDescriptor),
authenticatorData, signature, userHandle (optional per CTAP2.1 §6.2),
and numberOfCredentials. When the caller supplied `allowCredentials`,
the ceremony SHALL verify that the returned credential id is a member
of the allow list; a mismatch SHALL fail the ceremony with the typed
`Error::CredentialMismatch` variant (a library-safety rule; see design
OQ-3 for grounding status) rather than silently returning the foreign
assertion. The ceremony SHALL NOT verify the signature itself —
signature verification is the RP's responsibility (WebAuthn L2 §6.5).

#### Scenario: Wrong credential id rejected (CI: transport-soft wrong-credential-id knob)

- **WHEN** the soft token's wrong-credential-id knob (d) is armed, the
  caller supplied an allowList, and the returned assertion carries a
  different credential id
- **THEN** the ceremony fails with a typed error naming the credential
  mismatch instead of returning the foreign assertion, and the failure
  occurs within the remaining ceremony budget
