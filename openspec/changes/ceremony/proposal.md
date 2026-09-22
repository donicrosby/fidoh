# ceremony — authenticatorGetAssertion Orchestration

## Why

The async-core change defines the `Transport`/`Device`/`Ceremony`/`Sleep`
trait surface, and core-model defines the wire structures, but nothing yet
specifies HOW a caller-facing getAssertion run is orchestrated: how devices
are discovered across all registered transports, how exactly one device is
selected deterministically, how the CTAP2.1 §6.2 exchange is sequenced
against the single deadline budget (async-core D4), and how authenticator
status codes map onto typed ceremony errors. Without this spec, each caller
(or each crate) would invent its own discovery and selection logic — a
direct violation of the stack invariant "explicit, deterministic device
selection".

## What Changes

- Specify the **discovery phase**: enumerate every registered transport,
  enumerate candidate devices on each, and collect candidates into one
  pool. A discovery failure on one transport MUST NOT hide candidates
  found on others; per-transport errors are collected and reported in a
  typed `Error::NoDevice` if (and only if) zero candidates result.
- Specify **deterministic device selection**: policy enum
  `First | Select(fn) | Fail` with default `Fail` (stack invariant);
  multiple candidates under `Fail` produce typed `Error::AmbiguousDevice`
  carrying a descriptor per candidate (transport kind, device
  path/handle, AAGUID if a getInfo probe ran).
- Specify the **ceremony inputs**: `rpId`, caller-supplied
  `clientDataHash` (RP boundary rule — the library never constructs
  `clientDataJSON`; WebAuthn L2 §6.5 is the RP's responsibility),
  optional `allowCredentials` (an empty allowList MUST be omitted on the
  wire per CTAP2.1 §6.2, as modeled in core-model), a user-verification
  policy, no extensions in v1 (appid and hmac-secret explicitly out of
  scope), and the single deadline budget.
- Specify the **ceremony sequence per CTAP2.1 §6.2**: optional
  authenticatorGetInfo probe → send authenticatorGetAssertion →
  keepalive/user-presence wait loop bounded by the SINGLE remaining
  budget (async-core D4; each hop consumes the remainder) → typed
  handling of CTAP2 status codes (0x2E NO_CREDENTIALS, 0x27
  OPERATION_DENIED, 0x2D KEEPALIVE_CANCEL, 0x2F USER_ACTION_TIMEOUT, et
  al. per core-model's CTAP2.1 §8.2 status table) → return the raw
  assertion (credential, authenticatorData, signature, userHandle,
  numberOfCredentials).
- Specify **multi-assertion handling**: when the response carries
  `numberOfCredentials > 1`, the ceremony MUST drive
  authenticatorGetNextAssertion (CTAP2.1 §6.3) until all assertions are
  collected, each hop bounded by the remaining budget.
- Specify the **ceremony error taxonomy**: `NoDevice`,
  `AmbiguousDevice`, `UserActionTimeout`, `UserCancelled`,
  `NoCredentials`, `UpRejected`, `Timeout`, `Transport(io)`,
  `Ctap(status)` — all typed, no stringly errors.
- Specify **CI testability**: every requirement has at least one
  scenario, and at least two scenarios are expressible against
  transport-soft's error-injection knobs (keepalive-then-success,
  wrong-credential-id).

## Impact

- Affected specs: `ceremony` (new capability).
- Affected code: none — documents only (Phase B, spec-authoring).
- Depends on: `async-core` (traits, single-budget timeout model),
  `core-model` (wire structures, status codes), `transport-soft`
  (CI harness knobs).
- Downstream: implementation change-sets for `fidoh-core`'s ceremony
  orchestration consume this spec.

## Non-goals

- authenticatorMakeCredential as client API (project non-goal; harness
  plumbing only, per transport-soft).
- clientPIN/UV token acquisition, credential management, large blobs
  (project non-goals). PIN/UV auth parameters are accepted as opaque
  inputs only when the caller already holds a pinUvAuthToken.
- Extensions beyond v1 scope: `appid`, `hmac-secret`, and all other
  CTAP2.1 §12 extensions are explicitly out of scope.
- RP-side semantics: clientDataJSON construction, origin validation,
  attestation, signature verification (WebAuthn L2 §6.5 is the caller's
  responsibility).
- U2F/CTAP1 fallback signaling on authenticators that only advertise
  `U2F_V2` (v1 requires a CTAP2-capable authenticator).
