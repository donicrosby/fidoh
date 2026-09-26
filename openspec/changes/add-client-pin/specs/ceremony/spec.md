# ceremony Specification

Orchestration of the authenticatorGetAssertion ceremony: transport
discovery, deterministic device selection, the CTAP2.1 §6.2 exchange,
multi-assertion draining per CTAP2.1 §6.3, and the ceremony-layer error
taxonomy. Built on async-core's `Transport`/`Device`/`Ceremony`/`Sleep`
traits and single-budget timeout model (async-core D4), and on
core-model's wire structures and CTAP2.1 §8.2 status table. The library
is RP-agnostic: the caller supplies `clientDataHash` and consumes the
raw assertion; clientDataJSON construction and origin semantics are the
caller's responsibility (WebAuthn L2 §7.2). Since the add-client-pin
change (v2), the ceremony additionally performs the CTAP2.1 §6.5.5
clientPIN/pinUvAuth acquisition flow when the caller supplies a
PIN-provider handle, and reports the token-backed UV posture in the
outcome.

## MODIFIED Requirements

### Requirement: Ceremony inputs and RP-agnostic boundary

The ceremony SHALL accept: `rpId` (string); `clientDataHash`
(caller-supplied; the library SHALL NOT construct `clientDataJSON` or
apply origin semantics — WebAuthn L2 §7.2 is the RP's responsibility);
optional `allowCredentials`; a user-verification policy; a single
deadline budget; and, since v2, an optional PIN-provider handle and an
optional caller-pinned pinUvAuth protocol. When `allowCredentials` is
absent OR empty, the allowList key (0x03) SHALL be omitted from the
encoded request (CTAP2.1 §6.2: "A platform MUST NOT send an empty
allowList"; wire enforcement delegated to core-model). Extensions are
out of scope: the ceremony SHALL NOT send `appid`, `hmac-secret`, or any
other CTAP2.1 §12 extension, and the extensions parameter (0x04) SHALL
be absent from the request. Caller-supplied `pinUvAuthParam` /
`pinUvAuthProtocol` (core-model wire shapes) MAY be passed through when
the caller already holds a pinUvAuthToken; caller-held material takes
precedence over acquisition — when both are supplied the ceremony SHALL
use the caller-held material and SHALL NOT run the acquisition flow.
Supersession note (v2): v1 named pinUvAuthToken acquisition a project
non-goal (openspec/config.yaml "clientPIN / UV protocols … explicitly
out of scope for v1"; ceremony v1 proposal "Non-goals"); the owner
overturned that non-goal for v2 — acquisition is now specified in the
"pinUvAuthToken acquisition flow" requirement below. The PIN-provider
handle is caller-owned UI: `fidoh-core` SHALL NOT read stdin, SHALL NOT
spawn any user interface, and SHALL NOT retain PIN bytes beyond the
single acquisition transaction (error-diagnostics no-secrets rule).

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

#### Scenario: Caller-held token takes precedence over acquisition

- **WHEN** the caller supplies BOTH pinUvAuth material (keys 0x06/0x07
  inputs) AND a PIN-provider handle
- **THEN** the ceremony sends the caller-held material and never
  issues an authenticatorClientPIN (0x06) command — no PIN prompt is
  performed

### Requirement: Ceremony sequence per CTAP2.1 §6.2 with single-budget keepalive loop

The ceremony SHALL execute in order: (1) a mandatory
authenticatorGetInfo probe (CTAP2.1 §6.4) — always run, every ceremony;
the capabilities response SHALL drive request construction (options,
uv capability, pinUvAuthToken availability) and SHALL be included in
the ceremony outcome; (1a, v2) the pinUvAuthToken acquisition flow of
the "pinUvAuthToken acquisition flow" requirement when its preconditions
hold, every hop bounded by the remaining budget and named
`ClientPin`; (2) send authenticatorGetAssertion (CTAP2.1 §6.2); (3)
consume keepalive / user-presence progress signals surfaced by the
transport (CTAPHID KEEPALIVE UPNEEDED per CTAP2.1 §11.2.9.1.7; surfaced
as progress, not errors, per async-core) until a terminal response
arrives. The entire sequence — probe, acquisition hops, exchange, and
every keepalive wait — SHALL be bounded by the SINGLE caller-supplied
budget: each hop consumes only the remaining budget (async-core D4),
there are no independent per-hop or per-wait timeouts, and budget
expiry at any hop SHALL return `Error::Timeout` naming the expired
phase. On success the ceremony SHALL return the raw assertion:
credential, authenticatorData, signature, userHandle, and
numberOfCredentials (default 1), as modeled by core-model (CTAP2.1 §6.2
response).

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

#### Scenario: Budget expires during a clientPIN hop names ClientPin

- **WHEN** the acquisition flow is in progress and the remaining budget
  expires during (or before) an authenticatorClientPIN hop
  (getKeyAgreement, getPINRetries, or the token request)
- **THEN** the ceremony returns `Error::Timeout` naming the `ClientPin`
  phase, with no independent per-hop timeout having existed

### Requirement: Typed status-code handling

The ceremony SHALL map authenticator status codes (core-model's
CTAP2.1 §8.2 table) to typed ceremony errors as follows: 0x2E
CTAP2_ERR_NO_CREDENTIALS and 0x22 CTAP2_ERR_INVALID_CREDENTIAL →
`Error::NoCredentials`; 0x2F CTAP2_ERR_USER_ACTION_TIMEOUT →
`Error::UserActionTimeout`; 0x2D CTAP2_ERR_KEEPALIVE_CANCEL →
`Error::UserCancelled`; 0x27 CTAP2_ERR_OPERATION_DENIED, 0x3B
CTAP2_ERR_UP_REQUIRED, and the pinUvAuthToken-related codes 0x33
CTAP2_ERR_PIN_AUTH_INVALID, 0x36 CTAP2_ERR_PUAT_REQUIRED, 0x37
CTAP2_ERR_PIN_POLICY_VIOLATION, 0x3C CTAP2_ERR_UV_BLOCKED →
`Error::UpRejected`; 0x31 CTAP2_ERR_PIN_INVALID →
`Error::IncorrectPin` carrying the authenticator's remaining-retry
count when the response supplies it; 0x32 CTAP2_ERR_PIN_BLOCKED →
`Error::PinBlocked`; 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED →
`Error::PinAuthBlocked`; 0x35 CTAP2_ERR_PIN_NOT_SET →
`Error::PinNotSet`; every other status → `Error::Ctap(status)`
carrying the typed core-model status value. Transport I/O or framing
failures SHALL surface as `Error::Transport(io)`. No status byte SHALL
reach the caller as an untyped error.

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

#### Scenario: Wrong PIN maps to IncorrectPin with the retry count (CI: transport-soft clientPIN)

- **WHEN** the acquisition flow sends a pinHashEnc that fails the
  authenticator's PIN comparison, and the authenticator's response
  carries `pinRetries` (0x03)
- **THEN** the ceremony returns typed `Error::IncorrectPin` whose
  `remaining_retries` field equals the decremented count from the
  response, the retry counter on the token has been decremented
  exactly once, and no automatic re-prompt or re-submission occurred

#### Scenario: PIN blocked maps typed after exhaustion (CI: transport-soft clientPIN)

- **WHEN** the soft token's retry counter has reached zero and a
  PIN-bearing acquisition hop arrives
- **THEN** the token answers 0x32 CTAP2_ERR_PIN_BLOCKED and the
  ceremony returns typed `Error::PinBlocked`

#### Scenario: Three consecutive mismatches maps to PinAuthBlocked (CI: transport-soft clientPIN)

- **WHEN** the soft token has seen three consecutive PIN mismatches and
  a further PIN-bearing hop arrives
- **THEN** the token answers 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED, the
  ceremony returns typed `Error::PinAuthBlocked`, and the error text
  names the power-cycle requirement (CTAP2.1 §6.5.5.7.2)

#### Scenario: PIN not set maps typed and distinct from wrong PIN (CI: transport-soft clientPIN)

- **WHEN** the ceremony attempts acquisition against an
  authenticator that advertises clientPin support but has no PIN set
- **THEN** the ceremony returns typed `Error::PinNotSet`, a value
  distinct from `Error::IncorrectPin` in match position and in Display
  text

## ADDED Requirements

### Requirement: pinUvAuth protocols one and two

The library SHALL implement PIN/UV Auth Protocol One (CTAP2.1 §6.5.6)
and Protocol Two (CTAP2.1 §6.5.7) atop RustCrypto primitives
(P-256 ECDH, SHA-256, HKDF-SHA-256, HMAC-SHA-256, AES-256-CBC — never
hand-rolled; the canonical CBOR layer stays hand-rolled), with:

- key agreement: platform ephemeral P-256 key pair; Z = the 32-byte
  big-endian x-coordinate of the ECDH shared point; P1
  `sharedSecret = SHA-256(Z)`; P2 `sharedSecret = HKDF-SHA-256(salt =
  0x00×32, IKM = Z, L = 32, info = "CTAP2 HMAC key") ‖
  HKDF-SHA-256(salt = 0x00×32, IKM = Z, L = 32, info = "CTAP2 AES
  key")` — two HKDF invocations over the same extracted PRK,
  concatenated, never a single L=64 invocation (§6.5.7 note);
- the platform key-agreement COSE_Key emitted as
  `{1: 2, 3: -25, -1: 1, -2: x, -3: y}` in canonical CBOR (§6.5.6
  getPublicKey; alg −25 per §6.5.5 "MUST contain the optional alg
  parameter and MUST NOT contain any other optional parameters");
- `authenticate(key, message)`: P1 = first 16 bytes of HMAC-SHA-256;
  P2 = full 32 bytes of HMAC-SHA-256;
- `encrypt(key, plaintext)`: P1 = AES-256-CBC with an all-zero IV, no
  padding; P2 = AES-256-CBC with a fresh random 16-byte IV emitted as
  `iv ‖ ct`, no padding;
- `decrypt(key, ciphertext)`: P1 = AES-256-CBC all-zero IV, error on
  non-block-multiple input; P2 = split after the 16th byte into iv and
  ct, error when the input is shorter than 16 bytes.

All key material (PIN bytes, shared secrets, pinTokens) SHALL be
zeroized on drop, and SHALL never appear in `Debug` or `Display` output
of any public type (lengths only). The randomness for P2 IVs and
platform key pairs SHALL flow through an injectable byte-source trait;
the default in no_std builds is deterministic (harness-only), and
production callers inject an OS-backed source.

#### Scenario: Protocol one key agreement produces the specified shared secret

- **WHEN** the platform encapsulates the authenticator's keyAgreement
  COSE_Key under protocol 1 with a fixed platform key
- **THEN** the shared secret equals SHA-256 of the ECDH shared-point
  x-coordinate, the emitted COSE_Key encodes exactly the members
  {1: 2, 3: -25, -1: 1, -2: x, -3: y} in canonical CBOR order, and
  authenticate(key, message) returns exactly 16 bytes of truncated
  HMAC-SHA-256

#### Scenario: Protocol two key agreement concatenates two HKDFs

- **WHEN** the platform encapsulates under protocol 2 with the same
  fixed platform key and shared point Z
- **THEN** the 64-byte shared secret equals
  HKDF-SHA-256(salt 0x00×32, Z, L=32, "CTAP2 HMAC key") ‖
  HKDF-SHA-256(salt 0x00×32, Z, L=32, "CTAP2 AES key"), byte-compared
  against an independent RFC 5869 implementation of both invocations,
  and authenticate(key, message) returns the full 32-byte HMAC

#### Scenario: Protocol two encrypt emits fresh iv-prefixed ciphertext

- **WHEN** the same 16-byte plaintext is encrypted twice under
  protocol 2 with the same key
- **THEN** the two ciphertexts differ (fresh random IVs), each is
  exactly 16 + 16 bytes (iv ‖ one block), and the authenticator-side
  decrypt recovers the plaintext in both cases

#### Scenario: Malformed decrypt inputs are typed errors

- **WHEN** decrypt is called with a non-block-multiple ciphertext under
  protocol 1, or an input shorter than 16 bytes under protocol 2
- **THEN** the operation returns a typed error carrying no plaintext
  material and no panic occurs

### Requirement: PIN-provider callback seam

The ceremony input SHALL accept an optional PIN-provider handle — a
caller-supplied implementation of a single `provide_pin` operation
returning the PIN as UTF-8 bytes or a caller-typed failure. The
provider SHALL be invoked at most once per ceremony run, after the
shared secret is established and before the token request
(collect-before-use, CTAP2.1 §6.5.5.7.2 step 1 note). `fidoh-core`
SHALL NOT read stdin, open devices, spawn threads, or otherwise
perform I/O to obtain the PIN; the seam is the ONLY path by which PIN
bytes enter the library. A provider failure SHALL surface as the typed
`Error::PinProviderFailed` without any authenticator round-trip and
without retry. A PIN longer than 63 UTF-8 bytes SHALL be rejected
client-side (typed `Error::PinTooLong`) BEFORE any device traffic that
could consume budget or retry counters (CTAP2.1 §6.5.5.5 maximum PIN
length bound).

#### Scenario: Provider invoked exactly once and consumed

- **WHEN** the acquisition flow succeeds and later a second ceremony
  runs over the same connected device without a new provider
- **THEN** the first ceremony called provide_pin exactly once, and the
  second ceremony's input carries no PIN provider — no prompt is shown

#### Scenario: Provider failure surfaces typed before any authenticator call

- **WHEN** the provider returns its caller-typed cancellation error
- **THEN** the ceremony returns `Error::PinProviderFailed`, no
  authenticatorClientPIN command was issued after the provider step,
  the token's retry counter is unchanged, and the device remains
  usable

#### Scenario: Oversized PIN rejected before device traffic

- **WHEN** the provider returns 64 or more UTF-8 bytes
- **THEN** the ceremony fails with typed `Error::PinTooLong` before any
  clientPIN hop that consumes the shared secret, and no retry counter
  decrements

### Requirement: pinUvAuthToken acquisition flow

When ALL of the following hold — the caller's user-verification policy
is `Preferred`; no caller-held pinUvAuth material was supplied; a
PIN-provider handle was supplied; and the mandatory probe advertises
the `clientPin` option ID true with at least one supported
`pinUvAuthProtocols` entry (CTAP2.1 §6.4 member 0x06) — the ceremony
SHALL perform the CTAP2.1 §6.5.5 acquisition flow, every hop bounded by
the remaining budget and named `ClientPin`:

1. Select the pinUvAuth protocol: the caller-pinned protocol when
   supplied (rejected typed when not in the advertised list — existing
   §6.5.5 rule), otherwise the FIRST advertised entry the library
   implements (the authenticator's preference order, §6.5.5.4).
2. Send authenticatorClientPIN subCommand getKeyAgreement (0x02) with
   the chosen pinUvAuthProtocol; encapsulate the returned keyAgreement
   (0x01) member to derive the shared secret (CTAP2.1 §6.5.5.4). A
   missing keyAgreement member or an undecapsulable key is a typed
   `Error::Transport` failure naming the clientPIN layer.
3. Collect the PIN via the provider (see the PIN-provider seam
   requirement).
4. When the probe advertises the `pinUvAuthToken` option ID true:
   send subCommand getPinUvAuthTokenUsingPinWithPermissions (0x09)
   with `permissions = 0x02` (ga) and `rpId` = the ceremony's rpId
   (CTAP2.1 §6.5.5.7.2). Otherwise: send subCommand getPinToken
   (0x05) (CTAP2.1 §6.5.5.7.1, CTAP2.0-token fallback; default mc+ga
   permissions). `pinHashEnc = encrypt(sharedSecret, LEFT(SHA-256(PIN),
   16))` in both cases.
5. On success decrypt the pinUvAuthToken (0x02) member with the shared
   secret; compute `pinUvAuthParam = authenticate(pinToken,
   clientDataHash)` per CTAP2.1 §6.2 — the message construction is
   centralized in one named function pending OQ-9's owner
   verification — and shape the request with keys 0x06/0x07.
6. On 0x31 CTAP2_ERR_PIN_INVALID map typed per the status-table
   requirement (`Error::IncorrectPin`, retries surfaced when offered).
   The ceremony SHALL NOT retry the token request within the same run
   (no implicit retry, mirroring ceremony OQ-1); the caller re-runs.

The ceremony SHALL set `options.uv` on a request that carries
pinUvAuthParam (CTAP2.1 §6.2 mutual exclusion — by construction and
re-checked by core-model at encode time). The outcome SHALL report the
token-backed posture as `UvEffective::PinUvAuthToken` — never silent.
`UvPolicy::Discouraged` SHALL NOT trigger acquisition: no PIN prompt is
shown for a discouraged request. When the policy is `Preferred`, no
caller-held material and no provider were supplied, and the probe
indicates a PIN-capable key that lacks a usable built-in verifier, the
ceremony SHALL fail with typed `Error::PinRequired` naming the fix
(supply a PIN provider) instead of silently degrading to the
`Discouraged` wire shape; a key advertising the `uv` capability keeps
the existing `options.uv = true` shaping with
`UvEffective::UvOption` reported.

#### Scenario: Preferred with provider on a PIN-set protocol-2 token end to end (CI: transport-soft clientPIN)

- **WHEN** the soft token advertises clientPin + pinUvAuthToken +
  protocols [2, 1] with a PIN set, and the caller runs `Preferred`
  with a provider returning the correct PIN
- **THEN** the ceremony performs getKeyAgreement, the token request
  (0x09 with permissions 0x02 and rpId), receives the encrypted token,
  sends getAssertion with pinUvAuthParam + pinUvAuthProtocol(2) and
  WITHOUT options.uv, receives the assertion with the UV flag set by
  the authenticator, and reports `UvEffective::PinUvAuthToken`

#### Scenario: getPinToken fallback on a token without the pinUvAuthToken option

- **WHEN** the soft token advertises clientPin true, pinUvAuthToken
  false/absent, and protocols [1], with a PIN set
- **THEN** the acquisition uses subCommand 0x05, succeeds, and the
  subsequent request carries pinUvAuthParam under protocol 1

#### Scenario: Preferred without provider on a PIN-only key fails naming the fix

- **WHEN** the probe reports clientPin true, uv false/absent, no
  caller-held token and no provider
- **THEN** the ceremony returns typed `Error::PinRequired`, the Display
  text names the fix (supply a PIN provider), no authenticatorClientPIN
  command was issued, and no silent Discouraged degradation occurred

#### Scenario: Discouraged never prompts for a PIN

- **WHEN** the policy is `Discouraged` and a PIN provider is supplied
- **THEN** provide_pin is never invoked and no authenticatorClientPIN
  command is issued

#### Scenario: Caller-pinned protocol not advertised is rejected typed

- **WHEN** the caller pins protocol 1 and the token advertises only
  protocol 2
- **THEN** the ceremony returns the typed protocol-mismatch failure
  citing CTAP2.1 §6.5.5 before any clientPIN command, consistent with
  the existing unsupported-protocol rule

#### Scenario: Wrong PIN decrements exactly once and surfaces the count

- **WHEN** the provider returns a wrong PIN and the token answers 0x31
  with pinRetries = 7
- **THEN** the ceremony returns `Error::IncorrectPin { remaining_retries:
  Some(7) }`, the token's counter reads 7 (decremented exactly once),
  and a second run with the correct PIN succeeds from the same counter

#### Scenario: Budget expiry mid-acquisition is typed and cancellation-safe

- **WHEN** the remaining budget expires between the getKeyAgreement
  hop and the token request
- **THEN** the ceremony returns `Error::Timeout` naming `ClientPin`,
  the device remains usable for a subsequent ceremony, and no partially
  derived material leaks into any later run

### Requirement: Transport diagnostics name the real transport kind

Every `Transport` implementation SHALL expose its `TransportKind` (hid,
pcsc, soft) via the trait so per-transport discovery diagnostics
(`DiscoveryDiagnostic.kind`, surfaced through `Error::NoDevice` and
outcome diagnostics) name the actual failing layer instead of a
hardcoded default. The default trait answer for existing implementors
SHALL remain `soft` (additive for external impls); the in-tree hardware
transports SHALL override it.

#### Scenario: Mixed-transport NoDevice names each failing transport (CI: soft + a stub hardware transport)

- **WHEN** discovery runs a soft transport alongside a transport whose
  `kind()` is `Hid` and whose enumeration fails, and the soft transport
  finds nothing
- **THEN** `Error::NoDevice` carries one diagnostic per transport, the
  hid-registered one labeled `Hid` and the soft one labeled `Soft`

#### Scenario: Diagnostics with candidates present still report kind

- **WHEN** the failing transport's error is collected as an outcome
  diagnostic because another transport found a candidate
- **THEN** the diagnostic's kind equals the failing transport's
  `kind()` answer
