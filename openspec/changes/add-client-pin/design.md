# add-client-pin — Design

## Phase

Phase D (spec + implementation, v2 / 0.1.0-beta.1): the owner directive
authorizes landing spec and code together in this change set — an
explicit departure from the v1 task rule ("implementation tasks arrive
in a later change set"), recorded here as the reason. Spec deltas below
remain the normative contract; the tasks list carries both authoring and
implementation items.

## Context

The ceremony pipeline (probe → capability-driven request construction →
§6.2 exchange) already carries `pinUvAuthParam`/`pinUvAuthProtocol` as
opaque caller-held inputs, and core-model types them (pin.rs). What is
missing is everything between "the caller holds a pinUvAuthToken" and
"the caller holds a YubiKey": the authenticatorClientPIN (0x06)
command flow of CTAP2.1 §6.5.5, the two pinUvAuth protocol
instantiations (§6.5.6, §6.5.7), a no_std-safe way for the caller to
supply the PIN, and typed errors for the PIN-specific failure modes.
Production servers (Vaultwarden) set `userVerification=preferred` or
`required`; the owner's YubiKey 5C Nano (fw 5.7.4) is PIN-only in
practice (`makeCredUvNotRqd=true`, no built-in UV), so `Preferred`
currently degrades to `Discouraged` and the server requirement can
never be met.

Cleanroom grounding: every protocol step below is cited to the FIDO
CTAP2.1 proposed standard (fido-client-to-authenticator-protocol-v2.1-ps,
§6.2, §6.5.5, §6.5.6, §6.5.7, §6.5.8, §8.2) — read from the spec text
during this change's authoring, per the allowed-evidence rule. The
`getPinToken` (0x05) and `getPinUvAuthTokenUsingPinWithPermissions`
(0x09) platform flows, the authenticator-side verification order
(decapsulate → verify → decrypt → compare → decrement), and the retry
semantics (decrement on each PIN-bearing attempt; 0x32 PIN_BLOCKED at
zero; 0x34 PIN_AUTH_BLOCKED after 3 consecutive mismatches requiring a
power cycle) are taken from those sections verbatim.

### OQ-9 (OPEN): the getAssertion pinUvAuthParam message bytes

The directive specifies `pinUvAuthParam = authenticate(pinUvAuthToken,
⟨32 zero bytes ‖ clientDataHash⟩)`. CTAP2.1 §6.2 and CTAP2.2 PS
(2025-07-14, checked during authoring) both define the getAssertion
message as `authenticate(pinUvAuthToken, clientDataHash)` — bare
clientDataHash, no prefix. The `32×` byte prefixes the specs DO define
(§6.5.8 PRF table) are `0xff` prefixes on OTHER commands'
clientPIN/largeBlobs/config PRF contexts, never zeros on getAssertion.
Per the cleanroom rule ("if it's not in a standards doc or our own wire
capture, it doesn't go in a spec"), the implementation follows the
published spec shape (bare clientDataHash) and centralizes the message
construction in ONE named function
(`pin_uv_auth_param_message()`) so a confirmed deviation is a one-line
change. Flagged in the change report for the owner to re-verify against
their capture. If the owner's hardware proves the zero-prefixed shape,
the fix is confined to that function plus the harness mirror.

## Decisions

### D1: Crypto lives in fidoh-core, as a `crypto` module; deps deviation documented

The pinUvAuth protocols need: P-256 ECDH, HKDF-SHA-256, HMAC-SHA-256,
SHA-256, AES-256-CBC. House rule: primitives are never hand-rolled.
The zero-runtime-deps invariant of fidoh-core is therefore DELIBERATELY
deviated from for exactly these five RustCrypto crates (plus sha2 which
is already in the graph via dev-deps/soft token):

| crate | pinned version | declared rust-version | notes |
|---|---|---|---|
| p256 | =0.13.2 | 1.65 | already in graph (0.13 dev-dep + soft token); adds the `ecdh` feature |
| hkdf | =0.12.4 | (none declared; builds on 1.75 — verified) | hkdf 0.13.x declares MSRV 1.85 — FORBIDDEN |
| hmac | =0.12.1 | (none declared; builds on 1.75 — verified) | hmac 0.13 declares 1.85 — FORBIDDEN |
| sha2 | =0.10.9 | (none declared; already resolved at 0.10.9) | 0.11 declares 1.85 — FORBIDDEN |
| aes | =0.8.4 | 1.56 | aes 0.9.x declares MSRV 1.85 — FORBIDDEN |
| cbc | =0.1.2 | 1.56 | cbc 0.2.x declares MSRV 1.85 — FORBIDDEN |

MSRV verification (performed during authoring with the real 1.75.0
toolchain): a probe crate with exactly these pins (`default-features =
false`, p256 features `ecdsa,sha256,alloc,arithmetic,ecdh`) compiles
clean under `cargo +1.75.0 check`. The lockfile keeps base64ct 1.7.3
and zeroize 1.8.2 (both post-1.75 releases are edition-2024); `cargo
update` must not float them — the committed Cargo.lock pins them and CI
builds `--locked`. Exact `=` pins in the manifest make the intent
survive lockfile regeneration. This analysis is recorded in the change
report; if a future MSRV bump is ever on the table, hkdf/aes/cbc 0.13+/
0.9+/0.2+ become available as a package.

Alternatives: (a) ring — std/C-toolchain backend, violates no_std and
the RustCrypto house rule; rejected. (b) put crypto in a new
fidoh-crypto crate — splits the pin.rs wire types from their only
consumer and adds a crate for one module; rejected for v2 (revisit if
the module grows). (c) hand-roll AES/HKDF — forbidden by the house
rule, full stop.

### D2: Protocol surface — one struct, two instantiations

```rust
// fidoh-core::crypto (sketch — normative behavior in the spec delta)
pub struct PinUvAuth { protocol: PinUvAuthProtocol, /* opaque keys */ }
impl PinUvAuth {
    pub fn encapsulate(&mut self, peer_cose_key: &CborValue) -> Result<(CborValue, Self), PinError>;
    pub fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8>;   // §6.5.6/§6.5.7
    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PinError>;
    pub fn encrypt(&mut self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PinError>;
}
```

- `encapsulate` generates the platform's ephemeral P-256 key pair,
  computes `sharedSecret = kdf(ecdh(Z))`, and returns the COSE_Key
  (`{1:2, 3:-25, -1:1, -2:x, -3:y}`, §6.5.6 getPublicKey — note alg
  **-25**, not ES256's -7; §6.5.5 requires the optional `alg` member
  present and no other optional parameters) plus the shared-secret
  holder. COSE emission goes through the existing canonical CBOR
  encoder (sorted keys, minimal lengths).
- P1: `kdf(Z) = SHA-256(Z)`; `encrypt/decrypt` = AES-256-CBC, all-zero
  IV, no padding (plaintexts are block-multiples by construction —
  16-byte pinHashEnc, 64-byte-padded PINs, 16/32-byte tokens);
  `authenticate` = HMAC-SHA-256 truncated to 16 bytes.
- P2: `kdf(Z) = HKDF-SHA-256(salt=0x00×32, IKM=Z, L=32,
  info="CTAP2 HMAC key") ‖ HKDF-SHA-256(same, info="CTAP2 AES key")`
  — two separate HKDF invocations over the same 32-byte PRK, NOT one
  L=64 invocation (spec note, §6.5.7); implemented as extract-once +
  two expands via `Hkdf::from_prk`. `encrypt` returns `iv ‖ ct` with a
  fresh random IV per message; `decrypt` splits after byte 16 and
  rejects inputs < 16 bytes; `authenticate` = full 32-byte
  HMAC-SHA-256.
- The 32-byte IV/entropy source for P2 encrypts: an injectable
  `RngSource`-style trait seam with a caller-supplied default; the soft
  harness injects its deterministic stream so CI is reproducible. Real
  callers (tokio example) get OS entropy via their own handle.

### D3: PIN-provider seam — caller-owned, no_std, single-shot

```rust
pub trait PinProvider {
    fn provide_pin(&mut self) -> Result<alloc::vec::Vec<u8>, PinSourceError>;
}
```

- The ceremony accepts `Option<PinProviderHandle>` (a `Box<dyn
  PinProvider + Send>`-shaped handle built by the caller, or
  `PinProvider::from_closure(...)`). `fidoh-core` NEVER reads stdin,
  never spawns UI, never caches the PIN beyond the single acquisition
  transaction; the handle is consumed (taken) once the token is
  acquired or the flow failed terminally.
- `PinSourceError` is caller-typed: the provider may fail (user
  cancelled the prompt) and that failure maps to
  `CeremonyError::PinProviderFailed` — distinct from authenticator
  errors, never silently swallowed, never retried implicitly (the
  caller re-runs).
- UTF-8 PIN bytes are used verbatim per §6.5.5.7.2 (the platform
  collects Unicode NFC; normalization/UX checks are the caller's job —
  the library enforces only the byte-level ≤ 63 bytes protocol bound,
  surfacing a typed `PinTooLong` client-side check BEFORE any device
  traffic, because the §6.5.5.5/§6.5.5.7.2 note says the platform
  collects the PIN first to avoid burning shared secrets/retries on
  NFC field removal).
- Zeroize-on-drop for PIN bytes and derived keys: the provider's
  returned buffer and every intermediate key live in a
  zeroizing container (RustCrypto `zeroize`, already in the graph).
- No-secrets rule (error-diagnostics) extends: `Debug`/`Display` of
  every pin-related type shows lengths, never bytes.

### D4: Ceremony wiring — acquisition as phases inside the existing pipeline

The acquisition flow runs between the mandatory probe (phase 4) and
request construction (phase 5), entirely within the SINGLE remaining
budget (async-core D4 — no independent timeouts; expiry anywhere names
the phase it expired in). New phases: `ClientPin` for every
authenticatorClientPIN (0x06) hop ( getKeyAgreement, getPINRetries,
token request). Order (§6.2.1 step 1.1.2.2 + §6.5.5.4 + §6.5.5.7.2):

1. Probe reports `clientPin=true`, `pinUvAuthToken` option, and
   `pinUvAuthProtocols = [p…]`.
2. Caller policy says UV is wanted (`Preferred`) AND a PIN provider is
   supplied AND the caller did not already hand over
   `pin_uv_auth` material (caller-held token keeps precedence — zero
   behavior change for existing callers).
3. Protocol selection: the caller MAY pin a protocol; default = the
   first entry of the authenticator's list that fidoh implements (1 or
   2), honoring the authenticator's preference order (§6.5.5.4 "the
   one listed first").
4. `getKeyAgreement` (0x02) → `encapsulate` the returned COSE_Key.
5. PIN via provider (collected BEFORE the shared secret is used for
   anything that could reset it — NFC note, §6.5.5.7.2 step 1).
6. Token request: `getPinUvAuthTokenUsingPinWithPermissions` (0x09)
   with `permissions = 0x02` (ga) and `rpId` = the ceremony's rpId
   when the `pinUvAuthToken` option ID is advertised; otherwise
   `getPinToken` (0x05), which grants the default mc+ga permissions
   (§6.5.5.7) — CTAP2.0-token fallback. `pinHashEnc = encrypt(shared,
   LEFT(SHA-256(PIN), 16))` per §6.5.6/§6.5.7 encrypt.
7. On 0x31 PIN_INVALID: the response MAY carry `pinRetries` (0x03);
   surface typed `CeremonyError::IncorrectPin { remaining_retries }`
   (Option — absent when the authenticator omits it). NEVER retried
   in-ceremony (owner decision mirrors ceremony OQ-1: no implicit
   retry; the caller may re-run with a fresh provider call).
8. Decrypt the token (`decrypt(shared, pinUvAuthToken)`), compute
   `pinUvAuthParam = authenticate(pinToken, clientDataHash)` — the
   message-construction question is OQ-9 above — and shape the
   request: keys 0x06+0x07 set, `options.uv` NEVER set (mutual
   exclusion by construction, re-checked by core-model encode).
9. `Preferred` WITHOUT provider on a PIN-set key (clientPin=true,
   pinUvAuthToken advertised or clientPin-only): typed error
   `CeremonyError::PinRequired` naming the fix ("supply a PIN
   provider; the authenticator has no built-in verifier"). This
   REPLACES the silent Discouraged degradation on keys that cannot
   honor UV any other way. Preferred WITHOUT provider on a key that
   advertises the `uv` capability keeps today's `options.uv = true`
   shaping (reported `uv_effective = UvOption`).
10. `UvPolicy::Discouraged` NEVER acquires a token — no PIN prompt is
    shown for a discouraged request (a prompt is user-facing work the
    policy did not ask for).

UvEffective gains `PinUvAuthToken` (token acquisition succeeded) as a
fourth posture; the outcome reports it like the others — never silent.

### D5: Typed error surface — taxonomy stays closed, four new variants

The ceremony taxonomy (ceremony spec "exactly these typed variants")
gains four, each carrying actionable structured context:

- `IncorrectPin { remaining_retries: Option<u8> }` — 0x31
  CTAP2_ERR_PIN_INVALID with the authenticator's retry count when
  offered (§6.5.5 response member 0x03; also read pro-actively via
  getPINRetries 0x01 when 0x31 arrives without the member).
- `PinBlocked` — 0x32 CTAP2_ERR_PIN_BLOCKED (retries exhausted; the
  authenticator demands a power cycle/reset per its own policy).
- `PinAuthBlocked` — 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED (3 consecutive
  mismatches; power cycle required, §6.5.5.7.2).
- `PinRequired` / `PinProviderFailed` — see D4/D3. (Two variants:
  "the authenticator needs a PIN and the caller gave no provider" vs
  "the caller's provider itself failed".)

Map: 0x31 → IncorrectPin (with retries fetch), 0x32 → PinBlocked,
0x34 → PinAuthBlocked — REMOVED from the previous UpRejected catch-all
(the 0x33/0x36/0x37/0x3C pinUvAuth-adjacent codes STAY in UpRejected;
0x35 PIN_NOT_SET maps to `PinRequired`-family: `PinNotSet` distinct
variant carrying `remaining: Option<u8>` — distinct from wrong-PIN per
the directive). The Display impls name the fix (power cycle for 0x34;
re-enter PIN for 0x31). docs/errors.md gains the rows.

Blocking waits: every new device hop (getKeyAgreement, getPINRetries,
token request) goes through the same `race(hop, sleep, deadline,
Phase::ClientPin)` bound as the probe — the single budget; the PIN
provider call itself is NOT bounded by fidoh (it is caller UI; the
budget keeps consuming — expiry while the provider is pending fails
the ceremony typed at the next hop, which is the honest model of "the
user took too long").

### D6: transport_kind() — the Transport trait gains kind()

ceremony.rs's `transport_kind()` hardcodes `TransportKind::Soft`
(documented v1 shortcut, ceremony OQ-6). The async-core `Transport`
trait gains:

```rust
fn kind(&self) -> TransportKind { TransportKind::Soft }  // default
```

with overrides: hid → `Hid`, pcsc → `Pcsc`, soft → `Soft`. The
discovery diagnostics path calls `transport.kind()` — NoDevice
diagnostics finally name the real layer on mixed-transport machines
(the CLI's "Transport Other(2148532330)" cosmetic noise from hardware
day is separate pcsc-internal work, untouched here). Default-bodied
trait methods are additive for all external implementors (no break).

### D7: std-gated std::error::Error for CeremonyError

`fidoh-core` stays `no_std`; on the `std` feature (new, default-off)
`CeremonyError`, `Error`, `DecodeError`, `EncodeError`,
`TransportError` implement `std::error::Error` (description via
Display; sources: none structured — the payloads are typed fields).
This is MSRV-safe (no `core::error::Error`, which needs 1.81) and
unblocks `anyhow`/`Box<dyn Error>` consumers (the tokio example's
error printing). `thiserror` stays out. The root facade re-exports the
feature as `std` (off by default; `default = ["soft"]` unchanged).

### D8: UxDevice export — move to fidoh-core? No: re-export

`UxDevice` is std-flavored CLI UX but its definition is runtime-free
and no_std-safe; fidoh-cli-ui is the terminal leaf, so nothing can
import from it — the example (authenticate_user.rs) had to copy-paste
the shape as `PromptOnTouch`. Decision: MOVE the struct to
`fidoh-core::device` (it is a plain `Device` wrapper over a `FnMut(u8)`
sink — no std, no runtime) and re-export from fidoh-cli-ui for source
compatibility. The closure bound stays `FnMut(u8) + Send`; core's
version is generic and test-covered; the CLI keeps its TouchPrompt
dedup implementation as the reference UX sink.

### D9: Soft-token clientPIN model

The soft authenticator gains a clientPIN state machine mirroring the
§6.5.5/§6.5.7.2 authenticator side:

- State: `pin: Option<PinSecret>` (LEFT(SHA-256(pin),16)), `retries:
  u8` (default 8), `consecutive_mismatches: u8`, per-protocol key
  agreement + pinUvAuthToken registers, `pin_uv_auth_protocols:
  Vec<u8>` advertised in getInfo (default `[2, 1]` = prefer 2).
- Harness plumbing `set_pin(pin)` / `clear_pin()` (the makeCredential-
  style internal path; NOT client API — matches the v1 non-goal on
  set/change flows).
- authenticatorClientPIN (0x06) becomes a real `CtapCommand` variant
  carrying the request model (subCommand, pinUvAuthProtocol,
  keyAgreement, pinHashEnc, permissions, rpId) with a strict CBOR
  encode through the existing canonical layer.
- Authenticator-side verification per §6.5.5.7.2: protocol echo check
  (unsupported → 0x02 CTAP1_ERR_INVALID_PARAMETER — the §6.5.5.4
  error for protocol mismatch), decapsulate the platform key
  (P-256 ECDH against the SAME RustCrypto primitives, in the soft
  crate which already depends on p256), verify the pinUvAuthParam MAC
  (protocol-exact: 16-byte truncated for P1, 32-byte for P2),
  decrypt pinHashEnc, compare against the stored LEFT(SHA-256), THEN
  decrement retries (spec order — decrement before compare), wrong
  PIN → 0x31 + pinRetries member, zero retries → 0x32, three
  consecutive mismatches → 0x34, success → reset retries to max,
  mint a fresh 32-byte token (P1: 32 of the allowed 16/32; P2: 32
  mandatory), return `encrypt(shared, token)` + the response carries
  keyAgreement echo when asked.
- Knob symmetry: `inject_status` (a) fires on clientPIN hops exactly
  as on getAssertion; new knob `wrong_protocol_echo` forces the token
  to accept-and-misbehave on protocol 2 so the CLIENT's protocol
  verification (token length/MAC truncation) is exercised.
- getInfo: advertises `clientPin: true`, `pinUvAuthToken: true`,
  `pinUvAuthProtocols` per config; `forcePINChange`, `minPINLength`
  optional knobs (default absent).

### D10: Version bump mechanics

Every crate manifest: `version = "0.1.0-beta.1"`; every inter-crate
path dependency gains `version = "0.1.0-beta.1"` (path deps with
version fields — the facade pattern requires it for future
crates.io-publication sanity); workspace `[workspace.package]`
versions flow through `edition.workspace`-style inheritance where
already used; Cargo.lock regenerated with `cargo update -w --precise`
discipline (base64ct/zeroize stay at 1.7.3/1.8.2); README badge and
docs version strings updated; fuzz/ crate version left alone (own
workspace, excluded).

## Blocking waits and their timeout bounds

| Wait | Bound |
|---|---|
| getKeyAgreement / getPINRetries / token-request hops (each a `Device::send`) | remaining ceremony budget; phase `ClientPin` |
| PIN provider call (caller UI) | NOT bounded by fidoh; the budget keeps consuming and expiry surfaces typed at the next hop |
| P2 IV generation | no wait (injectable RNG) |
| All previously existing waits | unchanged (ceremony design table) |

No new unbounded wait. An unbounded wait is a spec violation.

## Alternatives Considered

### A1: getPinToken (0x05) only — rejected

0x05 is "superseded" in CTAP2.1 and grants only the default mc+ga
permissions with no RP binding. Implementing ONLY it would break on
tokens that drop it. Implementing ONLY 0x09 would break CTAP2.0-only
tokens (YubiKey pre-5.12 CTAP2.0 builds in the wild). Both, selected by
the advertised `pinUvAuthToken` option ID, is the §6.2.1 flow.

### A2: Acquire via built-in UV first (§6.5.5.7.3 SHOULD chain) — deferred

The spec's platform SHOULD-try order is UV-token-then-PIN-token. The
owner's key (and the Vaultwarden-attributed deployment) is PIN-only;
UV-token acquisition additionally needs the §6.5.5.7.3 subcommand,
UV-retry modeling, and preferredPlatformUvAttempts — a meaningful
follow-up change (named non-goal above). The typed `PinRequired` error
keeps the door open without pretending UV exists.

### A3: Crypto in the soft-token crate only, ceremony takes precomputed params — rejected

That would ship a clientPIN ceremony that NO caller could actually use
without importing the soft token (a harness crate) — inverting the
harness/library relationship. The ceremony must own the protocol.

### A4: std::error::Error via a hand-written cfg(doctest) shim in consumers — rejected

Consumers hand-rolling `From<CeremonyError>` per-crate is exactly the
friction the directive banks; the gated impl is 15 lines.

### A5: UvPolicy::Preferred silently keeping the v1 degradation — rejected

That is the bug being fixed (the directive's motivating case).

## Open Questions

- OQ-9 (OPEN, owner verification): getAssertion pinUvAuthParam message
  — spec says bare `clientDataHash`; the directive's
  `⟨0x00×32 ‖ clientDataHash⟩` matches no FIDO-published table we can
  cite. Implemented per spec behind ONE function
  (`pin_uv_auth_param_message`); one-line change if the owner's
  capture proves otherwise. This is the single highest-priority
  hardware re-verification item.
- OQ-10 (RESOLVED, authoring): `getPinToken` vs 0x09 selection —
  resolved to `pinUvAuthToken`-option-driven (A1); the soft harness
  models both.
- OQ-11 (RESOLVED, authoring): retry-fetch on 0x31 without a
  `pinRetries` member — the typed error carries `None` and the ceremony
  does NOT spend an extra round-trip on getPINRetries implicitly (the
  caller can via the public API); a second probe would burn budget and
  touch the device again post-failure.
