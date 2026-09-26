# add-client-pin — clientPIN / pinUvAuth Support (Protocols 1 + 2)

## Why

Production relying parties (e.g. Vaultwarden with
`userVerification=preferred/required`) expect real user verification, and
the owner's daily key — a YubiKey 5C Nano on firmware 5.7.4 — has a FIDO2
PIN set with no built-in biometric verifier (`uv` unsupported in
practice for RP flows). On such a PIN-only authenticator, today's
`UvPolicy::Preferred` cannot ever reach user verification: v1 named
clientPIN/pinUvAuth a **non-goal** (openspec/config.yaml "CTAP2 surface
in scope (v1)"; ceremony proposal "Non-goals"), so `Preferred` without a
caller-held token silently degrades to the `Discouraged` wire shape
(`uv_effective = NotRequested`), the server's UV requirement is never
satisfiable, and the correct fix — prompting the user for their PIN and
performing the CTAP2.1 §6.5.5 key agreement — is unreachable. The
owner has overturned the non-goal for v2 (hardware day 2026-09-25 proved
the stack end to end against this exact key).

## What Changes

- Specify the **pinUvAuthToken acquisition flow** (CTAP2.1 §6.5.5): the
  ceremony MAY acquire a pinUvAuthToken when the caller supplies a
  PIN-provider handle and the getInfo probe advertises the
  `clientPin` and `pinUvAuthToken` option IDs with at least one
  mutually supported `pinUvAuthProtocols` entry: select the protocol
  (§6.5.5.4 — the authenticator's first-listed protocol on ties),
  `getKeyAgreement` (0x02), ECDH P-256 encapsulate, collect the PIN via
  the caller-owned provider, then `getPinToken` (0x05) or
  `getPinUvAuthTokenUsingPinWithPermissions` (0x09, with the `ga`
  permission and permissions RP ID per §6.5.5.7.2) — the latter when the
  token advertises the `pinUvAuthToken` option ID, the former as the
  CTAP2.0 fallback. Built-in-UV acquisition
  (`getPinUvAuthTokenUsingUvWithPermissions`, §6.5.5.7.3) is in scope
  as a future change; `uv=true` option-key flows keep today's shaping.
- Specify the **PIN-provider callback seam** (no_std): the caller
  supplies a handle implementing a `provide_pin` operation returning
  the UTF-8 PIN bytes; `fidoh-core` never reads stdin and never stores
  the PIN (error-diagnostics no-secrets rule extends to PIN material
  and to all derived keys: the shared secret, the pinUvAuthToken, and
  the pinToken NEVER appear in error text, logs, or Debug output).
- Specify **pinUvAuth protocols 1 and 2** (CTAP2.1 §6.5.6, §6.5.7):
  P-256 ECDH shared-secret (Z = x-coordinate), P1 KDF SHA-256(Z),
  P2 KDF HKDF-SHA-256 ×2 concatenated ("CTAP2 HMAC key" then "CTAP2
  AES key", salt = 32 zero bytes), AES-256-CBC encrypt/decrypt (P1:
  all-zero IV; P2: `iv ‖ ct` with a fresh random IV), and the
  `authenticate` MAC (P1: first 16 bytes of HMAC-SHA-256; P2: full
  32 bytes). Crypto via RustCrypto crates only — primitives are
  exactly what the house rule "never hand-rolled" mandates; the
  canonical CBOR layer stays hand-rolled.
- Specify the **§6.2 request shaping with a token**: `pinUvAuthParam =
  authenticate(pinUvAuthToken, clientDataHash)` and the matching
  `pinUvAuthProtocol` are sent; `options.uv` is NEVER set alongside
  them (§6.2 mutual exclusion, already enforced by core-model at
  encode time). `UvPolicy::Preferred` end-to-end: with a token the
  request carries real UV; with a PIN-set key and no provider, the
  typed error names the fix (supply a PIN provider) instead of a
  silent downgrade.
- Specify **typed PIN failure surface**: PIN retry counters surfaced
  typed (`getPINRetries` 0x01), incorrect-PIN as a distinct typed error
  carrying the remaining-retries count, PIN-not-set as a distinct typed
  error, and PIN-auth-blocked (0x34) as its own typed error naming the
  power-cycle requirement (CTAP2.1 §8.2, §6.5.5.7.2).
- Extend the **transport-soft harness**: model the clientPIN state
  machine (PIN set/unset, retry counter with decrement + lockout
  semantics, key-agreement echo verification of the selected protocol,
  encrypted pinUvAuthToken issuance, wrong-PIN → 0x31 with `pinRetries`
  in the response) so the full acquisition flow has a CI proof without
  hardware, using the same error-injection knob pattern as the rest of
  the harness.
- Bank **three API-friction fixes** with tests: `transport_kind()`
  stops hardcoding `TransportKind::Soft` (the `Transport` trait gains a
  `kind()` method so NoDevice diagnostics name the real transport);
  `CeremonyError` gains a `std`-gated `std::error::Error` impl (core
  stays no_std; MSRV-safe); fidoh-cli-ui's `UxDevice` keepalive-UX
  wrapper is exported as the reusable seam.
- Bump the **workspace version** 0.1.0-alpha.1 → 0.1.0-beta.1 across
  all crate manifests, inter-crate dependency fields, Cargo.lock, and
  README/docs version references (owner overturned the stay-alpha
  policy after hardware day).

## Impact

- Affected specs: `ceremony` (MODIFIED: ceremony inputs; ceremony
  sequence; error taxonomy — pinUvAuth acquisition and the typed PIN
  errors are added requirements), `async-core` (MODIFIED: Transport
  trait gains `kind()`), `transport-soft` (MODIFIED: clientPIN
  model + knobs), `fidoh-cli-ui` (MODIFIED: UxDevice export),
  `error-diagnostics` (MODIFIED: no-secrets rule extended to PIN
  material; new typed errors join the operator table docs/errors.md).
- Affected code: `fidoh-core` (crypto module, ceremony wiring, error
  variants, std-gated Error impl, Transport::kind), the three hardware
  transports' `kind()` impls, `fidoh-transport-soft` (clientPIN state
  machine), `fidoh-cli-ui` (export + version), all manifests + lock +
  docs. This change set lands spec AND implementation together as v2
  / 0.1.0-beta.1 (owner directive).
- Depends on: core-model (pinUvAuthParam/pinUvAuthProtocol wire shapes
  already modeled), ceremony (probe → build → exchange pipeline),
  async-core (budget, traits), transport-soft (harness), error-diagnostics
  (no-secrets rule).
- Downstream: none blocked; large blobs, hmac-secret, credential
  management remain future work (non-goals below).

## Non-goals

- authenticatorMakeCredential as client API (still harness-only).
- `getPinUvAuthTokenUsingUvWithPermissions` (§6.5.5.7.3, built-in-UV
  token acquisition), PIN set/change flows (`setPIN` 0x03, `changePIN`
  0x04 — the soft token sets its PIN via harness plumbing), UV retry
  counters (`getUVRetries` 0x07), `minPINLength` enforcement UI, and
  PIN complexity policy: the library surfaces authenticator policy
  errors typed but performs no policy of its own.
- Extensions (appid, hmac-secret, largeBlobs), credential management,
  bio enrollment — unchanged from v1 non-goals (ceremony proposal).
- Biometric or OS-mediated PIN entry: the PIN-provider seam is
  deliberately caller-owned; fidoh never collects secrets itself.
- `forcePINChange` handling beyond surfacing the typed
  `PinPolicyViolation` (0x37) the authenticator returns.
