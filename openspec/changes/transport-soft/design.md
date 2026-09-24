# Design: transport-soft

**Phase: B** (soft-token transport, per the phased authoring plan; spec-authoring only — no code in this change).

The phase map lives in the cryptile workspace plan
(`.hermes/plans/2026-09-22-cleanroom-ctap2-library-specs.md`) until a local
one is authored for this repo.

## Architecture

The soft token is a plain Rust struct in a dedicated crate (e.g.
`fidoh-transport-soft`) implementing the same `Transport` and `Device` traits
defined by the async-core change that hardware transports (CTAPHID, PC/SC)
implement. It performs no I/O and no syscalls; all "wire" traffic is in-memory
CBOR request/response buffers, so the client stack exercises its real
CBOR encode/decode and error-mapping paths unchanged.

Two layers:

1. **Authenticator core** — pure state machine holding the credential store,
   a monotonically increasing global signature counter (CTAP2.1 §6.1.2
   recommends a global counter; the soft token uses one per the spec's
   "global signature counter" model, WebAuthn L2 §6.5 signCount semantics),
   the pinned AAGUID, and the configured behavior knobs. Methods correspond
   1:1 to CTAP2 commands: getInfo, makeCredential (internal), getAssertion.
2. **Transport shim** — the trait impl. Serializes command + CBOR map into
   the same request shape a hardware transport sends, feeds it to the core,
   and returns the CBOR response with a CTAP status byte (CTAP2.1 §8.2).
   This is where error injection, keepalive sequences, and delays hook in.

## Blocking waits and timeout bounds

- `require-explicit-poke` UP/UV mode: the authenticator returns
  `CTAP2_ERR_KEEPALIVE_CANCEL` if the caller cancels, otherwise it pends until
  an explicit `poke()` harness call or the **caller's ceremony deadline**
  expires — whichever comes first. There is no internal timer; the wait is
  bounded solely by the caller-provided deadline future (async-core timer
  trait). Bounded by: caller deadline.
- `delay-beyond-deadline` knob: the shim waits longer than the caller-provided
  deadline before responding, so the client-side timeout path is exercised.
  The shim's own wait is bounded by a hard internal cap of **deadline + 60 s**
  so a misconfigured test cannot hang CI forever. Bounded by: deadline + 60 s.
- All other commands respond synchronously (zero waits).

## makeCredential is internal-only

The client API v1 has no makeCredential. The soft token exposes
makeCredential only through a harness-facing method (e.g.
`SoftAuthenticator::make_credential(...)`) that test code calls directly to
mint credentials. The client-facing `Device` trait never routes to it.
Rationale: keeps the public surface matching the v1 scope while still letting
CI produce credential fixtures with real keys.

## Cryptography

- Keys: ECDSA P-256 (secp256r1) keypairs, generated per credential with a
  caller-supplied or default CSPRNG. Randomness source is injectable so
  conformance vectors are reproducible (deterministic RNG in fixtures only).
- Signatures: ECDSA over `authenticatorData || clientDataHash`, DER-encoded,
  per CTAP2.1 §6.2.2 step 5 and WebAuthn L2 §6.5.5.
- rpIdHash: SHA-256 of the RP ID, per WebAuthn L2 §6.1.
- COSE key encoding: `kty=2 (EC2)`, `alg=-7 (ES256)`, `crv=1 (P-256)`,
  `x`, `y` 32-byte coordinates — RFC 9052 §7, RFC 9053 §7.1. No `kid`,
  no key ops in the credential-source encoding.

## Alternatives considered

- **Replayed captured responses instead of live signing.** Rejected: cannot
  produce signatures over arbitrary caller-supplied clientDataHash values, so
  the client's signature-adjacent code paths would go untested; also raises
  cleanroom provenance questions for captured blobs.
- **Separate trait for the soft token.** Rejected: violates the stack
  invariant that soft and hardware transports share one trait; the whole
  point is exercising the hardware code path.
- **makeCredential via the public Device trait behind a feature flag.**
  Rejected: a feature flag is still public API surface; an internal harness
  method on the concrete type is invisible to client-API consumers.
- **Software crypto in pure Rust vs. ring/openssl.** Decision deferred to
  the implementation change; the spec only pins the algorithm (ES256/P-256),
  not the backend.

## Open questions

1. ~~Phase letter~~ — RESOLVED 2026-09-22: Phase B per the phased plan.
2. ~~Should keepalive injection emit the CTAPHID keepalive status byte or an
   NFC APDU "time extension"?~~ — RESOLVED 2026-09-22 (audit discharge): the
   spec deliberately keeps it abstract as a keepalive-event stream; the
   transport changes already answered the framing per transport
   (transport-hid: CTAPHID 0x01/0x02 status bytes per CTAP2.1 §11.2.9.1.7;
   transport-pcsc: APDU-layer progress signals). Nothing left to decide.
3. ~~Does the snapshot format need a version field for forward compatibility?
   Spec includes one; confirm serde format (JSON vs CBOR) at implementation.~~
   — RESOLVED 2026-09-22 (implementation crystallization): **JSON, version
   field `SNAPSHOT_VERSION = 1`, hex-encoded byte fields**, import of foreign
   versions is a typed rejection. serde/serde_json are behind the optional
   `snapshot` feature so the default build stays dependency-light.
4. ~~Implementation notes (2026-09-22)~~: pinned AAGUID is documented in
   docs/transport-soft.md as `b"fidoh-soft-token"` (16 ASCII bytes);
   default RNG is injectable build-salted deterministic (`RngSource`),
   `std` feature gates OS entropy; keepalive spacing and
   delay-beyond-deadline consume the caller's `Deadline` budget
   (budget-driven, not wall-clock) per async-core OQ-4; `getInfo` reports
   `uv: true` unless `up_mode`/`uv_mode` is `always-fail`; getNextAssertion
   drain is exposed as a `SoftDevice` harness method (client-side drain is
   ceremony-scope, not transport-scope).
