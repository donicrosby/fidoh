# Proposal: core-model

## Why

Every CTAP2 command, response, and error in fidoh flows through one data
model: the CTAP2 canonical CBOR wire encoding (CTAP2.1 §8), the
authenticatorGetInfo capability report (CTAP2.1 §6.4), the
authenticatorGetAssertion ceremony payload (CTAP2.1 §6.2), the status
code space (CTAP2.1 §8.2), the PIN/UV auth parameter shapes
(CTAP2.1 §6.5.4–§6.5.5), and the COSE key form for ES256 (RFC 9053 §7,
referenced by CTAP2.1). Getting these shapes wrong — or even loosely
decoding them — silently corrupts every higher-layer behavior that
depends on them. This change pins the model down in a spec before any
Rust is written, so that implementation phases have a single
authoritative, standards-cited contract to code against.

## What changes

- New capability spec `core-model` covering:
  - CTAP2 canonical CBOR encode/decode rules and the strict-vs-tolerant
    decode policy (CTAP2.1 §8), including unknown-map-key tolerance.
  - The authenticatorGetInfo response structure: every member, its CBOR
    key, type, and optionality (CTAP2.1 §6.4).
  - The authenticatorGetAssertion request and response structures:
    every parameter/member, key, type, and optionality (CTAP2.1 §6.2).
  - The full CTAP2 status/error code space as a Rust-enum-ready
    enumeration (CTAP2.1 §8.2).
  - The PIN/UV auth parameter shapes (`pinUvAuthParam`,
    `pinUvAuthProtocol`) as types only (CTAP2.1 §6.5.5); the clientPIN
    protocol itself is explicitly out of scope.
  - The COSE ES256 key representation (kty/alg/crv/x/y labels and
    values) per RFC 9053 §7.1.1 as used by CTAP2.

## Non-goals

- No Rust implementation — this is Phase A spec authoring; code lands in
  a later change set per config.yaml rules.
- authenticatorMakeCredential client API (out of scope for v1 per
  config.yaml).
- clientPIN/UV protocol operations, credential management, large blobs,
  hmac-secret (named Non-goals in config.yaml).
- Transport framing (CTAPHID, NFC APDU) — separate capability specs.
- Relying-party-side semantics: clientDataJSON construction, origin
  handling (RP boundary in config.yaml).

## Impact

- Establishes the canonical contract every later transport and ceremony
  spec cites.
- Flags any point not grounded in an allowed standards source as an
  open question in design.md, per the cleanroom rules in config.yaml.
