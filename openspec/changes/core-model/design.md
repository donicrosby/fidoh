# Design: core-model

**Phase: A** (spec/document authoring only — no code in this change;
implementation tasks arrive in a later change set per config.yaml rules).

## Context

fidoh's v1 client surface is authenticatorGetAssertion plus
authenticatorGetInfo for capability probing (config.yaml, "CTAP2 surface
in scope"). Everything those ceremonies touch — request maps, response
maps, error codes, COSE keys — is CBOR. The CTAP2.1 specification
constrains that CBOR far more tightly than generic CBOR: it mandates a
canonical encoding form (CTAP2.1 §8) and a specific map-key tolerance
rule. This design records the decisions the `core-model` spec makes
about those constraints, the evidence each one rests on, and the points
the evidence does not settle (open questions).

## Decisions

### D1 — Strict canonical form on encode, SHOULD-reject on decode

CTAP2.1 §8: "All encoders MUST serialize CBOR in the CTAP2 canonical
CBOR encoding form without duplicate map keys. All decoders SHOULD
reject CBOR that is not validly encoded in the CTAP2 canonical CBOR
encoding form and SHOULD reject messages with duplicate map keys."

The spec therefore defines two decode postures:

- **Strict decode** (default for all authenticator→client responses we
  parse): reject non-canonical integers/lengths, indefinite-length
  items, tags (§8: "Tags as defined in Section 2.4 in [RFC8949] MUST NOT
  be present"), unsorted map keys, duplicate map keys, and nesting
  deeper than 4 levels (§8 nesting limit). Strict decode maps to typed
  errors, satisfying the "typed errors everywhere" invariant.
- **Tolerant decode** (opt-in, test/probing only): accept non-canonical
  encodings but still reject structurally invalid CBOR and duplicate
  keys. This exists because §8's decode rule is SHOULD, not MUST — a
  real-world authenticator may deviate, and the soft-token harness must
  be able to model such a device. Tolerant mode never changes
  *semantic* validation (required members, types), only encoding
  strictness.

Alternative considered: always-tolerant decode. Rejected — the spec's
SHOULD-reject is the safer default for a client that must not build
behavior on malformed wire data, and strictness is what makes the
software-token CI harness a meaningful counterparty.

### D2 — Unknown map keys MUST be ignored, never rejected

CTAP2.1 §8: "If map keys are present that an implementation does not
understand, they MUST be ignored." This is a hard MUST and applies in
both directions (we ignore unknown keys in authenticator responses; we
must also tolerate authenticators ignoring unknown keys we would never
send anyway). The spec makes unknown-key rejection a spec violation.
This rule composes with D1: strictness applies to *encoding form*, not
to *key membership*.

### D3 — getInfo/getAssertion models include every member, with optionality preserved

The spec tables transcribe CTAP2.1 §6.4 (getInfo response, keys
0x01–0x15, plus the option-ID table) and §6.2 (getAssertion request
0x01–0x07 and response 0x01–0x07) verbatim in structure — every member
kept, each marked Required or Optional exactly as the spec's
"Required?" column states. Optional members we never send (e.g.
`extensions` in v1) are still modeled so the type is total over the
spec surface; config.yaml's scope limits only which members v1 *uses*,
not which the model *represents*.

### D4 — Status codes modeled as one enum over the full 0x00–0xFF space

CTAP2.1 §8.2 defines the code space with named values, reserved ranges
(spec 0x00–0xDF, extension 0xE0–0xEF, vendor 0xF0–0xFF), and an explicit
rule that unknown codes (including vendor codes) "are not interoperable
and the platform SHOULD treat these errors as any other unknown error
codes." The spec requires a total mapping: every named code is a named
variant, and all unnamed values collapse into a typed
`Unknown(u8)`-style catch-all — never an untyped error. This satisfies
"typed errors everywhere" without pretending reserved values have
meaning.

### D5 — PIN/UV auth shapes are types only; clientPIN protocol is out of scope

Per config.yaml, clientPIN/UV protocols are a named v1 non-goal. But
`pinUvAuthParam` (0x06) and `pinUvAuthProtocol` (0x07) appear in the
getAssertion request (CTAP2.1 §6.2), and `pinUvAuthProtocols` appears in
getInfo (§6.4), so the *shapes* must exist in the model or the getInfo/
getAssertion tables would be incomplete. The spec defines:

- `pinUvAuthProtocol`: unsigned integer; value 1 = PIN/UV Auth Protocol
  One (CTAP2.1 §6.5.6), value 2 = Protocol Two (CTAP2.1 §6.5.7).
- `pinUvAuthParam`: byte string, the output of the abstract
  `authenticate(key, message)` operation (CTAP2.1 §6.5.4); for
  getAssertion it is `authenticate(pinUvAuthToken, clientDataHash)` (§6.2).

Nothing else of clientPIN — key agreement, shared secrets, retries,
pinUvAuthToken lifecycle — is modeled here. The abstract interface
(§6.5.4) is referenced only to explain what a pinUvAuthParam *is*, not
to specify how it is produced.

### D6 — COSE ES256 keys modeled per RFC 9053 §7.1.1

CTAP2 uses COSE_Key structures (e.g. getInfo `algorithms`, clientPIN
`keyAgreement`, credential public keys inside authData). For ES256 the
model pins: kty=EC2(2), alg=ES256(-7, RFC 9053 §2.1/Table 1 — ECDSA w/
SHA-256), crv=P-256(1), x and y as bstr with leading zeros preserved
(RFC 9053 §7.1.1). Both x and y are REQUIRED for public keys per
RFC 9053 §7.1.1.

## Blocking waits / timeouts

None. This change introduces no waits — it is a pure data-model spec.
(The config.yaml invariant "every blocking wait names its timeout bound"
is satisfied vacuously; ceremony-level waits belong to later transport/
ceremony changes.)

## Alternatives considered (summary)

- Always-tolerant CBOR decode — rejected (see D1).
- Modeling only the getInfo/getAssertion members v1 uses — rejected
  (see D3); partial models rot and invite silent drift from the spec.
- Splitting status codes into per-feature enums — rejected (see D4);
  CTAP2.1 §8.2 defines one flat code space shared by all commands.
- Excluding PIN/UV shapes entirely as out of scope — rejected (see D5);
  the shapes are load-bearing for the getAssertion/getInfo tables.

## Open questions

- **Q1 — Preferred-float handling on decode.** CTAP2.1 §8 says "The
  representations of any floating-point values are not changed" and
  treats float bit-width as part of the value's meaning, but the task
  brief (and common canonical-CBOR practice) speaks of "shortest-form
  floats." No CTAP2.1 message in scope (getInfo, getAssertion) uses
  floats, so the model defines float handling only as "preserve
  bit-width representation per §8" and flags any shortest-form float
  canonicalization as ungrounded in CTAP2.1 §8. Resolve before any
  future command that carries floats is spec'd. *Status: open; not
  load-bearing for v1.*
- **Q2 — Behavior when strict decode meets an authenticator that
  violates canonical form in the field.** §8's SHOULD gives us license
  to accept, but whether fidoh should fall back to tolerant decode
  automatically (vs. surfacing a typed `NonCanonicalEncoding` error) is
  a policy choice the standards do not settle. Default per this design:
  surface the typed error; fallback is caller-driven. *Status: open;
  recorded so the implementation change set decides consciously.*
- **Q3 — `certifications` (getInfo 0x13) map value shape.** CTAP2.1 §6.4
  types it as "Map" referencing "authenticator certifications"
  (§7.3) without fixing the value schema. The model treats values as
  opaque CBOR until §7.3 is spec'd in a later change. *Status: open;
  non-blocking — modeled as map with uninterpreted values.*
