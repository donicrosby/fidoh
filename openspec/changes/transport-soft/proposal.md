# Proposal: transport-soft — in-process virtual CTAP2 authenticator

## Why

CI needs a deterministic, hardware-free authenticator so the client library's
ceremony logic (getInfo probing, getAssertion, timeouts, keepalive handling,
error mapping) can be exercised on every commit without physical devices. Per
the stack invariants, hardware transports and the software token implement the
SAME `Transport`/`Device` traits; this change specifies the software side.

## What changes

- New spec capability `transport-soft`: an in-process virtual CTAP2
  authenticator behind the async-core `Transport`/`Device` traits.
- `authenticatorGetInfo` with a pinned AAGUID, versions `FIDO_2_0` +
  `FIDO_2_1`, and options `rk`/`up`/`uv` (CTAP2.1 §6.4).
- `authenticatorMakeCredential` exposed as an INTERNAL harness operation only —
  never part of the client-facing API — that mints ES256 (P-256) keypairs and
  credential source records (CTAP2.1 §6.1; credential source fields per
  WebAuthn L2 §4).
- `authenticatorGetAssertion` producing real ECDSA P-256 signatures over
  `authenticatorData || clientDataHash` (CTAP2.1 §6.2.2 step 5;
  WebAuthn L2 §6.5).
- Full `authenticatorData` layout spec: rpIdHash (SHA-256), flags byte
  (UP=bit0, UV=bit2, AT=bit6, ED=bit7), 4-byte big-endian signCount, attested
  credential data only in makeCredential responses (WebAuthn L2 §6.5).
- COSE ES256 public-key encoding (alg -7, crv P-256) for credential sources
  (RFC 8152 §8, RFC 9053 §7).
- Configurable UP/UV behavior: auto-approve, always-fail, require-explicit-poke.
- Error-injection knobs: arbitrary CTAP status codes (CTAP2.1 §8.2), keepalive
  sequences before response, response delay beyond the caller deadline,
  wrong-credential-id responses.
- In-memory credential store plus an optional serde-serializable snapshot for
  test fixtures.
- `docs/transport-soft.md`: CI usage examples, knob table, conformance-vector
  generation.

## Non-goals

- clientPIN / UV protocols, credential management, large blobs, hmac-secret
  (project-wide v1 non-goals).
- Attestation certificate chains / packed or FIDO-U2F attestation formats;
  makeCredential uses `none` attestation only (WebAuthn L2 §6.5.4, §8.7).
- Resident-key enumeration APIs (authenticatorCredentialManagement).
- Any public client API surface for makeCredential.

## Impact

- New spec: `openspec/specs/transport-soft/` (via this change's delta).
- Depends on: async-core change (trait surface this implements).
- Enables: CI harness for all client-side ceremony specs.
