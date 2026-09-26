# add-client-pin — Tasks

Phase D (v2): spec authoring AND implementation land in this change
set (owner directive; the v1 documents-only task rule is superseded
for this change — see design.md Phase).

## 1. Spec authoring

- [x] 1.1 Author proposal.md (why/what/impact/non-goals; supersede the v1 non-goal explicitly)
- [x] 1.2 Author design.md (alternatives ledger; invariant-touching callouts: zero-deps deviation with MSRV table, non-goal supersession, OQ-9 pinUvAuthParam message discrepancy)
- [x] 1.3 Author spec deltas: ceremony (MODIFIED inputs/sequence/status table; ADDED protocols, PIN-provider seam, acquisition flow, transport kind), transport-soft (clientPIN state machine + knobs), async-core (Transport::kind), fidoh-cli-ui (UxDevice move), error-diagnostics (no-secrets extension, taxonomy extension, std-gated Error)
- [x] 1.4 Validate: `openspec validate add-client-pin --strict` green

## 2. Crypto module (fidoh-core::crypto)

- [x] 2.1 Add the six RustCrypto deps with exact pins and MSRV-verified feature sets (p256 =0.13.2 +ecdh, hkdf =0.12.4, hmac =0.12.1, sha2 =0.10.9, aes =0.8.4, cbc =0.1.2 +block-padding; default-features off); update the fidoh-core manifest comment (zero-deps invariant deviation per design D1)
- [x] 2.2 Implement `PinUvAuth` (encapsulate/authenticate/encrypt/decrypt) for protocols 1 and 2 per design D2; injectable RNG seam; zeroizing key material
- [x] 2.3 Unit tests: P1/P2 KDF vectors (HKDF cross-checked), COSE keyAgreement canonical bytes ({1:2, 3:-25, -1:1, -2, -3}), 16-vs-32-byte MAC truncation, zero-IV vs iv‖ct encrypt, malformed-decrypt typed errors, no-secrets Debug/Display
- [x] 2.4 `pin_uv_auth_param_message()` single-construction-point function (OQ-9) with the spec-cited shape and the discrepancy documented in place

## 3. Ceremony wiring

- [x] 3.1 Extend the ceremony input: `pin_provider` handle, optional pinned protocol; caller-held-material precedence
- [x] 3.2 Implement acquisition phases 1–6 (design D4) inside the single budget with `Phase::ClientPin`; protocol selection; getPinToken/0x09 selection by the pinUvAuthToken option
- [x] 3.3 Shape the §6.2 request with token material; never options.uv alongside; report `UvEffective::PinUvAuthToken`; implement `PinRequired` for Preferred-without-provider on PIN-only keys
- [x] 3.4 Typed errors: `IncorrectPin{remaining_retries}`, `PinBlocked`, `PinAuthBlocked`, `PinNotSet`, `PinRequired`, `PinProviderFailed`, `PinTooLong`; re-map 0x31/0x32/0x34/0x35 out of UpRejected/Ctap; Display texts name fixes
- [x] 3.5 Update docs/errors.md rows for the new variants

## 4. Transport-soft harness

- [x] 4.1 clientPIN state machine per transport-soft spec (PIN hash store, retries, mismatch counter, per-protocol KA + token registers, 0x01/0x02/0x05/0x09 subCommands, §6.5.5.7.2 verification order)
- [x] 4.2 Config/knobs: clientPIN feature flags, `wrong_protocol`, `pin_echo_decrypt`; generic status knob firing on clientPIN hops; getInfo advertisement
- [x] 4.3 `CtapCommand::ClientPin` request model with canonical CBOR encode/decode

## 5. CI-proof tests (scenario-ID named)

- [x] 5.1 fidoh-core tests/ceremony.rs additions: `pin_uv_acquisition_end_to_end_protocol_two`, `pin_uv_acquisition_get_pin_token_fallback_protocol_one`, `wrong_pin_surfaces_remaining_retries_and_decrements_once`, `pin_not_set_distinct_from_wrong_pin`, `pin_blocked_after_exhaustion`, `pin_auth_blocked_after_three_mismatches`, `preferred_without_provider_on_pin_only_key_names_fix`, `discouraged_never_prompts`, `caller_held_token_takes_precedence`, `pin_provider_failure_typed_no_device_traffic`, `oversized_pin_rejected_before_device_traffic`, `budget_expiry_mid_acquisition_names_client_pin`
- [x] 5.2 transport-soft tests: token-side state machine scenarios (getKeyAgreement echo, protocol mismatch 0x02, decrement-once semantics, three-strikes 0x34, knob (a) on clientPIN hops)
- [x] 5.3 Crypto unit vectors (2.3) pass; MSRV probe re-run recorded in the report

## 6. API-friction fixes

- [x] 6.1 `Transport::kind()` with default `Soft`; overrides in hid/pcsc/soft; ceremony discovery diagnostics use it; tests (mixed-kind NoDevice diagnostics)
- [x] 6.2 std-gated `std::error::Error` impls for the five public error types; `std` feature in fidoh-core + root facade; test under the feature
- [x] 6.3 Move `UxDevice` to `fidoh_core::device`; re-export from fidoh-cli-ui; example/test import from core

## 7. Version bump 0.1.0-beta.1

- [x] 7.1 All six crate manifests + root facade: version = 0.1.0-beta.1; inter-crate path deps gain version fields; Cargo.lock regenerated with base64ct 1.7.3 / zeroize 1.8.2 held
- [x] 7.2 README/docs version references updated

## 8. Gates

- [x] 8.1 `cargo fmt --all` clean
- [x] 8.2 `cargo clippy --workspace --all-targets -- -D warnings` clean
- [x] 8.3 `cargo test --workspace` green (including every 5.x test by name)
- [x] 8.4 `openspec validate add-client-pin --strict` green
- [x] 8.5 MSRV: `cargo +1.75.0 check --workspace` green (or documented conflict)
- [ ] 8.6 Report: change id, pinned versions + MSRV analysis, gate outputs, CI-workflow needs, owner hardware acceptance script
