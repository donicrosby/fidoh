# core-model Specification

Core CTAP2 data model: canonical CBOR encoding rules, command/response
structures for authenticatorGetInfo and authenticatorGetAssertion, the
status code space, PIN/UV auth parameter shapes, and the COSE ES256 key
representation. All protocol claims cite the governing standard section.

## ADDED Requirements

### Requirement: CTAP2 canonical CBOR encoding

The library SHALL serialize every CTAP2 message in the CTAP2 canonical
CBOR encoding form defined by CTAP2.1 §8, with these properties:

| Rule | Requirement | Source |
|---|---|---|
| Integer minimality | Integers MUST be encoded as small as possible: 0–23 and −1–−24 in the same byte as the major type; 24–255 and −25–−256 with one uint8; 256–65535 and −257–−65536 with one uint16; 65536–4294967295 and −65537–−4294967296 with one uint32. | CTAP2.1 §8 |
| Length minimality | The expression of lengths in major types 2–5 MUST be as short as possible, following the integer rule. | CTAP2.1 §8 |
| Definite length only | Indefinite-length items MUST be made into definite-length items; no indefinite-length item may appear in an encoded message. | CTAP2.1 §8 |
| No tags | Tags as defined in RFC 8949 §2.4 MUST NOT be present. | CTAP2.1 §8 |
| Sorted map keys | Keys in every map MUST be sorted lowest to highest: lower major type first; then shorter encoded key first; then lower byte-wise lexical order. | CTAP2.1 §8 |
| No duplicate map keys | Encoders MUST NOT emit duplicate map keys. | CTAP2.1 §8 |
| Nesting depth | No more than 4 levels of nested CBOR maps/arrays in any message. | CTAP2.1 §8 |
| Floats | Floating-point representations are not changed by canonicalization; bit-width is part of the value's meaning. (No v1-scope message uses floats; see design.md Q1.) | CTAP2.1 §8 |

#### Scenario: Encoding a getInfo request map with multiple keys

- WHEN the library encodes a CBOR map containing an unsigned-integer key
  and a text-string key
- THEN the unsigned-integer key sorts before the text-string key because
  major type 0 precedes major type 3 (CTAP2.1 §8)
- AND every integer and length in the output uses the smallest permitted
  encoding
- AND the output contains no tags, no indefinite-length items, and no
  duplicate keys

#### Scenario: Encoding a nested structure at the depth limit

- WHEN the library encodes a message whose structure nests maps and
  arrays to 4 levels
- THEN the encoding succeeds
- AND any structure requiring a 5th level is rejected with a typed
  encoding error before serialization (CTAP2.1 §8)

### Requirement: CBOR decode strictness policy

The library SHALL provide two decode postures over CTAP2.1 §8:

1. **Strict decode (default)** — the decoder SHALL reject, with a typed
   error: non-minimally encoded integers or lengths; indefinite-length
   items; CBOR tags (RFC 8949 §2.4); unsorted map keys; duplicate map
   keys; nesting beyond 4 levels; and any structurally invalid CBOR.
   This implements CTAP2.1 §8's "All decoders SHOULD reject CBOR that is
   not validly encoded in the CTAP2 canonical CBOR encoding form and
   SHOULD reject messages with duplicate map keys."
2. **Tolerant decode (opt-in, test/probing only)** — the decoder SHALL
   accept non-canonical encodings (non-minimal integers/lengths,
   unsorted keys) but SHALL still reject structurally invalid CBOR,
   duplicate map keys, indefinite-length items that cannot be resolved
   to definite form, and nesting beyond 4 levels. Tolerant decode
   changes encoding-form strictness only; semantic validation (required
   members, member types) is identical in both postures.

#### Scenario: Strict decode rejects a non-canonical response

- WHEN an authenticator response encodes the integer 200 with a uint16
  argument (non-minimal per CTAP2.1 §8)
- THEN strict decode fails with a typed `NonCanonicalEncoding` error
- AND the same bytes decode successfully under tolerant decode with the
  same semantic value 200

#### Scenario: Strict decode rejects duplicate map keys

- WHEN a response map contains the same key twice
- THEN strict decode fails with a typed duplicate-key error (CTAP2.1 §8
  duplicate-key SHOULD-reject)
- AND tolerant decode also fails, because duplicate keys are a semantic
  ambiguity, not an encoding-form deviation

#### Scenario: CBOR nesting beyond the limit is rejected

- WHEN a message nests maps/arrays to a 5th level
- THEN both strict and tolerant decode fail with a typed depth-limit
  error (CTAP2.1 §8 nesting limit)

### Requirement: Unknown map key tolerance

When decoding any CBOR map, the library SHALL ignore keys it does not
understand and SHALL NOT reject a map solely because it contains unknown
keys, per CTAP2.1 §8: "If map keys are present that an implementation
does not understand, they MUST be ignored." This applies identically in
strict and tolerant decode postures: strictness governs encoding form,
never key membership.

#### Scenario: getInfo response with a newer, unknown member

- WHEN an authenticatorGetInfo response contains a member key not listed
  in this specification (e.g. one introduced by a later CTAP version)
- THEN decoding succeeds and the unknown member is ignored (CTAP2.1 §8)
- AND all known members are available to the caller with their decoded
  values

#### Scenario: Unknown key vs wrong type on a known key

- WHEN a response contains an unknown key with an arbitrary value
- THEN decoding succeeds (CTAP2.1 §8 unknown-key MUST-ignore)
- BUT WHEN a known key carries a value of the wrong CBOR type
- THEN decoding fails with a typed type-mismatch error, because the
  unknown-key rule does not excuse malformed known members

### Requirement: authenticatorGetInfo response structure

The library SHALL model the authenticatorGetInfo response (CTAP2.1 §6.4)
with exactly the members, CBOR keys, types, and optionality below.
`versions` and `aaguid` are Required; all other members are Optional.
The model SHALL preserve optionality exactly as the specification states
it, including members v1 never sends or consumes.

| Key | Member | CBOR type | Required? | Notes (CTAP2.1 §6.4) |
|---|---|---|---|---|
| 0x01 | versions | Array of strings | Required | e.g. "FIDO_2_1", "FIDO_2_0", "FIDO_2_1_PRE", "U2F_V2" |
| 0x02 | extensions | Array of strings | Optional | Supported extensions |
| 0x03 | aaguid | Byte string | Required | 16 bytes |
| 0x04 | options | Map (string → bool) | Optional | Option IDs per the option table below |
| 0x05 | maxMsgSize | Unsigned integer | Optional | Max message size |
| 0x06 | pinUvAuthProtocols | Array of unsigned integers | Optional | Decreasing authenticator preference; no duplicates; non-empty if present |
| 0x07 | maxCredentialCountInList | Unsigned integer | Optional | > 0 if present |
| 0x08 | maxCredentialIdLength | Unsigned integer | Optional | > 0 if present |
| 0x09 | transports | Array of strings | Optional | WebAuthn AuthenticatorTransport values; no duplicates; non-empty if present; unknown values tolerated |
| 0x0A | algorithms | Array of PublicKeyCredentialParameters | Optional | Ordered most- to least-preferred; no duplicates; non-empty if present |
| 0x0B | maxSerializedLargeBlobArray | Unsigned integer | Optional | ≥ 1024 if present |
| 0x0C | forcePINChange | Boolean | Optional | |
| 0x0D | minPINLength | Unsigned integer | Optional | Present iff clientPIN supported |
| 0x0E | firmwareVersion | Unsigned integer | Optional | |
| 0x0F | maxCredBlobLength | Unsigned integer | Optional | ≥ 32 if present |
| 0x10 | maxRPIDsForSetMinPINLength | Unsigned integer | Optional | Only if setMinPINLength supported |
| 0x11 | preferredPlatformUvAttempts | Unsigned integer (major type 0) | Optional | > 0 |
| 0x12 | uvModality | Unsigned integer (major type 0) | Optional | FIDORegistry §3.1 user verification methods |
| 0x13 | certifications | Map | Optional | Value shape unspecified here (design.md Q3) |
| 0x14 | remainingDiscoverableCredentials | Unsigned integer | Optional | |
| 0x15 | vendorPrototypeConfigCommands | Array of unsigned integers | Optional | May be empty |

#### Scenario: Minimal getInfo response decodes

- WHEN an authenticatorGetInfo response contains only `versions`
  (0x01) and `aaguid` (0x03)
- THEN decoding succeeds because all other members are Optional
  (CTAP2.1 §6.4)
- AND the model reports absent optional members as absent, not as
  defaults

#### Scenario: getInfo response missing a required member

- WHEN an authenticatorGetInfo response lacks `aaguid` (0x03)
- THEN decoding fails with a typed missing-required-member error,
  because `aaguid` is Required (CTAP2.1 §6.4)

### Requirement: authenticatorGetInfo option IDs

The library SHALL model the `options` (0x04) member of the
authenticatorGetInfo response as a map from option-ID string to boolean,
recognizing the option IDs defined by CTAP2.1 §6.4 with their defaults:
`plat` (default false), `rk` (false), `clientPin` (not supported),
`up` (true), `uv` (not supported), `pinUvAuthToken` (not supported),
`noMcGaPermissionsWithClientPin` (false), `largeBlobs` (not supported),
`ep` (not supported), `bioEnroll` (not supported),
`userVerificationMgmtPreview` (not supported), `uvBioEnroll` (not
supported), `authnrCfg` (not supported), `uvAcfg` (not supported),
`credMgmt` (not supported), `credentialMgmtPreview` (not supported),
`setMinPINLength` (not supported), `makeCredUvNotRqd` (false),
`alwaysUv` (not supported). An option ID absent from the map SHALL be
reported with its specification default. Unknown option-ID strings SHALL
be ignored per the unknown-map-key rule (CTAP2.1 §8).

#### Scenario: Absent option ID yields its specification default

- WHEN a getInfo `options` map contains `rk: true` but no `up` entry
- THEN the model reports `rk` as true and `up` as its default true
  (CTAP2.1 §6.4 option defaults)

#### Scenario: Unknown option ID is ignored

- WHEN a getInfo `options` map contains an unrecognized option-ID string
- THEN decoding succeeds and the unknown option is ignored (CTAP2.1 §8
  unknown-key MUST-ignore)

### Requirement: authenticatorGetAssertion request structure

The library SHALL model the authenticatorGetAssertion request
(CTAP2.1 §6.2) with exactly the parameters, CBOR keys, types, and
optionality below. `rpId` and `clientDataHash` are Required; all other
parameters are Optional. An empty `allowList` MUST NOT be sent — it MUST
be omitted instead (CTAP2.1 §6.2). The request MUST NOT include both
`options.uv` and `pinUvAuthParam` in the same message, and MUST NOT
include the `rk` option key (CTAP2.1 §6.2).

| Key | Parameter | CBOR type | Required? | Notes (CTAP2.1 §6.2) |
|---|---|---|---|---|
| 0x01 | rpId | String | Required | Relying party identifier (WebAuthn) |
| 0x02 | clientDataHash | Byte string | Required | Hash of serialized client data (WebAuthn) |
| 0x03 | allowList | Array of PublicKeyCredentialDescriptor | Optional | Omit if empty |
| 0x04 | extensions | CBOR map (extension ID → input) | Optional | |
| 0x05 | options | Map of authenticator options | Optional | Keys: `up` (bool, default true), `uv` (bool, default false, deprecated in CTAP2.1) |
| 0x06 | pinUvAuthParam | Byte string | Optional | `authenticate(pinUvAuthToken, clientDataHash)` |
| 0x07 | pinUvAuthProtocol | Unsigned integer | Optional | Selected PIN/UV protocol version |

#### Scenario: Minimal getAssertion request encodes

- WHEN the caller supplies only `rpId` and `clientDataHash`
- THEN the request encodes with exactly keys 0x01 and 0x02 in canonical
  order (CTAP2.1 §6.2, §8)

#### Scenario: Empty allowList is omitted, not sent

- WHEN the caller supplies an empty allowList
- THEN key 0x03 is absent from the encoded request (CTAP2.1 §6.2: "A
  platform MUST NOT send an empty allowList")

#### Scenario: uv option and pinUvAuthParam are mutually exclusive

- WHEN a request would carry both `options.uv` and `pinUvAuthParam`
  (0x06)
- THEN the library rejects the request before encoding with a typed
  invalid-request error (CTAP2.1 §6.2: "Platforms MUST NOT include both
  'uv' and pinUvAuthParam parameters in same request")

### Requirement: authenticatorGetAssertion response structure

The library SHALL model the authenticatorGetAssertion response
(CTAP2.1 §6.2) with exactly the members, CBOR keys, types, and
optionality below. `credential`, `authData`, and `signature` are
Required; all other members are Optional.

| Key | Member | CBOR type | Required? | Notes (CTAP2.1 §6.2) |
|---|---|---|---|---|
| 0x01 | credential | PublicKeyCredentialDescriptor | Required | Credential identifier used |
| 0x02 | authData | Byte string | Required | Signed-over contextual bindings (WebAuthn) |
| 0x03 | signature | Byte string | Required | Assertion signature (WebAuthn) |
| 0x04 | user | PublicKeyCredentialUserEntity | Optional | Identifiable info absent if UV not performed; `id` mandatory for discoverable credentials |
| 0x05 | numberOfCredentials | Integer | Optional | Defaults to 1; required when multiple credentials found and no display or UV/UP flags false |
| 0x06 | userSelected | Boolean | Optional | Defaults to false; MUST NOT be present when allowList was given, when numberOfCredentials > 1, or in getNextAssertion responses |
| 0x07 | largeBlobKey | Byte string | Optional | Present only if the credential has an associated largeBlobKey |

#### Scenario: Minimal getAssertion response decodes

- WHEN a response contains only `credential` (0x01), `authData` (0x02),
  and `signature` (0x03)
- THEN decoding succeeds; `numberOfCredentials` is reported as its
  default 1 and `userSelected` as its default false (CTAP2.1 §6.2)

#### Scenario: Response missing a required member fails

- WHEN a response lacks `signature` (0x03)
- THEN decoding fails with a typed missing-required-member error
  (CTAP2.1 §6.2)

#### Scenario: userSelected constraints are validated

- WHEN a response carries `userSelected: true` alongside
  `numberOfCredentials` greater than one
- THEN decoding fails with a typed invalid-response error, because
  `userSelected` MUST NOT be present in that case (CTAP2.1 §6.2)

### Requirement: CTAP2 status code space

The library SHALL model the complete CTAP2 status/error code space
(CTAP2.1 §8.2) as a single total enumeration: every named code below is
a distinct named variant, and every other value in 0x00–0xFF maps to a
typed unknown-code catch-all carrying the raw byte. Per CTAP2.1 §8.2,
values 0x00–0xDF are spec-reserved, 0xE0–0xEF are extension-specific,
0xF0–0xFF are vendor-specific, and vendor/unknown codes SHALL be treated
as any other unknown error. The enumeration is Rust-enum-ready as:

| Code | Name | Meaning (CTAP2.1 §8.2) |
|---|---|---|
| 0x00 | CTAP1_ERR_SUCCESS / CTAP2_OK | Successful response |
| 0x01 | CTAP1_ERR_INVALID_COMMAND | Not a valid CTAP command |
| 0x02 | CTAP1_ERR_INVALID_PARAMETER | Command included an invalid parameter |
| 0x03 | CTAP1_ERR_INVALID_LENGTH | Invalid message or item length |
| 0x04 | CTAP1_ERR_INVALID_SEQ | Invalid message sequencing |
| 0x05 | CTAP1_ERR_TIMEOUT | Message timed out |
| 0x06 | CTAP1_ERR_CHANNEL_BUSY | Channel busy; client SHOULD retry after a short delay |
| 0x0A | CTAP1_ERR_LOCK_REQUIRED | Command requires channel lock |
| 0x0B | CTAP1_ERR_INVALID_CHANNEL | Command not allowed on this cid |
| 0x11 | CTAP2_ERR_CBOR_UNEXPECTED_TYPE | Invalid/unexpected CBOR error |
| 0x12 | CTAP2_ERR_INVALID_CBOR | Error when parsing CBOR |
| 0x14 | CTAP2_ERR_MISSING_PARAMETER | Missing non-optional parameter |
| 0x15 | CTAP2_ERR_LIMIT_EXCEEDED | Limit for number of items exceeded |
| 0x17 | CTAP2_ERR_FP_DATABASE_FULL | Fingerprint database full |
| 0x18 | CTAP2_ERR_LARGE_BLOB_STORAGE_FULL | Large blob storage full |
| 0x19 | CTAP2_ERR_CREDENTIAL_EXCLUDED | Valid credential found in exclude list |
| 0x21 | CTAP2_ERR_PROCESSING | Lengthy operation in progress |
| 0x22 | CTAP2_ERR_INVALID_CREDENTIAL | Credential not valid for the authenticator |
| 0x23 | CTAP2_ERR_USER_ACTION_PENDING | Waiting for user interaction |
| 0x24 | CTAP2_ERR_OPERATION_PENDING | Lengthy operation in progress |
| 0x25 | CTAP2_ERR_NO_OPERATIONS | No request pending |
| 0x26 | CTAP2_ERR_UNSUPPORTED_ALGORITHM | Requested algorithm unsupported |
| 0x27 | CTAP2_ERR_OPERATION_DENIED | Not authorized for requested operation |
| 0x28 | CTAP2_ERR_KEY_STORE_FULL | Internal key storage full |
| 0x2B | CTAP2_ERR_UNSUPPORTED_OPTION | Unsupported option |
| 0x2C | CTAP2_ERR_INVALID_OPTION | Not a valid option for current operation |
| 0x2D | CTAP2_ERR_KEEPALIVE_CANCEL | Pending keepalive cancelled |
| 0x2E | CTAP2_ERR_NO_CREDENTIALS | No valid credentials provided |
| 0x2F | CTAP2_ERR_USER_ACTION_TIMEOUT | User action timeout occurred |
| 0x30 | CTAP2_ERR_NOT_ALLOWED | Continuation command (e.g. getNextAssertion) not allowed |
| 0x31 | CTAP2_ERR_PIN_INVALID | PIN invalid |
| 0x32 | CTAP2_ERR_PIN_BLOCKED | PIN blocked |
| 0x33 | CTAP2_ERR_PIN_AUTH_INVALID | pinUvAuthParam verification failed |
| 0x34 | CTAP2_ERR_PIN_AUTH_BLOCKED | PIN auth blocked; requires power cycle |
| 0x35 | CTAP2_ERR_PIN_NOT_SET | No PIN has been set |
| 0x36 | CTAP2_ERR_PUAT_REQUIRED | pinUvAuthToken required for the selected operation |
| 0x37 | CTAP2_ERR_PIN_POLICY_VIOLATION | PIN policy violation (currently minimum length) |
| 0x38 | (reserved) | Reserved for future use |
| 0x39 | CTAP2_ERR_REQUEST_TOO_LARGE | Request too large for authenticator memory |
| 0x3A | CTAP2_ERR_ACTION_TIMEOUT | Current operation timed out |
| 0x3B | CTAP2_ERR_UP_REQUIRED | User presence required |
| 0x3C | CTAP2_ERR_UV_BLOCKED | Built-in user verification disabled |
| 0x3D | CTAP2_ERR_INTEGRITY_FAILURE | Checksum did not match |
| 0x3E | CTAP2_ERR_INVALID_SUBCOMMAND | Subcommand invalid or not implemented |
| 0x3F | CTAP2_ERR_UV_INVALID | Built-in UV unsuccessful; platform SHOULD retry |
| 0x40 | CTAP2_ERR_UNAUTHORIZED_PERMISSION | Permissions parameter contains unauthorized permission |
| 0x7F | CTAP1_ERR_OTHER | Other unspecified error |
| 0xDF | CTAP2_ERR_SPEC_LAST | Spec-range last error (range marker) |
| 0xE0 | CTAP2_ERR_EXTENSION_FIRST | Extension-specific range start |
| 0xEF | CTAP2_ERR_EXTENSION_LAST | Extension-specific range end |
| 0xF0 | CTAP2_ERR_VENDOR_FIRST | Vendor-specific range start |
| 0xFF | CTAP2_ERR_VENDOR_LAST | Vendor-specific range end |

#### Scenario: Named code maps to its variant

- WHEN an authenticator returns status byte 0x2E
- THEN the library reports the typed `CTAP2_ERR_NO_CREDENTIALS` variant
  with the meaning "No valid credentials provided" (CTAP2.1 §8.2)

#### Scenario: Vendor-range code maps to the unknown catch-all

- WHEN an authenticator returns a status byte in 0xF0–0xFF other than a
  recognized range marker
- THEN the library reports the typed unknown-code catch-all carrying the
  raw byte, treating it as any other unknown error (CTAP2.1 §8.2: vendor
  codes "are not interoperable and the platform SHOULD treat these
  errors as any other unknown error codes")
- AND no value in 0x00–0xFF causes an untyped or panic path

### Requirement: PIN/UV auth parameter shapes

The library SHALL model the PIN/UV auth parameters as types only, per
CTAP2.1 §6.2 and §6.5.5:

- `pinUvAuthProtocol`: unsigned integer selecting the PIN/UV auth
  protocol. Value 1 denotes PIN/UV Auth Protocol One (CTAP2.1 §6.5.6);
  value 2 denotes PIN/UV Auth Protocol Two (CTAP2.1 §6.5.7). The value
  MUST be one the authenticator supports, as reported by the getInfo
  `pinUvAuthProtocols` (0x06) member (CTAP2.1 §6.5.5).
- `pinUvAuthParam`: byte string carrying the output of the abstract
  `authenticate(key, message)` operation (CTAP2.1 §6.5.4); in
  authenticatorGetAssertion it is `authenticate(pinUvAuthToken,
  clientDataHash)` (CTAP2.1 §6.2).

The clientPIN protocol itself — key agreement, shared-secret derivation,
pinUvAuthToken lifecycle, retries — is OUT of scope for this spec
(named non-goal in config.yaml); only the wire shapes are modeled.

#### Scenario: getAssertion request carries both PIN/UV parameters

- WHEN a getAssertion request includes `pinUvAuthParam` (0x06) as a byte
  string and `pinUvAuthProtocol` (0x07) as the unsigned integer 2
- THEN the model accepts both as typed values (byte string, protocol
  selector = Protocol Two per CTAP2.1 §6.5.7)

#### Scenario: pinUvAuthProtocol present without authenticator support is rejected at the ceremony layer

- WHEN a caller selects `pinUvAuthProtocol` 1 but the authenticator's
  getInfo `pinUvAuthProtocols` member does not list 1
- THEN the model records the mismatch so the ceremony layer can fail
  with a typed error, because the value MUST be supported by the
  authenticator (CTAP2.1 §6.5.5)

### Requirement: COSE ES256 key representation

The library SHALL model COSE_Key structures for ES256 as used by CTAP2
(e.g. getInfo `algorithms`, clientPIN `keyAgreement`, credential public
keys) with the parameter labels and values of RFC 9053 §7 and §7.1.1:

| Name | Label | CBOR type | Value for ES256 | Source |
|---|---|---|---|---|
| kty | 1 | int | 2 (EC2 — elliptic curve keys with x- and y-coordinate pair) | RFC 9053 §7, Table 17 |
| alg | 3 | int | −7 (ES256 — ECDSA with SHA-256) | RFC 9053 §2.1 (COSE algorithm registry value) |
| crv | −1 | int | 1 (P-256, a.k.a. secp256r1) | RFC 9053 §7.1, Table 18 |
| x | −2 | bstr | x-coordinate; leading-zero octets MUST be preserved | RFC 9053 §7.1.1 |
| y | −3 | bstr | y-coordinate; leading-zero octets MUST be preserved | RFC 9053 §7.1.1 |

For public keys, `crv`, `x`, and `y` SHALL be REQUIRED (RFC 9053
§7.1.1). The library SHALL reject a key whose curve and key type are
inconsistent, per RFC 9053 §7.1: "Applications MUST check that the curve
and the key type are consistent and reject a key if they are not."

#### Scenario: Well-formed ES256 public key decodes

- WHEN a COSE_Key map contains kty=2 (label 1), alg=−7 (label 3),
  crv=1 (label −1), and 32-byte bstr values for x (label −2) and y
  (label −3)
- THEN the model decodes it as an ES256 P-256 public key (RFC 9053
  §7.1.1)

#### Scenario: Inconsistent curve and key type rejected

- WHEN a COSE_Key declares kty=2 (EC2) but crv=6 (Ed25519, an OKP curve
  per RFC 9053 §7.1 Table 18)
- THEN decoding fails with a typed inconsistent-key error (RFC 9053
  §7.1 MUST-check rule)

#### Scenario: Missing y coordinate on a public key rejected

- WHEN a COSE_Key for an EC2 public key omits the y member (label −3)
- THEN decoding fails with a typed missing-required-member error,
  because crv, x, and y are REQUIRED for public keys (RFC 9053 §7.1.1)
