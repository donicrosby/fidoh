//! Typed error taxonomy for the core model.
//!
//! Stack invariant (openspec/config.yaml): "Typed errors everywhere."
//! thiserror is intentionally not used: thiserror 1.x generates
//! `std::error::Error` impls (fails under `no_std`), and thiserror 2.x's
//! no_std path relies on `core::error::Error`, stabilized in Rust 1.81 —
//! beyond the workspace MSRV of 1.75. `Display` is implemented manually.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::status::StatusCode;
use crate::time::Phase;
use crate::transport::{CandidateDescriptor, DeviceId, TransportKind};

/// Decode posture over CTAP2.1 §8 (design D1).
///
/// §8's decode rule is a SHOULD, so strict is the default posture and
/// tolerant exists only for test/probing of deviant authenticators.
/// Tolerant decode changes *encoding-form* strictness only; semantic
/// validation (required members, member types) is identical in both
/// postures (core-model spec, "CBOR decode strictness policy").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DecodePolicy {
    /// Reject anything not in the CTAP2 canonical CBOR encoding form:
    /// non-minimal integers/lengths, indefinite-length items, tags,
    /// unsorted map keys, duplicate map keys, nesting beyond 4 levels,
    /// and structurally invalid CBOR (CTAP2.1 §8).
    #[default]
    Strict,
    /// Accept non-minimal integers/lengths and unsorted map keys; still
    /// reject structurally invalid CBOR, duplicate map keys,
    /// indefinite-length items, tags, and nesting beyond 4 levels.
    Tolerant,
}

impl DecodePolicy {
    /// Whether this posture rejects non-canonical encoding form.
    pub fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}

/// Errors produced while decoding CBOR or model structures.
///
/// Every variant carries structured context: a byte `offset` for wire
/// errors, and the CBOR member name for model errors.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodeError {
    /// Input ended before the current item was complete.
    UnexpectedEof {
        /// Byte offset where more input was required.
        offset: usize,
    },
    /// Bytes remained after the top-level CBOR item.
    TrailingBytes {
        /// Byte offset of the first trailing byte.
        offset: usize,
    },
    /// Structurally invalid CBOR (e.g. reserved additional-info values,
    /// break outside an indefinite item, simple values other than
    /// false/true/null).
    InvalidStructure {
        /// Byte offset of the offending initial byte.
        offset: usize,
        /// What was invalid.
        detail: &'static str,
    },
    /// Indefinite-length item (additional info 31). CTAP2.1 §8 requires
    /// definite-length items only; rejected in both postures.
    IndefiniteLength {
        /// Byte offset of the indefinite-length initial byte.
        offset: usize,
    },
    /// CBOR tag (major type 6). CTAP2.1 §8: "Tags as defined in Section
    /// 2.4 in [RFC8949] MUST NOT be present."
    TagNotAllowed {
        /// Byte offset of the tag initial byte.
        offset: usize,
        /// The tag number encountered.
        tag: u64,
    },
    /// Non-minimal integer or length encoding (strict decode only).
    /// CTAP2.1 §8 integer/length minimality rules. The core-model spec
    /// names this typed error `NonCanonicalEncoding`.
    NonCanonicalEncoding {
        /// Byte offset of the non-minimal item's initial byte.
        offset: usize,
    },
    /// Map keys out of canonical order (strict decode only).
    /// CTAP2.1 §8 sorted-map-keys rule.
    UnsortedKeys {
        /// Byte offset of the out-of-order key.
        offset: usize,
    },
    /// Duplicate map key. Rejected in both postures: CTAP2.1 §8's
    /// duplicate-key SHOULD-reject is a semantic ambiguity, not an
    /// encoding-form deviation (core-model spec scenario "Strict decode
    /// rejects duplicate map keys").
    DuplicateKey {
        /// Byte offset of the map containing the duplicate.
        offset: usize,
    },
    /// Nesting beyond 4 levels of maps/arrays (CTAP2.1 §8). Rejected in
    /// both postures.
    DepthLimitExceeded {
        /// Byte offset of the container that would exceed the limit.
        offset: usize,
    },
    /// Floating-point item encountered. No v1-scope CTAP2 message uses
    /// floats (design Q1); decoding them is unsupported.
    FloatNotSupported {
        /// Byte offset of the float initial byte.
        offset: usize,
    },
    /// A known map member carried a value of the wrong CBOR type. The
    /// unknown-key MUST-ignore rule (CTAP2.1 §8) does not excuse
    /// malformed known members.
    TypeMismatch {
        /// Name of the known member.
        member: &'static str,
        /// Expected CBOR type description.
        expected: &'static str,
    },
    /// A required map member was absent.
    MissingMember {
        /// Name of the required member.
        member: &'static str,
    },
    /// A member value violated a semantic constraint from the governing
    /// spec table (e.g. aaguid length, non-empty-if-present arrays,
    /// minimum integer values).
    InvalidValue {
        /// Name of the offending member.
        member: &'static str,
        /// Human-readable constraint description.
        detail: String,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { offset } => {
                write!(f, "unexpected end of input at byte offset {offset}")
            }
            Self::TrailingBytes { offset } => {
                write!(f, "trailing bytes after CBOR item at offset {offset}")
            }
            Self::InvalidStructure { offset, detail } => {
                write!(f, "invalid CBOR structure at offset {offset}: {detail}")
            }
            Self::IndefiniteLength { offset } => write!(
                f,
                "indefinite-length CBOR item at offset {offset} (CTAP2.1 §8: definite length only)"
            ),
            Self::TagNotAllowed { offset, tag } => write!(
                f,
                "CBOR tag {tag} at offset {offset} (CTAP2.1 §8: tags MUST NOT be present)"
            ),
            Self::NonCanonicalEncoding { offset } => write!(
                f,
                "non-canonical (non-minimal) integer or length at offset {offset} (CTAP2.1 §8)"
            ),
            Self::UnsortedKeys { offset } => write!(
                f,
                "map keys out of canonical order at offset {offset} (CTAP2.1 §8)"
            ),
            Self::DuplicateKey { offset } => {
                write!(f, "duplicate map key in map at offset {offset} (CTAP2.1 §8)")
            }
            Self::DepthLimitExceeded { offset } => write!(
                f,
                "CBOR nesting beyond 4 levels at offset {offset} (CTAP2.1 §8)"
            ),
            Self::FloatNotSupported { offset } => write!(
                f,
                "floating-point item at offset {offset} is not supported (no v1-scope CTAP2 message uses floats)"
            ),
            Self::TypeMismatch { member, expected } => {
                write!(f, "member '{member}' has wrong CBOR type; expected {expected}")
            }
            Self::MissingMember { member } => {
                write!(f, "required member '{member}' is missing")
            }
            Self::InvalidValue { member, detail } => {
                write!(f, "member '{member}' is invalid: {detail}")
            }
        }
    }
}

/// Errors produced while encoding a model to canonical CBOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The structure would require more than 4 nested map/array levels
    /// (CTAP2.1 §8 nesting limit); rejected before serialization.
    DepthLimitExceeded,
    /// Encoders MUST NOT emit duplicate map keys (CTAP2.1 §8); the
    /// supplied map contained one.
    DuplicateKey,
    /// The request model violates a wire rule from the governing
    /// command spec; carries the typed reason.
    InvalidRequest(InvalidRequest),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DepthLimitExceeded => {
                write!(f, "structure nests deeper than 4 levels (CTAP2.1 §8)")
            }
            Self::DuplicateKey => {
                write!(f, "map contains a duplicate key (CTAP2.1 §8)")
            }
            Self::InvalidRequest(reason) => write!(f, "invalid request: {reason}"),
        }
    }
}

/// Typed reasons a request model may be rejected before encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidRequest {
    /// CTAP2.1 §6.2: "Platforms MUST NOT include both 'uv' and
    /// pinUvAuthParam parameters in same request."
    UvOptionWithPinUvAuthParam,
    /// CTAP2.1 §6.2: "A platform MUST NOT send an empty allowList" —
    /// key 0x03 MUST be omitted instead.
    EmptyAllowList,
}

impl fmt::Display for InvalidRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UvOptionWithPinUvAuthParam => write!(
                f,
                "options.uv and pinUvAuthParam are mutually exclusive (CTAP2.1 §6.2)"
            ),
            Self::EmptyAllowList => write!(
                f,
                "empty allowList MUST be omitted, not sent (CTAP2.1 §6.2)"
            ),
        }
    }
}

/// The async-core transport/orchestration error taxonomy
/// (async-core spec, "Typed errors extending the existing error.rs house
/// style"; ceremony-layer mappings live in the ceremony change).
///
/// Distinct from the wire-level [`DecodeError`]/[`EncodeError`] pairs:
/// these variants surface at the `Transport`/`Device`/`Ceremony` trait
/// boundaries. Display is manual (thiserror is std-only on MSRV 1.75 —
/// see the module header).
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// A wait exceeded its deadline. Carries the ceremony phase that
    /// expired (async-core spec: single-budget timeout model — "Expiry
    /// at any hop SHALL return a typed `Error::Timeout` naming the
    /// ceremony phase").
    Timeout(Phase),
    /// Enumeration found multiple candidates and the caller's selection
    /// policy was `Fail` (the default). Carries every candidate so the
    /// caller can disambiguate (async-core spec: "ambiguity SHALL
    /// surface as a typed `AmbiguousDevice` error listing candidates";
    /// stack invariant: never silently pick).
    AmbiguousDevice(Vec<CandidateDescriptor>),
    /// The supplied device identifier did not match any candidate the
    /// transport currently enumerates.
    UnknownDevice(DeviceId),
    /// The transport or device failed an underlying I/O or framing
    /// operation. The boxed string carries transport-specific detail
    /// (never a bare string error at a call site — this is the payload).
    Transport(TransportError),
    /// The device closed the channel or disappeared mid-operation.
    DeviceGone,
    /// The channel identifier the device supplied on a previous
    /// operation is no longer valid (e.g. after cancellation and
    /// re-handshake, CTAP2.1 §11.2.3 channel lifetime).
    ChannelClosed,
    /// The transport rejected an operation on this device that another
    /// operation still holds (busy/locked, CTAP2.1 §11.2.5 arbitration,
    /// §11.2.6 channel locking semantics).
    Busy,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout(phase) => write!(f, "deadline exceeded during {phase} phase"),
            Self::AmbiguousDevice(candidates) => {
                write!(f, "multiple candidate devices; selection required:")?;
                for c in candidates {
                    write!(f, " {c}")?;
                }
                Ok(())
            }
            Self::UnknownDevice(id) => {
                write!(f, "no device matches identifier {id}")
            }
            Self::Transport(e) => write!(f, "transport I/O failure: {e}"),
            Self::DeviceGone => write!(f, "device disappeared mid-operation"),
            Self::ChannelClosed => write!(f, "device channel closed or no longer valid"),
            Self::Busy => write!(f, "device busy with another operation"),
        }
    }
}

/// Transport-specific I/O/framing failure detail.
///
/// `kind` names the transport layer (e.g. `"hid"`, `"pcsc"`, `"soft"`);
/// `detail` carries the human-readable cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportError {
    /// Which transport layer produced the failure.
    pub kind: &'static str,
    /// Human-readable cause (typed carriers are added per-transport in
    /// their own crates; core keeps the diagnostic string).
    pub detail: String,
}

impl TransportError {
    /// Build a transport error from its kind and human-readable cause.
    pub fn new(kind: &'static str, detail: String) -> Self {
        Self { kind, detail }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.detail)
    }
}

/// One per-transport discovery failure, as carried by
/// [`CeremonyError::NoDevice`] (ceremony spec: "`NoDevice` carrying
/// per-transport discovery errors... transport kind plus typed cause").
///
/// Diagnostics are also attached to a successful outcome
/// ([`GetAssertionOutcome::discovery_diagnostics`]
/// [crate::ceremony::GetAssertionOutcome]) when candidates were found
/// despite some transports failing — never silently dropped.
#[derive(Clone, Debug, PartialEq)]
pub struct DiscoveryDiagnostic {
    /// Which transport failed.
    pub kind: TransportKind,
    /// The typed discovery cause (async-core `Error` taxonomy).
    pub cause: Error,
}

impl DiscoveryDiagnostic {
    /// Pair a transport kind with its typed discovery cause.
    pub fn new(kind: TransportKind, cause: Error) -> Self {
        Self { kind, cause }
    }
}

impl fmt::Display for DiscoveryDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.cause)
    }
}

/// The ceremony-layer error taxonomy (ceremony spec: "exactly these
/// typed error variants"). Every ceremony failure is one of these
/// values — never a string, an untyped error, or a panic (stack
/// invariant). Display is implemented manually (house style: no
/// thiserror on MSRV 1.75, see the module header).
///
/// Mapping from authenticator status codes (CTAP2.1 §8.2 via
/// core-model), per the ceremony spec table:
///
/// | Status | Variant |
/// |---|---|
/// | 0x2E `NO_CREDENTIALS`, 0x22 `INVALID_CREDENTIAL` | [`CeremonyError::NoCredentials`] |
/// | 0x2F `USER_ACTION_TIMEOUT` | [`CeremonyError::UserActionTimeout`] |
/// | 0x2D `KEEPALIVE_CANCEL` | [`CeremonyError::UserCancelled`] |
/// | 0x27, 0x3B, 0x33, 0x34, 0x36, 0x37, 0x3C | [`CeremonyError::UpRejected`] |
/// | everything else | [`CeremonyError::Ctap`] |
#[derive(Clone, Debug, PartialEq)]
pub enum CeremonyError {
    /// Zero candidates across every transport. Carries one diagnostic
    /// per failing transport (empty when all transports enumerated
    /// cleanly but found nothing).
    NoDevice(Vec<DiscoveryDiagnostic>),
    /// More than one candidate under the default `Fail` policy (or a
    /// `Select(fn)` that declined every candidate): carries every
    /// candidate descriptor; `connect` is never invoked.
    AmbiguousDevice(Vec<CandidateDescriptor>),
    /// Authenticator-side user-action timeout (0x2F
    /// CTAP2_ERR_USER_ACTION_TIMEOUT) — distinct from
    /// [`CeremonyError::Timeout`], which is the caller's budget.
    UserActionTimeout,
    /// Pending keepalive cancelled (0x2D CTAP2_ERR_KEEPALIVE_CANCEL).
    UserCancelled,
    /// No credential on the authenticator matches (0x2E
    /// CTAP2_ERR_NO_CREDENTIALS, 0x22 CTAP2_ERR_INVALID_CREDENTIAL).
    /// Surfaced immediately; the ceremony never retries it.
    NoCredentials,
    /// UP/UV refused (0x27 OPERATION_DENIED, 0x3B UP_REQUIRED, and the
    /// pinUvAuthToken-related 0x33 PIN_AUTH_INVALID, 0x34
    /// PIN_AUTH_BLOCKED, 0x36 PUAT_REQUIRED, 0x37 PIN_POLICY_VIOLATION,
    /// 0x3C UV_BLOCKED).
    UpRejected,
    /// The caller's single ceremony budget expired; names the expired
    /// phase (async-core D4 single-budget model).
    Timeout(Phase),
    /// Transport I/O or framing failure (async-core `Error`
    /// taxonomy: `Transport`, `DeviceGone`, `ChannelClosed`, `Busy`,
    /// and response-decode failures).
    Transport(TransportError),
    /// Any other authenticator status, carrying the typed core-model
    /// status value (CTAP2.1 §8.2). Retriable codes (0x06 CHANNEL_BUSY,
    /// 0x3F UV_INVALID) surface here immediately — the ceremony never
    /// retries implicitly (design OQ-1, resolved).
    Ctap(StatusCode),
    /// The returned credential id is not in the caller's allow list
    /// (library-safety rule, design OQ-3). Display identifies the
    /// mismatch with truncated-safe ids; the full ids are carried here
    /// for typed consumers.
    CredentialMismatch {
        /// The credential id the authenticator returned.
        returned: Vec<u8>,
        /// The ids the caller's allow list permits.
        allowed: Vec<Vec<u8>>,
    },
}

impl CeremonyError {
    /// Map a device/transport [`Error`] onto the ceremony taxonomy.
    ///
    /// - `Timeout(phase)` keeps its phase;
    /// - `AmbiguousDevice` / `UnknownDevice` keep their payloads;
    /// - `Transport`, `DeviceGone`, `ChannelClosed`, and `Busy` fold
    ///   into [`CeremonyError::Transport`] (the async-core device-state
    ///   failures are transport-layer failures from the ceremony's
    ///   vantage; the cause text is preserved in the
    ///   [`TransportError`] detail).
    pub fn from_core(err: Error) -> Self {
        match err {
            Error::Timeout(phase) => Self::Timeout(phase),
            Error::AmbiguousDevice(candidates) => Self::AmbiguousDevice(candidates),
            Error::UnknownDevice(id) => Self::Transport(TransportError::new(
                "device",
                alloc::format!("no device matches identifier {id}"),
            )),
            Error::Transport(e) => Self::Transport(e),
            Error::DeviceGone => Self::Transport(TransportError::new(
                "device",
                String::from("device disappeared mid-operation"),
            )),
            Error::ChannelClosed => Self::Transport(TransportError::new(
                "device",
                String::from("device channel closed or no longer valid"),
            )),
            Error::Busy => Self::Transport(TransportError::new(
                "device",
                String::from("device busy with another operation"),
            )),
        }
    }

    /// Map a CTAP2 status byte (CTAP2.1 §8.2) to its typed ceremony
    /// error. `Ok` maps to `None` (success); every other byte maps to
    /// exactly one variant — no status byte reaches the caller
    /// untyped.
    pub fn from_status(status: StatusCode) -> Option<Self> {
        match status {
            StatusCode::Ok => None,
            StatusCode::NoCredentials | StatusCode::InvalidCredential => Some(Self::NoCredentials),
            StatusCode::UserActionTimeout => Some(Self::UserActionTimeout),
            StatusCode::KeepaliveCancel => Some(Self::UserCancelled),
            StatusCode::OperationDenied
            | StatusCode::UpRequired
            | StatusCode::PinAuthInvalid
            | StatusCode::PinAuthBlocked
            | StatusCode::PuatRequired
            | StatusCode::PinPolicyViolation
            | StatusCode::UvBlocked => Some(Self::UpRejected),
            other => Some(Self::Ctap(other)),
        }
    }
}

impl fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevice(diag) => {
                f.write_str("no authenticator found on any transport")?;
                if diag.is_empty() {
                    f.write_str(" (no transport reported an error)")
                } else {
                    for d in diag {
                        write!(f, "; {d}")?;
                    }
                    Ok(())
                }
            }
            Self::AmbiguousDevice(candidates) => {
                f.write_str("multiple candidate devices; selection required:")?;
                for c in candidates {
                    write!(f, " {c}")?;
                }
                Ok(())
            }
            Self::UserActionTimeout => {
                f.write_str("user action timed out on the authenticator (CTAP2_ERR_USER_ACTION_TIMEOUT)")
            }
            Self::UserCancelled => {
                f.write_str("pending operation cancelled (CTAP2_ERR_KEEPALIVE_CANCEL)")
            }
            Self::NoCredentials => {
                f.write_str("no credential on the authenticator matches the request (CTAP2_ERR_NO_CREDENTIALS)")
            }
            Self::UpRejected => {
                f.write_str("user presence/verification refused (CTAP2_ERR_OPERATION_DENIED, UP_REQUIRED, or pin/uv auth failure)")
            }
            Self::Timeout(phase) => write!(f, "ceremony budget exceeded during {phase} phase"),
            Self::Transport(e) => write!(f, "transport I/O failure: {e}"),
            Self::Ctap(status) => write!(f, "authenticator error: {status}"),
            Self::CredentialMismatch { returned, allowed } => write!(
                f,
                "returned credential id {} is not in the allow list ({})",
                hex_truncated(returned),
                HexIdList(allowed),
            ),
        }
    }
}

/// First-8-byte truncated-safe hex of an id (design OQ-3b: the
/// CredentialMismatch message identifies ids without printing whole
/// credential ids into logs).
fn hex_truncated(bytes: &[u8]) -> alloc::string::String {
    use alloc::fmt::Write as _;
    const PREFIX: usize = 8;
    let mut out = alloc::string::String::new();
    for b in bytes.iter().take(PREFIX) {
        let _ = write!(out, "{b:02x}");
    }
    if bytes.len() > PREFIX {
        let _ = write!(out, "…({} bytes)", bytes.len());
    }
    out
}

/// Comma-separated truncated-safe hex list (Display helper for
/// [`CeremonyError::CredentialMismatch`]).
struct HexIdList<'a>(&'a [Vec<u8>]);

impl fmt::Display for HexIdList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, id) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(&hex_truncated(id))?;
        }
        Ok(())
    }
}
