//! CTAP2 status code space (CTAP2.1 §8.2), modeled as one total
//! enumeration (design D4): every named code is a distinct named
//! variant; every other value in 0x00–0xFF maps to the typed
//! `Unknown(u8)` catch-all carrying the raw byte. Vendor and other
//! unknown codes are treated as any other unknown error, per §8.2:
//! "vendor error codes ... are not interoperable and the platform
//! SHOULD treat these errors as any other unknown error codes."

use core::fmt;

/// A CTAP2 status/response code (CTAP2.1 §8.2).
///
/// Total over 0x00–0xFF: `from_u8` never fails and no value takes an
/// untyped or panic path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StatusCode {
    /// 0x00 — CTAP1_ERR_SUCCESS / CTAP2_OK. Successful response.
    Ok,
    /// 0x01 — CTAP1_ERR_INVALID_COMMAND. Not a valid CTAP command.
    InvalidCommand,
    /// 0x02 — CTAP1_ERR_INVALID_PARAMETER. Command included an invalid
    /// parameter.
    InvalidParameter,
    /// 0x03 — CTAP1_ERR_INVALID_LENGTH. Invalid message or item length.
    InvalidLength,
    /// 0x04 — CTAP1_ERR_INVALID_SEQ. Invalid message sequencing.
    InvalidSeq,
    /// 0x05 — CTAP1_ERR_TIMEOUT. Message timed out.
    Timeout,
    /// 0x06 — CTAP1_ERR_CHANNEL_BUSY. Channel busy; the client SHOULD
    /// retry after a short delay.
    ChannelBusy,
    /// 0x0A — CTAP1_ERR_LOCK_REQUIRED. Command requires channel lock.
    LockRequired,
    /// 0x0B — CTAP1_ERR_INVALID_CHANNEL. Command not allowed on this
    /// channel.
    InvalidChannel,
    /// 0x11 — CTAP2_ERR_CBOR_UNEXPECTED_TYPE. Invalid/unexpected CBOR.
    CborUnexpectedType,
    /// 0x12 — CTAP2_ERR_INVALID_CBOR. Error when parsing CBOR.
    InvalidCbor,
    /// 0x14 — CTAP2_ERR_MISSING_PARAMETER. Missing non-optional
    /// parameter.
    MissingParameter,
    /// 0x15 — CTAP2_ERR_LIMIT_EXCEEDED. Limit for number of items
    /// exceeded.
    LimitExceeded,
    /// 0x17 — CTAP2_ERR_FP_DATABASE_FULL. Fingerprint database full.
    FpDatabaseFull,
    /// 0x18 — CTAP2_ERR_LARGE_BLOB_STORAGE_FULL. Large blob storage
    /// full.
    LargeBlobStorageFull,
    /// 0x19 — CTAP2_ERR_CREDENTIAL_EXCLUDED. Valid credential found in
    /// the exclude list.
    CredentialExcluded,
    /// 0x21 — CTAP2_ERR_PROCESSING. Lengthy operation in progress.
    Processing,
    /// 0x22 — CTAP2_ERR_INVALID_CREDENTIAL. Credential not valid for
    /// the authenticator.
    InvalidCredential,
    /// 0x23 — CTAP2_ERR_USER_ACTION_PENDING. Waiting for user
    /// interaction.
    UserActionPending,
    /// 0x24 — CTAP2_ERR_OPERATION_PENDING. Lengthy operation in
    /// progress.
    OperationPending,
    /// 0x25 — CTAP2_ERR_NO_OPERATIONS. No request pending.
    NoOperations,
    /// 0x26 — CTAP2_ERR_UNSUPPORTED_ALGORITHM. Requested algorithm
    /// unsupported.
    UnsupportedAlgorithm,
    /// 0x27 — CTAP2_ERR_OPERATION_DENIED. Not authorized for the
    /// requested operation.
    OperationDenied,
    /// 0x28 — CTAP2_ERR_KEY_STORE_FULL. Internal key storage full.
    KeyStoreFull,
    /// 0x2B — CTAP2_ERR_UNSUPPORTED_OPTION. Unsupported option.
    UnsupportedOption,
    /// 0x2C — CTAP2_ERR_INVALID_OPTION. Not a valid option for the
    /// current operation.
    InvalidOption,
    /// 0x2D — CTAP2_ERR_KEEPALIVE_CANCEL. Pending keepalive cancelled.
    KeepaliveCancel,
    /// 0x2E — CTAP2_ERR_NO_CREDENTIALS. No valid credentials provided.
    NoCredentials,
    /// 0x2F — CTAP2_ERR_USER_ACTION_TIMEOUT. User action timeout
    /// occurred.
    UserActionTimeout,
    /// 0x30 — CTAP2_ERR_NOT_ALLOWED. Continuation command (e.g.
    /// getNextAssertion) not allowed.
    NotAllowed,
    /// 0x31 — CTAP2_ERR_PIN_INVALID. PIN invalid.
    PinInvalid,
    /// 0x32 — CTAP2_ERR_PIN_BLOCKED. PIN blocked.
    PinBlocked,
    /// 0x33 — CTAP2_ERR_PIN_AUTH_INVALID. pinUvAuthParam verification
    /// failed.
    PinAuthInvalid,
    /// 0x34 — CTAP2_ERR_PIN_AUTH_BLOCKED. PIN auth blocked; requires
    /// power cycle.
    PinAuthBlocked,
    /// 0x35 — CTAP2_ERR_PIN_NOT_SET. No PIN has been set.
    PinNotSet,
    /// 0x36 — CTAP2_ERR_PUAT_REQUIRED. pinUvAuthToken required for the
    /// selected operation.
    PuatRequired,
    /// 0x37 — CTAP2_ERR_PIN_POLICY_VIOLATION. PIN policy violation
    /// (currently minimum length).
    PinPolicyViolation,
    /// 0x38 — Reserved for future use (CTAP2.1 §8.2).
    ReservedForFutureUse,
    /// 0x39 — CTAP2_ERR_REQUEST_TOO_LARGE. Request too large for
    /// authenticator memory.
    RequestTooLarge,
    /// 0x3A — CTAP2_ERR_ACTION_TIMEOUT. Current operation timed out.
    ActionTimeout,
    /// 0x3B — CTAP2_ERR_UP_REQUIRED. User presence required.
    UpRequired,
    /// 0x3C — CTAP2_ERR_UV_BLOCKED. Built-in user verification
    /// disabled.
    UvBlocked,
    /// 0x3D — CTAP2_ERR_INTEGRITY_FAILURE. Checksum did not match.
    IntegrityFailure,
    /// 0x3E — CTAP2_ERR_INVALID_SUBCOMMAND. Subcommand invalid or not
    /// implemented.
    InvalidSubcommand,
    /// 0x3F — CTAP2_ERR_UV_INVALID. Built-in user verification
    /// unsuccessful; the platform SHOULD retry.
    UvInvalid,
    /// 0x40 — CTAP2_ERR_UNAUTHORIZED_PERMISSION. Permissions parameter
    /// contains an unauthorized permission.
    UnauthorizedPermission,
    /// 0x7F — CTAP1_ERR_OTHER. Other unspecified error.
    Other,
    /// 0xDF — CTAP2_ERR_SPEC_LAST. Spec-range last error (range
    /// marker).
    SpecLast,
    /// 0xE0 — CTAP2_ERR_EXTENSION_FIRST. Extension-specific range
    /// start.
    ExtensionFirst,
    /// 0xEF — CTAP2_ERR_EXTENSION_LAST. Extension-specific range end.
    ExtensionLast,
    /// 0xF0 — CTAP2_ERR_VENDOR_FIRST. Vendor-specific range start.
    VendorFirst,
    /// 0xFF — CTAP2_ERR_VENDOR_LAST. Vendor-specific range end.
    VendorLast,
    /// Catch-all for every unnamed value in 0x00–0xFF, carrying the raw
    /// byte. Vendor-specific codes land here (§8.2: treat as any other
    /// unknown error) except the named range markers above.
    Unknown(u8),
}

impl StatusCode {
    /// Map a raw status byte to its typed variant. Total: every value
    /// in 0x00–0xFF maps to a named variant or `Unknown(u8)`.
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            0x00 => Self::Ok,
            0x01 => Self::InvalidCommand,
            0x02 => Self::InvalidParameter,
            0x03 => Self::InvalidLength,
            0x04 => Self::InvalidSeq,
            0x05 => Self::Timeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            0x11 => Self::CborUnexpectedType,
            0x12 => Self::InvalidCbor,
            0x14 => Self::MissingParameter,
            0x15 => Self::LimitExceeded,
            0x17 => Self::FpDatabaseFull,
            0x18 => Self::LargeBlobStorageFull,
            0x19 => Self::CredentialExcluded,
            0x21 => Self::Processing,
            0x22 => Self::InvalidCredential,
            0x23 => Self::UserActionPending,
            0x24 => Self::OperationPending,
            0x25 => Self::NoOperations,
            0x26 => Self::UnsupportedAlgorithm,
            0x27 => Self::OperationDenied,
            0x28 => Self::KeyStoreFull,
            0x2B => Self::UnsupportedOption,
            0x2C => Self::InvalidOption,
            0x2D => Self::KeepaliveCancel,
            0x2E => Self::NoCredentials,
            0x2F => Self::UserActionTimeout,
            0x30 => Self::NotAllowed,
            0x31 => Self::PinInvalid,
            0x32 => Self::PinBlocked,
            0x33 => Self::PinAuthInvalid,
            0x34 => Self::PinAuthBlocked,
            0x35 => Self::PinNotSet,
            0x36 => Self::PuatRequired,
            0x37 => Self::PinPolicyViolation,
            0x38 => Self::ReservedForFutureUse,
            0x39 => Self::RequestTooLarge,
            0x3A => Self::ActionTimeout,
            0x3B => Self::UpRequired,
            0x3C => Self::UvBlocked,
            0x3D => Self::IntegrityFailure,
            0x3E => Self::InvalidSubcommand,
            0x3F => Self::UvInvalid,
            0x40 => Self::UnauthorizedPermission,
            0x7F => Self::Other,
            0xDF => Self::SpecLast,
            0xE0 => Self::ExtensionFirst,
            0xEF => Self::ExtensionLast,
            0xF0 => Self::VendorFirst,
            0xFF => Self::VendorLast,
            other => Self::Unknown(other),
        }
    }

    /// The raw status byte for this variant. `Unknown(b)` round-trips
    /// to `b`.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Ok => 0x00,
            Self::InvalidCommand => 0x01,
            Self::InvalidParameter => 0x02,
            Self::InvalidLength => 0x03,
            Self::InvalidSeq => 0x04,
            Self::Timeout => 0x05,
            Self::ChannelBusy => 0x06,
            Self::LockRequired => 0x0A,
            Self::InvalidChannel => 0x0B,
            Self::CborUnexpectedType => 0x11,
            Self::InvalidCbor => 0x12,
            Self::MissingParameter => 0x14,
            Self::LimitExceeded => 0x15,
            Self::FpDatabaseFull => 0x17,
            Self::LargeBlobStorageFull => 0x18,
            Self::CredentialExcluded => 0x19,
            Self::Processing => 0x21,
            Self::InvalidCredential => 0x22,
            Self::UserActionPending => 0x23,
            Self::OperationPending => 0x24,
            Self::NoOperations => 0x25,
            Self::UnsupportedAlgorithm => 0x26,
            Self::OperationDenied => 0x27,
            Self::KeyStoreFull => 0x28,
            Self::UnsupportedOption => 0x2B,
            Self::InvalidOption => 0x2C,
            Self::KeepaliveCancel => 0x2D,
            Self::NoCredentials => 0x2E,
            Self::UserActionTimeout => 0x2F,
            Self::NotAllowed => 0x30,
            Self::PinInvalid => 0x31,
            Self::PinBlocked => 0x32,
            Self::PinAuthInvalid => 0x33,
            Self::PinAuthBlocked => 0x34,
            Self::PinNotSet => 0x35,
            Self::PuatRequired => 0x36,
            Self::PinPolicyViolation => 0x37,
            Self::ReservedForFutureUse => 0x38,
            Self::RequestTooLarge => 0x39,
            Self::ActionTimeout => 0x3A,
            Self::UpRequired => 0x3B,
            Self::UvBlocked => 0x3C,
            Self::IntegrityFailure => 0x3D,
            Self::InvalidSubcommand => 0x3E,
            Self::UvInvalid => 0x3F,
            Self::UnauthorizedPermission => 0x40,
            Self::Other => 0x7F,
            Self::SpecLast => 0xDF,
            Self::ExtensionFirst => 0xE0,
            Self::ExtensionLast => 0xEF,
            Self::VendorFirst => 0xF0,
            Self::VendorLast => 0xFF,
            Self::Unknown(b) => b,
        }
    }

    /// The specification name of this code (e.g.
    /// `CTAP2_ERR_NO_CREDENTIALS`), or `None` for unknown values.
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::Ok => Some("CTAP2_OK"),
            Self::InvalidCommand => Some("CTAP1_ERR_INVALID_COMMAND"),
            Self::InvalidParameter => Some("CTAP1_ERR_INVALID_PARAMETER"),
            Self::InvalidLength => Some("CTAP1_ERR_INVALID_LENGTH"),
            Self::InvalidSeq => Some("CTAP1_ERR_INVALID_SEQ"),
            Self::Timeout => Some("CTAP1_ERR_TIMEOUT"),
            Self::ChannelBusy => Some("CTAP1_ERR_CHANNEL_BUSY"),
            Self::LockRequired => Some("CTAP1_ERR_LOCK_REQUIRED"),
            Self::InvalidChannel => Some("CTAP1_ERR_INVALID_CHANNEL"),
            Self::CborUnexpectedType => Some("CTAP2_ERR_CBOR_UNEXPECTED_TYPE"),
            Self::InvalidCbor => Some("CTAP2_ERR_INVALID_CBOR"),
            Self::MissingParameter => Some("CTAP2_ERR_MISSING_PARAMETER"),
            Self::LimitExceeded => Some("CTAP2_ERR_LIMIT_EXCEEDED"),
            Self::FpDatabaseFull => Some("CTAP2_ERR_FP_DATABASE_FULL"),
            Self::LargeBlobStorageFull => Some("CTAP2_ERR_LARGE_BLOB_STORAGE_FULL"),
            Self::CredentialExcluded => Some("CTAP2_ERR_CREDENTIAL_EXCLUDED"),
            Self::Processing => Some("CTAP2_ERR_PROCESSING"),
            Self::InvalidCredential => Some("CTAP2_ERR_INVALID_CREDENTIAL"),
            Self::UserActionPending => Some("CTAP2_ERR_USER_ACTION_PENDING"),
            Self::OperationPending => Some("CTAP2_ERR_OPERATION_PENDING"),
            Self::NoOperations => Some("CTAP2_ERR_NO_OPERATIONS"),
            Self::UnsupportedAlgorithm => Some("CTAP2_ERR_UNSUPPORTED_ALGORITHM"),
            Self::OperationDenied => Some("CTAP2_ERR_OPERATION_DENIED"),
            Self::KeyStoreFull => Some("CTAP2_ERR_KEY_STORE_FULL"),
            Self::UnsupportedOption => Some("CTAP2_ERR_UNSUPPORTED_OPTION"),
            Self::InvalidOption => Some("CTAP2_ERR_INVALID_OPTION"),
            Self::KeepaliveCancel => Some("CTAP2_ERR_KEEPALIVE_CANCEL"),
            Self::NoCredentials => Some("CTAP2_ERR_NO_CREDENTIALS"),
            Self::UserActionTimeout => Some("CTAP2_ERR_USER_ACTION_TIMEOUT"),
            Self::NotAllowed => Some("CTAP2_ERR_NOT_ALLOWED"),
            Self::PinInvalid => Some("CTAP2_ERR_PIN_INVALID"),
            Self::PinBlocked => Some("CTAP2_ERR_PIN_BLOCKED"),
            Self::PinAuthInvalid => Some("CTAP2_ERR_PIN_AUTH_INVALID"),
            Self::PinAuthBlocked => Some("CTAP2_ERR_PIN_AUTH_BLOCKED"),
            Self::PinNotSet => Some("CTAP2_ERR_PIN_NOT_SET"),
            Self::PuatRequired => Some("CTAP2_ERR_PUAT_REQUIRED"),
            Self::PinPolicyViolation => Some("CTAP2_ERR_PIN_POLICY_VIOLATION"),
            Self::ReservedForFutureUse => Some("CTAP2_ERR_RESERVED_FOR_FUTURE_USE"),
            Self::RequestTooLarge => Some("CTAP2_ERR_REQUEST_TOO_LARGE"),
            Self::ActionTimeout => Some("CTAP2_ERR_ACTION_TIMEOUT"),
            Self::UpRequired => Some("CTAP2_ERR_UP_REQUIRED"),
            Self::UvBlocked => Some("CTAP2_ERR_UV_BLOCKED"),
            Self::IntegrityFailure => Some("CTAP2_ERR_INTEGRITY_FAILURE"),
            Self::InvalidSubcommand => Some("CTAP2_ERR_INVALID_SUBCOMMAND"),
            Self::UvInvalid => Some("CTAP2_ERR_UV_INVALID"),
            Self::UnauthorizedPermission => Some("CTAP2_ERR_UNAUTHORIZED_PERMISSION"),
            Self::Other => Some("CTAP1_ERR_OTHER"),
            Self::SpecLast => Some("CTAP2_ERR_SPEC_LAST"),
            Self::ExtensionFirst => Some("CTAP2_ERR_EXTENSION_FIRST"),
            Self::ExtensionLast => Some("CTAP2_ERR_EXTENSION_LAST"),
            Self::VendorFirst => Some("CTAP2_ERR_VENDOR_FIRST"),
            Self::VendorLast => Some("CTAP2_ERR_VENDOR_LAST"),
            Self::Unknown(_) => None,
        }
    }

    /// Whether this code indicates success (CTAP2_OK, 0x00).
    pub fn is_success(self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:02X})", self.to_u8()),
            None => write!(f, "unknown CTAP2 status code 0x{:02X}", self.to_u8()),
        }
    }
}

impl From<u8> for StatusCode {
    fn from(byte: u8) -> Self {
        Self::from_u8(byte)
    }
}

impl From<StatusCode> for u8 {
    fn from(code: StatusCode) -> Self {
        code.to_u8()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    // ------------------------------------------------------------------
    // Scenario: Named code maps to its variant
    // ------------------------------------------------------------------
    #[test]
    fn named_code_maps_to_its_variant() {
        // 0x2E -> CTAP2_ERR_NO_CREDENTIALS, "No valid credentials
        // provided" (CTAP2.1 §8.2).
        assert_eq!(StatusCode::from_u8(0x2E), StatusCode::NoCredentials);
        assert_eq!(
            StatusCode::NoCredentials.name(),
            Some("CTAP2_ERR_NO_CREDENTIALS")
        );
        assert_eq!(
            StatusCode::NoCredentials.to_string(),
            "CTAP2_ERR_NO_CREDENTIALS (0x2E)"
        );
        assert_eq!(StatusCode::NoCredentials.to_u8(), 0x2E);
        // Range-adjacent codes named by the core-model spec table.
        assert_eq!(StatusCode::from_u8(0x2D), StatusCode::KeepaliveCancel);
        assert_eq!(StatusCode::from_u8(0x2F), StatusCode::UserActionTimeout);
        assert_eq!(StatusCode::from_u8(0x00), StatusCode::Ok);
        assert!(StatusCode::Ok.is_success());
        assert!(!StatusCode::NoCredentials.is_success());
    }

    // ------------------------------------------------------------------
    // Scenario: Vendor-range code maps to the unknown catch-all
    // ------------------------------------------------------------------
    #[test]
    fn vendor_range_code_maps_to_unknown_catch_all() {
        // Vendor 0xF0–0xFF (excluding named markers), extension
        // 0xE0–0xEF (excluding markers), and plain unassigned values
        // all land in Unknown(u8) with the raw byte preserved.
        for byte in [0xF1u8, 0xFA, 0xFF - 1, 0xE5, 0xC0, 0x7E, 0x41, 0x29] {
            match StatusCode::from_u8(byte) {
                StatusCode::Unknown(raw) => assert_eq!(raw, byte),
                other => panic!("byte {byte:#04x} mapped to {other:?}, expected Unknown"),
            }
            assert_eq!(StatusCode::from_u8(byte).to_u8(), byte);
            // Unknown values display without panicking.
            let _ = StatusCode::from_u8(byte).to_string();
        }
        // Named range markers stay named even inside vendor/extension
        // ranges.
        assert_eq!(StatusCode::from_u8(0xF0), StatusCode::VendorFirst);
        assert_eq!(StatusCode::from_u8(0xFF), StatusCode::VendorLast);
        assert_eq!(StatusCode::from_u8(0xE0), StatusCode::ExtensionFirst);
        assert_eq!(StatusCode::from_u8(0xEF), StatusCode::ExtensionLast);
    }

    // Every value in 0x00–0xFF takes a typed path: from_u8 -> to_u8 is
    // the identity, and Display never panics (no untyped or panic path
    // anywhere in the space — core-model spec scenario requirement).
    #[test]
    fn full_status_space_is_total() {
        for byte in 0u8..=255 {
            let code = StatusCode::from_u8(byte);
            assert_eq!(code.to_u8(), byte, "round trip of {byte:#04x}");
            let _ = code.to_string();
        }
    }

    // Every code in the core-model §8.2 table is a distinct named
    // variant at exactly its specified byte.
    #[test]
    fn every_spec_named_code_is_a_distinct_variant() {
        let named: &[(u8, StatusCode)] = &[
            (0x00, StatusCode::Ok),
            (0x01, StatusCode::InvalidCommand),
            (0x02, StatusCode::InvalidParameter),
            (0x03, StatusCode::InvalidLength),
            (0x04, StatusCode::InvalidSeq),
            (0x05, StatusCode::Timeout),
            (0x06, StatusCode::ChannelBusy),
            (0x0A, StatusCode::LockRequired),
            (0x0B, StatusCode::InvalidChannel),
            (0x11, StatusCode::CborUnexpectedType),
            (0x12, StatusCode::InvalidCbor),
            (0x14, StatusCode::MissingParameter),
            (0x15, StatusCode::LimitExceeded),
            (0x17, StatusCode::FpDatabaseFull),
            (0x18, StatusCode::LargeBlobStorageFull),
            (0x19, StatusCode::CredentialExcluded),
            (0x21, StatusCode::Processing),
            (0x22, StatusCode::InvalidCredential),
            (0x23, StatusCode::UserActionPending),
            (0x24, StatusCode::OperationPending),
            (0x25, StatusCode::NoOperations),
            (0x26, StatusCode::UnsupportedAlgorithm),
            (0x27, StatusCode::OperationDenied),
            (0x28, StatusCode::KeyStoreFull),
            (0x2B, StatusCode::UnsupportedOption),
            (0x2C, StatusCode::InvalidOption),
            (0x2D, StatusCode::KeepaliveCancel),
            (0x2E, StatusCode::NoCredentials),
            (0x2F, StatusCode::UserActionTimeout),
            (0x30, StatusCode::NotAllowed),
            (0x31, StatusCode::PinInvalid),
            (0x32, StatusCode::PinBlocked),
            (0x33, StatusCode::PinAuthInvalid),
            (0x34, StatusCode::PinAuthBlocked),
            (0x35, StatusCode::PinNotSet),
            (0x36, StatusCode::PuatRequired),
            (0x37, StatusCode::PinPolicyViolation),
            (0x38, StatusCode::ReservedForFutureUse),
            (0x39, StatusCode::RequestTooLarge),
            (0x3A, StatusCode::ActionTimeout),
            (0x3B, StatusCode::UpRequired),
            (0x3C, StatusCode::UvBlocked),
            (0x3D, StatusCode::IntegrityFailure),
            (0x3E, StatusCode::InvalidSubcommand),
            (0x3F, StatusCode::UvInvalid),
            (0x40, StatusCode::UnauthorizedPermission),
            (0x7F, StatusCode::Other),
            (0xDF, StatusCode::SpecLast),
            (0xE0, StatusCode::ExtensionFirst),
            (0xEF, StatusCode::ExtensionLast),
            (0xF0, StatusCode::VendorFirst),
            (0xFF, StatusCode::VendorLast),
        ];
        for (byte, expected) in named.iter().copied() {
            assert_eq!(StatusCode::from_u8(byte), expected, "byte {byte:#04x}");
            assert_eq!(expected.to_u8(), byte);
            assert!(expected.name().is_some());
        }
        for (i, &(_, a)) in named.iter().enumerate() {
            for &(_, b) in named.iter().skip(i + 1) {
                assert_ne!(
                    core::mem::discriminant(&a),
                    core::mem::discriminant(&b),
                    "{a:?} and {b:?} share a variant"
                );
            }
        }
    }

    #[test]
    fn u8_conversions_round_trip() {
        assert_eq!(StatusCode::from(0x31u8), StatusCode::PinInvalid);
        assert_eq!(u8::from(StatusCode::PinInvalid), 0x31);
        // Unknown values survive both conversion directions.
        assert_eq!(StatusCode::from(0xAAu8), StatusCode::Unknown(0xAA));
        assert_eq!(u8::from(StatusCode::Unknown(0xAA)), 0xAA);
    }
}
