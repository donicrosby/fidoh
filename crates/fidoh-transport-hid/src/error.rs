//! Typed errors for the HID transport layer.
//!
//! House style (fidoh-core `error.rs`): manual `Display`, no thiserror
//! (std-only on MSRV 1.75), every variant structured. These are the
//! transport-internal taxonomies; anything leaving through the
//! [`Device`](fidoh_core::Device)/[`Transport`](fidoh_core::Transport)
//! traits folds into `fidoh_core::Error::Transport` via
//! [`HidError::into_core`].

use alloc::string::String;
use core::fmt;

/// A CTAPHID framing violation, as classified by the spec's own error
/// codes (§11.2.9.1.6) plus the host-side decode rules (§11.2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FramingError {
    /// A host-initiated message exceeded the §11.2.4 maximum of 7609
    /// bytes; rejected before any packet is written.
    MessageTooLong {
        /// The offending payload length.
        len: usize,
    },
    /// A received initialization packet's BCNT exceeded the 7609-byte
    /// message ceiling (§11.2.4).
    LengthBeyondMaximum {
        /// The BCNT value received.
        bcnt: usize,
    },
    /// A received packet was shorter than the 64-byte report the
    /// transport requires (§11.2.4).
    ShortReport {
        /// Bytes actually read.
        got: usize,
    },
    /// A received message's payload ran short: the init/continuation
    /// bytes delivered fewer than BCNT before the final expected
    /// packet (or more than BCNT arrived).
    LengthMismatch {
        /// BCNT announced by the initialization packet.
        expected: usize,
        /// Payload bytes actually accumulated.
        got: usize,
    },
    /// A continuation packet carried a SEQ other than the expected
    /// ascending value (§11.2.9.1.6 ERR_INVALID_SEQ). Carries the CID
    /// of the offending packet.
    InvalidSeq {
        /// The channel the packet arrived on.
        cid: u32,
        /// The sequence number received.
        got: u8,
        /// The sequence number expected.
        expected: u8,
    },
    /// The INIT response echoed a nonce other than the one sent
    /// (§11.2.9.1.3: the nonce "is used to match the response") — the
    /// reply may belong to another host contending for the device.
    NonceMismatch,
    /// The INIT response allocated channel 0 or 0xFFFFFFFF, both
    /// reserved (§11.2.3).
    ReservedCid {
        /// The reserved value the device returned.
        cid: u32,
    },
    /// The INIT response was shorter than the 17-byte layout
    /// (§11.2.9.1.3).
    InitResponseShort {
        /// BCNT received.
        got: usize,
    },
    /// The response's command byte did not match the command sent
    /// (e.g. a PING answered with something else) — treated as
    /// ERR_INVALID_CMD-class framing (§11.2.9.1.6).
    UnexpectedCommand {
        /// The command byte received (bit 7 stripped).
        got: u8,
        /// The command byte expected.
        expected: u8,
    },
    /// A keepalive or ERROR frame carried a payload length other than
    /// the 1 byte the spec fixes for it (§11.2.9.1.6/§11.2.9.1.7).
    UnexpectedBcnt {
        /// The command byte of the frame.
        cmd: u8,
        /// The BCNT received.
        got: usize,
    },
    /// A PING response did not echo the sent payload (§11.2.9.1.1:
    /// "the data sent in the request SHALL be returned").
    PingEchoMismatch,
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLong { len } => write!(
                f,
                "outgoing message payload {len} exceeds the CTAPHID maximum {MAX} bytes \
                 (CTAP2.1 §11.2.4)",
                MAX = crate::consts::MAX_MESSAGE_SIZE
            ),
            Self::LengthBeyondMaximum { bcnt } => {
                write!(
                    f,
                    "received BCNT {bcnt} exceeds the {MAX}-byte maximum (§11.2.4)",
                    MAX = crate::consts::MAX_MESSAGE_SIZE
                )
            }
            Self::ShortReport { got } => {
                write!(
                    f,
                    "short HID report: got {got} bytes, expected 64 (§11.2.4)"
                )
            }
            Self::LengthMismatch { expected, got } => {
                write!(f, "message length mismatch: BCNT announced {expected}, received {got} payload bytes")
            }
            Self::InvalidSeq { cid, got, expected } => write!(
                f,
                "continuation packet on channel 0x{cid:08X} has SEQ 0x{got:02X}, expected \
                 0x{expected:02X} (ERR_INVALID_SEQ, CTAP2.1 §11.2.9.1.6)"
            ),
            Self::NonceMismatch => write!(
                f,
                "INIT response echoed a different nonce (CTAP2.1 §11.2.9.1.3); another host \
                 may be allocating the device concurrently"
            ),
            Self::ReservedCid { cid } => write!(
                f,
                "device allocated reserved channel id 0x{cid:08X} (CTAP2.1 §11.2.3)"
            ),
            Self::InitResponseShort { got } => write!(
                f,
                "INIT response payload is {got} bytes, shorter than the 17-byte layout \
                 (CTAP2.1 §11.2.9.1.3)"
            ),
            Self::UnexpectedCommand { got, expected } => write!(
                f,
                "response command 0x{got:02X} does not match the command sent 0x{expected:02X} \
                 (CTAP2.1 §11.2.9.1.6 ERR_INVALID_CMD class)"
            ),
            Self::UnexpectedBcnt { cmd, got } => write!(
                f,
                "frame 0x{cmd:02X} carries BCNT {got}; the spec fixes its payload at 1 byte"
            ),
            Self::PingEchoMismatch => write!(
                f,
                "PING response did not echo the sent payload (CTAP2.1 §11.2.9.1.1)"
            ),
        }
    }
}

/// A CTAPHID_ERROR code (§11.2.9.1.6 table), total over 0x00–0xFF:
/// every named code is a distinct variant, everything else lands in
/// [`HidErrorCode::Unknown`] (the core-model total status posture).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HidErrorCode {
    /// 0x01 — the command in the request is invalid.
    InvalidCmd,
    /// 0x02 — the parameter(s) in the request are invalid.
    InvalidPar,
    /// 0x03 — the length field BCNT is invalid for the request.
    InvalidLen,
    /// 0x04 — the sequence does not match the expected value.
    InvalidSeq,
    /// 0x05 — the message has timed out.
    MsgTimeout,
    /// 0x06 — the device is busy for the requesting channel; the
    /// client SHOULD retry after a short delay (§11.2.9.1.6).
    ChannelBusy,
    /// 0x0A — command requires channel lock. fidoh never locks
    /// (§11.2.6), so this surfaces typed without retry.
    LockRequired,
    /// 0x0B — CID is not valid.
    InvalidChannel,
    /// 0x7F — unspecified error.
    Other,
    /// Any code outside the §11.2.9.1.6 table, carrying the raw byte.
    Unknown(u8),
}

impl HidErrorCode {
    /// Map a raw CTAPHID_ERROR code byte to its typed variant. Total:
    /// every value maps to a named variant or `Unknown(u8)`.
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            0x01 => Self::InvalidCmd,
            0x02 => Self::InvalidPar,
            0x03 => Self::InvalidLen,
            0x04 => Self::InvalidSeq,
            0x05 => Self::MsgTimeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            0x7F => Self::Other,
            other => Self::Unknown(other),
        }
    }

    /// The raw code byte. `Unknown(b)` round-trips to `b`.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::InvalidCmd => 0x01,
            Self::InvalidPar => 0x02,
            Self::InvalidLen => 0x03,
            Self::InvalidSeq => 0x04,
            Self::MsgTimeout => 0x05,
            Self::ChannelBusy => 0x06,
            Self::LockRequired => 0x0A,
            Self::InvalidChannel => 0x0B,
            Self::Other => 0x7F,
            Self::Unknown(b) => b,
        }
    }

    /// The spec name (e.g. `ERR_CHANNEL_BUSY`), `None` for unknown codes.
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::InvalidCmd => Some("ERR_INVALID_CMD"),
            Self::InvalidPar => Some("ERR_INVALID_PAR"),
            Self::InvalidLen => Some("ERR_INVALID_LEN"),
            Self::InvalidSeq => Some("ERR_INVALID_SEQ"),
            Self::MsgTimeout => Some("ERR_MSG_TIMEOUT"),
            Self::ChannelBusy => Some("ERR_CHANNEL_BUSY"),
            Self::LockRequired => Some("ERR_LOCK_REQUIRED"),
            Self::InvalidChannel => Some("ERR_INVALID_CHANNEL"),
            Self::Other => Some("ERR_OTHER"),
            Self::Unknown(_) => None,
        }
    }

    /// Whether this code is ERR_CHANNEL_BUSY — the one code the
    /// transport retries (bounded, §11.2.9.1.6 client-SHOULD-retry).
    pub fn is_channel_busy(self) -> bool {
        matches!(self, Self::ChannelBusy)
    }
}

impl fmt::Display for HidErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:02X})", self.to_u8()),
            None => write!(f, "unknown CTAPHID error code 0x{:02X}", self.to_u8()),
        }
    }
}

/// The HID transport's typed errors: framing, device-reported CTAPHID
/// errors, capability gating, and OS I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HidError {
    /// A CTAPHID framing violation on encode or decode.
    Framing(FramingError),
    /// The device answered with CTAPHID_ERROR (§11.2.9.1.6).
    Device(HidErrorCode),
    /// A capability-gated command (WINK per 0x01, CBOR per 0x04,
    /// §11.2.9.1.3) was requested but the device's capabilities byte
    /// does not advertise it; nothing was written to the device.
    UnsupportedOperation {
        /// Which capability the command needs.
        required: Capability,
    },
    /// The device's INIT capabilities byte set reserved bits
    /// (§11.2.9.1.3: unused bits MUST be zero from vendors). Recorded
    /// as metadata, non-fatal for CTAP2 use — surfaced here for
    /// diagnostics and the hardware probes.
    ReservedCapabilityBits {
        /// The reserved bits set (masked off the known bits).
        bits: u8,
    },
    /// The device does not advertise CAPABILITY_CBOR, so it cannot
    /// serve CTAP2 at all; connect fails typed (design D6).
    NoCbor,
    /// An OS-level I/O failure carrying the failing path and a
    /// human-readable errno description (docs/transport-hid.md
    /// diagnostics table: permission vs missing device).
    Io {
        /// The file involved (`/dev/hidrawN` or a sysfs path).
        path: String,
        /// What the operation was.
        op: &'static str,
        /// Human-readable cause (errno string).
        cause: String,
    },
}

impl HidError {
    /// Build an [`HidError::Io`] from path, operation, and cause.
    pub fn io(path: impl Into<String>, op: &'static str, cause: impl Into<String>) -> Self {
        Self::Io {
            path: path.into(),
            op,
            cause: cause.into(),
        }
    }

    /// Fold into the async-core taxonomy (`Error::Transport`).
    pub fn into_core(self) -> fidoh_core::Error {
        fidoh_core::Error::Transport(fidoh_core::TransportError::new(
            "hid",
            alloc::format!("{self}"),
        ))
    }
}

impl fmt::Display for HidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(e) => write!(f, "CTAPHID framing: {e}"),
            Self::Device(code) => write!(f, "device reported CTAPHID_ERROR {code} (§11.2.9.1.6)"),
            Self::UnsupportedOperation { required } => write!(
                f,
                "command requires capability {required:?}, not advertised by the device \
                 (CTAP2.1 §11.2.9.1.3); nothing written"
            ),
            Self::ReservedCapabilityBits { bits } => write!(
                f,
                "device capabilities byte sets reserved bits 0x{bits:02X} (§11.2.9.1.3: \
                 reserved bits MUST be zero from vendors)"
            ),
            Self::NoCbor => write!(
                f,
                "device does not advertise CAPABILITY_CBOR and cannot serve CTAP2 (design D6)"
            ),
            Self::Io { path, op, cause } => write!(f, "{op} {path}: {cause}"),
        }
    }
}

impl From<FramingError> for HidError {
    fn from(e: FramingError) -> Self {
        Self::Framing(e)
    }
}

/// The INIT-response capabilities bits (§11.2.9.1.3), exposed parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability(pub u8);

impl Capability {
    /// Whether the device implements CTAPHID_WINK (bit 0x01).
    pub fn wink(self) -> bool {
        self.0 & crate::consts::CAPABILITY_WINK != 0
    }

    /// Whether the device implements CTAPHID_CBOR — required for CTAP2.
    pub fn cbor(self) -> bool {
        self.0 & crate::consts::CAPABILITY_CBOR != 0
    }

    /// Whether the device does NOT implement CTAPHID_MSG (bit 0x08).
    /// v1 never uses CTAPHID_MSG; recorded as metadata only.
    pub fn nmsg(self) -> bool {
        self.0 & crate::consts::CAPABILITY_NMSG != 0
    }

    /// The reserved bits (any bit outside WINK|CBOR|NMSG).
    pub fn reserved_bits(self) -> u8 {
        self.0 & !crate::consts::CAPABILITY_KNOWN_MASK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    // Spec scenario: "Error codes map to typed variants" — every table
    // code maps to its distinct variant; unknown codes land in the
    // typed catch-all with the raw byte preserved.
    #[test]
    fn hid_error_codes_map_typed_total() {
        let named: &[(u8, HidErrorCode)] = &[
            (0x01, HidErrorCode::InvalidCmd),
            (0x02, HidErrorCode::InvalidPar),
            (0x03, HidErrorCode::InvalidLen),
            (0x04, HidErrorCode::InvalidSeq),
            (0x05, HidErrorCode::MsgTimeout),
            (0x06, HidErrorCode::ChannelBusy),
            (0x0A, HidErrorCode::LockRequired),
            (0x0B, HidErrorCode::InvalidChannel),
            (0x7F, HidErrorCode::Other),
        ];
        for (byte, want) in named {
            assert_eq!(HidErrorCode::from_u8(*byte), *want);
            assert_eq!(want.to_u8(), *byte);
            assert!(want.name().is_some());
        }
        for byte in [0x00u8, 0x07, 0x08, 0x0C, 0x50, 0xFF] {
            match HidErrorCode::from_u8(byte) {
                HidErrorCode::Unknown(raw) => assert_eq!(raw, byte),
                other => panic!("byte {byte:#04x} mapped to {other:?}, expected Unknown"),
            }
            assert_eq!(HidErrorCode::from_u8(byte).to_u8(), byte);
        }
        assert!(HidErrorCode::ChannelBusy.is_channel_busy());
        assert!(!HidErrorCode::Other.is_channel_busy());
    }

    // Capability bit accessors per §11.2.9.1.3.
    #[test]
    fn capability_bits_decode() {
        let caps = Capability(0x05); // WINK | CBOR
        assert!(caps.wink());
        assert!(caps.cbor());
        assert!(!caps.nmsg());
        assert_eq!(caps.reserved_bits(), 0);
        let caps = Capability(0x0D); // WINK | CBOR | NMSG
        assert!(caps.nmsg());
        assert_eq!(caps.reserved_bits(), 0);
        let caps = Capability(0x70);
        assert!(!caps.wink() && !caps.cbor() && !caps.nmsg());
        assert_eq!(caps.reserved_bits(), 0x70);
    }

    // Display of every error variant renders without panicking (house
    // total-posture check).
    #[test]
    fn all_error_displays_render() {
        let errs = [
            HidError::Framing(FramingError::MessageTooLong { len: 8000 }),
            HidError::Framing(FramingError::ShortReport { got: 3 }),
            HidError::Device(HidErrorCode::ChannelBusy),
            HidError::Device(HidErrorCode::Unknown(0x42)),
            HidError::UnsupportedOperation {
                required: Capability(0x01),
            },
            HidError::ReservedCapabilityBits { bits: 0x70 },
            HidError::NoCbor,
            HidError::io("/dev/hidraw0", "open", "Permission denied (os error 13)"),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
        // into_core folds into the async-core transport taxonomy.
        let core = errs[2].clone().into_core();
        assert!(matches!(core, fidoh_core::Error::Transport(_)));
        assert!(core.to_string().contains("ERR_CHANNEL_BUSY"));
    }
}
