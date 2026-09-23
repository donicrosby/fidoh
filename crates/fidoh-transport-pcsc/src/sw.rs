//! ISO 7816-4 status words (SW1SW2), typed per the transport-pcsc
//! spec's error-mapping table. Pure decoding — no library context.
//!
//! The spec's mapping table is total over 0x0000–0xFFFF: named
//! variants for the SWs the spec singles out, plus [`StatusWord::Warn`]
//! (62xx other than 6283), [`StatusWord::MoreData`]/[`StatusWord::
//! WrongLe`] parameterized forms, and [`StatusWord::Other`] carrying
//! the raw pair. Nothing reaches the caller untyped.

use core::fmt;

/// A raw ISO 7816-4 status word pair (SW1 || SW2).
pub type RawSw = [u8; 2];

/// A typed ISO 7816-4 status word (transport-pcsc spec, error-mapping
/// table rows "SELECT: …" through "Other ISO 7816-4 error SW").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StatusWord {
    /// `9000` — success.
    Ok,
    /// `61xx` — more data available; xx bytes remain (ISO 7816-4;
    /// triggers the GET RESPONSE procedure, INS 0xC0).
    MoreData(u8),
    /// `6Cxx` — wrong Le; retry once with Le = xx (ISO 7816-4).
    WrongLe(u8),
    /// `6A82` — file/applet not found: SELECT's not-FIDO skip
    /// (CTAP2.1 §11.3.3 semantics; ISO 7816-4 file-not-found).
    NotFound,
    /// `6985` — conditions of use not satisfied: SELECT's typed skip
    /// with the `condition` qualifier.
    ConditionsNotSatisfied,
    /// `6283` — selected file invalidated: SELECT's typed skip with
    /// the `invalidated` qualifier (applet present but unusable this
    /// power cycle).
    FileInvalidated,
    /// `6986` — command not allowed: typed `sw` Transport error.
    NotAllowed,
    /// `6D00` — instruction not supported: typed `sw` Transport
    /// error. Kept distinct from `6986` so round-trips preserve the
    /// exact SW (both map to the same `sw` cause in the error
    /// table).
    NotAllowed6D00,
    /// `9100` — status update available (CTAP2.1 §11.3.5.2); the
    /// NFCCTAP_GETRESPONSE loop (§11.3.7.2) consumes it.
    StatusUpdate,
    /// Any other `62xx` warning: typed `Transport` error with the SW
    /// attached (the transport does not guess semantics ISO 7816-4
    /// leaves implementation-specific).
    Warn(u8),
    /// Any other status word: typed `sw` Transport error carrying the
    /// raw SW.
    Other(RawSw),
}

impl StatusWord {
    /// Decode a SW from the final two response bytes.
    pub fn from_slice(tail: &[u8]) -> Option<Self> {
        let (sw1, sw2) = match tail {
            [.., sw1, sw2] => (*sw1, *sw2),
            _ => return None,
        };
        Some(Self::from_pair(sw1, sw2))
    }

    /// Decode a typed SW from its two bytes.
    pub fn from_pair(sw1: u8, sw2: u8) -> Self {
        match (sw1, sw2) {
            (0x90, 0x00) => Self::Ok,
            (0x61, n) => Self::MoreData(n),
            (0x6C, n) => Self::WrongLe(n),
            (0x6A, 0x82) => Self::NotFound,
            (0x69, 0x85) => Self::ConditionsNotSatisfied,
            (0x62, 0x83) => Self::FileInvalidated,
            (0x69, 0x86) => Self::NotAllowed,
            (0x6D, 0x00) => Self::NotAllowed6D00,
            (0x91, 0x00) => Self::StatusUpdate,
            (0x62, n) => Self::Warn(n),
            (sw1, sw2) => Self::Other([sw1, sw2]),
        }
    }

    /// The raw SW bytes this variant represents.
    pub fn to_pair(self) -> RawSw {
        match self {
            Self::Ok => [0x90, 0x00],
            Self::MoreData(n) => [0x61, n],
            Self::WrongLe(n) => [0x6C, n],
            Self::NotFound => [0x6A, 0x82],
            Self::ConditionsNotSatisfied => [0x69, 0x85],
            Self::FileInvalidated => [0x62, 0x83],
            Self::NotAllowed => [0x69, 0x86],
            Self::NotAllowed6D00 => [0x6D, 0x00],
            Self::StatusUpdate => [0x91, 0x00],
            Self::Warn(n) => [0x62, n],
            Self::Other(pair) => pair,
        }
    }

    /// Whether the SW is `9000` (success).
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Whether the SW is one of SELECT's three typed skips
    /// (`6A82`, `6985`, `6283`).
    pub fn is_select_skip(self) -> bool {
        matches!(
            self,
            Self::NotFound | Self::ConditionsNotSatisfied | Self::FileInvalidated
        )
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [sw1, sw2] = self.to_pair();
        match self {
            Self::Ok => write!(f, "SW 9000 (success)"),
            Self::MoreData(n) => write!(f, "SW 61{n:02X} (more data, {n} bytes)"),
            Self::WrongLe(n) => write!(f, "SW 6C{n:02X} (wrong Le; retry with Le={n:#04x})"),
            Self::NotFound => write!(f, "SW 6A82 (file/applet not found)"),
            Self::ConditionsNotSatisfied => {
                write!(f, "SW 6985 (conditions of use not satisfied)")
            }
            Self::FileInvalidated => write!(f, "SW 6283 (selected file invalidated)"),
            Self::NotAllowed | Self::NotAllowed6D00 => {
                write!(f, "SW {sw1:02X}{sw2:02X} (command not allowed)")
            }
            Self::StatusUpdate => write!(f, "SW 9100 (status update available)"),
            Self::Warn(n) => write!(f, "SW 62{n:02X} (warning)"),
            Self::Other(_) => write!(f, "SW {sw1:02X}{sw2:02X}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sw_in_the_spec_matrix_types() {
        assert_eq!(StatusWord::from_pair(0x90, 0x00), StatusWord::Ok);
        assert_eq!(StatusWord::from_pair(0x61, 0x05), StatusWord::MoreData(5));
        assert_eq!(StatusWord::from_pair(0x6C, 0x20), StatusWord::WrongLe(0x20));
        assert_eq!(StatusWord::from_pair(0x6A, 0x82), StatusWord::NotFound);
        assert_eq!(
            StatusWord::from_pair(0x69, 0x85),
            StatusWord::ConditionsNotSatisfied
        );
        assert_eq!(
            StatusWord::from_pair(0x62, 0x83),
            StatusWord::FileInvalidated
        );
        assert_eq!(StatusWord::from_pair(0x69, 0x86), StatusWord::NotAllowed);
        assert_eq!(
            StatusWord::from_pair(0x6D, 0x00),
            StatusWord::NotAllowed6D00
        );
        assert_eq!(StatusWord::from_pair(0x91, 0x00), StatusWord::StatusUpdate);
        assert_eq!(StatusWord::from_pair(0x62, 0x81), StatusWord::Warn(0x81));
        assert_eq!(
            StatusWord::from_pair(0x6F, 0x00),
            StatusWord::Other([0x6F, 0x00])
        );
    }

    #[test]
    fn round_trip_is_identity() {
        for (sw1, sw2) in [
            (0x90u8, 0x00u8),
            (0x61, 0xFF),
            (0x6C, 0x00),
            (0x6A, 0x82),
            (0x69, 0x85),
            (0x62, 0x83),
            (0x69, 0x86),
            (0x6D, 0x00),
            (0x62, 0x45),
            (0x67, 0x00),
            (0x6F, 0xFF),
        ] {
            assert_eq!(StatusWord::from_pair(sw1, sw2).to_pair(), [sw1, sw2]);
        }
    }

    #[test]
    fn from_slice_takes_the_last_two_bytes() {
        assert_eq!(
            StatusWord::from_slice(&[0x01, 0x02, 0x03, 0x04]),
            Some(StatusWord::Other([0x03, 0x04]))
        );
        assert_eq!(StatusWord::from_slice(&[0x90]), None);
    }
}
