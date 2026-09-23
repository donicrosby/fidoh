//! Typed error taxonomy for the PC/SC transport: PC/SC return codes
//! and ISO 7816 status words onto the async-core/ceremony taxonomy
//! (transport-pcsc spec, "Typed error mapping" requirement — no PC/SC
//! code or status word MAY surface untyped, and no mapping may be
//! invented outside that table).
//!
//! Two layers:
//!
//! - [`PcscCause`] / [`SkipCause`] — the typed causes of the spec's
//!   table, carried in this crate's own [`PcscError`];
//! - conversion into fidoh-core's taxonomy: `Transport` errors with
//!   the cause named in the detail text, `Timeout(Phase)` for
//!   `SCARD_E_TIMEOUT`, and typed *skips* (`PcscError::Skip`) that
//!   discovery records per-device and continues past (ceremony D2).
//!
//! When the `pcsc` feature is on, `pcsc::Error` converts via
//! [`map_pcsc_error`]; the pure mapping [`map_raw_pcsc`] takes the
//! raw 32-bit code so the whole table stays CI-testable without a
//! resource manager.

use alloc::format;
use alloc::string::String;

use fidoh_core::{Error, Phase, TransportError};

/// The typed cause of a PC/SC-layer failure (spec mapping table,
/// "PC/SC code" column semantics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcscCause {
    /// Resource manager not running (`SCARD_E_NO_SERVICE`,
    /// `SCARD_E_SERVICE_STOPPED`).
    NoService,
    /// No readers attached (`SCARD_E_NO_READERS_AVAILABLE`) — a typed
    /// skip for the transport, discovery continues.
    NoReaders,
    /// No card in reader at connect/exchange
    /// (`SCARD_E_NO_SMARTCARD`).
    Absent,
    /// Card removed mid-operation (`SCARD_W_REMOVED_CARD`,
    /// `SCARD_E_NO_SMARTCARD` during transmit) — terminal for the
    /// attempt.
    Removed,
    /// Another connection holds the reader
    /// (`SCARD_E_SHARING_VIOLATION`) — bounded retry, then typed.
    Sharing,
    /// Protocol mismatch on connect (`SCARD_E_PROTO_MISMATCH`).
    Protocol,
    /// Card silent/unusable (`SCARD_W_UNRESPONSIVE_CARD`,
    /// `SCARD_W_UNPOWERED_CARD`) — typed skip for that reader.
    UnusableCard,
    /// Card reset under us (`SCARD_W_RESET_CARD`) — never retried
    /// implicitly.
    Reset,
    /// Reader-level failure (`SCARD_E_READER_UNAVAILABLE`,
    /// `SCARD_E_NOT_TRANSACTED`, `SCARD_E_COMM_DATA_LOST`).
    Reader,
    /// Operation deadline exceeded by the resource manager
    /// (`SCARD_E_TIMEOUT`) — `Timeout` naming the in-flight phase,
    /// never retried implicitly.
    Timeout,
    /// Any other PC/SC code — the `pcsc(code)` catch-all.
    Other(u32),
}

impl PcscCause {
    /// Human-readable cause name used in typed error details.
    pub fn name(self) -> &'static str {
        match self {
            Self::NoService => "no-service",
            Self::NoReaders => "no-readers",
            Self::Absent => "absent",
            Self::Removed => "removed",
            Self::Sharing => "sharing",
            Self::Protocol => "protocol",
            Self::UnusableCard => "unusable-card",
            Self::Reset => "reset",
            Self::Reader => "reader",
            Self::Timeout => "timeout",
            Self::Other(_) => "pcsc",
        }
    }
}

/// The typed skip causes: per-device negative results that discovery
/// records and continues past — never discovery/ceremony failures
/// (ceremony D2 collect-never-short-circuit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipCause {
    /// No readers attached at all (`no-readers`): a whole-transport
    /// skip.
    NoReaders,
    /// Card silent/unusable on connect (`unusable-card`).
    UnusableCard,
    /// SELECT says not FIDO (`not-fido`): `6A82`; qualifiers
    /// `condition` (`6985`) and `invalidated` (`6283`).
    NotFido {
        /// `None` for plain `6A82`; `Some("condition")` for `6985`;
        /// `Some("invalidated")` for `6283`.
        qualifier: Option<&'static str>,
        /// The raw status word that produced the skip.
        sw: u16,
    },
}

impl SkipCause {
    /// Human-readable cause name used in typed skip details.
    pub fn name(self) -> &'static str {
        match self {
            Self::NoReaders => "no-readers",
            Self::UnusableCard => "unusable-card",
            Self::NotFido { .. } => "not-fido",
        }
    }
}

/// The typed PC/SC transport error: a cause-carrying `Transport`
/// error, a typed skip, or a `Timeout` naming the phase — exactly the
/// variants the spec's mapping table produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PcscError {
    /// A `Transport` error with the named cause; `context` identifies
    /// the reader/operation.
    Transport {
        /// The typed cause from the mapping table.
        cause: PcscCause,
        /// Reader name / operation context for the error text.
        context: String,
        /// The raw PC/SC code when one was the source.
        code: Option<u32>,
    },
    /// A typed skip (per-device negative result).
    Skip {
        /// The typed skip cause.
        cause: SkipCause,
        /// Reader name the skip attaches to.
        reader: String,
    },
    /// Budget/deadline expiry: `Timeout` naming the phase that was in
    /// flight (async-core D4). Also produced by `SCARD_E_TIMEOUT`.
    Timeout(Phase),
}

impl PcscError {
    /// Convert into fidoh-core's [`Error`] taxonomy.
    ///
    /// Skips convert to `Error::Transport` with the skip named in the
    /// detail — the `Transport` trait's `enumerate` has no skip channel
    /// in its signature, so a skip rides the same typed error shape
    /// with a `skip:` marker discovery layers can classify; the
    /// ceremony treats it as a per-device negative, not an abort
    /// (ceremony D2). This conversion is the single seam where the
    /// spec's skip concept meets the core taxonomy.
    pub fn into_core(self) -> Error {
        match self {
            Self::Transport {
                cause,
                context,
                code,
            } => Error::Transport(TransportError::new(
                "pcsc",
                match code {
                    Some(code) => {
                        format!(
                            "{context}: {} cause (PC/SC code {code:#010x})",
                            cause.name()
                        )
                    }
                    None => format!("{context}: {} cause", cause.name()),
                },
            )),
            Self::Skip { cause, reader } => Error::Transport(TransportError::new(
                "pcsc",
                match cause {
                    SkipCause::NotFido { qualifier, sw } => match qualifier {
                        Some(q) => format!(
                            "skip {reader}: {} cause (qualifier {q}, SW {sw:#06x})",
                            cause.name()
                        ),
                        None => format!("skip {reader}: {} cause (SW {sw:#06x})", cause.name()),
                    },
                    other => format!("skip {reader}: {} cause", other.name()),
                },
            )),
            Self::Timeout(phase) => Error::Timeout(phase),
        }
    }

    /// Whether this error is a typed skip (per-device negative).
    pub fn is_skip(&self) -> bool {
        matches!(self, Self::Skip { .. })
    }
}

/// Map a raw PC/SC return code (the shared Windows/pcsclite values,
/// PC/SC Core Specification Part 3) onto the spec's table. Pure, so
/// the whole table is testable without pcscd.
pub fn map_raw_pcsc(raw: u32, context: &str, phase: Phase) -> PcscError {
    // Values per pcsclite's pcsclite.h (shared with WinSCard).
    const SCARD_E_TIMEOUT: u32 = 0x8010_000A;
    const SCARD_E_SHARING_VIOLATION: u32 = 0x8010_000B;
    const SCARD_E_NO_SMARTCARD: u32 = 0x8010_000C;
    const SCARD_E_PROTO_MISMATCH: u32 = 0x8010_000F;
    const SCARD_E_NOT_TRANSACTED: u32 = 0x8010_0016;
    const SCARD_E_READER_UNAVAILABLE: u32 = 0x8010_0017;
    const SCARD_E_NO_SERVICE: u32 = 0x8010_001D;
    const SCARD_E_SERVICE_STOPPED: u32 = 0x8010_001E;
    const SCARD_E_COMM_DATA_LOST: u32 = 0x8010_002F;
    const SCARD_E_NO_READERS_AVAILABLE: u32 = 0x8010_002E;
    const SCARD_W_UNRESPONSIVE_CARD: u32 = 0x8010_0066;
    const SCARD_W_UNPOWERED_CARD: u32 = 0x8010_0067;
    const SCARD_W_RESET_CARD: u32 = 0x8010_0068;
    const SCARD_W_REMOVED_CARD: u32 = 0x8010_0069;

    let cause = match raw {
        SCARD_E_NO_SERVICE | SCARD_E_SERVICE_STOPPED => PcscCause::NoService,
        SCARD_E_NO_READERS_AVAILABLE => {
            return PcscError::Skip {
                cause: SkipCause::NoReaders,
                reader: String::from("pcsc"),
            }
        }
        SCARD_E_NO_SMARTCARD => PcscCause::Absent,
        SCARD_W_REMOVED_CARD => PcscCause::Removed,
        SCARD_E_SHARING_VIOLATION => PcscCause::Sharing,
        SCARD_E_PROTO_MISMATCH => PcscCause::Protocol,
        SCARD_W_UNRESPONSIVE_CARD | SCARD_W_UNPOWERED_CARD => {
            return PcscError::Skip {
                cause: SkipCause::UnusableCard,
                reader: String::from(context),
            };
        }
        SCARD_W_RESET_CARD => PcscCause::Reset,
        SCARD_E_TIMEOUT => return PcscError::Timeout(phase),
        SCARD_E_READER_UNAVAILABLE | SCARD_E_NOT_TRANSACTED | SCARD_E_COMM_DATA_LOST => {
            PcscCause::Reader
        }
        other => PcscCause::Other(other),
    };
    PcscError::Transport {
        cause,
        context: String::from(context),
        code: Some(raw),
    }
}

/// Map a `pcsc` crate error onto the typed table (feature `pcsc`).
#[cfg(feature = "pcsc")]
pub fn map_pcsc_error(err: pcsc::Error, context: &str, phase: Phase) -> PcscError {
    map_raw_pcsc(err as u32, context, phase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_row_maps_typed() {
        // The spec table, row by row.
        let cases: &[(u32, PcscCause)] = &[
            (0x8010_001D, PcscCause::NoService),
            (0x8010_001E, PcscCause::NoService),
            (0x8010_000C, PcscCause::Absent),
            (0x8010_0069, PcscCause::Removed),
            (0x8010_000B, PcscCause::Sharing),
            (0x8010_000F, PcscCause::Protocol),
            (0x8010_0068, PcscCause::Reset),
            (0x8010_0017, PcscCause::Reader),
            (0x8010_0016, PcscCause::Reader),
            (0x8010_002F, PcscCause::Reader),
        ];
        for &(raw, cause) in cases {
            match map_raw_pcsc(raw, "reader-a", Phase::Connect) {
                PcscError::Transport { cause: c, code, .. } => {
                    assert_eq!(c, cause, "raw {raw:#010x}");
                    assert_eq!(code, Some(raw));
                }
                other => panic!("raw {raw:#010x}: expected Transport, got {other:?}"),
            }
        }
    }

    #[test]
    fn timeout_maps_to_typed_phase() {
        assert_eq!(
            map_raw_pcsc(0x8010_000A, "r", Phase::GetInfo),
            PcscError::Timeout(Phase::GetInfo)
        );
    }

    #[test]
    fn no_readers_is_a_transport_level_skip() {
        let err = map_raw_pcsc(0x8010_002E, "pcsc", Phase::Enumeration);
        assert_eq!(
            err,
            PcscError::Skip {
                cause: SkipCause::NoReaders,
                reader: String::from("pcsc"),
            }
        );
        assert!(err.is_skip());
    }

    #[test]
    fn unusable_card_is_a_reader_level_skip() {
        let err = map_raw_pcsc(0x8010_0066, "reader-a", Phase::Connect);
        assert_eq!(
            err,
            PcscError::Skip {
                cause: SkipCause::UnusableCard,
                reader: String::from("reader-a"),
            }
        );
    }

    #[test]
    fn catch_all_carries_the_raw_code() {
        match map_raw_pcsc(0x8010_0ABC, "r", Phase::CommandExchange) {
            PcscError::Transport {
                cause: PcscCause::Other(0x8010_0ABC),
                ..
            } => {}
            other => panic!("expected catch-all, got {other:?}"),
        }
    }

    #[test]
    fn into_core_produces_the_documented_shapes() {
        // Transport cause → Error::Transport with the cause named.
        let core = map_raw_pcsc(0x8010_0069, "reader-a", Phase::CommandExchange).into_core();
        match core {
            Error::Transport(e) => {
                assert!(e.detail.contains("removed"), "{}", e.detail);
                assert!(e.detail.contains("reader-a"), "{}", e.detail);
                assert!(e.detail.contains("0x80100069"), "{}", e.detail);
            }
            other => panic!("expected Transport, got {other:?}"),
        }
        // Timeout keeps its phase.
        assert_eq!(
            PcscError::Timeout(Phase::Connect).into_core(),
            Error::Timeout(Phase::Connect)
        );
        // Skip → Error::Transport with the `skip` marker.
        let skip = PcscError::Skip {
            cause: SkipCause::NotFido {
                qualifier: None,
                sw: 0x6A82,
            },
            reader: String::from("reader-b"),
        }
        .into_core();
        match skip {
            Error::Transport(e) => {
                assert!(e.detail.contains("skip reader-b"), "{}", e.detail);
                assert!(e.detail.contains("not-fido"), "{}", e.detail);
                assert!(e.detail.contains("0x6a82"), "{}", e.detail);
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }
}
