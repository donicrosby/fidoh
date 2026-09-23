//! The library-context seam: the transport engine talks to PC/SC
//! through the [`Library`] trait, so the real `pcsc` crate (feature
//! `pcsc`) and fakes drive the SAME engine code. CI runs entirely on
//! fakes; the real binding is exercised only under
//! `FIDOH_HARDWARE_TESTS=1` (tests/hardware.rs).
//!
//! The `pcsc` crate is thin and faithful to the C API (it wraps
//! SCard* 1:1 — see the pcsc crate docs, which document each method
//! as the SCard function it wraps), so the trait mirrors its surface
//! with owned data, and the real impl is a mechanical mapping.

use alloc::string::String;
use alloc::vec::Vec;

/// Card state as the resource manager reports it (PC/SC Part 3,
/// SCardGetStatusChange / SCardStatus state bits, narrowed to what
/// this spec consumes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardState {
    /// `SCARD_STATE_PRESENT`.
    pub present: bool,
    /// `SCARD_STATE_MUTE` (present but unusable).
    pub mute: bool,
    /// `SCARD_STATE_UNPOWERED` (ccid readers report this for
    /// touch-required cards).
    pub unpowered: bool,
}

impl CardState {
    /// Whether the reader is a connect candidate: card present and
    /// not MUTE (spec: "`SCARD_STATE_PRESENT`, absent
    /// `SCARD_STATE_MUTE`"). UNPOWERED cards are connect candidates
    /// (CCID YubiKeys are unpowered until touched; the connect powers
    /// the interface).
    pub fn is_connectable(self) -> bool {
        self.present && !self.mute
    }
}

/// One PC/SC reader the resource manager reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderEntry {
    /// The reader name (`SCardListReaders` multi-string entry).
    pub name: String,
    /// Current card state.
    pub state: CardState,
    /// ATR when the manager supplied one (not interpreted by fidoh).
    pub atr: Vec<u8>,
}

/// The negotiated protocol of an active card connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveProtocol {
    /// T=0 character-level protocol.
    T0,
    /// T=1 block-level protocol (CCID readers; also what T=CL
    /// contactless readers typically expose after the PC/SC layer
    /// terminates ISO 14443-4).
    T1,
    /// RAW (direct to reader; not used for APDU exchange).
    Raw,
}

/// The sharing mode of a `SCardConnect` (PC/SC Part 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareMode {
    /// Shared: other applications keep access (the default for BOTH
    /// NFC and CCID per spec D2).
    Shared,
    /// Exclusive: explicit caller opt-in only; never an automatic
    /// escalation.
    Exclusive,
}

/// The result of one blocking library operation, as the engine
/// consumes it.
pub type LibResult<T> = Result<T, crate::error::PcscError>;

/// The PC/SC resource-manager surface the engine needs.
///
/// Implementors: the real binding (behind feature `pcsc`) and test
/// fakes. Every method is a BLOCKING call from the engine's point of
/// view — the async wrapper slices the budget around each call (the
/// engine issues at most one call per granted slice).
///
/// `Send + Sync` bounds: engine futures are `Send` by the
/// `Transport`/`Device` trait contract (async-core A4), so a library
/// held inside them must be shareable across the blocking pool's
/// threads; the real `pcsc::Context`/`Card` types are Send+Sync
/// already (pcsc crate).
pub trait Library: Send + Sync {
    /// `SCardListReaders`: enumerate readers with their card states.
    ///
    /// The real binding issues SCardEstablishContext lazily (a fresh
    /// Context per call is acceptable at PC/SC client scale; the
    /// context lives for the transport's lifetime in the real impl).
    fn list_readers(&self) -> LibResult<Vec<ReaderEntry>>;

    /// `SCardConnect`: open `reader` in `mode`, preferring T=1 then
    /// T=0 (`Protocols::ANY` semantics in the real binding). Returns
    /// the negotiated protocol and a connection handle token.
    fn connect(&self, reader: &str, mode: ShareMode) -> LibResult<(ActiveProtocol, ConnToken)>;

    /// `SCardStatus`: current card state of an open connection.
    fn status(&self, conn: &ConnToken) -> LibResult<CardState>;

    /// `SCardTransmit`: one command APDU in, one response out
    /// (data || SW).
    fn transmit(&self, conn: &ConnToken, command: &[u8]) -> LibResult<Vec<u8>>;

    /// `SCardDisconnect` (Disposition::LeaveCard semantics: never
    /// reset the card implicitly — a reset would invalidate another
    /// applet's session on a composite key).
    fn disconnect(&self, conn: ConnToken);
}

/// An opaque open-connection handle. The real binding wraps the
/// `pcsc::Card`; fakes key their state table on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnToken(pub u64);

#[cfg(feature = "pcsc")]
mod real {
    //! The real-library wrapper: a mechanical mapping onto the `pcsc`
    //! crate (which wraps each SCard function 1:1; see that crate's
    //! docs — each method documents the C function it wraps).

    use super::{ActiveProtocol, CardState, ConnToken, Library, ReaderEntry, ShareMode};
    use crate::error::{map_pcsc_error, PcscError};
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::ffi::CStr;
    use fidoh_core::Phase;

    /// Real `pcsc` crate-backed library. Owns one shared
    /// `pcsc::Context` for the transport's lifetime (SCardEstablish
    /// Context once; SCard* calls take the handle).
    pub struct PcscLibrary {
        ctx: pcsc::Context,
        next_token: core::sync::atomic::AtomicU64,
        /// Cards are not Sync; access is serialized by the engine
        /// (one blocking op at a time per transport).
        cards: std::sync::Mutex<alloc::collections::BTreeMap<u64, pcsc::Card>>,
    }

    impl PcscLibrary {
        /// Establish the context (`SCardEstablishContext`,
        /// `Scope::User` per the pcsc crate's documented default
        /// usage). Fails typed when pcscd is not running.
        pub fn establish() -> Result<Self, PcscError> {
            let ctx = pcsc::Context::establish(pcsc::Scope::User)
                .map_err(|e| map_pcsc_error(e, "pcsc (establish)", Phase::Enumeration))?;
            Ok(Self {
                ctx,
                next_token: core::sync::atomic::AtomicU64::new(1),
                cards: std::sync::Mutex::new(alloc::collections::BTreeMap::new()),
            })
        }

        fn phase_of(op: &str) -> Phase {
            // Named phases for timeouts: enumeration ops name
            // Enumeration; connect ops name Connect; transmit ops name
            // CommandExchange. Kept as a function so the mapping sits
            // in one place.
            match op {
                "list" => Phase::Enumeration,
                "connect" => Phase::Connect,
                _ => Phase::CommandExchange,
            }
        }
    }

    impl Library for PcscLibrary {
        fn list_readers(&self) -> Result<Vec<ReaderEntry>, PcscError> {
            let phase = Self::phase_of("list");
            // Two-step SCardListReaders (len, then fill), per the pcsc
            // crate's documented usage.
            let names = self
                .ctx
                .list_readers_owned()
                .map_err(|e| map_pcsc_error(e, "pcsc (list_readers)", phase))?;

            let mut readers = Vec::with_capacity(names.len());
            for name in names {
                let mut state_buf = [0u8; 64];
                let mut atr_buf = [0u8; pcsc::MAX_ATR_SIZE];
                let reader_state = pcsc::ReaderState::new(&*name, pcsc::State::UNAWARE);
                let mut states = [reader_state];
                // Zero-timeout SCardGetStatusChange: snapshot current
                // states without blocking (PC/SC Part 3: unaware
                // current-state returns the state immediately).
                self.ctx
                    .get_status_change(core::time::Duration::ZERO, &mut states)
                    .map_err(|e| map_pcsc_error(e, "pcsc (status change)", phase))?;
                let st = &states[0];
                let event = st.event_state();
                let state = CardState {
                    present: event.contains(pcsc::State::PRESENT),
                    mute: event.contains(pcsc::State::MUTE),
                    unpowered: event.contains(pcsc::State::UNPOWERED),
                };
                let _ = (&mut state_buf, &mut atr_buf);
                readers.push(ReaderEntry {
                    name: String::from_utf8_lossy(name.to_bytes()).into_owned(),
                    state,
                    atr: st.atr().to_vec(),
                });
            }
            Ok(readers)
        }

        fn connect(
            &self,
            reader: &str,
            mode: ShareMode,
        ) -> Result<(ActiveProtocol, ConnToken), PcscError> {
            let phase = Self::phase_of("connect");
            let share = match mode {
                ShareMode::Shared => pcsc::ShareMode::Shared,
                ShareMode::Exclusive => pcsc::ShareMode::Exclusive,
            };
            let reader_z = alloc::format!("{reader}\0");
            let creader = CStr::from_bytes_with_nul(reader_z.as_bytes()).map_err(|_| {
                PcscError::Transport {
                    cause: crate::error::PcscCause::Other(0),
                    context: String::from(reader),
                    code: None,
                }
            })?;
            let card = self
                .ctx
                .connect(creader, share, pcsc::Protocols::ANY)
                .map_err(|e| map_pcsc_error(e, reader, phase))?;
            // pcsc::Card's active_protocol field is private; the
            // negotiated protocol comes back through SCardStatus
            // (pcsc crate's CardStatus::protocol2 handles the
            // direct-connection None case).
            let status = card
                .status2_owned()
                .map_err(|e| map_pcsc_error(e, reader, phase))?;
            let protocol = match status.protocol2() {
                Some(pcsc::Protocol::T0) => ActiveProtocol::T0,
                Some(pcsc::Protocol::T1) => ActiveProtocol::T1,
                Some(pcsc::Protocol::RAW) => ActiveProtocol::Raw,
                None => {
                    return Err(PcscError::Transport {
                        cause: crate::error::PcscCause::Protocol,
                        context: String::from(reader),
                        code: None,
                    })
                }
            };
            let token = ConnToken(
                self.next_token
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            );
            self.cards
                .lock()
                .expect("pcsc card map")
                .insert(token.0, card);
            Ok((protocol, token))
        }

        fn status(&self, conn: &ConnToken) -> Result<CardState, PcscError> {
            let cards = self.cards.lock().expect("pcsc card map");
            let card = cards.get(&conn.0).ok_or_else(not_connected)?;
            // status2 into stack buffers: reader names ≤ MAX_READERNAME
            // and ATR ≤ MAX_ATR_SIZE are the PC/SC-defined caps.
            let mut names = [0u8; 256];
            let mut atr = [0u8; pcsc::MAX_ATR_SIZE];
            let status = card
                .status2(&mut names, &mut atr)
                .map_err(|e| map_pcsc_error(e, "pcsc (status)", Phase::CommandExchange))?;
            // CardStatus::state() is the pcsc crate's Status
            // (SCARD_ABSENT/PRESENT/NEGOTIABLE/SPECIFIC/POWERED/
            // NOPOWER/UNPOWERED/UNUSABLE/UNKNOWN), not the State
            // bitflags SCardGetStatusChange returns. Map: present
            // unless ABSENT/UNKNOWN; MUTE has no Status equivalent —
            // PC/SC treats a mute card as UNUSABLE, surfaced here as
            // present=false via the UNUSABLE arm.
            let state = status.status();
            // pcsc crate Status constants: UNKNOWN / ABSENT /
            // PRESENT / SWALLOWED / POWERED / NEGOTIABLE / SPECIFIC
            // (names per the crate docs, mapping onto SCARD_ABSENT /
            // SCARD_PRESENT / etc.). A mute card surfaces as ABSENT
            // or UNKNOWN at this layer; the connect-time SCARD_STATE
            // path in list_readers handles MUTE/UNPOWERED.
            Ok(CardState {
                present: state.contains(pcsc::Status::PRESENT)
                    && !state.intersects(pcsc::Status::ABSENT | pcsc::Status::UNKNOWN),
                mute: false,
                unpowered: state.contains(pcsc::Status::PRESENT)
                    && !state.contains(pcsc::Status::POWERED),
            })
        }

        fn transmit(&self, conn: &ConnToken, command: &[u8]) -> Result<Vec<u8>, PcscError> {
            let cards = self.cards.lock().expect("pcsc card map");
            let card = cards.get(&conn.0).ok_or_else(not_connected)?;
            // CTAP2.1 §11 responses can exceed the short-APDU default;
            // ISO 7816-4 caps one TPDU exchange at 65538 (data + SW),
            // and pcsc-lite enforces a buffer the CCID driver sizes.
            let mut recv = [0u8; 65538];
            let response = card
                .transmit(command, &mut recv)
                .map_err(|e| map_pcsc_error(e, "pcsc (transmit)", Phase::CommandExchange))?;
            Ok(response.to_vec())
        }

        fn disconnect(&self, conn: ConnToken) {
            // LeaveCard: never reset implicitly (other applets may hold
            // session state on the composite device).
            if let Some(card) = self.cards.lock().expect("pcsc card map").remove(&conn.0) {
                let _ = card.disconnect(pcsc::Disposition::LeaveCard);
            }
        }
    }

    fn not_connected() -> PcscError {
        PcscError::Transport {
            cause: crate::error::PcscCause::Other(0),
            context: String::from("pcsc (no open connection)"),
            code: None,
        }
    }
}

#[cfg(feature = "pcsc")]
pub use real::PcscLibrary;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connectable_states() {
        assert!(CardState {
            present: true,
            mute: false,
            unpowered: false
        }
        .is_connectable());
        assert!(CardState {
            present: true,
            mute: false,
            unpowered: true
        }
        .is_connectable());
        assert!(!CardState {
            present: false,
            mute: false,
            unpowered: false
        }
        .is_connectable());
        // MUTE is present-but-unusable: excluded by the spec.
        assert!(!CardState {
            present: true,
            mute: true,
            unpowered: false
        }
        .is_connectable());
    }
}
