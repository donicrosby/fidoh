//! The scenario fake: a programmable PC/SC library driving the engine
//! through every spec scenario without hardware (error injection,
//! scripted SW sequences, interleaved transactions, budget stalls).
//!
//! std-only by design: stalls use `std::thread::sleep` and the shared
//! state is an `std::sync::Mutex` (the fake is a TEST double — CI
//! builds with std — and never ships in a no_std target).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use std::sync::Mutex;

use crate::error::{map_raw_pcsc, PcscError};
use crate::library::{ActiveProtocol, CardState, ConnToken, Library, ReaderEntry, ShareMode};

/// A scripted transmit result (fed to successive
/// [`FakeLibrary::transmit`] calls for one connection).
#[derive(Clone, Debug)]
enum Scripted {
    /// Respond with these bytes (data || SW).
    Response(Vec<u8>),
    /// Fail the transmit with this raw PC/SC code.
    Pcsc(u32),
}

/// One connection slot (history + live state), as tests observe it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeConn {
    /// Token identifying this connection.
    pub token: u64,
    /// Reader the connection was opened on.
    pub reader: String,
    /// Sharing mode requested at connect.
    pub mode: ShareMode,
    /// Whether the card is still in the reader/field.
    pub card_present: bool,
    /// Whether the connection is open (false after disconnect).
    pub open: bool,
    /// Transmits issued on this connection.
    pub transmits: usize,
}

/// Interior-mutable state (`Library` methods take `&self`).
#[derive(Debug, Default)]
struct Inner {
    readers: Vec<ReaderEntry>,
    fail_list_readers: Option<u32>,
    connections: Vec<FakeConn>,
    next_token: u64,
    fail_connect: VecDeque<(String, u32)>,
    pending_scripts: VecDeque<VecDeque<Scripted>>,
    /// Per-connection transmit scripts, shared with transmit so the
    /// queue can be consumed without re-entrant borrows.
    scripts: Vec<(u64, alloc::sync::Arc<Mutex<VecDeque<Scripted>>>)>,
    default_response: Vec<u8>,
    /// When set, every transmit fails with this raw code (persistent
    /// error injection; one-shot scripts layer in front).
    persistent_fail: Option<u32>,
    stall_transmit_ms: Option<u64>,
    stall_connect_ms: Option<u64>,
    transmit_count: usize,
    connect_count: usize,
    disconnect_count: usize,
}

/// The programmable fake `Library`.
#[derive(Debug, Default)]
pub struct FakeLibrary {
    inner: Mutex<Inner>,
}

/// Hard cap on fake stalls (mirrors transport-soft's DELAY_HARD_CAP
/// practice): a misconfigured test must never hang CI.
const STALL_HARD_CAP_MS: u64 = 5_000;

/// `CardState::present`, not muted.
pub const CARD_PRESENT: CardState = CardState {
    present: true,
    mute: false,
    unpowered: false,
};

impl FakeLibrary {
    /// An empty fake: no readers, no scripts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a reader with the given card state.
    pub fn reader(self, name: &str, state: CardState) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .readers
            .push(ReaderEntry {
                name: String::from(name),
                state,
                atr: Vec::new(),
            });
        self
    }

    /// Make the next `list_readers` fail with a raw PC/SC code.
    pub fn fail_list_readers(self, code: u32) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail_list_readers = Some(code);
        self
    }

    /// Make the next connect to `reader` fail with `code` (once).
    pub fn fail_connect(self, reader: &str, code: u32) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail_connect
            .push_back((String::from(reader), code));
        self
    }

    /// Script transmit results for the NEXT connection opened (data
    /// || SW responses, consumed FIFO).
    pub fn with_script(self, responses: &[&[u8]]) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_scripts
            .push_back(
                responses
                    .iter()
                    .map(|r| Scripted::Response(r.to_vec()))
                    .collect(),
            );
        self
    }

    /// Script a PC/SC transmit failure for the NEXT connection's
    /// first exchange (one-shot; later exchanges fall back to the
    /// default response / persistent injection).
    pub fn fail_transmit_next_conn(self, code: u32) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_scripts
            .push_back(alloc::collections::VecDeque::from([Scripted::Pcsc(code)]));
        self
    }

    /// Every transmit on any connection fails with `code` (persistent
    /// error injection for mid-exchange failure tests).
    pub fn fail_transmit_persistent(self, code: u32) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .persistent_fail = Some(code);
        self
    }

    /// The default response for un-scripted exchanges.
    pub fn default_response(self, bytes: &[u8]) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .default_response = bytes.to_vec();
        self
    }

    /// Real-thread stall before each transmit returns (budget tests:
    /// the fake's blocking call outlives a tiny caller budget).
    pub fn stall_transmit(self, ms: u64) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stall_transmit_ms = Some(ms);
        self
    }

    /// Real-thread stall before each connect returns.
    pub fn stall_connect(self, ms: u64) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stall_connect_ms = Some(ms);
        self
    }

    /// Simulate card removal on an open connection (mid-ceremony
    /// field loss): subsequent transmits fail `RemovedCard`, status
    /// reports absent.
    pub fn remove_card(&self, token: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for conn in &mut inner.connections {
            if conn.token == token {
                conn.card_present = false;
            }
        }
    }

    /// Restore the card (re-present tests).
    pub fn insert_card(&self, token: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for conn in &mut inner.connections {
            if conn.token == token {
                conn.card_present = true;
            }
        }
    }

    /// Drop the PC/SC-level connection (sharing-contention
    /// simulation): transmits fail `SharingViolation` while dropped.
    pub fn drop_connection(&self, token: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for conn in &mut inner.connections {
            if conn.token == token {
                conn.open = false;
            }
        }
    }

    /// The token of the Nth opened connection (test handles).
    pub fn token_of(&self, n: usize) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connections[n]
            .token
    }

    /// Total transmits across all connections.
    pub fn transmit_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .transmit_count
    }

    /// Total connect attempts.
    pub fn connect_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connect_count
    }

    /// Total disconnects.
    pub fn disconnect_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .disconnect_count
    }

    /// Connection history snapshot.
    pub fn connections(&self) -> Vec<FakeConn> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connections
            .clone()
    }
}

impl Library for FakeLibrary {
    fn list_readers(&self) -> Result<Vec<ReaderEntry>, PcscError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(code) = inner.fail_list_readers.take() {
            return Err(map_raw_pcsc(
                code,
                "pcsc (list_readers)",
                fidoh_core::Phase::Enumeration,
            ));
        }
        Ok(inner.readers.clone())
    }

    fn connect(
        &self,
        reader: &str,
        mode: ShareMode,
    ) -> Result<(ActiveProtocol, ConnToken), PcscError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.connect_count += 1;
        if let Some(ms) = inner.stall_connect_ms {
            drop(inner);
            std::thread::sleep(core::time::Duration::from_millis(ms.min(STALL_HARD_CAP_MS)));
            inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        // One-shot queued failure for this reader.
        if let Some(pos) = inner.fail_connect.iter().position(|(r, _)| r == reader) {
            let (_, code) = inner.fail_connect.remove(pos).expect("position verified");
            return Err(map_raw_pcsc(code, reader, fidoh_core::Phase::Connect));
        }
        // No reader by this name → typed reader-unavailable.
        let Some(entry) = inner.readers.iter().find(|r| r.name == reader) else {
            return Err(map_raw_pcsc(
                0x8010_0017,
                reader,
                fidoh_core::Phase::Connect,
            ));
        };
        if !entry.state.is_connectable() {
            return Err(map_raw_pcsc(
                0x8010_000C,
                reader,
                fidoh_core::Phase::Connect,
            ));
        }
        let token = inner.next_token;
        inner.next_token += 1;
        let script = inner.pending_scripts.pop_front().unwrap_or_default();
        inner
            .scripts
            .push((token, alloc::sync::Arc::new(Mutex::new(script))));
        inner.connections.push(FakeConn {
            token,
            reader: String::from(reader),
            mode,
            card_present: true,
            open: true,
            transmits: 0,
        });
        Ok((ActiveProtocol::T1, ConnToken(token)))
    }

    fn status(&self, conn: &ConnToken) -> Result<CardState, PcscError> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(c) = inner
            .connections
            .iter()
            .find(|c| c.token == conn.0 && c.open)
        else {
            return Err(map_raw_pcsc(
                0x8010_0017,
                "pcsc (status)",
                fidoh_core::Phase::CommandExchange,
            ));
        };
        Ok(CardState {
            present: c.card_present,
            mute: false,
            unpowered: false,
        })
    }

    fn transmit(&self, conn: &ConnToken, _command: &[u8]) -> Result<Vec<u8>, PcscError> {
        let stall = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.transmit_count += 1;
            let Some(c) = inner
                .connections
                .iter_mut()
                .find(|c| c.token == conn.0 && c.open)
            else {
                return Err(map_raw_pcsc(
                    0x8010_000B,
                    "pcsc (transmit: connection closed)",
                    fidoh_core::Phase::CommandExchange,
                ));
            };
            if !c.card_present {
                return Err(map_raw_pcsc(
                    0x8010_0069,
                    &c.reader,
                    fidoh_core::Phase::CommandExchange,
                ));
            }
            c.transmits += 1;
            inner.stall_transmit_ms
        };
        if let Some(ms) = stall {
            std::thread::sleep(core::time::Duration::from_millis(ms.min(STALL_HARD_CAP_MS)));
        }
        let script = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner
                .scripts
                .iter()
                .find(|(t, _)| *t == conn.0)
                .map(|(_, s)| s.clone())
                .expect("script exists for every open connection")
        };
        let mut script = script
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let injected = match script.pop_front() {
            Some(Scripted::Response(bytes)) => return Ok(bytes),
            Some(Scripted::Pcsc(code)) => Some(code),
            None => None,
        };
        let persistent = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .persistent_fail;
        match injected.or(persistent) {
            Some(code) => Err(map_raw_pcsc(
                code,
                "pcsc (transmit)",
                fidoh_core::Phase::CommandExchange,
            )),
            None => Ok(self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .default_response
                .clone()),
        }
    }

    fn disconnect(&self, conn: ConnToken) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.disconnect_count += 1;
        for c in &mut inner.connections {
            if c.token == conn.0 {
                c.open = false;
            }
        }
        inner.scripts.retain(|(t, _)| *t != conn.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn scripts_flow_to_successive_connections() {
        let fake = FakeLibrary::new()
            .reader("r1", CARD_PRESENT)
            .with_script(&[&[0x6A, 0x82]])
            .with_script(&[&[0x90, 0x00]]);
        let (_, c1) = fake.connect("r1", ShareMode::Shared).unwrap();
        let (_, c2) = fake.connect("r1", ShareMode::Shared).unwrap();
        assert_eq!(fake.transmit(&c1, &[0x00]).unwrap(), vec![0x6A, 0x82]);
        assert_eq!(fake.transmit(&c2, &[0x00]).unwrap(), vec![0x90, 0x00]);
    }

    #[test]
    fn removal_fails_transmits_with_removed_card() {
        let fake = FakeLibrary::new()
            .reader("nfc0", CARD_PRESENT)
            .default_response(&[0x90, 0x00]);
        let (_, c) = fake.connect("nfc0", ShareMode::Shared).unwrap();
        assert_eq!(fake.transmit(&c, &[0x00]).unwrap(), vec![0x90, 0x00]);
        fake.remove_card(c.0);
        let err = fake.transmit(&c, &[0x00]).unwrap_err();
        assert!(matches!(
            err,
            PcscError::Transport {
                cause: crate::error::PcscCause::Removed,
                ..
            }
        ));
        fake.insert_card(c.0);
        assert!(fake.transmit(&c, &[0x00]).is_ok());
    }

    #[test]
    fn one_shot_connect_failures_are_consumed_in_order() {
        let fake = FakeLibrary::new()
            .reader("r", CARD_PRESENT)
            .fail_connect("r", 0x8010_000B);
        assert!(fake.connect("r", ShareMode::Shared).is_err());
        assert!(fake.connect("r", ShareMode::Shared).is_ok());
        assert_eq!(fake.connect_count(), 2);
    }

    #[test]
    fn dropped_connection_fails_with_sharing_violation() {
        let fake = FakeLibrary::new()
            .reader("r", CARD_PRESENT)
            .default_response(&[0x90, 0x00]);
        let (_, c) = fake.connect("r", ShareMode::Shared).unwrap();
        fake.drop_connection(c.0);
        assert!(matches!(
            fake.transmit(&c, &[0x00]),
            Err(PcscError::Transport {
                cause: crate::error::PcscCause::Sharing,
                ..
            })
        ));
    }
}
