//! The engine: async [`Transport`]/[`Device`] over any [`Library`].
//!
//! One APDU engine serves CCID and NFC alike (spec: "No
//! interface-specific second implementation"); NFC-specific behavior
//! is confined to the named NFC requirements — the §11.3.7.2
//! status-update loop, presence polling in ≤ 1 s slices, and the
//! §5 120 s presence-window cap.
//!
//! Bounded waits (spec: "Every APDU exchange and wait is bounded by
//! the ceremony budget"): each blocking library call is granted one
//! slice from the remaining budget
//! ([`fidoh_core::policy::hop_slice`], NFC polls
//! [`nfc_field_poll_slice`]); the call races a `Sleep`-factory timer
//! for the slice, so a stalled call loses the race to a typed
//! `Timeout(Phase)` and no further PC/SC calls are issued after
//! expiry. All engine futures are `Send`, so the real
//! `spawn_blocking` adapter (async-core D3, living in `fidoh-tokio`)
//! wraps them unchanged.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;

use fidoh_core::device::{CtapCommand, Device as CtapDevice, DeviceEvent};
use fidoh_core::policy::nfc_field_poll_slice;
use fidoh_core::sleep::SleepHandle;
use fidoh_core::time::{Deadline, Phase};
use fidoh_core::transport::{DeviceId, DeviceInfo, Transport};
use fidoh_core::{ChannelId, Error};

use crate::error::{PcscError, SkipCause};
use crate::framing::{command_byte, Exchange, Step};
use crate::library::{CardState, ConnToken, Library, ShareMode};
use crate::select::{evaluate_select, select_fido_aid, SelectOutcome};

/// The PC/SC transport over a [`Library`] (real binding behind
/// feature `pcsc`, fakes in CI). One engine for CCID and NFC.
pub struct PcscTransport<L: Library + 'static> {
    lib: Arc<L>,
    /// Readers whose card is contactless (T=CL): these get NFC
    /// presence polling and the §5 presence-window cap. Metadata
    /// only — the APDU layer never branches on it (spec: no
    /// transport behavior branches on the interface type except the
    /// NFC-specific handling this spec names).
    nfc_readers: Vec<String>,
    /// Connect sharing (SHARED default; EXCLUSIVE explicit opt-in).
    share: ShareMode,
}

impl<L: Library + 'static> PcscTransport<L> {
    /// Wrap a library (real or fake).
    pub fn new(lib: L) -> Self {
        Self {
            lib: Arc::new(lib),
            nfc_readers: Vec::new(),
            share: ShareMode::Shared,
        }
    }

    /// Shared-arc constructor (tests assert against the same fake).
    pub fn from_arc(lib: Arc<L>) -> Self {
        Self {
            lib,
            nfc_readers: Vec::new(),
            share: ShareMode::Shared,
        }
    }

    /// Declare which enumerated readers are NFC/T=CL.
    pub fn with_nfc_readers(mut self, readers: &[&str]) -> Self {
        self.nfc_readers = readers.iter().map(|s| String::from(*s)).collect();
        self
    }

    /// Explicit EXCLUSIVE opt-in (spec: the transport never escalates
    /// shared→exclusive on its own).
    pub fn exclusive(mut self) -> Self {
        self.share = ShareMode::Exclusive;
        self
    }

    fn is_nfc(&self, reader: &str) -> bool {
        self.nfc_readers.iter().any(|n| n == reader)
    }
}

/// One budget-granted blocking library call.
///
/// The slice granted is the remaining budget (this op may use all of
/// it); the grant consumes the budget BEFORE the call issues, so a
/// budget exhausted by earlier hops means this call never reaches the
/// library ("no further PC/SC calls issued after expiry"). The call
/// races the slice timer; expiry is `Timeout(phase)` and the in-flight
/// call is dropped at the slice edge (the abort path: a dropped
/// future's thread exits within its slice).
async fn granted<T>(
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
    phase: Phase,
    op: impl Future<Output = Result<T, PcscError>> + Send,
) -> Result<T, Error> {
    // Zero-budget: nothing may run, nothing is granted (the typed
    // timeout fires before any PC/SC call issues).
    if deadline.remaining().is_zero() {
        return Err(Error::Timeout(phase));
    }
    let timer = sleep.sleep(deadline.remaining());
    let mut op = core::pin::pin!(op);
    match fidoh_core::future::select(op.as_mut(), timer).await {
        fidoh_core::future::Either::Left(result) => result.map_err(|e| pcsc_into_core(e, phase)),
        fidoh_core::future::Either::Right(()) => Err(Error::Timeout(phase)),
    }
}

/// Typed sharing-violation detection for the bounded connect retry
/// (SCARD_E_SHARING_VIOLATION, 0x8010_000B per the error table).
fn is_sharing_violation(err: &Error) -> bool {
    matches!(err, Error::Transport(e) if e.kind == "pcsc" && e.detail.contains("sharing cause"))
}

fn pcsc_into_core(err: PcscError, phase: Phase) -> Error {
    match err {
        PcscError::Timeout(_) => Error::Timeout(phase),
        other => other.into_core(),
    }
}

impl<L: Library + 'static> Transport for PcscTransport<L> {
    fn kind(&self) -> fidoh_core::transport::TransportKind {
        // add-client-pin: discovery diagnostics name the real layer.
        fidoh_core::transport::TransportKind::Pcsc
    }

    type Device = PcscDevice<L>;

    async fn enumerate(
        &self,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<Vec<DeviceInfo>, Error> {
        let lib = Arc::clone(&self.lib);
        let entries = granted(deadline, sleep, Phase::Enumeration, async move {
            lib.list_readers()
        })
        .await?;
        // Candidate gate: card present and not MUTE (spec:
        // card-present detection; absent SCARD_STATE_MUTE).
        let mut devices = Vec::new();
        for entry in entries {
            if !entry.state.is_connectable() {
                continue;
            }
            devices.push(DeviceInfo {
                id: DeviceId::new(entry.name.clone()),
                name: entry.name,
                aaguid: None,
            });
        }
        Ok(devices)
    }

    async fn connect(
        &self,
        id: &DeviceId,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<Self::Device, Error> {
        let reader = id.as_str();
        let nfc = self.is_nfc(reader);
        // Bounded SHARED-mode retry: a sharing violation retries
        // within the remaining budget; the transport never escalates
        // to EXCLUSIVE. No private backoff timer: retries are driven
        // by budget consumption alone (spec blocking-wait table:
        // "retry loop has no private backoff timer").
        #[allow(unused_assignments)] // Some(...) is always set before break
        let mut opened = None;
        loop {
            let lib = Arc::clone(&self.lib);
            let reader_name = String::from(reader);
            let mode = self.share;
            let attempt = granted(deadline, sleep, Phase::Connect, async move {
                lib.connect(&reader_name, mode)
            })
            .await;
            match attempt {
                Ok(open) => {
                    opened = Some(open);
                    break;
                }
                Err(err) if is_sharing_violation(&err) => {
                    // Contended: retry within the remaining budget; the
                    // transport never escalates to EXCLUSIVE.
                    if deadline.remaining().is_zero() {
                        return Err(Error::Timeout(Phase::Connect));
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        let Some((protocol, token)) = opened else {
            unreachable!("the loop exits only via break with `opened` set")
        };
        let _ = protocol;

        // The §11.3.3 SELECT is the channel-open hop: "A client SHALL
        // send a Select to the authenticator before any other
        // command" (§11.3.3). A typed skip (6A82/6985/6283) fails
        // connect typed so discovery classifies-then-skips per
        // ceremony D2.
        let mut device = PcscDevice {
            lib: Arc::clone(&self.lib),
            reader: String::from(reader),
            conn: Some(token),
            nfc,
            channel: None,
        };
        device.select_applet(deadline, sleep).await?;
        Ok(device)
    }
}

/// A connected PC/SC device (CCID or NFC — one code path).
#[derive(Debug)]
pub struct PcscDevice<L: Library + 'static> {
    lib: Arc<L>,
    reader: String,
    conn: Option<ConnToken>,
    nfc: bool,
    channel: Option<ChannelId>,
}

impl<L: Library + 'static> PcscDevice<L> {
    /// §11.3.3 FIDO applet SELECT — the channel-open hop (fidoh-core
    /// `Device::open_channel` doc: "APDU SELECT of the FIDO
    /// application per CTAP2.1 §11 for PC/SC").
    async fn select_applet(
        &mut self,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<(), Error> {
        let Some(conn) = self.conn else {
            return Err(Error::ChannelClosed);
        };
        let lib = Arc::clone(&self.lib);
        let command = select_fido_aid();
        let response = granted(deadline, sleep, Phase::ChannelOpen, async move {
            lib.transmit(&conn, &command)
        })
        .await?;
        match evaluate_select(&response) {
            Ok(outcome @ SelectOutcome::Selected { .. }) => {
                // Candidate: CTAP2 capability stays undecided here —
                // the mandatory getInfo probe (ceremony D3) settles
                // it within the same budget.
                self.channel = Some(CHANNEL);
                let _ = outcome;
                Ok(())
            }
            Ok(skip) => {
                self.release();
                Err(skip_error(&self.reader, &skip))
            }
            Err(e) => {
                self.release();
                Err(e)
            }
        }
    }

    fn release(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.lib.disconnect(conn);
        }
        self.channel = None;
    }

    /// One bounded presence poll (≤ [`NFC_POLL_SLICE`], through the
    /// `Sleep` factory): removal is observed within one slice plus
    /// the current exchange (spec NFC requirement).
    async fn presence(
        &mut self,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<bool, Error> {
        let Some(conn) = self.conn else {
            return Err(Error::ChannelClosed);
        };
        let Some(slice) = nfc_field_poll_slice(deadline) else {
            return Err(Error::Timeout(Phase::UserPresence));
        };
        let lib = Arc::clone(&self.lib);
        let phase = Phase::CommandExchange;
        let mut poll =
            core::pin::pin!(async move { lib.status(&conn).map(|state: CardState| state.present) });
        match fidoh_core::future::select(poll.as_mut(), sleep.sleep(slice.granted)).await {
            fidoh_core::future::Either::Left(result) => {
                result.map_err(|e| pcsc_into_core(e, phase))
            }
            fidoh_core::future::Either::Right(()) => Err(Error::Timeout(phase)),
        }
    }

    /// The NFC presence loop (spec: "Presence poll slices stay
    /// bounded"): each slice is at most [`NFC_POLL_SLICE`] and goes
    /// through the `Sleep` factory; the loop terminates at the
    /// budget. Returns when the card is back in the field.
    pub async fn wait_for_field(
        &mut self,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<(), Error> {
        loop {
            if self.presence(deadline, sleep).await? {
                return Ok(());
            }
        }
    }

    /// Whether this connection is NFC/T=CL (metadata; the APDU layer
    /// is identical on both media).
    pub fn is_nfc(&self) -> bool {
        self.nfc
    }

    /// The reader name (typed errors and hardware logs identify it).
    pub fn reader_name(&self) -> &str {
        &self.reader
    }
}

/// The logical channel id of a PC/SC connection (fidoh-core
/// `ChannelId` doc: "PC/SC has a logical per-connection channel").
const CHANNEL: ChannelId = ChannelId(1);

fn skip_error(reader: &str, outcome: &SelectOutcome) -> Error {
    let cause = match outcome {
        SelectOutcome::NotFido => SkipCause::NotFido {
            qualifier: None,
            sw: 0x6A82,
        },
        SelectOutcome::ConditionSkip => SkipCause::NotFido {
            qualifier: Some("condition"),
            sw: 0x6985,
        },
        SelectOutcome::InvalidatedSkip => SkipCause::NotFido {
            qualifier: Some("invalidated"),
            sw: 0x6283,
        },
        SelectOutcome::Selected { .. } => unreachable!("skip path only"),
    };
    PcscError::Skip {
        cause,
        reader: String::from(reader),
    }
    .into_core()
}

fn encode_error(phase: Phase, detail: String) -> Error {
    Error::Transport(fidoh_core::TransportError::new(
        "pcsc",
        alloc::format!("request encoding ({phase} phase): {detail}"),
    ))
}

impl<L: Library + 'static> CtapDevice for PcscDevice<L> {
    async fn send(
        &mut self,
        cmd: &CtapCommand,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<DeviceEvent, Error> {
        let Some(conn) = self.conn else {
            return Err(Error::ChannelClosed);
        };
        let phase = cmd.phase();
        if deadline.remaining().is_zero() {
            return Err(Error::Timeout(phase));
        }
        // Encode the CTAP command per §11.3.5.1: command byte ||
        // canonical CBOR (fidoh-core model encoders).
        let (byte, payload): (u8, Vec<u8>) = match cmd {
            CtapCommand::GetInfo => (command_byte::GET_INFO, Vec::new()),
            CtapCommand::GetAssertion(request) => {
                let payload = request
                    .encode()
                    .map_err(|e| encode_error(phase, alloc::format!("{e}")))?;
                (command_byte::GET_ASSERTION, payload)
            }
            CtapCommand::ClientPin(request) => {
                // authenticatorClientPIN is CTAP command 0x06
                // (CTAP2.1 §6.5.5); add-client-pin wires the transport
                // framing for the acquisition hops.
                let payload = request
                    .encode()
                    .map_err(|e| encode_error(phase, alloc::format!("{e}")))?;
                (command_byte::CLIENT_PIN, payload)
            }
        };
        // One exchange state machine per send (§11.3.5.2 receive
        // procedure). Every hop — command, GET RESPONSE, Le retry,
        // GETRESPONSE poll — is one budget-bounded transmit.
        let mut exchange = Exchange::new(byte, &payload, phase);
        let mut next = crate::framing::framed(byte, &payload);
        loop {
            let lib = Arc::clone(&self.lib);
            let command = next.as_bytes().to_vec();
            let response = granted(deadline, sleep, phase, async move {
                lib.transmit(&conn, &command)
            })
            .await?;
            match exchange.step(&response)? {
                Step::Send(hop) => next = hop,
                Step::Done(ctap) => {
                    return Ok(DeviceEvent::Response {
                        status: ctap.status,
                        body: ctap.body,
                    });
                }
            }
        }
    }

    async fn open_channel(
        &mut self,
        _deadline: &Deadline,
        _sleep: SleepHandle<'_>,
    ) -> Result<ChannelId, Error> {
        // SELECT already ran at connect (§11.3.3 "before any other
        // command"); re-running it here would multiply device traffic
        // for zero information (design A3's principle applied to
        // channels). The logical channel exists as long as the
        // connection does.
        if self.conn.is_none() {
            return Err(Error::ChannelClosed);
        }
        self.channel = Some(CHANNEL);
        Ok(CHANNEL)
    }

    async fn close(mut self) -> Result<(), Error> {
        self.release();
        Ok(())
    }
}

impl<L: Library + 'static> Drop for PcscDevice<L> {
    fn drop(&mut self) {
        // Best-effort release (fidoh-core Device doc: a device
        // dropped mid-operation makes a best-effort release attempt;
        // a later connect to the same reader succeeds).
        self.release();
    }
}
