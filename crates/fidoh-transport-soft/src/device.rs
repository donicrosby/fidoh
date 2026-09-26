//! The transport shim: [`Transport`](fidoh_core::Transport) /
//! [`Device`](fidoh_core::Device) impls over the authenticator core,
//! plus all error-injection knob handling (keepalive sequences,
//! delays, status injection — design's "transport shim" layer).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use fidoh_core::device::{ChannelId, CtapCommand, Device, DeviceEvent};
use fidoh_core::sleep::SleepHandle;
use fidoh_core::time::{Deadline, Phase};
use fidoh_core::transport::{DeviceId, DeviceInfo, Transport};
use fidoh_core::{Error, StatusCode, DEFAULT_WAIT_SLICE};

use spin::Mutex;

use crate::auth::SoftAuthenticator;
use crate::config::{Config, UpUvMode};
use crate::rng::{soft_err, RngSource};
use crate::wire;
use crate::DELAY_HARD_CAP;

/// Shared, `Send`-able handle to the authenticator core. The mutex is
/// held only for synchronous sections (never across `.await`), so no
/// executor fairness concerns apply; `spin::Mutex` keeps the crate
/// no_std (`std::sync::Mutex` would drag in `std`).
pub type SoftDeviceCore = Arc<Mutex<SoftAuthenticator>>;

/// The soft transport (transport-soft spec "Transport/Device trait
/// parity"). Enumerates exactly one device per authenticator instance;
/// `connect` hands out a [`SoftDevice`] sharing the core.
pub struct SoftTransport {
    core: SoftDeviceCore,
}

impl SoftTransport {
    /// Wrap an authenticator as a transport.
    pub fn new(auth: SoftAuthenticator) -> Self {
        Self {
            core: Arc::new(Mutex::new(auth)),
        }
    }

    /// Build a transport from a plain config (convenience).
    pub fn from_config(config: Config) -> Self {
        Self::new(SoftAuthenticator::new(config))
    }

    /// Shared access to the authenticator core for harness calls
    /// (minting credentials, poking UP/UV, arming knobs).
    pub fn core(&self) -> SoftDeviceCore {
        Arc::clone(&self.core)
    }
}

impl Transport for SoftTransport {
    type Device = SoftDevice;

    async fn enumerate(
        &self,
        _deadline: &Deadline,
        _sleep: SleepHandle<'_>,
    ) -> Result<Vec<DeviceInfo>, Error> {
        Ok(alloc::vec![DeviceInfo {
            id: DeviceId::new("soft-0"),
            name: String::from("fidoh soft token"),
            aaguid: Some(crate::auth::AAGUID),
        }])
    }

    async fn connect(
        &self,
        id: &DeviceId,
        _deadline: &Deadline,
        _sleep: SleepHandle<'_>,
    ) -> Result<Self::Device, Error> {
        if id.as_str() != "soft-0" {
            return Err(Error::UnknownDevice(id.clone()));
        }
        let channel = ChannelId(0x50F7_0001);
        Ok(SoftDevice {
            core: Arc::clone(&self.core),
            channel: Some(channel),
            events: alloc::collections::VecDeque::new(),
            pending_response: None,
            pending_overshoot: false,
        })
    }
}

/// A connected soft device handle.
pub struct SoftDevice {
    core: SoftDeviceCore,
    channel: Option<ChannelId>,
    /// Progress events staged ahead of the terminal response
    /// (keepalive sequence, poke-wait keepalives): drained one per
    /// `send` before the response.
    events: alloc::collections::VecDeque<DeviceEvent>,
    /// A computed terminal response held back while a configured
    /// delay/overshoot runs its course (delivered after the staged
    /// keepalives are drained).
    pending_response: Option<DeviceEvent>,
    /// Whether the held-back response's delay consumed the whole
    /// shared budget (the client's typed deadline timeout fires
    /// meanwhile; the token itself stays bounded by the hard cap).
    pending_overshoot: bool,
}

impl SoftDevice {
    /// Shared access to the authenticator core (harness use: poke,
    /// knobs, snapshots).
    pub fn core(&self) -> SoftDeviceCore {
        Arc::clone(&self.core)
    }
}

impl Device for SoftDevice {
    async fn send(
        &mut self,
        cmd: &CtapCommand,
        deadline: &Deadline,
        _sleep: SleepHandle<'_>,
    ) -> Result<DeviceEvent, Error> {
        if self.channel.is_none() {
            return Err(Error::ChannelClosed);
        }
        // The shared budget is the single source of timeout truth: an
        // exhausted budget means the caller's ceremony deadline has
        // expired — the typed timeout wins over everything, including
        // a pending delayed response (that response is never delivered
        // to a caller whose deadline is gone; the token's own delay
        // stayed bounded by the hard cap).
        let phase = cmd.phase();
        if deadline.remaining().is_zero() {
            return Err(Error::Timeout(phase));
        }
        // Staged progress first: one event per send, then the terminal
        // response (DeviceEvent stream semantics).
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        if let Some(response) = self.pending_response.take() {
            if self.pending_overshoot {
                // First send after the delay was armed: surface the
                // in-flight delay as UP_PROCESSING progress; the
                // response stays held until the next send (which will
                // only happen if the caller still has budget).
                self.pending_response = Some(response);
                self.pending_overshoot = false;
                return Ok(DeviceEvent::Keepalive { status: 0x01 });
            }
            return Ok(response);
        }
        match cmd {
            CtapCommand::GetInfo => self.exchange_get_info(),
            CtapCommand::GetAssertion(request) => {
                self.exchange_get_assertion(request, deadline, phase)
            }
            CtapCommand::ClientPin(request) => self.exchange_client_pin(request),
        }
    }

    async fn open_channel(
        &mut self,
        _deadline: &Deadline,
        _sleep: SleepHandle<'_>,
    ) -> Result<ChannelId, Error> {
        // In-process: no INIT/SELECT exchange, but the lifecycle is
        // modeled so client code runs identically to hardware.
        let channel = ChannelId(0x50F7_0001);
        self.channel = Some(channel);
        Ok(channel)
    }

    async fn close(mut self) -> Result<(), Error> {
        self.channel = None;
        Ok(())
    }
}

impl SoftDevice {
    fn exchange_get_info(&mut self) -> Result<DeviceEvent, Error> {
        let mut core = self.core.lock();
        if let Some(status) = take_injected_status(&mut core) {
            return Ok(DeviceEvent::Response {
                status: status.to_u8(),
                body: Vec::new(),
            });
        }
        let body = core
            .get_info()
            .to_wire_cbor()
            .map_err(|e| soft_err(alloc::format!("{e}")))?;
        Ok(DeviceEvent::Response {
            status: StatusCode::Ok.to_u8(),
            body,
        })
    }

    /// One authenticatorClientPIN (0x06) exchange (add-client-pin):
    /// status-injection knob first (knob (a) fires here exactly as on
    /// getAssertion), then the authenticator-core state machine. The
    /// soft token's key generation/token minting entropy comes from the
    /// SAME injected `RngSource` as credential keys — deterministic
    /// fixtures stay byte-reproducible.
    fn exchange_client_pin(
        &mut self,
        request: &fidoh_core::pin::ClientPinRequest,
    ) -> Result<DeviceEvent, Error> {
        let mut core = self.core.lock();
        if let Some(status) = take_injected_status(&mut core) {
            return Ok(DeviceEvent::Response {
                status: status.to_u8(),
                body: Vec::new(),
            });
        }
        // Bridge the token's RngSource onto the PinEntropySource seam.
        // The stream is temporarily taken out of the core so the state
        // machine can run on `&mut core` while drawing entropy (the
        // stream is put back before ANY return path).
        let mut rng_stream = core::mem::replace(
            &mut core.rng,
            Box::new(crate::rng::DeterministicRng::build_salted()),
        );
        let mut entropy = SoftEntropy {
            rng: &mut rng_stream,
        };
        let outcome = core.client_pin_exchange(request, &mut entropy);
        core.rng = rng_stream;
        match outcome {
            Ok(response) => {
                let value = fidoh_core::cbor::CborValue::Map(encode_client_pin_response(&response));
                let body = value
                    .encode()
                    .map_err(|e| soft_err(alloc::format!("{e}")))?;
                Ok(DeviceEvent::Response {
                    status: StatusCode::Ok.to_u8(),
                    body,
                })
            }
            Err(status) => {
                // 0x31 carries the pinRetries member per §6.5.5 (the
                // client surfaces it typed).
                let body = if status == StatusCode::PinInvalid {
                    let retries = core.pin_retries().unwrap_or_default();
                    let value = fidoh_core::cbor::CborValue::Map(alloc::vec![(
                        fidoh_core::cbor::CborValue::Int(0x03),
                        fidoh_core::cbor::CborValue::Int(i128::from(retries)),
                    )]);
                    value
                        .encode()
                        .map_err(|e| soft_err(alloc::format!("{e}")))?
                } else {
                    Vec::new()
                };
                Ok(DeviceEvent::Response {
                    status: status.to_u8(),
                    body,
                })
            }
        }
    }

    fn exchange_get_assertion(
        &mut self,
        request: &fidoh_core::get_assertion::GetAssertionRequest,
        deadline: &Deadline,
        phase: Phase,
    ) -> Result<DeviceEvent, Error> {
        // (a) Status injection fires before any real processing.
        {
            let mut core = self.core.lock();
            if let Some(status) = take_injected_status(&mut core) {
                return Ok(DeviceEvent::Response {
                    status: status.to_u8(),
                    body: Vec::new(),
                });
            }
        }

        // (b) Keepalive sequence: each event is staged BEFORE the
        // terminal response; its spacing is consumed from the shared
        // ceremony budget (spacing is a design property of the
        // sequence, enforced by the test clock driving the budget).
        let events = {
            let mut core = self.core.lock();
            if core.knobs.persistent {
                core.knobs.keepalive_sequence.clone()
            } else {
                core::mem::take(&mut core.knobs.keepalive_sequence)
            }
        };
        for event in &events {
            consume_budget_slice(deadline, event.spacing, phase)?;
            self.events.push_back(DeviceEvent::Keepalive {
                status: event.status,
            });
        }
        if !self.events.is_empty() {
            // First keepalive goes out with THIS exchange; the rest
            // drain on subsequent sends before the response.
            return Ok(self
                .events
                .pop_front()
                .unwrap_or(DeviceEvent::Keepalive { status: 0x02 }));
        }

        // (c) UP/UV behavior modes. `always-fail` rejects immediately
        // with CTAP2_ERR_OPERATION_DENIED (0x27); `require-explicit-poke`
        // pends on the harness poke — the budget consumed per poll
        // slice is bounded SOLELY by the caller's deadline (design
        // §Blocking waits): expiry surfaces as a typed timeout and
        // there is no internal timer.
        let up = match self.await_up_uv(deadline, phase, Requirement::Up)? {
            Outcome::Satisfied => true,
            Outcome::Denied => {
                return Ok(DeviceEvent::Response {
                    status: StatusCode::OperationDenied.to_u8(),
                    body: Vec::new(),
                });
            }
            // Still pended on an explicit poke: the staged UP_NEEDED
            // keepalive is returned as surfaced progress; no response
            // this exchange — the poke or the deadline decides.
            Outcome::Pending => {
                return match self.events.pop_front() {
                    Some(event) => Ok(event),
                    None => Ok(DeviceEvent::Keepalive { status: 0x02 }),
                };
            }
        };
        let uv = match self.await_up_uv(deadline, phase, Requirement::Uv)? {
            Outcome::Satisfied => true,
            Outcome::Denied => {
                return Ok(DeviceEvent::Response {
                    status: StatusCode::OperationDenied.to_u8(),
                    body: Vec::new(),
                });
            }
            Outcome::Pending => {
                return match self.events.pop_front() {
                    Some(event) => Ok(event),
                    None => Ok(DeviceEvent::Keepalive { status: 0x02 }),
                };
            }
        };

        // (d) Delay-beyond-deadline: the response is computed, then
        // held back. The delay's budget cost is
        // `deadline.remaining() + delay` (hard-capped overshoot at
        // DELAY_HARD_CAP = 60 s) — strictly more than the caller can
        // ever have left, so the client-side deadline path ALWAYS
        // fires before delivery; the token's own wait stays bounded.
        let delay = {
            let mut core = self.core.lock();
            if core.knobs.persistent {
                core.knobs.delay_beyond_deadline
            } else {
                core.knobs.delay_beyond_deadline.take()
            }
        };
        let overshoot = delay.is_some();
        if let Some(delay) = delay {
            let bounded = delay.min(deadline.remaining() + DELAY_HARD_CAP);
            let _ = consume_budget_slice(deadline, bounded, phase);
        }

        // Real command processing.
        let mut core = self.core.lock();
        let matching = match core.select_credentials(request) {
            Ok(m) => m,
            Err(status) => {
                return Ok(DeviceEvent::Response {
                    status: status.to_u8(),
                    body: Vec::new(),
                })
            }
        };
        let wrong_id = if core.knobs.persistent {
            core.knobs.wrong_credential_id
        } else {
            core::mem::take(&mut core.knobs.wrong_credential_id)
        };
        let selected = matching[0];
        // Wrong-credential-id: echo a DIFFERENT stored credential ID in
        // the descriptor while signing under the selected credential
        // (signature must stay valid per the spec scenario).
        let echoed = if wrong_id {
            core.credentials
                .iter()
                .position(|c| c.id != core.credentials[selected].id)
                .unwrap_or(selected)
        } else {
            selected
        };
        let echoed_id = core.credentials[echoed].id.clone();
        let user_handle = core.credentials[selected]
            .resident
            .then(|| core.credentials[selected].user_handle.clone());
        let (auth_data, signature) =
            core.sign_assertion(selected, &request.client_data_hash, up, uv)?;
        let number = if matching.len() > 1 {
            // Park the rest for getNextAssertion draining.
            core.assertion_queue = matching[1..]
                .iter()
                .map(|&i| (i, up, uv))
                .take(crate::auth::MAX_ASSERTION_QUEUE)
                .collect();
            Some(u64::try_from(matching.len()).unwrap_or(u64::MAX))
        } else {
            None
        };
        let body = wire::AssertionParts::encode_response(
            &echoed_id,
            &auth_data,
            &signature,
            user_handle.as_deref(),
            number,
        )
        .map_err(|e| soft_err(alloc::format!("{e}")))?;
        drop(core);
        if overshoot {
            // Hold the response back: the caller's budget is already
            // exhausted, so the typed deadline timeout fires before
            // delivery; further sends surface the pending state as a
            // UP_PROCESSING keepalive and then the response.
            self.pending_response = Some(DeviceEvent::Response {
                status: StatusCode::Ok.to_u8(),
                body,
            });
            self.pending_overshoot = true;
            return Ok(DeviceEvent::Keepalive { status: 0x01 });
        }
        Ok(DeviceEvent::Response {
            status: StatusCode::Ok.to_u8(),
            body,
        })
    }

    /// Resolve one UP/UV requirement under its configured mode.
    ///
    /// Synchronous: `require-explicit-poke` consumes one poll slice
    /// ([`crate::POKE_POLL_SLICE`], DEFAULT_WAIT_SLICE-capped) per
    /// `send` while it stays unsatisfied, staging an UP_NEEDED
    /// keepalive as surfaced progress (async-core: keepalives are
    /// progress signals, not errors). The wait is bounded SOLELY by
    /// the caller's shared budget — `consume_budget_slice` returns the
    /// typed timeout when the deadline expires; the token has no
    /// internal timer (design §Blocking waits).
    fn await_up_uv(
        &mut self,
        deadline: &Deadline,
        phase: Phase,
        requirement: Requirement,
    ) -> Result<Outcome, Error> {
        let mode = {
            let core = self.core.lock();
            match requirement {
                Requirement::Up => core.up_mode(),
                Requirement::Uv => core.uv_mode(),
            }
        };
        match mode {
            UpUvMode::AutoApprove => Ok(Outcome::Satisfied),
            UpUvMode::AlwaysFail => Ok(Outcome::Denied),
            UpUvMode::RequireExplicitPoke => {
                let poked = {
                    let mut core = self.core.lock();
                    match requirement {
                        Requirement::Up => core.take_up_poke(),
                        Requirement::Uv => core.take_uv_poke(),
                    }
                };
                if poked {
                    return Ok(Outcome::Satisfied);
                }
                // Consume this exchange's poll slice; the poke may land
                // before the caller's next `send`. Budget exhaustion is
                // the typed deadline timeout.
                consume_budget_slice(deadline, crate::POKE_POLL_SLICE, phase)?;
                self.events
                    .push_back(DeviceEvent::Keepalive { status: 0x02 });
                Ok(Outcome::Pending)
            }
        }
    }

    /// Await a queued getNextAssertion (multi-assertion drain).
    ///
    /// Not a `CtapCommand` variant in v1's client scope, so this is a
    /// harness-level method mirroring what the ceremony layer will
    /// drive once getNextAssertion lands (transport-soft spec
    /// "multi-assertion getNextAssertion drain" scenario).
    pub fn get_next_assertion(
        &mut self,
        client_data_hash: &[u8],
        _deadline: &Deadline,
    ) -> Result<DeviceEvent, Error> {
        let mut core = self.core.lock();
        let next = if core.assertion_queue.is_empty() {
            None
        } else {
            Some(core.assertion_queue.remove(0))
        };
        let Some((index, up, uv)) = next else {
            return Ok(DeviceEvent::Response {
                status: StatusCode::NotAllowed.to_u8(),
                body: Vec::new(),
            });
        };
        let record_id = core.credentials[index].id.clone();
        let user_handle = core.credentials[index]
            .resident
            .then(|| core.credentials[index].user_handle.clone());
        let (auth_data, signature) = core.sign_assertion(index, client_data_hash, up, uv)?;
        let body = wire::AssertionParts::encode_response(
            &record_id,
            &auth_data,
            &signature,
            user_handle.as_deref(),
            None,
        )
        .map_err(|e| soft_err(alloc::format!("{e}")))?;
        Ok(DeviceEvent::Response {
            status: StatusCode::Ok.to_u8(),
            body,
        })
    }
}

#[derive(Clone, Copy)]
enum Requirement {
    Up,
    Uv,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The requirement is satisfied for this exchange.
    Satisfied,
    /// The requirement is configured to fail
    /// (CTAP2_ERR_OPERATION_DENIED).
    Denied,
    /// Still pending (require-explicit-poke): progress was staged and
    /// a poll slice consumed; the caller re-issues the command.
    Pending,
}

/// Consume an injected status knob (one-shot unless persistent).
fn take_injected_status(core: &mut SoftAuthenticator) -> Option<StatusCode> {
    if core.knobs.persistent {
        core.knobs.inject_status
    } else {
        core.knobs.inject_status.take()
    }
}

/// Bridge the token's `RngSource` onto the crypto layer's
/// `PinEntropySource` seam (the soft token has ONE injected entropy
/// stream; fixtures stay deterministic across both).
struct SoftEntropy<'a> {
    rng: &'a mut Box<dyn RngSource + Send>,
}

impl fidoh_core::crypto::PinEntropySource for SoftEntropy<'_> {
    fn fill_random(&mut self, dest: &mut [u8]) -> Result<(), fidoh_core::crypto::PinCryptoError> {
        self.rng
            .fill(dest)
            .map_err(|_| fidoh_core::crypto::PinCryptoError::Random)
    }
}

/// Response-map encoding for a successful clientPIN exchange
/// (CTAP2.1 §6.5.5 response members; absent members omitted).
fn encode_client_pin_response(
    response: &fidoh_core::pin::ClientPinResponse,
) -> alloc::vec::Vec<(fidoh_core::cbor::CborValue, fidoh_core::cbor::CborValue)> {
    use fidoh_core::cbor::CborValue;
    let mut entries = alloc::vec::Vec::new();
    if let Some(ka) = &response.key_agreement {
        entries.push((CborValue::Int(0x01), ka.clone()));
    }
    if let Some(token) = &response.pin_uv_auth_token {
        entries.push((CborValue::Int(0x02), CborValue::Bytes(token.clone())));
    }
    if let Some(retries) = response.pin_retries {
        entries.push((CborValue::Int(0x03), CborValue::Int(i128::from(retries))));
    }
    if let Some(retries) = response.uv_retries {
        entries.push((CborValue::Int(0x05), CborValue::Int(i128::from(retries))));
    }
    entries
}

/// Consume a duration from the shared ceremony budget
/// (DEFAULT_WAIT_SLICE-capped re-slicing); budget exhaustion surfaces
/// the typed deadline timeout. Pure budget accounting — the token
/// performs no executor-blocking wait of its own (see the crate-level
/// SELF_WAIT_NOTE in this module's header docs).
fn consume_budget_slice(deadline: &Deadline, d: Duration, phase: Phase) -> Result<(), Error> {
    let mut remaining = d;
    while !remaining.is_zero() {
        let Some(slice) = deadline.consume_slice(remaining.min(DEFAULT_WAIT_SLICE)) else {
            return Err(Error::Timeout(phase));
        };
        remaining = remaining.saturating_sub(slice);
    }
    Ok(())
}
