//! The orchestration layer: selection, the keepalive UX tap, and the
//! assert exchange path — runtime-agnostic (design D2: everything
//! above the adapter names no runtime; the `Sleep` handle arrives as
//! the parameter it has everywhere else in the stack).
//!
//! Composition model (ceremony design D1, two-stage entry):
//! discovery is the caller's (`discover.rs` — it differs between
//! hardware listing and demo mode); from selection on, this module
//! owns the pipeline: `select_device` (explicit policy, default
//! `Fail`), then `run_exchange` — the mandatory getInfo probe
//! (CTAP2.1 §6.4; ceremony OQ-2) + the §6.2 exchange with its
//! keepalive loop, via [`GetAssertionExchange`], bounded by the ONE
//! shared [`Deadline`] the caller has been passing since discovery.
//!
//! # Keepalive UX (design D4)
//!
//! Core surfaces keepalives as progress *inside* the ceremony loop;
//! they never escape [`Ceremony::run`]. The CLI taps the event stream
//! with [`UxDevice`]: a `Device` wrapper that forwards every event
//! unchanged and calls the UX sink for each keepalive. The display
//! dedup ([`TouchPrompt`]) prints the touch prompt on the FIRST
//! `UP_NEEDED` only — device-event fidelity stays in the libraries,
//! pretty suppression is a caller concern.

use core::time::Duration;
use std::format;
use std::string::String;
use std::vec::Vec;

use fidoh_core::device::{ChannelId, CtapCommand, Device, DeviceEvent};
use fidoh_core::error::CeremonyError;
use fidoh_core::get_assertion::{
    CredentialType, GetAssertionRequest, PublicKeyCredentialDescriptor,
};
use fidoh_core::sleep::SleepHandle;
use fidoh_core::time::Deadline;
use fidoh_core::transport::{apply_selection, CandidateDescriptor, DeviceInfo, SelectionPolicy};
use fidoh_core::{Ceremony, GetAssertionExchange, GetAssertionOutcome, UvPolicy};

use crate::args::AssertArgs;

/// The default ceremony budget: 45 s covers discovery + a human
/// walking to the token; overridable with `--budget`.
pub const DEFAULT_BUDGET: Duration = Duration::from_secs(45);

/// The clientDataHash this tool binds (CTAP2.1 §6.2 request key 0x02).
/// A fixed tool-side constant: `fidoh` is not an RP, it mints no
/// WebAuthn context, and it prints the raw assertion for a human (the
/// RP boundary — clientDataJSON construction + verification — stays
/// with the actual relying party per the stack's RP-agnostic rule).
pub const CLIENT_DATA_HASH: [u8; 32] = [0xAB; 32];

/// The UP_NEEDED keepalive status byte (CTAP2.1 §11.2.9.1.7: 0x01
/// processing, 0x02 UP_NEEDED).
pub const UP_NEEDED: u8 = 0x02;

/// The prompt line printed on the first UP_NEEDED.
pub const TOUCH_PROMPT: &str = "touch your token...";

// --------------------------------------------------------------------
// Selection (explicit, deterministic; default Fail).
// --------------------------------------------------------------------

/// Apply the CLI's selection policy over the folded candidate list.
///
/// `first == false` (the default) maps to [`SelectionPolicy::Fail`] —
/// multiple candidates refuse to run with the typed `AmbiguousDevice`
/// carrying every candidate; a single candidate proceeds; zero
/// candidates is `NoDevice`. `first == true` is the explicit `First`
/// opt-in (ceremony design A2: it must be chosen explicitly).
pub fn select_device(
    candidates: Vec<DeviceInfo>,
    first: bool,
) -> Result<DeviceInfo, CeremonyError> {
    let descriptors: Vec<CandidateDescriptor> =
        candidates.iter().map(|info| info.descriptor()).collect();
    let policy = if first {
        SelectionPolicy::First
    } else {
        SelectionPolicy::Fail
    };
    let selected = apply_selection(&policy, &descriptors).map_err(CeremonyError::from_core)?;
    let chosen = selected.ok_or_else(|| CeremonyError::NoDevice(Vec::new()))?;
    // Map the chosen descriptor back to its DeviceInfo by position
    // (descriptors were built from the same list, in order).
    let idx = descriptors
        .iter()
        .position(|d| *d == chosen)
        .ok_or_else(|| {
            CeremonyError::Transport(fidoh_core::TransportError::new(
                "cli",
                format!("selected device {} lost from the candidate list", chosen.id),
            ))
        })?;
    match candidates.into_iter().nth(idx) {
        Some(info) => Ok(info),
        None => Err(CeremonyError::Transport(fidoh_core::TransportError::new(
            "cli",
            format!("selected device {} lost from the candidate list", chosen.id),
        ))),
    }
}

// --------------------------------------------------------------------
// Keepalive UX (design D4: display-level dedup).
// --------------------------------------------------------------------

/// The display-level dedup printer: calls its sink with
/// [`TOUCH_PROMPT`] on the FIRST `UP_NEEDED` (0x02) only; every other
/// keepalive is silent. The sink is injectable (the executable wires
/// stderr; tests capture a buffer).
pub struct TouchPrompt<S> {
    printed: bool,
    sink: S,
}

impl<S: FnMut(&str)> TouchPrompt<S> {
    /// A prompt wired to any line sink.
    pub fn with_sink(sink: S) -> Self {
        Self {
            printed: false,
            sink,
        }
    }

    /// Whether the prompt has fired (test seam).
    pub fn printed(&self) -> bool {
        self.printed
    }
}

impl Default for TouchPrompt<fn(&str)> {
    fn default() -> Self {
        Self::with_sink(|_| {})
    }
}

/// The keepalive UX seam (design D4): called for every keepalive the
/// ceremony surfaces; implementors decide what to show.
pub trait KeepaliveUX {
    /// One keepalive status byte surfaced by the ceremony.
    fn on_keepalive(&mut self, status: u8);
}

impl<S: FnMut(&str)> KeepaliveUX for TouchPrompt<S> {
    fn on_keepalive(&mut self, status: u8) {
        if status == UP_NEEDED && !self.printed {
            self.printed = true;
            (self.sink)(TOUCH_PROMPT);
        }
    }
}

/// A `Device` wrapper that taps the event stream for the UX while
/// forwarding everything unchanged to the inner device (the ceremony
/// keeps driving the wrapper; the CLI observes what it would never see
/// through the trait otherwise).
///
/// `F: FnMut(u8) + Send + 'static` — the UX closure crosses onto the
/// ceremony future (its futures are `Send` by design, async-core A4).
pub struct UxDevice<D, F> {
    inner: D,
    ux: F,
}

impl<D, F> UxDevice<D, F> {
    /// Wrap a connected device with a keepalive observer.
    pub fn new(inner: D, ux: F) -> Self {
        Self { inner, ux }
    }
}

impl<D: Device + Send, F: FnMut(u8) + Send> Device for UxDevice<D, F> {
    async fn send(
        &mut self,
        cmd: &CtapCommand,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<DeviceEvent, fidoh_core::Error> {
        let event = self.inner.send(cmd, deadline, sleep).await;
        if let Ok(DeviceEvent::Keepalive { status }) = &event {
            (self.ux)(*status);
        }
        event
    }

    async fn open_channel(
        &mut self,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<ChannelId, fidoh_core::Error> {
        self.inner.open_channel(deadline, sleep).await
    }

    async fn close(self) -> Result<(), fidoh_core::Error> {
        self.inner.close().await
    }
}

// --------------------------------------------------------------------
// Request construction + the assert exchange path.
// --------------------------------------------------------------------

/// Build the allow-list descriptors from validated hex ids (CTAP2.1
/// §6.2 key 0x03). The parser guarantees well-formed hex; undecodable
/// entries are skipped defensively (the empty list is omitted on the
/// wire by the ceremony's own empty-allowList rule).
pub fn allow_list(ids: &[String]) -> Vec<PublicKeyCredentialDescriptor> {
    ids.iter()
        .filter_map(|s| crate::args::decode_hex(s))
        .map(|id| PublicKeyCredentialDescriptor {
            type_field: CredentialType::PublicKey,
            id,
            transports: None,
        })
        .collect()
}

/// The exchange-only ceremony input for the CLI's `assert`:
/// capability-driven request construction (the mandatory probe inside
/// [`GetAssertionExchange::run`]), UV policy `Discouraged` (scope
/// fence: no interactive PIN/UV entry in v1).
pub fn exchange_input(args: &AssertArgs) -> GetAssertionExchange {
    GetAssertionExchange {
        rp_id: args.rp_id.clone(),
        client_data_hash: CLIENT_DATA_HASH.to_vec(),
        allow_credentials: match allow_list(&args.allow) {
            list if list.is_empty() => None,
            list => Some(list),
        },
        user_verification: UvPolicy::Discouraged,
        pin_uv_auth: None,
        drain: None,
    }
}

/// Run the assert exchange over an already-connected device: the
/// mandatory getInfo probe, the §6.2 exchange with its keepalive loop
/// (tapped for the UX), bounded by the shared budget. One budget, no
/// per-hop timeouts (async-core D4).
///
/// The UX callback is owned and `'static`: the ceremony future is
/// `Send` and may outlive this call frame's borrows, so the tap owns
/// its sink (the executable hands in the prompt; tests hand in a
/// capturing closure).
pub async fn run_exchange<D, F>(
    device: D,
    args: &AssertArgs,
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
    on_keepalive: F,
) -> Result<GetAssertionOutcome, CeremonyError>
where
    D: Device + Send + 'static,
    F: FnMut(u8) + Send + 'static,
{
    let taps = UxDevice::new(device, on_keepalive);
    exchange_input(args).run(taps, deadline, sleep).await
}

/// The §6.2 request the CLI builds (exposed for tests: wire rules —
/// empty allowList omission, uv/pinUvAuth exclusion — are the
/// ceremony's; this only shows what the CLI's input produces).
#[allow(dead_code)]
fn wire_preview(
    info: &fidoh_core::get_info::GetInfoResponse,
    args: &AssertArgs,
) -> Result<GetAssertionRequest, CeremonyError> {
    let mut request = GetAssertionRequest::new(args.rp_id.clone(), CLIENT_DATA_HASH.to_vec())
        .map_err(|e| {
            CeremonyError::Transport(fidoh_core::TransportError::new(
                "cli",
                format!("request construction: {e}"),
            ))
        })?;
    request.allow_list = match allow_list(&args.allow) {
        list if list.is_empty() => None,
        list => Some(list),
    };
    let _ = info;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn dev(id: &str, name: &str) -> DeviceInfo {
        DeviceInfo {
            id: fidoh_core::transport::DeviceId::new(id),
            name: String::from(name),
            aaguid: None,
        }
    }

    #[test]
    fn select_fails_typed_on_multiple_candidates() {
        let err = select_device(vec![dev("a", "A"), dev("b", "B")], false).unwrap_err();
        match &err {
            CeremonyError::AmbiguousDevice(c) => {
                assert_eq!(c.len(), 2);
                assert_eq!(c[0].id.as_str(), "a");
                assert_eq!(c[1].id.as_str(), "b");
            }
            other => panic!("expected AmbiguousDevice, got {other:?}"),
        }
    }

    #[test]
    fn select_single_candidate_proceeds_and_empty_is_no_device() {
        assert_eq!(
            select_device(vec![dev("only", "One")], false)
                .expect("single candidate")
                .id
                .as_str(),
            "only"
        );
        assert!(matches!(
            select_device(vec![], false),
            Err(CeremonyError::NoDevice(_))
        ));
    }

    #[test]
    fn select_first_policy_explicit() {
        let d = select_device(vec![dev("a", "A"), dev("b", "B")], true)
            .expect("first policy picks deterministically");
        assert_eq!(d.id.as_str(), "a");
    }

    #[test]
    fn touch_prompt_prints_exactly_once() {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_lines = Arc::clone(&lines);
        let mut prompt = TouchPrompt::with_sink(move |line: &str| {
            sink_lines
                .lock()
                .expect("sink lock")
                .push(String::from(line));
        });
        // A stream of repeated UP_NEEDED keepalives (the fake-stream
        // shape the spec scenario describes)...
        for _ in 0..10 {
            KeepaliveUX::on_keepalive(&mut prompt, UP_NEEDED);
        }
        // ...and other processing keepalives interleaved.
        KeepaliveUX::on_keepalive(&mut prompt, 0x01);
        KeepaliveUX::on_keepalive(&mut prompt, UP_NEEDED);
        let got = lines.lock().expect("sink lock");
        assert_eq!(
            got.len(),
            1,
            "the touch prompt must print exactly once, got {got:?}"
        );
        assert_eq!(got[0], TOUCH_PROMPT);
        assert!(prompt.printed());
    }

    #[test]
    fn allow_list_decodes_and_omits_empty() {
        let list = allow_list(&[String::from("aabb"), String::from("0xCCDD")]);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, vec![0xaa, 0xbb]);
        assert_eq!(list[1].id, vec![0xcc, 0xdd]);
        assert!(allow_list(&[]).is_empty());
        let input = exchange_input(&AssertArgs {
            rp_id: String::from("example.com"),
            allow: vec![],
            first: false,
            budget_secs: 5,
            demo: true,
        });
        assert!(input.allow_credentials.is_none());
        assert_eq!(input.rp_id, "example.com");
    }
}
