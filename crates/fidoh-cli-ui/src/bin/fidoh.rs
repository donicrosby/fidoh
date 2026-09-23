//! The `fidoh` binary: a thin `main` over the lib (spec requirement:
//! binary behavior is testable through the lib, so this file only
//! glues process I/O, exit codes, and the runtime-context entry).
//!
//! Exit codes (design D6): 0 success — including "no devices" on
//! `list` — 2 usage errors, 1 typed error paths. Text to humans; the
//! typed variant names are the grep anchors.

use std::process::ExitCode;

use fidoh_cli_ui::args::{parse, usage, Invocation, ParseOutcome};
use fidoh_cli_ui::discover::{enumerate_hid, enumerate_pcsc, fold, kind_label};
use fidoh_cli_ui::exe::{with_run, Out, SleepRef};
use fidoh_cli_ui::render;
use fidoh_cli_ui::run::{self, DEFAULT_BUDGET};
use fidoh_core::device::Device;
use fidoh_core::transport::Transport;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut out = Out::new();
    let code = dispatch(&argv, &mut out);
    out.emit();
    ExitCode::from(code as u8)
}

fn dispatch(argv: &[String], out: &mut Out) -> i32 {
    match ParseOutcome::into_outcome(parse(argv)) {
        ParsedHelp::Help => {
            out.line(&usage());
            0
        }
        ParsedHelp::Failed(f) => {
            out.eline(&format!("fidoh: {}", f.message()));
            out.eline("run `fidoh help` for usage");
            2
        }
        ParsedHelp::Parsed(Invocation::List) => run_list(out),
        ParsedHelp::Parsed(Invocation::Info {
            device,
            budget_secs,
        }) => run_info(device.as_deref(), budget_secs, out),
        ParsedHelp::Parsed(Invocation::Assert(args)) => {
            // One ceremony pipeline for hardware and demo alike (D5):
            // only the transport source differs.
            run_assert(args, out)
        }
    }
}

/// Distinguish help from a typed usage failure without a second parse.
enum ParsedHelp {
    Help,
    Failed(fidoh_cli_ui::args::FailedFlag),
    Parsed(Invocation),
}

/// Fold a [`ParseOutcome`] into the dispatch enum (args::ParseOutcome
/// already carries all three shapes; this just re-tags Help).
trait IntoOutcome {
    fn into_outcome(o: ParseOutcome) -> ParsedHelp;
}

impl IntoOutcome for ParseOutcome {
    fn into_outcome(o: ParseOutcome) -> ParsedHelp {
        match o {
            ParseOutcome::Help => ParsedHelp::Help,
            ParseOutcome::Failed(f) => ParsedHelp::Failed(f),
            ParseOutcome::Parsed(i) => ParsedHelp::Parsed(i),
        }
    }
}

/// The ceremony budget from `--budget` seconds.
fn budget(secs: u64) -> std::time::Duration {
    std::time::Duration::from_secs(secs)
}

// --------------------------------------------------------------------
// Hardware composition: real transports behind the same lib paths the
// tests drive with fakes.
// --------------------------------------------------------------------

fn hid_transport() -> fidoh_transport_hid::HidTransport {
    fidoh_transport_hid::HidTransport::new()
}

/// The real PC/SC transport, or a typed failure detail (pcscd down).
fn pcsc_transport(
) -> Result<fidoh_transport_pcsc::PcscTransport<fidoh_transport_pcsc::library::PcscLibrary>, String>
{
    match fidoh_transport_pcsc::library::PcscLibrary::establish() {
        Ok(lib) => Ok(fidoh_transport_pcsc::PcscTransport::new(lib)),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// The typed runtime-entry error path (D6): rendered like any other
/// failure, exit 1. Only reachable if the runtime cannot be installed.
fn runtime_entry_error(e: &str, out: &mut Out) -> i32 {
    out.eline(&format!("fidoh: {e}"));
    1
}

// --------------------------------------------------------------------
// list
// --------------------------------------------------------------------

fn run_list(out: &mut Out) -> i32 {
    match with_run(|sleep| run_list_body(sleep, out)) {
        Ok(code) => code,
        Err(e) => runtime_entry_error(&e, out),
    }
}

async fn run_list_body(sleep: SleepRef, out: &mut Out) -> i32 {
    let deadline = fidoh_core::Deadline::new(DEFAULT_BUDGET);
    let hid = hid_transport();
    let hid_enum = enumerate_hid(&hid, &deadline, sleep.as_ref()).await;
    let pcsc_enum = match pcsc_transport() {
        Ok(t) => enumerate_pcsc(&t, &deadline, sleep.as_ref()).await,
        Err(detail) => {
            fidoh_cli_ui::discover::Enumeration::failed(fidoh_core::TransportKind::Pcsc, detail)
        }
    };
    let report = fidoh_cli_ui::discover::ListReport {
        transports: vec![hid_enum, pcsc_enum],
    };
    list_exit(report, out)
}

/// Render a `list` report and decide the exit (spec requirement:
/// one line per candidate; diagnostics under their own lines; zero
/// candidates + zero errors → explicit message + exit 0; errors + zero
/// candidates → non-zero with per-transport causes rendered).
fn list_exit(report: fidoh_cli_ui::discover::ListReport, out: &mut Out) -> i32 {
    let mut candidates = 0usize;
    let mut errors: Vec<fidoh_core::error::DiscoveryDiagnostic> = Vec::new();
    for t in &report.transports {
        let label = kind_label(t.kind);
        if let Some(detail) = &t.transport_error {
            errors.push(fidoh_core::error::DiscoveryDiagnostic::new(
                t.kind,
                fidoh_core::Error::Transport(fidoh_core::TransportError::new(
                    label,
                    detail.clone(),
                )),
            ));
            continue;
        }
        for node in &t.nodes {
            match node {
                fidoh_cli_ui::discover::NodeOutcome::Listed(info) => {
                    candidates += 1;
                    out.line(&format!("{}: {} ({})", label, info.id.as_str(), info.name));
                }
                fidoh_cli_ui::discover::NodeOutcome::Skip { node, reason } => {
                    out.eline(&format!("{label}: skip {node}: {reason}"));
                }
                fidoh_cli_ui::discover::NodeOutcome::Diagnostic { node, detail } => {
                    out.eline(&format!("{label}: {node}: {detail}"));
                }
            }
        }
    }
    if candidates == 0 {
        if errors.is_empty() {
            out.line("no devices found");
            return 0;
        }
        let err = fidoh_core::CeremonyError::NoDevice(errors);
        for line in render::error_lines(&err) {
            out.eline(&line);
        }
        return 1;
    }
    0
}

// --------------------------------------------------------------------
// info
// --------------------------------------------------------------------

fn run_info(device: Option<&str>, budget_secs: u64, out: &mut Out) -> i32 {
    match with_run(|sleep| run_info_body(device, budget_secs, sleep, out)) {
        Ok(code) => code,
        Err(e) => runtime_entry_error(&e, out),
    }
}

async fn run_info_body(
    device: Option<&str>,
    budget_secs: u64,
    sleep: SleepRef,
    out: &mut Out,
) -> i32 {
    let deadline = fidoh_core::Deadline::new(budget(budget_secs));
    let (enumerations, pcsc_err) = discover_hardware(&deadline, &sleep).await;
    let (candidates, mut diagnostics) = fold(enumerations);
    let candidates: Vec<_> = match device {
        Some(want) => candidates
            .into_iter()
            .filter(|c| c.id.as_str() == want)
            .collect(),
        None => candidates,
    };
    if candidates.is_empty() {
        if let Some(detail) = pcsc_err {
            diagnostics.push(fidoh_core::error::DiscoveryDiagnostic::new(
                fidoh_core::TransportKind::Pcsc,
                fidoh_core::Error::Transport(fidoh_core::TransportError::new("pcsc", detail)),
            ));
        }
        let err = fidoh_core::CeremonyError::NoDevice(diagnostics);
        for line in render::error_lines(&err) {
            out.eline(&line);
        }
        return 1;
    }
    let selected = match fidoh_cli_ui::run::select_device(candidates, false) {
        Ok(s) => s,
        Err(e) => return render_error(&e, out),
    };
    // Connect exactly the selected candidate (ceremony D1: connect
    // once), then the mandatory probe (OQ-2).
    let transport_kind = if selected.id.as_str().starts_with("/dev/") {
        fidoh_core::TransportKind::Hid
    } else {
        fidoh_core::TransportKind::Pcsc
    };
    let connected = match transport_kind {
        fidoh_core::TransportKind::Hid => {
            let hid = hid_transport();
            hid.connect(&selected.id, &deadline, sleep.as_ref())
                .await
                .map(Which::Hid)
        }
        _ => match pcsc_transport() {
            Ok(t) => t
                .connect(&selected.id, &deadline, sleep.as_ref())
                .await
                .map(Which::Pcsc),
            Err(detail) => Err(fidoh_core::Error::Transport(
                fidoh_core::TransportError::new("pcsc", detail),
            )),
        },
    };
    match connected {
        Err(e) => render_error(&fidoh_core::CeremonyError::from_core(e), out),
        Ok(which) => match probe(which, &deadline, &sleep).await {
            Ok(info) => {
                out.line(&format!("aaguid: {}", render::hex(&info.aaguid)));
                out.line(&format!("versions: {}", info.versions.join(", ")));
                if let Some(opts) = &info.options {
                    let mut keys: Vec<&String> = opts.entries.keys().collect();
                    keys.sort();
                    for k in keys {
                        out.line(&format!("option {}: {}", k, opts.entries[k]));
                    }
                }
                if let Some(protocols) = &info.pin_uv_auth_protocols {
                    let list: Vec<String> =
                        protocols.iter().map(|p| p.to_u32().to_string()).collect();
                    out.line(&format!("pinUvAuthProtocols: {}", list.join(", ")));
                }
                0
            }
            Err(e) => render_error(&e, out),
        },
    }
}

/// Both hardware enumerations, in deterministic order (hid, pcsc).
/// A PC/SC context failure is returned separately as the typed detail.
async fn discover_hardware(
    deadline: &fidoh_core::Deadline,
    sleep: &SleepRef,
) -> (Vec<fidoh_cli_ui::discover::Enumeration>, Option<String>) {
    let hid = hid_transport();
    let hid_enum = enumerate_hid(&hid, deadline, sleep.as_ref()).await;
    match pcsc_transport() {
        Ok(t) => {
            let pcsc_enum = enumerate_pcsc(&t, deadline, sleep.as_ref()).await;
            (vec![hid_enum, pcsc_enum], None)
        }
        Err(detail) => (vec![hid_enum], Some(detail)),
    }
}

/// A connected device handle, transport-tagged (demo adds the soft
/// device under the `demo` feature).
enum Which {
    Hid(fidoh_transport_hid::HidDevice),
    Pcsc(fidoh_transport_pcsc::PcscDevice<fidoh_transport_pcsc::library::PcscLibrary>),
    #[cfg(feature = "demo")]
    Soft(fidoh_transport_soft::SoftDevice),
}

/// The mandatory getInfo probe over a connected device (CTAP2.1 §6.4),
/// decoded with the same strictness the ceremony applies.
async fn probe(
    which: Which,
    deadline: &fidoh_core::Deadline,
    sleep: &SleepRef,
) -> Result<fidoh_core::get_info::GetInfoResponse, fidoh_core::CeremonyError> {
    let cmd = fidoh_core::CtapCommand::GetInfo;
    let event = match which {
        Which::Hid(mut d) => d.send(&cmd, deadline, sleep.as_ref()).await,
        Which::Pcsc(mut d) => d.send(&cmd, deadline, sleep.as_ref()).await,
        #[cfg(feature = "demo")]
        Which::Soft(mut d) => d.send(&cmd, deadline, sleep.as_ref()).await,
    };
    decode_info(event)
}

fn decode_info(
    event: Result<fidoh_core::DeviceEvent, fidoh_core::Error>,
) -> Result<fidoh_core::get_info::GetInfoResponse, fidoh_core::CeremonyError> {
    use fidoh_core::cbor::CborValue;
    use fidoh_core::error::DecodePolicy;
    use fidoh_core::get_info::GetInfoResponse;
    let event = event.map_err(fidoh_core::CeremonyError::from_core)?;
    let (status, body) = match event {
        fidoh_core::DeviceEvent::Response { status, body } => (status, body),
        fidoh_core::DeviceEvent::Keepalive { .. } => {
            return Err(fidoh_core::CeremonyError::Transport(
                fidoh_core::TransportError::new(
                    "cli",
                    String::from("getInfo probe produced a keepalive progress signal"),
                ),
            ));
        }
    };
    if let Some(err) =
        fidoh_core::CeremonyError::from_status(fidoh_core::StatusCode::from_u8(status))
    {
        return Err(err);
    }
    let value = CborValue::decode_map(&body, DecodePolicy::Strict).map_err(|e| {
        fidoh_core::CeremonyError::Transport(fidoh_core::TransportError::new(
            "cli",
            format!("getInfo probe: {e}"),
        ))
    })?;
    GetInfoResponse::from_cbor(&value).map_err(|e| {
        fidoh_core::CeremonyError::Transport(fidoh_core::TransportError::new(
            "cli",
            format!("getInfo probe: {e}"),
        ))
    })
}

// --------------------------------------------------------------------
// assert (hardware + demo: the same pipeline, D5)
// --------------------------------------------------------------------

fn run_assert(args: fidoh_cli_ui::args::AssertArgs, out: &mut Out) -> i32 {
    match with_run(|sleep| run_assert_body(args, sleep, out)) {
        Ok(code) => code,
        Err(e) => runtime_entry_error(&e, out),
    }
}

async fn run_assert_body(
    args: fidoh_cli_ui::args::AssertArgs,
    sleep: SleepRef,
    out: &mut Out,
) -> i32 {
    let deadline = fidoh_core::Deadline::new(budget(args.budget_secs));
    // Discovery + selection + connect (one budget); then the exchange
    // gets the remainder (D4). The keepalive tap owns its prompt state
    // ('static: the ceremony future may outlive this frame) and prints
    // the touch prompt exactly once (design D4).
    let prompt_lines: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let tap = make_prompt_tap(&prompt_lines);
    // outcome: the ceremony result paired with the discovery
    // diagnostics both paths carry (D2: never silently dropped).
    let outcome = match connect_for_assert(&args, &deadline, &sleep).await {
        Ok((which, diagnostics)) => {
            let exchanged = match which {
                Which::Hid(d) => run::run_exchange(d, &args, &deadline, sleep.as_ref(), tap).await,
                Which::Pcsc(d) => run::run_exchange(d, &args, &deadline, sleep.as_ref(), tap).await,
                #[cfg(feature = "demo")]
                Which::Soft(d) => run::run_exchange(d, &args, &deadline, sleep.as_ref(), tap).await,
            };
            exchanged.map_err(|e| (e, diagnostics))
        }
        Err((e, diagnostics)) => Err((e, diagnostics)),
    };
    match outcome {
        Ok(o) => {
            print_assertion(&o, &args.rp_id, out);
            0
        }
        Err((e, diagnostics)) => {
            for line in prompt_lines.lock().expect("prompt lock").iter() {
                out.eline(line);
            }
            // Discovery diagnostics stay visible on the error path
            // (D2: never silently dropped).
            for d in &diagnostics {
                out.eline(&format!(
                    "  {}: {}",
                    fidoh_cli_ui::discover::kind_label(d.kind),
                    d.cause
                ));
            }
            render_error(&e, out)
        }
    }
}

/// A `'static` keepalive tap backed by the lib's `TouchPrompt` dedup
/// (design D4): owns its state, records prompt lines into `sink`.
fn make_prompt_tap(
    sink: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) -> impl FnMut(u8) + Send + 'static {
    let sink = std::sync::Arc::clone(sink);
    let mut prompt = fidoh_cli_ui::run::TouchPrompt::with_sink(move |line: &str| {
        sink.lock().expect("prompt lock").push(String::from(line));
    });
    move |status: u8| {
        fidoh_cli_ui::run::KeepaliveUX::on_keepalive(&mut prompt, status);
    }
}

async fn connect_for_assert(
    args: &fidoh_cli_ui::args::AssertArgs,
    deadline: &fidoh_core::Deadline,
    sleep: &SleepRef,
) -> Result<
    (Which, Vec<fidoh_core::error::DiscoveryDiagnostic>),
    (
        fidoh_core::CeremonyError,
        Vec<fidoh_core::error::DiscoveryDiagnostic>,
    ),
> {
    if args.demo {
        return connect_demo(args, deadline, sleep).await;
    }
    let (enumerations, pcsc_err) = discover_hardware(deadline, sleep).await;
    let (candidates, mut diagnostics) = fold(enumerations);
    if let Some(detail) = pcsc_err {
        diagnostics.push(fidoh_core::error::DiscoveryDiagnostic::new(
            fidoh_core::TransportKind::Pcsc,
            fidoh_core::Error::Transport(fidoh_core::TransportError::new("pcsc", detail)),
        ));
    }
    let selected = match fidoh_cli_ui::run::select_device(candidates, args.first) {
        Ok(s) => s,
        Err(e) => return Err((e, diagnostics)),
    };
    let connected = if selected.id.as_str().starts_with("/dev/") {
        let hid = hid_transport();
        hid.connect(&selected.id, deadline, sleep.as_ref())
            .await
            .map(Which::Hid)
    } else {
        match pcsc_transport() {
            Ok(t) => t
                .connect(&selected.id, deadline, sleep.as_ref())
                .await
                .map(Which::Pcsc),
            Err(detail) => Err(fidoh_core::Error::Transport(
                fidoh_core::TransportError::new("pcsc", detail),
            )),
        }
    };
    match connected {
        Ok(which) => Ok((which, diagnostics)),
        Err(e) => Err((fidoh_core::CeremonyError::from_core(e), diagnostics)),
    }
}

/// The demo transport source (design D5): the soft token in-process,
/// minted against the requested rpId, never in hardware discovery.
#[cfg(feature = "demo")]
async fn connect_demo(
    args: &fidoh_cli_ui::args::AssertArgs,
    deadline: &fidoh_core::Deadline,
    sleep: &SleepRef,
) -> Result<
    (Which, Vec<fidoh_core::error::DiscoveryDiagnostic>),
    (
        fidoh_core::CeremonyError,
        Vec<fidoh_core::error::DiscoveryDiagnostic>,
    ),
> {
    use fidoh_transport_soft::{Config, MakeCredentialArgs, SoftAuthenticator, SoftTransport};
    let mut auth = SoftAuthenticator::new(Config::default());
    let minted = auth.make_credential(MakeCredentialArgs {
        rp_id: args.rp_id.clone(),
        user_handle: b"cli-demo-user".to_vec(),
        resident: true,
    });
    if let Err(e) = minted {
        return Err((
            fidoh_core::CeremonyError::Transport(fidoh_core::TransportError::new(
                "soft",
                format!("demo credential mint: {e}"),
            )),
            Vec::new(),
        ));
    }
    let transport = SoftTransport::new(auth);
    let connected = Transport::connect(
        &transport,
        &fidoh_core::DeviceId::new("soft-0"),
        deadline,
        sleep.as_ref(),
    )
    .await
    .map(Which::Soft);
    match connected {
        Ok(which) => Ok((which, Vec::new())),
        Err(e) => Err((fidoh_core::CeremonyError::from_core(e), Vec::new())),
    }
}

#[cfg(not(feature = "demo"))]
async fn connect_demo(
    _args: &fidoh_cli_ui::args::AssertArgs,
    _deadline: &fidoh_core::Deadline,
    _sleep: &SleepRef,
) -> Result<
    (Which, Vec<fidoh_core::error::DiscoveryDiagnostic>),
    (
        fidoh_core::CeremonyError,
        Vec<fidoh_core::error::DiscoveryDiagnostic>,
    ),
> {
    Err((
        fidoh_core::CeremonyError::Transport(fidoh_core::TransportError::new(
            "cli",
            String::from("--demo requires a build with the `demo` feature"),
        )),
        Vec::new(),
    ))
}

fn render_error(e: &fidoh_core::CeremonyError, out: &mut Out) -> i32 {
    for line in render::error_lines(e) {
        out.eline(&line);
    }
    1
}

fn print_assertion(o: &fidoh_core::GetAssertionOutcome, rp_id: &str, out: &mut Out) {
    let first = o.first();
    out.line(&format!("rpId: {rp_id}"));
    out.line(&format!(
        "credentialId: {}",
        render::hex(&first.credential.id)
    ));
    if first.user_selected_present {
        out.line(&format!("userSelected: {}", first.user_selected));
    }
    out.line(&format!("authData: {}", render::hex(&first.auth_data)));
    out.line(&format!("signature: {}", render::hex(&first.signature)));
}
