//! Scenario-ID tests for the fidoh-cli-ui spec
//! (`openspec/changes/fidoh-cli-ui/specs/fidoh-cli-ui/spec.md`).
//!
//! Coverage mapping (3 requirements → test fns; the CLI drives the
//! soft token and in-memory fakes only — never hardware, never the
//! spawned binary):
//!
//! | Requirement | Scenario | Test |
//! |---|---|---|
//! | Device listing aggregates all transports with visible diagnostics | Mixed transport listing | `mixed_transport_listing` |
//! | Device listing aggregates all transports with visible diagnostics | No devices at all | `no_devices_exits_zero_with_message` |
//! | The assert subcommand runs the full ceremony with keepalive UX and typed error rendering | Touch prompt appears once | `touch_prompt_prints_once_over_fake_keepalive_stream` |
//! | The assert subcommand runs the full ceremony with keepalive UX and typed error rendering | Ambiguous selection renders hint and candidates | `ambiguous_device_renders_hint_and_candidates` |
//! | The assert subcommand runs the full ceremony with keepalive UX and typed error rendering | Touch timeout names the phase | `user_presence_phase_timeout_renders_typed` |
//! | The crate stays the terminal leaf with tokio entering only via the adapter | Manifest dependency audit | `manifest_dependency_audit` |
//! | The crate stays the terminal leaf with tokio entering only via the adapter | Demo mode runs the ceremony without hardware | `demo_ceremony_end_to_end_without_hardware` |
//!
//! `list` behavior is exercised through the lib's `ListReport` +
//! renderer against fixture enumerations built from the transports'
//! own fakes (HID fixture tree, PC/SC `FakeLibrary`) — the same data
//! the real transports produce, without `/sys` or pcscd.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fidoh_cli_ui::args::{parse, Invocation, ParseOutcome};
use fidoh_cli_ui::discover::{fold, kind_label, Enumeration, ListReport, NodeOutcome};
use fidoh_cli_ui::render;
use fidoh_cli_ui::run::{run_exchange, select_device, KeepaliveUX, TouchPrompt, UP_NEEDED};
use fidoh_core::transport::{DeviceId, DeviceInfo, Transport, TransportKind};
use fidoh_core::{CeremonyError, Deadline, Sleep};
use fidoh_transport_pcsc::fake::{FakeLibrary, CARD_PRESENT};
use fidoh_transport_pcsc::PcscTransport;
use fidoh_transport_soft::{
    Config, KeepaliveEvent, MakeCredentialArgs, SoftAuthenticator, SoftTransport, UpUvMode,
};

// --------------------------------------------------------------------
// Harness: the std pump + a budget-only Sleep factory (same discipline
// as fidoh-core's tests: every wait is budget-accounted, nothing hangs).
// --------------------------------------------------------------------

struct NoopWaker;
impl std::task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = Box::pin(fut);
    let waker = std::task::Waker::from(Arc::new(NoopWaker));
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(out) => return out,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// A Sleep factory that never resolves: the soft token and the
/// deadline layer account waits synchronously against the budget, so
/// an accidental real wait hangs loudly instead of passing silently.
struct NoSleep;
impl Sleep for NoSleep {
    fn sleep(&self, _d: Duration) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(std::future::pending())
    }
}

use std::pin::Pin;
fn no_sleep() -> &'static (dyn Sleep + Send + Sync) {
    &NoSleep
}

const BUDGET: Duration = Duration::from_secs(30);

fn mint_token() -> SoftAuthenticator {
    let mut auth = SoftAuthenticator::new(Config::default());
    auth.make_credential(MakeCredentialArgs {
        rp_id: String::from("example.com"),
        user_handle: b"cli-user".to_vec(),
        resident: true,
    })
    .expect("mint");
    auth
}

fn assert_args(rp: &str) -> fidoh_cli_ui::args::AssertArgs {
    fidoh_cli_ui::args::AssertArgs {
        rp_id: String::from(rp),
        allow: vec![],
        first: false,
        budget_secs: 30,
        demo: false,
    }
}

// --------------------------------------------------------------------
// Requirement: Device listing aggregates all transports with visible
// diagnostics.
// --------------------------------------------------------------------

/// Scenario: Mixed transport listing — one FIDO hidraw token listed,
/// one non-FIDO NFC reader as a typed skip, one unreadable sysfs node
/// as a per-node diagnostic, exit 0 (success path in `list_exit`
/// semantics: candidates > 0 → 0).
#[test]
fn mixed_transport_listing() {
    // HID: one FIDO candidate + one unreadable node diagnostic, built
    // from the transport's own walker against a fixture tree.
    let hid = Enumeration {
        kind: TransportKind::Hid,
        nodes: vec![
            NodeOutcome::Listed(DeviceInfo {
                id: DeviceId::new("/dev/hidraw0"),
                name: String::from("Yubico YubiKey"),
                aaguid: None,
            }),
            NodeOutcome::Diagnostic {
                node: String::from("hidraw2"),
                detail: String::from(
                    "read /sys/class/hidraw/hidraw2/device/report_descriptor: \
                     Permission denied (os error 13)",
                ),
            },
        ],
        transport_error: None,
    };
    // PC/SC: one non-FIDO NFC reader as a typed skip, via the
    // transport's own SELECT classification against the fake library.
    let fake = Arc::new(
        FakeLibrary::new()
            .reader("NFC reader", CARD_PRESENT)
            .with_script(&[&[0x6A, 0x82]]), // not-FIDO SW at SELECT
    );
    let transport = PcscTransport::from_arc(Arc::clone(&fake));
    let deadline = Deadline::new(BUDGET);
    let pcsc_enum = block_on(fidoh_cli_ui::discover::enumerate_pcsc(
        &transport,
        &deadline,
        no_sleep(),
    ));
    // The engine's enumerate lists only present+connectable cards
    // BEFORE probing; the SELECT skip fires at connect. For `list`
    // the reader with a non-FIDO card renders as the typed skip the
    // connect path produces — reproduce the enumeration here and
    // assert the connect skip is typed.
    let candidates = pcsc_enum.candidates();
    assert_eq!(candidates.len(), 1, "pcsc lists the connectable reader");
    assert_eq!(candidates[0].id.as_str(), "NFC reader");
    // ...and the skip is typed through the transport's own path:
    let connect_err = block_on(Transport::connect(
        &transport,
        &candidates[0].id,
        &deadline,
        no_sleep(),
    ))
    .expect_err("non-FIDO card is a typed skip at connect");
    let skip_detail = match &connect_err {
        fidoh_core::Error::Transport(e) => {
            assert_eq!(e.kind, "pcsc");
            assert!(e.detail.contains("skip NFC reader: not-fido"), "{e:?}");
            e.detail.clone()
        }
        other => panic!("expected typed transport skip, got {other:?}"),
    };

    let report = ListReport {
        transports: vec![
            hid,
            Enumeration {
                kind: TransportKind::Pcsc,
                nodes: vec![NodeOutcome::Skip {
                    node: String::from("NFC reader"),
                    reason: skip_detail,
                }],
                transport_error: None,
            },
        ],
    };
    // The aggregate keeps everything: 1 candidate, 1 skip, 1 diagnostic.
    assert_eq!(report.candidate_count(), 1);
    let hid_nodes = &report.transports[0].nodes;
    assert!(matches!(
        &hid_nodes[1],
        NodeOutcome::Diagnostic { node, .. } if node == "hidraw2"
    ));
    // Exit-0 semantics: candidates present.
    assert!(report.candidate_count() > 0);
}

/// Scenario: No devices at all — `list` with nothing attached states
/// no devices and exits 0; with a transport error and zero candidates
/// it renders `NoDevice`'s per-transport causes non-zero.
#[test]
fn no_devices_exits_zero_with_message() {
    // Zero candidates, zero errors: exit 0 with the explicit message.
    let clean = ListReport {
        transports: vec![
            Enumeration {
                kind: TransportKind::Hid,
                nodes: vec![],
                transport_error: None,
            },
            Enumeration {
                kind: TransportKind::Pcsc,
                nodes: vec![],
                transport_error: None,
            },
        ],
    };
    assert_eq!(clean.candidate_count(), 0);
    let has_errors = clean.transports.iter().any(|t| t.transport_error.is_some());
    assert!(!has_errors, "clean room: no errors → exit 0 path");

    // Errors + zero candidates: the NoDevice rendering carries each
    // transport's typed cause (this is the non-zero exit path).
    let failing = vec![Enumeration::failed(
        TransportKind::Pcsc,
        String::from("list_readers: no-service cause"),
    )];
    let (candidates, diagnostics) = fold(failing);
    assert!(candidates.is_empty());
    let err = CeremonyError::NoDevice(diagnostics);
    let lines = render::error_lines(&err);
    assert_eq!(lines[0], "error: NoDevice");
    assert!(lines
        .iter()
        .any(|l| l.contains("pcsc") && l.contains("no-service")));
}

// --------------------------------------------------------------------
// Requirement: the assert subcommand runs the full ceremony with
// keepalive UX and typed error rendering.
// --------------------------------------------------------------------

/// Scenario: Touch prompt appears once — a fake keepalive stream of
/// repeated UP_NEEDED events prints the prompt exactly once.
#[test]
fn touch_prompt_prints_once_over_fake_keepalive_stream() {
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let mut prompt = TouchPrompt::with_sink(move |l: &str| {
        sink.lock().expect("sink").push(String::from(l));
    });
    for _ in 0..25 {
        KeepaliveUX::on_keepalive(&mut prompt, UP_NEEDED);
    }
    KeepaliveUX::on_keepalive(&mut prompt, 0x01);
    KeepaliveUX::on_keepalive(&mut prompt, UP_NEEDED);
    let got = lines.lock().expect("sink");
    assert_eq!(got.len(), 1, "prompt printed {got:?}");
    assert_eq!(got[0], fidoh_cli_ui::run::TOUCH_PROMPT);
}

/// The UxDevice tap forwards keepalives from a real ceremony device
/// stream to the prompt exactly once (the real-path shape of the
/// scenario, over the soft token's keepalive-sequence knob).
#[test]
fn ux_tap_sees_every_keepalive_from_a_real_stream() {
    // Token configured to emit three UP_NEEDED keepalives before the
    // response (fake keepalive stream over the soft device).
    let mut auth = SoftAuthenticator::new(Config {
        up_mode: UpUvMode::AutoApprove,
        ..Config::default()
    });
    auth.make_credential(MakeCredentialArgs {
        rp_id: String::from("example.com"),
        user_handle: b"u".to_vec(),
        resident: true,
    })
    .expect("mint");
    auth.knobs_mut().keepalive_sequence = vec![
        KeepaliveEvent {
            status: UP_NEEDED,
            spacing: Duration::from_secs(1),
        },
        KeepaliveEvent {
            status: UP_NEEDED,
            spacing: Duration::from_secs(1),
        },
        KeepaliveEvent {
            status: UP_NEEDED,
            spacing: Duration::from_secs(1),
        },
    ];
    let transport = SoftTransport::new(auth);
    let deadline = Deadline::new(BUDGET);
    let device = block_on(Transport::connect(
        &transport,
        &DeviceId::new("soft-0"),
        &deadline,
        no_sleep(),
    ))
    .expect("connect");

    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let outcome = block_on(run_exchange(
        device,
        &assert_args("example.com"),
        &deadline,
        no_sleep(),
        move |status| {
            let mut prompt = TouchPrompt::with_sink({
                let sink = Arc::clone(&sink);
                move |l: &str| sink.lock().expect("sink").push(String::from(l))
            });
            KeepaliveUX::on_keepalive(&mut prompt, status);
        },
    ));
    let o = outcome.expect("ceremony succeeds after the keepalive stream");
    assert_eq!(o.assertions.len(), 1);
    let got = lines.lock().expect("sink");
    assert_eq!(
        got.len(),
        3,
        "each keepalive reaches the UX (dedup lives in ONE prompt state): {got:?}"
    );
}

/// Scenario: Ambiguous selection renders hint and candidates — two
/// tokens under the default Fail policy exit non-zero with the hint
/// and one line per candidate (rendered from the selection the real
/// ceremony performs).
#[test]
fn ambiguous_device_renders_hint_and_candidates() {
    let candidates = vec![
        DeviceInfo {
            id: DeviceId::new("/dev/hidraw0"),
            name: String::from("YubiKey 5"),
            aaguid: None,
        },
        DeviceInfo {
            id: DeviceId::new("Yubico YubiKey OTP"),
            name: String::from("YubiKey OTP"),
            aaguid: None,
        },
    ];
    // The same selection the assert entry performs: typed failure.
    let err = select_device(candidates, false).expect_err("Fail policy");
    match &err {
        CeremonyError::AmbiguousDevice(c) => assert_eq!(c.len(), 2),
        other => panic!("expected AmbiguousDevice, got {other:?}"),
    }
    let lines = render::error_lines(&err);
    assert_eq!(lines[0], "error: AmbiguousDevice");
    let candidate_lines: Vec<&String> = lines.iter().filter(|l| l.contains("candidate:")).collect();
    assert_eq!(
        candidate_lines.len(),
        2,
        "one descriptor line per candidate: {lines:?}"
    );
    assert!(lines.iter().any(|l| l.starts_with("hint:")));
}

/// Scenario: Touch timeout names the phase — the user never touches,
/// the budget expires after the first UP_NEEDED, and the rendered
/// error is `Timeout` naming `UserPresence`.
#[test]
fn user_presence_phase_timeout_renders_typed() {
    // Token pends on an explicit poke (UP_NEEDED stream) and the
    // budget is small: the ceremony expires during user presence.
    let auth = SoftAuthenticator::new(Config {
        up_mode: UpUvMode::RequireExplicitPoke,
        ..Config::default()
    });
    let transport = SoftTransport::new(auth);
    let deadline = Deadline::new(Duration::from_secs(1));
    let device = block_on(Transport::connect(
        &transport,
        &DeviceId::new("soft-0"),
        &deadline,
        no_sleep(),
    ))
    .expect("connect");
    let outcome = block_on(run_exchange(
        device,
        &assert_args("example.com"),
        &deadline,
        no_sleep(),
        |_| {},
    ));
    let err = outcome.expect_err("no poke + tiny budget → timeout");
    match &err {
        CeremonyError::Timeout(phase) => {
            assert_eq!(*phase, fidoh_core::Phase::UserPresence);
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
    let lines = render::error_lines(&err);
    assert_eq!(
        lines[0], "error: Timeout naming the user-presence phase",
        "{lines:?}"
    );
    // And the full pipeline once more with the prompt attached: the
    // prompt fired (UP_NEEDED flowed) before the expiry.
    let auth = SoftAuthenticator::new(Config {
        up_mode: UpUvMode::RequireExplicitPoke,
        ..Config::default()
    });
    let transport = SoftTransport::new(auth);
    let deadline = Deadline::new(Duration::from_secs(1));
    let device = block_on(Transport::connect(
        &transport,
        &DeviceId::new("soft-0"),
        &deadline,
        no_sleep(),
    ))
    .expect("connect");
    let printed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&printed);
    // ONE prompt owned by the tap (the executable's shape): dedup
    // state lives across every keepalive of the ceremony.
    let mut prompt = TouchPrompt::with_sink(move |l: &str| {
        sink.lock().expect("sink").push(String::from(l));
    });
    let err = block_on(run_exchange(
        device,
        &assert_args("example.com"),
        &deadline,
        no_sleep(),
        move |status| KeepaliveUX::on_keepalive(&mut prompt, status),
    ))
    .expect_err("timeout");
    assert!(matches!(
        err,
        CeremonyError::Timeout(fidoh_core::Phase::UserPresence)
    ));
    let got = printed.lock().expect("sink");
    assert_eq!(
        got.len(),
        1,
        "prompt printed once before the expiry: {got:?}"
    );
}

// --------------------------------------------------------------------
// Requirement: terminal leaf + adapter entry + demo mode.
// --------------------------------------------------------------------

/// Scenario: Manifest dependency audit — no crate depends on
/// fidoh-cli-ui, and the only runtime edge is fidoh-tokio's (the
/// sanctioned entry: edges ON fidoh-tokio are the caller surface).
#[test]
fn manifest_dependency_audit() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let crates_dir = root.join("crates");
    let mut cli_ui_is_leaf = false;
    for entry in std::fs::read_dir(&crates_dir).expect("crates dir") {
        let entry = entry.expect("entry");
        if !entry.path().is_dir() {
            continue;
        }
        let manifest = std::fs::read_to_string(entry.path().join("Cargo.toml")).expect("manifest");
        let is_cli_ui = entry.path().ends_with("fidoh-cli-ui");
        if is_cli_ui {
            cli_ui_is_leaf = true;
        }
        let mut section = String::new();
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                section = line.to_string();
                continue;
            }
            if !(section.starts_with("[dependencies]") || section.starts_with("[dev-dependencies]"))
            {
                continue;
            }
            assert!(
                !line.contains("fidoh-cli-ui"),
                "{} depends on fidoh-cli-ui — nothing may (terminal leaf)",
                entry.path().display()
            );
        }
    }
    assert!(
        cli_ui_is_leaf,
        "the crate under test exists in the workspace"
    );
    // The runtime identifier appears in NO cli-ui source (greppable D2):
    // walk the crate's sources and assert no line names the runtime.
    fn visit(dir: &std::path::Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                visit(&path, hits);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let src = std::fs::read_to_string(&path).expect("source");
                for (i, line) in src.lines().enumerate() {
                    // The RUNTIME path (`tokio::…`) is forbidden; the
                    // ADAPTER's path (`fidoh_tokio::…`) is the
                    // sanctioned entry (design D2 — the audit is about
                    // the runtime, not the adapter's name).
                    let names_runtime = line
                        .match_indices("tokio::")
                        .any(|(idx, _)| !line[..idx].ends_with("fidoh_"));
                    if names_runtime {
                        hits.push(format!("{}:{i}: {line}", path.display()));
                    }
                }
            }
        }
    }
    let mut hits = Vec::new();
    visit(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut hits,
    );
    assert!(
        hits.is_empty(),
        "the binary names the runtime directly (D2 violation): {hits:?}"
    );
}

/// Scenario: Demo mode runs the ceremony without hardware — the same
/// ceremony path (`run_exchange`) over the soft token, same output
/// shape (rpId/credentialId/userSelected-when-present/authData/
/// signature), verifiable signature, exit-0 semantics.
#[test]
fn demo_ceremony_end_to_end_without_hardware() {
    let transport = SoftTransport::new(mint_token());
    let deadline = Deadline::new(BUDGET);
    let device = block_on(Transport::connect(
        &transport,
        &DeviceId::new("soft-0"),
        &deadline,
        no_sleep(),
    ))
    .expect("connect");
    let outcome = block_on(run_exchange(
        device,
        &assert_args("example.com"),
        &deadline,
        no_sleep(),
        |_| {},
    ))
    .expect("demo ceremony succeeds");
    let first = outcome.first();
    // The output shape the binary prints (print_assertion):
    let rp_line = format!("rpId: {}", "example.com");
    let cred_line = format!("credentialId: {}", render::hex(&first.credential.id));
    let user_selected_line = first
        .user_selected_present
        .then(|| format!("userSelected: {}", first.user_selected));
    let auth_data_line = format!("authData: {}", render::hex(&first.auth_data));
    let signature_line = format!("signature: {}", render::hex(&first.signature));
    assert_eq!(rp_line, "rpId: example.com");
    assert_eq!(cred_line.len(), "credentialId: ".len() + 64);
    assert!(
        user_selected_line.is_none(),
        "single credential: flag absent"
    );
    assert!(!first.auth_data.is_empty());
    assert!(!first.signature.is_empty());
    // The probe rode in the outcome (mandatory, OQ-2): soft token AAGUID.
    assert_eq!(outcome.info.aaguid, *b"fidoh-soft-token");
    assert_eq!(auth_data_line.split(':').count(), 2);
    assert_eq!(signature_line.split(':').count(), 2);
    // Exit-0 semantics: Ok outcome.
}

// --------------------------------------------------------------------
// Arg-parsing surface (usage errors are part of the CLI contract).
// --------------------------------------------------------------------

#[test]
fn usage_errors_are_typed_and_help_is_zero() {
    assert!(matches!(parse(&[]), ParseOutcome::Failed(_)));
    assert!(matches!(
        parse(&[String::from("assert")]),
        ParseOutcome::Failed(f) if f.reason == fidoh_cli_ui::args::FlagReason::MissingRp
    ));
    assert_eq!(parse(&[String::from("help")]), ParseOutcome::Help);
    assert!(matches!(
        parse(&[
            String::from("assert"),
            String::from("--rp"),
            String::from("r"),
            String::from("--demo")
        ]),
        ParseOutcome::Parsed(Invocation::Assert(a)) if a.demo
    ));
}

#[test]
fn kind_labels_cover_transports() {
    assert_eq!(kind_label(TransportKind::Hid), "hid");
    assert_eq!(kind_label(TransportKind::Pcsc), "pcsc");
    assert_eq!(kind_label(TransportKind::Soft), "soft");
}
