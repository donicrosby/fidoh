//! The full-entry ceremony in ~50 lines: [`GetAssertionCeremony`] does
//! discovery, explicit selection, connection, the mandatory getInfo
//! probe, the §6.2 exchange, and the §6.3 drain behind one call,
//! bounded by ONE deadline — "give fidoh transports and a request,
//! get an assertion".
//!
//! It also demonstrates the failure posture an app must handle: the
//! soft token here holds a perfectly valid credential but refuses
//! user presence (`UpUvMode::AlwaysFail` — the authenticator returns
//! 0x27 CTAP2_ERR_OPERATION_DENIED after a successful probe), and the
//! typed [`CeremonyError::UpRejected`] that comes back is matched:
//! retry on `UpRejected`, enroll first on `NoCredentials`.
//!
//! Run: `cargo run -p fidoh-transport-soft --example assert_minimal`

use std::process::ExitCode;
use std::time::Duration;

use fidoh_core::{CeremonyError, GetAssertionCeremony};
use fidoh_transport_soft::{Config, SoftAuthenticator, SoftTransport, UpUvMode};
use sha2::{Digest, Sha256};

const RP_ID: &str = "example.com";
/// 10 s — short, so a failed ceremony returns quickly.
const BUDGET: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    let run = fidoh_tokio::run(do_ceremony());
    match run {
        Ok(Ok(outcome)) => {
            let first = outcome.first();
            println!("assertion: credential {}", hex(&first.credential.id));
            println!("token: aaguid {}", hex(&outcome.info.aaguid));
            ExitCode::SUCCESS
        }
        Ok(Err(err)) => {
            eprintln!("ceremony failed: {err}");
            // The retry decision is the app's: user refusal is
            // transient, a missing account is not.
            match err {
                CeremonyError::UpRejected | CeremonyError::UserActionTimeout => {
                    eprintln!("  user did not approve — a real app retries the sign-in");
                }
                CeremonyError::NoCredentials => {
                    eprintln!("  this token holds no credential for {RP_ID} — enroll first");
                }
                _ => eprintln!("  see docs/errors.md for the typed error table"),
            }
            ExitCode::FAILURE
        }
        Err(e) => {
            // `run` refuses to nest inside an existing runtime and
            // reports runtime-build failures — typed, no panics.
            eprintln!("fidoh-tokio: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn do_ceremony() -> Result<fidoh_core::GetAssertionOutcome, CeremonyError> {
    // Every wait the ceremony performs is driven through the Sleep
    // factory — on tokio's real timer here.
    let sleep = fidoh_tokio::TokioSleep;

    // The user's token, virtual this run: one resident credential for
    // the RP, but UP is set to always refuse — the token-side picture
    // of a user who declines the touch prompt.
    let mut token = SoftAuthenticator::new(Config {
        up_mode: UpUvMode::AlwaysFail,
        ..Config::default()
    });
    token
        .make_credential(fidoh_transport_soft::MakeCredentialArgs {
            rp_id: String::from(RP_ID),
            user_handle: b"user-42".to_vec(),
            resident: true,
        })
        .map_err(|e| {
            CeremonyError::Transport(fidoh_core::TransportError::new(
                "demo-enroll",
                e.to_string(),
            ))
        })?;

    // YOUR app's job (WebAuthn L2 §6.5): serialize clientDataJSON —
    // type, server-supplied challenge, origin — and hand fidoh its
    // SHA-256. fidoh never builds this for you.
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://login.example.com\"}}",
        hex(&Sha256::digest(b"server-challenge-7f3a"))
    );
    println!("clientDataJSON: {client_data_json}");

    // The whole ceremony in one call: discovery over every transport,
    // explicit selection (default policy `Fail` refuses to guess),
    // connect, the mandatory getInfo probe, the §6.2 exchange with
    // its keepalive loop, and the §6.3 drain — all bounded by the
    // single deadline.
    GetAssertionCeremony::new(
        vec![SoftTransport::new(token)],
        String::from(RP_ID),
        Sha256::digest(client_data_json.as_bytes()).to_vec(),
        BUDGET,
    )
    .run(sleep.handle())
    .await
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
