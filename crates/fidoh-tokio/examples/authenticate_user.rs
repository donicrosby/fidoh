//! End-to-end FIDO2 sign-in with fidoh: enroll → assert → verify.
//!
//! This is the "incorporate FIDO2 into your application" walkthrough.
//! The user's token is stood in for by `fidoh-transport-soft`, the
//! in-process virtual authenticator — every line of APPLICATION code
//! below (clientDataJSON, discovery, selection, connection, the
//! ceremony, the multi-assertion drain, and ES256 verification) is the
//! same code that runs against a real USB (CTAPHID) or NFC/CCID
//! (PC/SC) token; only the transport construction differs.
//!
//! The division of labor fidoh enforces (WebAuthn L2 §7.2):
//!
//! - YOUR app builds `clientDataJSON` (type, challenge from your
//!   server, origin) and hands fidoh its SHA-256 hash;
//! - fidoh runs the CTAP2.1 §6.2 getAssertion ceremony and returns raw
//!   assertion fields;
//! - YOUR app (really: your RP server) verifies the signature against
//!   the public key stored at enrollment — done here with real ECDSA.
//!
//! Run: `cargo run -p fidoh-tokio --example authenticate_user`

use std::process::ExitCode;
use std::time::Duration;

use fidoh_core::cose::CoseEs256Key;
use fidoh_core::device::{ChannelId, CtapCommand, Device, DeviceEvent};
use fidoh_core::error::{CeremonyError, Error, TransportError};
use fidoh_core::get_assertion::{CredentialType, PublicKeyCredentialDescriptor};
use fidoh_core::sleep::SleepHandle;
use fidoh_core::time::{Deadline, Phase};
use fidoh_core::transport::{apply_selection, CandidateDescriptor, SelectionPolicy, Transport};
use fidoh_core::{Ceremony, Drain, GetAssertionExchange, UvPolicy};
use fidoh_tokio::TokioSleep;
use fidoh_transport_soft::{
    Config, KeepaliveEvent, Knobs, MakeCredentialArgs, SoftAuthenticator, SoftTransport,
};
use sha2::{Digest, Sha256};

/// The relying party you are signing the user in to (CTAP2.1 §6.2
/// key 0x01). Must match the rpId the credential was enrolled under.
const RP_ID: &str = "example.com";

/// The WebAuthn origin your site is served from — it goes into
/// clientDataJSON, which your RP server will re-check.
const ORIGIN: &str = "https://login.example.com";

/// The whole ceremony budget (async-core design D4): discovery,
/// connect, probe, exchange, and every drain hop share it. 45 s
/// covers a human walking to their token.
const BUDGET: Duration = Duration::from_secs(45);

/// CTAPHID keepalive status "user presence needed" (CTAP2.1
/// §11.2.9.1.7). The ceremony surfaces these as progress, never errors.
const UP_NEEDED: u8 = 0x02;

fn main() -> ExitCode {
    match fidoh_tokio::run(authenticate()) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(err)) => {
            eprintln!("sign-in failed: {err}");
            explain(&err);
            ExitCode::FAILURE
        }
        Err(e) => {
            // `run` refuses to nest inside an existing runtime and
            // reports runtime-build failures — both typed, no panics.
            eprintln!("fidoh-tokio: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Typed remediation hints, one per ceremony failure class
/// (`docs/errors.md` is the full operator table).
fn explain(err: &CeremonyError) {
    let hint = match err {
        CeremonyError::NoDevice(_) => {
            "no authenticator found on any transport — is a token plugged in?"
        }
        CeremonyError::AmbiguousDevice(_) => {
            "several tokens are present — pick one explicitly (SelectionPolicy)"
        }
        CeremonyError::UserActionTimeout | CeremonyError::UpRejected => {
            "the user did not approve the prompt in time — retry the sign-in"
        }
        CeremonyError::UserCancelled => "the user declined on the token — retry when ready",
        CeremonyError::NoCredentials => {
            "this token holds no credential for the account — enroll it first"
        }
        CeremonyError::Timeout(phase) => {
            eprintln!("  hint: budget expired during the {phase} phase — raise BUDGET");
            return;
        }
        _ => "see docs/errors.md for the typed error table",
    };
    eprintln!("  hint: {hint}");
}

async fn authenticate() -> Result<(), CeremonyError> {
    // ------------------------------------------------------------------
    // 1. The caller's WebAuthn job: clientDataJSON → SHA-256.
    //
    // A real app takes `challenge` from its own server's login
    // response; it is fixed here so the transcript is reproducible.
    // ------------------------------------------------------------------
    let challenge_hex = "3a5f1c9e8b2d47a06f5c8e1d3b7a9f20c4e6d8b0a2f4c6e8d0b2a4c6e8f0a2c4";
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge_hex}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}"
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();
    println!("clientDataJSON: {client_data_json}");

    // ------------------------------------------------------------------
    // 2. The user's token — virtual here, same traits as hardware.
    //
    // Enrollment normally happened when the user registered; the
    // harness-only makeCredential below is what your server's
    // registration flow would have put on the token. We enroll TWO
    // credentials so the response reports numberOfCredentials = 2 and
    // the §6.3 multi-assertion drain is exercised for real.
    // ------------------------------------------------------------------
    let mut token = SoftAuthenticator::new(Config {
        // One UP_NEEDED keepalive before the response: drives the
        // touch prompt below exactly as a hardware token would.
        knobs: Knobs {
            keepalive_sequence: vec![KeepaliveEvent {
                status: UP_NEEDED,
                spacing: Duration::from_millis(250),
            }],
            ..Knobs::default()
        },
        ..Config::default()
    });
    let mut enrolled_ids: Vec<Vec<u8>> = Vec::new();
    for _ in 0..2 {
        let minted = token
            .make_credential(MakeCredentialArgs {
                rp_id: String::from(RP_ID),
                user_handle: b"user-42".to_vec(),
                resident: true,
            })
            .map_err(|e| {
                CeremonyError::Transport(TransportError::new("demo-enroll", e.to_string()))
            })?;
        enrolled_ids.push(minted.record.id.clone());
        // In a real app this public key is stored SERVER-side at
        // registration, keyed by credential id — the verify step at
        // the end looks credentials up exactly that way.
        remember_enrollment(minted.record.id.clone(), minted.record.public_key());
    }
    println!(
        "enrolled 2 credentials for {RP_ID}: {} {}",
        hex(&enrolled_ids[0]),
        hex(&enrolled_ids[1])
    );

    let sleep = TokioSleep;
    let deadline = Deadline::new(BUDGET);

    // ------------------------------------------------------------------
    // 3. Discovery: enumerate candidates (a real app would stack its
    //    HID and PC/SC transports into the same list).
    // ------------------------------------------------------------------
    let transport = SoftTransport::new(token);
    let candidates = transport
        .enumerate(&deadline, sleep.handle())
        .await
        .map_err(CeremonyError::from_core)?;
    println!("discovered {} authenticator(s):", candidates.len());
    for info in &candidates {
        println!("  - {} [{}]", info.name, info.id.as_str());
    }

    // 4. Explicit, deterministic selection (the default `Fail` policy
    //    refuses to guess among multiple candidates).
    let descriptors: Vec<CandidateDescriptor> =
        candidates.iter().map(|info| info.descriptor()).collect();
    let selected = apply_selection(&SelectionPolicy::First, &descriptors)
        .map_err(CeremonyError::from_core)?
        .ok_or(CeremonyError::NoDevice(Vec::new()))?;
    println!("selected: {}", selected.id.as_str());

    // 5. Connect. A second handle to the SAME authenticator carries
    //    the §6.3 drain hook: continuation state (the queued
    //    assertions) lives in the token, not in any one connection.
    let device = transport
        .connect(&selected.id, &deadline, sleep.handle())
        .await
        .map_err(CeremonyError::from_core)?;
    let mut drainer = transport
        .connect(&selected.id, &deadline, sleep.handle())
        .await
        .map_err(CeremonyError::from_core)?;

    // The drain hook returns the next queued assertion. Hops are
    // budgeted by the ceremony itself; the hook carries its own
    // deadline handle as the caller-side bound (soft-token
    // continuations are synchronous, so they are always immediately
    // ready — same discipline as fidoh-core's ceremony tests).
    let drain_deadline = Deadline::new(BUDGET);
    let drain_hash = client_data_hash.clone();
    let drain = Drain::new(move || {
        if drain_deadline.remaining().is_zero() {
            return Err(Error::Timeout(Phase::GetNextAssertion));
        }
        drainer.get_next_assertion(&drain_hash, &drain_deadline)
    });

    // ------------------------------------------------------------------
    // 6. The §6.2 exchange. allowList restricts the token to the two
    //    enrolled ids (and makes fidoh reject any other credential id
    //    the token might return — a library-side safety check).
    // ------------------------------------------------------------------
    let allow_list: Vec<PublicKeyCredentialDescriptor> = enrolled_ids
        .iter()
        .map(|id| PublicKeyCredentialDescriptor {
            type_field: CredentialType::PublicKey,
            id: id.clone(),
            transports: None,
        })
        .collect();
    let exchange = GetAssertionExchange {
        rp_id: String::from(RP_ID),
        client_data_hash: client_data_hash.clone(),
        allow_credentials: Some(allow_list),
        user_verification: UvPolicy::Discouraged,
        pin_uv_auth: None,
        // v2 fields: this example keeps the v1 non-interactive shape
        // (Discouraged policy never triggers PIN acquisition; the
        // acquisition path is exercised in the fidoh-core ceremony
        // tests via the PIN-provider seam).
        pin_provider: None,
        pin_uv_auth_protocol: None,
        entropy: None,
        drain: Some(drain),
    };

    // Wrap the connected device so keepalives become UI: the ceremony
    // handles them internally as progress, so this wrapper is the one
    // seam an app has for "touch your token" prompts. It prints on
    // the FIRST UP_NEEDED only — dedup is a display concern.
    let outcome = exchange
        .run(PromptOnTouch::new(device), &deadline, sleep.handle())
        .await?;

    // ------------------------------------------------------------------
    // 7. The outcome: capabilities, UV posture, assertions.
    // ------------------------------------------------------------------
    println!(
        "token: aaguid {} versions {}",
        hex(&outcome.info.aaguid),
        outcome.info.versions.join(", ")
    );
    println!("uv posture: {:?}", outcome.uv_effective);
    if outcome.assertions.len() > 1 {
        println!(
            "token reports {} credentials; drained {} via getNextAssertion",
            outcome.first().number_of_credentials,
            outcome.assertions.len() - 1
        );
    }

    let mut verified = 0usize;
    for (i, assertion) in outcome.assertions.iter().enumerate() {
        let stage = if i == 0 { "§6.2" } else { "§6.3" };
        // authenticatorData (WebAuthn L2 §6.1):
        //   rpIdHash(32) | flags(1) | signCount(4) [| extensions]
        if assertion.auth_data.len() < 37 {
            return Err(CeremonyError::Transport(TransportError::new(
                "verify",
                String::from("authenticatorData shorter than the 37-byte fixed prefix"),
            )));
        }
        let flags = assertion.auth_data[32];
        let sign_count = u32::from_be_bytes([
            assertion.auth_data[33],
            assertion.auth_data[34],
            assertion.auth_data[35],
            assertion.auth_data[36],
        ]);
        let user = assertion
            .user
            .as_ref()
            .map(|u| hex(&u.id))
            .unwrap_or_else(|| String::from("<absent: UV not performed>"));
        println!(
            "assertion {} [{stage}]: cred {} user {user} up={} uv={} signCount={sign_count}",
            i + 1,
            hex(&assertion.credential.id),
            flags & 0x01 != 0,
            flags & 0x04 != 0,
        );
        verify_assertion(
            &assertion.auth_data,
            &assertion.signature,
            &assertion.credential.id,
            &client_data_hash,
        )
        .map_err(|e| CeremonyError::Transport(TransportError::new("verify", e)))?;
        verified += 1;
    }
    println!(
        "sign-in complete: {verified} assertion(s) ES256-verified over authData || clientDataHash"
    );
    Ok(())
}

/// Real ES256 verification (never a tautology): the signature covers
/// `authData || clientDataHash` under the credential's public key —
/// on a real RP the public key comes from your server's enrollment
/// record, looked up by the returned credential id.
fn verify_assertion(
    auth_data: &[u8],
    signature: &[u8],
    credential_id: &[u8],
    client_data_hash: &[u8],
) -> Result<(), String> {
    // The demo looks the key up in the token we enrolled with.
    let key = lookup_enrolled_key(credential_id).ok_or_else(|| {
        format!(
            "returned credential id {} is not one we enrolled",
            hex(credential_id)
        )
    })?;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let point = p256::EncodedPoint::from_affine_coordinates(
        &p256::FieldBytes::from_iter(key.x.iter().copied()),
        &p256::FieldBytes::from_iter(key.y.iter().copied()),
        false,
    );
    let vk = VerifyingKey::from_sec1_bytes(point.as_bytes())
        .map_err(|e| format!("bad public key: {e}"))?;
    let sig = Signature::from_der(signature).map_err(|e| format!("bad DER signature: {e}"))?;
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(client_data_hash);
    vk.verify(&signed, &sig)
        .map_err(|e| format!("ECDSA verify failed: {e}"))
}

// Demo-only credential registry: what a real app keeps server-side.
use std::sync::Mutex;
static ENROLLED: Mutex<Vec<(Vec<u8>, CoseEs256Key)>> = Mutex::new(Vec::new());

fn remember_enrollment(id: Vec<u8>, key: CoseEs256Key) {
    ENROLLED.lock().expect("registry lock").push((id, key));
}

fn lookup_enrolled_key(id: &[u8]) -> Option<CoseEs256Key> {
    ENROLLED
        .lock()
        .expect("registry lock")
        .iter()
        .find(|(stored, _)| stored == id)
        .map(|(_, key)| key.clone())
}

/// A `Device` wrapper that turns UP_NEEDED keepalives into a UI
/// prompt while forwarding everything unchanged — the keepalive UX
/// seam (the reference implementation lives in fidoh-cli-ui's
/// `UxDevice`).
struct PromptOnTouch<D> {
    inner: D,
    prompted: bool,
}

impl<D> PromptOnTouch<D> {
    fn new(inner: D) -> Self {
        Self {
            inner,
            prompted: false,
        }
    }
}

impl<D: Device + Send> Device for PromptOnTouch<D> {
    async fn send(
        &mut self,
        cmd: &CtapCommand,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<DeviceEvent, Error> {
        let event = self.inner.send(cmd, deadline, sleep).await;
        if let Ok(DeviceEvent::Keepalive { status }) = &event {
            if *status == UP_NEEDED && !self.prompted {
                self.prompted = true;
                eprintln!("touch your authenticator to approve the sign-in…");
            }
        }
        event
    }

    async fn open_channel(
        &mut self,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<ChannelId, Error> {
        self.inner.open_channel(deadline, sleep).await
    }

    async fn close(self) -> Result<(), Error> {
        self.inner.close().await
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
