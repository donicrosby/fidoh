//! Deterministic conformance-vector generator (testing-strategy spec
//! requirement "Conformance vector provenance", scenario "Constructed
//! vectors are labeled and regenerable").
//!
//! Mints credentials into soft-token snapshots under the
//! [`DeterministicRng`] (fixed seed, transport-soft spec "Deterministic
//! fixtures") and writes the serialized snapshot bytes into
//! `vectors/constructed/`. Re-running this exact script reproduces the
//! committed bytes identically; CI (`.github/workflows/vectors.yml`)
//! asserts that regeneration is clean.
//!
//! Usage:
//!
//! ```text
//! cargo run -p fidoh-transport-soft --example generate_vectors -- <output-dir>
//! ```
//!
//! `<output-dir>` receives one `.json` file per constructed vector set.
//! Pass the repo's `vectors/constructed` directory to refresh the
//! committed fixtures, or a scratch directory to verify determinism
//! (`diff -r` against the committed set must be empty). Snapshot bytes
//! derive only from the fixed RNG seed and this script's fixed minting
//! sequence — never from wall-clock time, the environment, or a
//! third-party authenticator (cleanroom rule).

use std::path::PathBuf;

use fidoh_transport_soft::{
    snapshot_export, snapshot_to_json, Config, DeterministicRng, MakeCredentialArgs, RngConfig,
    SoftAuthenticator,
};

/// The seed every committed constructed vector is minted under.
/// Changing this value changes every output file and must land together
/// with a regenerated `vectors/constructed/` in the same commit.
pub const SEED: u64 = 0xC0FF_EE00;

/// Generator version recorded in `vectors/manifest.json` provenance.
/// Bump when the minting script changes shape (which also requires
/// regenerating the committed vectors in the same commit).
pub const GENERATOR_VERSION: &str = "1.0.0";

/// One constructed vector set: a file name under the output directory
/// plus the fixed minting sequence that produces its bytes.
struct VectorSet {
    file_name: &'static str,
    mints: &'static [Mint],
    initial_sign_count: u32,
}

/// One harness-only makeCredential call.
struct Mint {
    rp_id: &'static str,
    user_handle: &'static [u8],
    resident: bool,
}

const SINGLE_RP: &[Mint] = &[Mint {
    rp_id: "example.com",
    user_handle: b"vector-user-1",
    resident: true,
}];

const MULTI_RP: &[Mint] = &[
    Mint {
        rp_id: "example.com",
        user_handle: b"vector-user-1",
        resident: true,
    },
    Mint {
        rp_id: "example.com",
        user_handle: b"vector-user-2",
        resident: true,
    },
    Mint {
        rp_id: "example.com",
        user_handle: b"vector-user-3",
        resident: true,
    },
    Mint {
        rp_id: "other.example",
        user_handle: b"vector-user-4",
        resident: true,
    },
];

const VECTOR_SETS: &[VectorSet] = &[
    VectorSet {
        file_name: "snapshot-single-credential.json",
        mints: SINGLE_RP,
        initial_sign_count: 0,
    },
    VectorSet {
        file_name: "snapshot-multi-credential.json",
        mints: MULTI_RP,
        initial_sign_count: 7,
    },
];

fn main() {
    let out_dir = match std::env::args().nth(1) {
        Some(dir) => PathBuf::from(dir),
        None => {
            eprintln!(
                "usage: cargo run -p fidoh-transport-soft --example generate_vectors -- <output-dir>"
            );
            std::process::exit(2);
        }
    };
    if let Err(err) = generate(&out_dir) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn generate(out_dir: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(out_dir).map_err(|e| format!("creating {}: {e}", out_dir.display()))?;
    for set in VECTOR_SETS {
        let bytes = render(set)?;
        let path = out_dir.join(set.file_name);
        std::fs::write(&path, &bytes).map_err(|e| format!("writing {}: {e}", path.display()))?;
        println!("{} ({} bytes)", path.display(), bytes.len());
    }
    Ok(())
}

/// Build one vector set: seed the RNG, mint the fixed credential
/// sequence, export the snapshot, serialize to JSON. Deterministic by
/// construction: the only inputs are [`SEED`] and the fixed mint list.
fn render(set: &VectorSet) -> Result<String, String> {
    let config = Config {
        rng: RngConfig::Seeded(DeterministicRng::seeded(SEED)),
        initial_sign_count: set.initial_sign_count,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(config);
    for mint in set.mints {
        auth.make_credential(MakeCredentialArgs {
            rp_id: std::string::String::from(mint.rp_id),
            user_handle: mint.user_handle.to_vec(),
            resident: mint.resident,
        })
        .map_err(|e| format!("minting into {}: {e}", set.file_name))?;
    }
    snapshot_to_json(&snapshot_export(&auth)).map_err(|e| format!("serializing: {e}"))
}
