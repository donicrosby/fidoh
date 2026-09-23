//! Injectable randomness (design §Cryptography: "Randomness source is
//! injectable so conformance vectors are reproducible").

use alloc::string::String;

use fidoh_core::{Error, TransportError};

/// A source of random bytes for key generation and credential IDs.
///
/// Implemented by [`DeterministicRng`]; harnesses may supply their own
/// (e.g. an OS-CSPRNG-backed source) via
/// [`SoftAuthenticator::with_rng`](crate::SoftAuthenticator::with_rng).
pub trait RngSource {
    /// Fill `dest` with random bytes, or fail with a typed transport
    /// error naming the soft layer.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), Error>;

    /// Draw the given number of bytes as a fresh vector.
    fn bytes(&mut self, n: usize) -> Result<alloc::vec::Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; n];
        self.fill(&mut out)?;
        Ok(out)
    }
}

/// A deterministic counter-based byte stream (SplitMix64-expanded),
/// for committed conformance fixtures ONLY.
///
/// This is **not** a cryptographic RNG. It exists so the fixture
/// generation script (docs/transport-soft.md, "Conformance vectors")
/// reproduces byte-identical snapshots on every run, per the
/// transport-soft spec "Deterministic fixtures" scenario. Keys minted
/// under it are real P-256 keys (reduced mod the group order), just
/// drawn from a predictable stream — never use it where key secrecy
/// matters.
#[derive(Clone, Debug)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// A stream seeded from `seed`.
    pub fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The default stream: seeded from a compile-time build salt so
    /// distinct builds mint distinct credentials while a single binary
    /// stays reproducible. (No OS entropy — this crate is no_std and
    /// never reads the environment.)
    pub fn build_salted() -> Self {
        // option_env! resolves at compile time of THIS crate; None in
        // hermetic builds, giving the fixed salt below.
        let salt: u64 = match option_env!("FIDOH_SOFT_BUILD_SALT") {
            Some(s) => {
                let mut h = 0xcbf2_9ce4_8422_2325u64;
                for b in s.as_bytes() {
                    h ^= u64::from(*b);
                    h = h.wrapping_mul(0x0000_0100_0000_01b3);
                }
                h
            }
            None => 0xF1D0_4F1D_0000_0001,
        };
        Self::seeded(salt)
    }

    fn next_u64(&mut self) -> u64 {
        // SplitMix64: public-domain counter mixer; deterministic by
        // construction (fixture use only — see type docs).
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Default for DeterministicRng {
    fn default() -> Self {
        Self::build_salted()
    }
}

impl RngSource for DeterministicRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_be_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// Map an internal crypto/RNG failure into the typed transport-error
/// seam (`kind: "soft"`).
pub(crate) fn soft_err(detail: String) -> Error {
    Error::Transport(TransportError::new("soft", detail))
}
