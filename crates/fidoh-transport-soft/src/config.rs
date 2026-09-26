//! Configuration: UP/UV behavior modes and error-injection knobs
//! (transport-soft spec, "UP/UV behavior modes" and "Error injection
//! knobs"; docs/transport-soft.md knob table).

use alloc::vec::Vec;
use core::time::Duration;

use fidoh_core::StatusCode;

use crate::rng::DeterministicRng;

/// User-presence / user-verification behavior mode (transport-soft
/// spec, "UP/UV behavior modes").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UpUvMode {
    /// The requirement is satisfied immediately (the default for both
    /// UP and UV).
    #[default]
    AutoApprove,
    /// The command fails with `CTAP2_ERR_OPERATION_DENIED` (0x27,
    /// CTAP2.1 §8.2) and the signCount does not increment.
    AlwaysFail,
    /// The command pends (emitting `UP_NEEDED` keepalives) until
    /// harness code calls the poke method or the caller's ceremony
    /// deadline expires (typed timeout; the wait is bounded solely by
    /// the caller deadline).
    RequireExplicitPoke,
}

/// Error-injection knobs applying to the next matching command
/// (transport-soft spec, "Error injection knobs"). Knobs reset after
/// firing unless [`Knobs::persistent`] is set.
#[derive(Clone, Debug, Default)]
pub struct Knobs {
    /// Return this CTAP status code (CTAP2.1 §8.2) instead of a normal
    /// response. Any code is accepted — the 11-code client mapping
    /// matrix (0x2E, 0x22, 0x2F, 0x2D, 0x27, 0x3B, 0x33, 0x34, 0x36,
    /// 0x37, 0x3C) is therefore fully exercisable.
    pub inject_status: Option<StatusCode>,
    /// Keepalive events (status byte + spacing) emitted before the
    /// final response.
    pub keepalive_sequence: Vec<KeepaliveEvent>,
    /// Delay the final response past the caller's deadline. `Some(d)`
    /// delays by `d`, hard-capped at
    /// [`crate::DELAY_HARD_CAP`] (deadline + 60 s bound; this token's
    /// own wait never exceeds remaining + cap).
    pub delay_beyond_deadline: Option<Duration>,
    /// Return a validly signed assertion under a DIFFERENT stored
    /// credential ID than the one the client asked for, to exercise
    /// client-side credential matching.
    pub wrong_credential_id: bool,
    /// When false (default), injection knobs reset after firing once.
    pub persistent: bool,
}

/// One keepalive progress event: a raw CTAPHID keepalive status byte
/// (CTAP2.1 §11.2.9.1.7: 0x01 processing, 0x02 UP_NEEDED) plus the
/// spacing to wait before emitting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepaliveEvent {
    /// The keepalive status byte to surface.
    pub status: u8,
    /// How long to wait before emitting this event.
    pub spacing: Duration,
}

/// clientPIN-specific injection knobs (add-client-pin, transport-soft
/// spec "clientPIN error injection"). Applied by the authenticator
/// core on authenticatorClientPIN (0x06) processing; all default to
/// off so the default build answers per the plain §6.5.5 flow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientPinKnobs {
    /// Accept the platform handshake on a protocol that was NOT the
    /// one requested: the getKeyAgreement register (and the shared
    /// secret the token derives) uses `wrong_protocol_to` while the
    /// client believes it negotiated its own selector. Exercises the
    /// CLIENT's protocol-exact verification (KDF choice + MAC length
    /// + token length) against a deviant peer.
    pub wrong_protocol_echo: bool,
    /// Decrypt pinHashEnc with a DIFFERENT key than the correctly
    /// derived shared secret (the token derives P2 when the client
    /// used P1 and vice versa), so the client's own
    /// decapsulate/derive path is proven — the resulting failure is
    /// the authenticator-side 0x31/0x33 family, NOT a wrong PIN.
    pub pin_echo_decrypt: bool,
}

/// Authenticator configuration (docs/transport-soft.md knob table).
pub struct Config {
    /// UP behavior mode (default `auto-approve`).
    pub up_mode: UpUvMode,
    /// UV behavior mode (default `auto-approve`).
    pub uv_mode: UpUvMode,
    /// Starting value of the global signature counter (CTAP2.1 §6.1.2
    /// global-counter model). Default 0.
    pub initial_sign_count: u32,
    /// Randomness source for key generation and credential IDs. The
    /// deterministic mode is for committed fixtures only.
    pub rng: RngConfig,
    /// Error-injection knobs.
    pub knobs: Knobs,
    /// The advertised pinUvAuthProtocols list when the clientPIN
    /// feature is armed (add-client-pin: the harness config; default
    /// `[2, 1]` = the authenticator's decreasing preference order,
    /// CTAP2.1 §6.4). An empty list advertises no protocols — the
    /// acquisition flow's "no mutually supported protocol" typed
    /// failure then applies.
    pub pin_uv_auth_protocols: alloc::vec::Vec<fidoh_core::pin::PinUvAuthProtocol>,
    /// Whether the `pinUvAuthToken` option ID is advertised when the
    /// clientPIN feature is armed (default true = the §6.5.5.7.2 0x09
    /// flow; false = the CTAP2.0 getPinToken 0x05 fallback shape).
    pub advertise_pin_uv_auth_token: bool,
    /// clientPIN-directed injection knobs (see [`ClientPinKnobs`]).
    pub client_pin_knobs: ClientPinKnobs,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            up_mode: UpUvMode::AutoApprove,
            uv_mode: UpUvMode::AutoApprove,
            initial_sign_count: 0,
            rng: RngConfig::Default,
            knobs: Knobs::default(),
            pin_uv_auth_protocols: alloc::vec![
                fidoh_core::pin::PinUvAuthProtocol::Two,
                fidoh_core::pin::PinUvAuthProtocol::One,
            ],
            advertise_pin_uv_auth_token: true,
            client_pin_knobs: ClientPinKnobs::default(),
        }
    }
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("up_mode", &self.up_mode)
            .field("uv_mode", &self.uv_mode)
            .field("initial_sign_count", &self.initial_sign_count)
            .field("rng", &self.rng)
            .field("knobs", &self.knobs)
            .field("pin_uv_auth_protocols", &self.pin_uv_auth_protocols)
            .field(
                "advertise_pin_uv_auth_token",
                &self.advertise_pin_uv_auth_token,
            )
            .field("client_pin_knobs", &self.client_pin_knobs)
            .finish()
    }
}

/// Randomness source selection (docs/transport-soft.md `rng` knob).
#[derive(Default)]
pub enum RngConfig {
    /// Build-salt-seeded deterministic stream: unique per compiled
    /// binary, reproducible within it. This is the default because the
    /// crate is no_std and carries no OS-entropy dependency; harnesses
    /// needing cross-run uniqueness can use `Seeded` with a counter or
    /// supply their own [`crate::RngSource`] via
    /// [`crate::SoftAuthenticator::with_rng`].
    #[default]
    Default,
    /// Fully deterministic stream from an explicit seed — for
    /// committed conformance fixtures only (byte-identical snapshots
    /// across runs; transport-soft spec "Deterministic fixtures").
    Seeded(DeterministicRng),
}

impl core::fmt::Debug for RngConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::Seeded(_) => f.write_str("seeded(..)"),
        }
    }
}
