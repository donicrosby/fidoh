//! CTAPHID protocol constants (CTAP2.1 §11.2) — every value verified
//! against the published spec text (transport-hid design.md, task 1).
//!
//! `pub(crate)`: the constants frame the wire inside this crate; the
//! public surface exposes parsed capabilities and typed errors instead.

use core::time::Duration;

/// HID report size for full-speed devices (§11.2.4; the 64-byte report
/// is always sent in full, unused bytes zeroed).
pub(crate) const REPORT_SIZE: usize = 64;

/// Initialization-packet header: CID(4) + CMD(1) + BCNT(2) (§11.2.4).
pub(crate) const INIT_HEADER: usize = 7;

/// Initialization-packet payload capacity: 64 − 7 (§11.2.4).
pub(crate) const INIT_PAYLOAD: usize = REPORT_SIZE - INIT_HEADER;

/// Continuation-packet header: CID(4) + SEQ(1) (§11.2.4).
pub(crate) const CONT_HEADER: usize = 5;

/// Continuation-packet payload capacity: 64 − 5 (§11.2.4).
pub(crate) const CONT_PAYLOAD: usize = REPORT_SIZE - CONT_HEADER;

/// Maximum message payload: 64 − 7 + 128 × (64 − 5) = 7609 bytes
/// (§11.2.4).
pub const MAX_MESSAGE_SIZE: usize = INIT_PAYLOAD + 128 * CONT_PAYLOAD;

/// Broadcast CID — all channels before allocation (§11.2.3).
pub(crate) const BROADCAST_CID: u32 = 0xFFFF_FFFF;

/// CTAPHID_PING (§11.2.9.1.1). Not used by v1 ceremony flows; the
/// hardware probe suite uses it as an echo sanity check.
pub(crate) const CMD_PING: u8 = 0x01;

/// CTAPHID_LOCK (§11.2.9.2.2). Never sent (spec requirement: no lock
/// command on the wire, v1; §11.2.6).
#[allow(
    dead_code,
    reason = "modeled for completeness; never sent in v1 (spec SHALL NOT send)"
)]
pub(crate) const CMD_LOCK: u8 = 0x04;

/// CTAPHID_INIT (§11.2.9.1.3): channel allocation / resync.
pub(crate) const CMD_INIT: u8 = 0x06;

/// CTAPHID_WINK (§11.2.9.2.1): capability-gated attention pulse.
pub(crate) const CMD_WINK: u8 = 0x08;

/// CTAPHID_CBOR (§11.2.9.1.2): every CTAP2 command exchange.
pub(crate) const CMD_CBOR: u8 = 0x10;

/// CTAPHID_CANCEL (§11.2.9.1.5): abort the pending transaction.
pub(crate) const CMD_CANCEL: u8 = 0x11;

/// CTAPHID_KEEPALIVE (§11.2.9.1.7): device → host progress.
pub(crate) const CMD_KEEPALIVE: u8 = 0x3B;

/// CTAPHID_ERROR (§11.2.9.1.6): device → host framing error.
pub(crate) const CMD_ERROR: u8 = 0x3F;

/// Command bit 7 — always set on initialization packets (§11.2.4).
pub(crate) const CMD_TYPE_BIT: u8 = 0x80;

/// CTAPHID protocol version identifier in the INIT response (§11.2.9.1.3).
/// Exposed for the hardware probes and docs; the FSM records it via
/// `InitInfo::protocol_version`.
#[allow(dead_code)] // referenced by hardware probes (tests/probes.rs)
pub(crate) const PROTOCOL_VERSION: u8 = 2;

/// INIT request payload: the 8-byte nonce (§11.2.9.1.3).
pub(crate) const INIT_NONCE_LEN: usize = 8;

/// INIT response payload: nonce(8) + CID(4) + version(1) +
/// dev-version(3) + capabilities(1) = 17 (§11.2.9.1.3).
pub(crate) const INIT_RESPONSE_LEN: usize = 17;

/// CAPABILITY_WINK — implements CTAPHID_WINK (§11.2.9.1.3).
pub(crate) const CAPABILITY_WINK: u8 = 0x01;

/// CAPABILITY_CBOR — implements CTAPHID_CBOR (§11.2.9.1.3).
pub(crate) const CAPABILITY_CBOR: u8 = 0x04;

/// CAPABILITY_NMSG — does NOT implement CTAPHID_MSG (§11.2.9.1.3).
pub(crate) const CAPABILITY_NMSG: u8 = 0x08;

/// Reserved capability bits MUST be zero from vendors (§11.2.9.1.3).
pub(crate) const CAPABILITY_KNOWN_MASK: u8 = CAPABILITY_WINK | CAPABILITY_CBOR | CAPABILITY_NMSG;

/// STATUS_PROCESSING — still processing (§11.2.9.1.7).
#[allow(
    dead_code,
    reason = "referenced by probes; the FSM surfaces statuses as raw bytes"
)]
pub(crate) const STATUS_PROCESSING: u8 = 0x01;

/// STATUS_UPNEEDED — waiting for user presence (§11.2.9.1.7).
pub(crate) const STATUS_UPNEEDED: u8 = 0x02;

/// Expected keepalive cadence (§11.2.9.1.7: at least every 100 ms).
/// Not used as a timeout anywhere (design OQ-2): recorded as the
/// documented expectation for the hardware probes to measure against.
#[allow(dead_code)] // probe expectation record, design OQ-2
pub(crate) const KEEPALIVE_EXPECTED_CADENCE: Duration = Duration::from_millis(100);
