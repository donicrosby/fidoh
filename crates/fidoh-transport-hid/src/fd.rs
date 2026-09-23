//! The real fd layer: open/read/write `/dev/hidrawN`.
//!
//! Design split: everything above this module is pure and CI-tested;
//! this is the ONLY code touching real file descriptors. [`RawFd`]
//! abstracts it so the fake-fd integration tests drive the full
//! framing state machine without hardware (and without /dev).
//!
//! Linux hidraw semantics relied on (kernel `Documentation/hid/
//! hidraw.rst`):
//! - `read()` blocks until a full report is available and returns one
//!   report per call (up to the buffer's size);
//! - `write()` delivers an OUTPUT report via the interrupt OUT
//!   endpoint, or via a control (SET_REPORT) transfer when the device
//!   has no OUT endpoint — the CTAPHID CANCEL write path (design
//!   OQ-3);
//! - nonblocking mode (`O_NONBLOCK`) makes `read` fail `EAGAIN`
//!   instead of blocking, which is how a blocking read is sliced
//!   without threads: sleep a slice, poll for available reports,
//!   repeat until the budget runs out.
//!
//! No `unsafe`: `std::fs` only. The open flags are the libc
//! `O_RDWR | O_NONBLOCK | O_CLOEXEC` values, named as Linux constants
//! with their documented octal values (asm-generic/fcntl.h), so the
//! crate needs no libc dependency and stays `deny(unsafe_code)`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use std::fs::File;
use std::os::unix::fs::OpenOptionsExt;

use crate::error::HidError;

/// Linux `O_RDWR` (asm-generic/fcntl.h: 0o2).
pub(crate) const O_RDWR: u32 = 0o2;
/// Linux `O_NONBLOCK` (asm-generic/fcntl.h: 0o4000).
pub(crate) const O_NONBLOCK: u32 = 0o4000;
/// Linux `O_CLOEXEC` (asm-generic/fcntl.h: 0o2000000).
pub(crate) const O_CLOEXEC: u32 = 0o200_0000;

/// The CTAPHID report size (§11.2.4); writes are exact 64-byte
/// reports.
pub(crate) const REPORT: usize = crate::consts::REPORT_SIZE;

/// A hidraw file handle (the fd seam: the pure layers are tested
/// against fakes implementing this trait).
pub trait RawFd {
    /// Write one 64-byte report (blocking; the kernel converts it to
    /// an OUT report — OQ-3 notes the SET_REPORT caveat on devices
    /// without an OUT endpoint).
    fn write_report(&mut self, report: &[u8]) -> Result<(), HidError>;

    /// Read whatever is available now WITHOUT blocking (the fd is
    /// opened `O_NONBLOCK`). Returns:
    /// - `Ok(Some(bytes))` — one report (≤64 bytes as the kernel
    ///   delivered it; the framing layer validates);
    /// - `Ok(None)` — nothing available yet (EAGAIN);
    /// - `Err` — a real I/O error (ENODEV on unplug, …).
    fn read_nonblocking(&mut self) -> Result<Option<Vec<u8>>, HidError>;
}

/// A real `/dev/hidrawN` node.
pub struct HidRawFile {
    file: File,
}

impl HidRawFile {
    /// Open a hidraw node nonblocking, read-write. Permission-denied
    /// and missing-node failures carry the path (docs/transport-hid.md
    /// diagnostics table maps them to remediation).
    /// Open the node nonblocking read-write.
    pub fn open(dev_path: &str) -> Result<Self, HidError> {
        // custom_flags carries the raw open(2) mode bits on Linux.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags((O_RDWR | O_NONBLOCK | O_CLOEXEC) as i32)
            .open(dev_path)
            .map_err(|e| HidError::io(dev_path, "open", format!("{e}")))?;
        Ok(Self { file })
    }
}

impl RawFd for HidRawFile {
    fn write_report(&mut self, report: &[u8]) -> Result<(), HidError> {
        debug_assert_eq!(report.len(), REPORT);
        use std::io::Write;
        self.file
            .write_all(report)
            .map_err(|e| HidError::io("hidraw", "write", format!("{e}")))
    }

    fn read_nonblocking(&mut self) -> Result<Option<Vec<u8>>, HidError> {
        use std::io::Read;
        let mut buf = [0u8; REPORT];
        match self.file.read(&mut buf) {
            // Zero-length read: treat as "nothing yet" (a real
            // unplug surfaces as ENODEV on the next op).
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(buf[..n].to_vec())),
            // EAGAIN / EWOULDBLOCK: nothing available (nonblocking).
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(HidError::io("hidraw", "read", format!("{e}"))),
        }
    }
}

/// Open a hidraw node (the fd layer's only non-test entry point).
/// Open a hidraw node.
pub fn open_node(dev_path: &str) -> Result<HidRawFile, HidError> {
    HidRawFile::open(dev_path)
}

/// Error detail string helper: path + cause flattened for
/// [`HidError::Io`] consumers that log a single line.
/// Flatten path + cause for single-line logs.
pub fn io_detail(path: &str, cause: &str) -> String {
    format!("{path}: {cause}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Flag constants are the documented Linux values (asm-generic
    // fcntl.h); a regression here would open the wrong access mode.
    #[test]
    fn open_flags_match_linux_constants() {
        assert_eq!(O_RDWR, 0o2);
        assert_eq!(O_NONBLOCK, 0o4000);
        assert_eq!(O_CLOEXEC, 0o200_0000);
    }

    #[test]
    fn io_detail_flattens() {
        assert_eq!(
            io_detail("/dev/hidraw0", "Permission denied"),
            "/dev/hidraw0: Permission denied"
        );
    }
}
