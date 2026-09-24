//! The real sysfs reader: std::fs backed [`SysfsRead`] implementation
//! used by enumeration. Split from `sysfs.rs` so the tree model and
//! walker stay pure; this module is the only std::fs contact point
//! besides `fd.rs`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::HidError;
use crate::sysfs::SysfsRead;

/// Reads real filesystem paths under a root (normally `/sys`).
pub(crate) struct FsSysfs {
    /// Root prepended to every path (tests can point it at a fixture
    /// tree; production uses `/sys`).
    root: String,
}

impl FsSysfs {
    /// The production reader rooted at `/sys`.
    pub(crate) fn system() -> Self {
        Self {
            root: String::from("/sys"),
        }
    }

    /// A reader rooted elsewhere (fixture trees in integration tests).
    pub(crate) fn rooted(root: &str) -> Self {
        Self {
            root: String::from(root),
        }
    }

    fn full(&self, path: &str) -> String {
        alloc::format!("{}{}", self.root, path)
    }
}

impl SysfsRead for FsSysfs {
    fn read(&self, path: &str) -> Result<Vec<u8>, HidError> {
        std::fs::read(self.full(path))
            .map_err(|e| HidError::io(path, "read", alloc::format!("{e}")))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<String>, HidError> {
        let mut out: Vec<String> = Vec::new();
        // A directory entry racing an unplug mid-iteration is skipped,
        // not fatal.
        for entry in std::fs::read_dir(self.full(path))
            .map_err(|e| HidError::io(path, "read_dir", alloc::format!("{e}")))?
            .flatten()
        {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
        Ok(out)
    }
}

/// Enumerate FIDO hidraw candidates on the real system: walk
/// `/sys/class/hidraw` (design D7), returning matching entries and
/// per-node diagnostics.
#[allow(dead_code)]
pub(crate) fn enumerate_system() -> (Vec<crate::sysfs::HidRawEntry>, Vec<HidError>) {
    crate::sysfs::walk(&FsSysfs::system(), "/sys/class/hidraw")
}
