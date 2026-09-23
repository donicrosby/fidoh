//! The executable seam: process exit codes, I/O plumbing, and the
//! runtime-context entry (design D2 extended to binaries: this is the
//! ONLY file between `main` and the lib, and it still names no
//! runtime).
//!
//! # The entry seam (crystallized)
//!
//! The adapter's public surface is the [`Sleep`](fidoh_core::Sleep)
//! factory + blocking bridge; its timer futures must be *created*
//! inside the runtime's reactor context, and timer deadlines only
//! fire while the runtime's own `block_on` loop polls. The adapter
//! therefore owns the entry — `fidoh_tokio::run(future)` builds a
//! fresh single-threaded runtime and drives the CEREMONY FUTURE
//! itself — and this file wraps it exactly once: [`with_run`].
//! Subcommand bodies are async fns; the binary never pumps futures by
//! hand. (An earlier std park/unpark pump under a
//! `block_on(async { body() })` seam parked the timer driver in
//! `body`'s frame: the first REAL-timer wait — a hardware token's
//! keepalive — could never be woken and would hang. Found in review,
//! removed before any hardware run; the shape is banned here.)
//!
//! The zero-runtime-identifier invariant (greppable D2 audit) is
//! preserved: the runtime enters only through `fidoh_tokio::run`;
//! `exe` never writes a runtime path itself.

use std::sync::Arc;

use fidoh_core::Sleep;

/// Output ports of the executable: the lib returns values, `exe`
/// decides where they go. Tests substitute the buffers.
pub struct Out {
    /// stdout lines (progress, listings, results).
    pub out: Vec<String>,
    /// stderr lines (prompts, errors — the grep anchors).
    pub err: Vec<String>,
    /// The process exit code (design D6: 0 success, non-zero typed
    /// error path).
    pub code: i32,
}

impl Out {
    /// A clean slate.
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            err: Vec::new(),
            code: 0,
        }
    }

    /// Print a line to the stdout port.
    pub fn line(&mut self, text: &str) {
        self.out.push(String::from(text));
    }

    /// Print a line to the stderr port.
    pub fn eline(&mut self, text: &str) {
        self.err.push(String::from(text));
    }

    /// Flush to the real process streams (production only).
    pub fn emit(&self) {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        for l in &self.out {
            let _ = writeln!(lock, "{l}");
        }
        let stderr = std::io::stderr();
        let mut lock = stderr.lock();
        for l in &self.err {
            let _ = writeln!(lock, "{l}");
        }
    }
}

impl Default for Out {
    fn default() -> Self {
        Self::new()
    }
}

/// A `Sleep` handle as the stack passes it (the object-safe shared
/// form). The concrete factory comes from the adapter at `main` time;
/// the orchestration layer only ever sees this trait object.
pub type SleepRef = Arc<dyn Sleep + Send + Sync>;

/// Run the future produced by `make` to completion under the
/// adapter's single-threaded runtime, handing it the adapter's
/// [`SleepRef`] (the ONLY runtime-context line in the crate: the
/// entry is the adapter's own `run`, so the grep-audit invariant —
/// the binary never writes a runtime path — stays true by
/// construction, D2).
///
/// The future is driven by the runtime's own `block_on` loop, so
/// timer deadlines fire and wake it correctly — including the
/// real-timer keepalive waits a hardware token produces. The handle
/// moves: `make` receives the [`SleepRef`] by value and the produced
/// future owns it (an Arc clone), so the future never borrows the
/// seam's frame. A context/nesting or build failure surfaces as the
/// typed `String` the caller maps onto the D6 exit path.
pub fn with_run<R: Send, F>(make: impl FnOnce(SleepRef) -> F + Send) -> Result<R, String>
where
    F: std::future::Future<Output = R> + Send,
{
    fidoh_tokio::run(async move {
        let factory = fidoh_tokio::TokioSleep::shared();
        make(factory).await
    })
    .map_err(|e| format!("fidoh-tokio: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_run_drives_a_future_on_the_runtime() {
        let v = with_run(|_sleep| async { 41 + 1 }).expect("fresh test thread has no runtime");
        assert_eq!(v, 42);
    }

    #[test]
    fn with_run_hands_the_adapter_factory() {
        let name = with_run(|sleep| async move {
            // The factory handle must be usable as the stack's Sleep.
            let _handle: &(dyn Sleep + Send + Sync) = sleep.as_ref();
            String::from("factory-ok")
        })
        .expect("fresh test thread has no runtime");
        assert_eq!(name, "factory-ok");
    }

    #[test]
    fn nested_run_entry_is_typed_not_panicking() {
        with_run(|_sleep| async {
            // Inside the runtime now: a nested entry must be a typed
            // error, never a panic (the documented rule).
            assert!(fidoh_tokio::run(async {}).is_err());
        })
        .expect("outer entry on a fresh test thread");
    }

    #[test]
    fn out_ports_stay_separate() {
        let mut o = Out::new();
        o.line("stdout");
        o.eline("stderr");
        assert_eq!(o.out, vec![String::from("stdout")]);
        assert_eq!(o.err, vec![String::from("stderr")]);
        assert_eq!(o.code, 0);
    }
}
