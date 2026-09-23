//! Executor-free future combinators (an allocation-free [`select`]).
//!
//! `core::future` ships no combinators and the stack invariant forbids
//! an executor dependency, so `fidoh-core` owns the small polling
//! machinery it needs: [`Either`], the branch type, and [`select`],
//! which races two futures to first completion. Dropping the `select`
//! future drops both inputs — the cancellation-safety story for every
//! bounded wait in [`Deadline::wait`](crate::time::Deadline::wait).

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Result of [`select`]: whichever future completed first, with the
/// other future still pending and reachable for further polling.
#[derive(Debug, PartialEq, Eq)]
pub enum Either<A, B> {
    /// The first future completed first.
    Left(A),
    /// The second future completed first.
    Right(B),
}

/// Race two futures, resolving with whichever completes first.
///
/// Cancellation-safe: the unfinished future is returned inside the
/// [`Either`] and may be resumed by its owner; dropping the `Either`
/// drops it. Dropping the `select` future itself drops both inputs.
///
/// Both futures must be [`Unpin`] so they can be polled by reference
/// without structural pinning (workspace `deny(unsafe_code)`); every
/// future core itself produces is `Unpin` (`Pin<Box<...>>` from
/// [`Sleep`](crate::sleep::Sleep) or state machines over plain data),
/// so the bound is not a practical restriction here.
pub fn select<A, B>(a: A, b: B) -> Select<A, B>
where
    A: Future + Unpin,
    B: Future + Unpin,
{
    Select { a, b }
}

/// Future returned by [`select`].
#[derive(Debug)]
pub struct Select<A, B> {
    a: A,
    b: B,
}

impl<A, B> Future for Select<A, B>
where
    A: Future + Unpin,
    B: Future + Unpin,
{
    type Output = Either<A::Output, B::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Both fields are Unpin, so `Select` is Unpin and the Pin is
        // structurally inert; `get_mut` is the sound, unsafe-free way
        // through.
        let this = self.get_mut();
        if let Poll::Ready(out) = Pin::new(&mut this.a).poll(cx) {
            return Poll::Ready(Either::Left(out));
        }
        if let Poll::Ready(out) = Pin::new(&mut this.b).poll(cx) {
            return Poll::Ready(Either::Right(out));
        }
        Poll::Pending
    }
}
