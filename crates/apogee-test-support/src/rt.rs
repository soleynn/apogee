//! A minimal blocking executor for tests.
//!
//! Drives a future to completion by polling it on the current thread with a no-op waker. It is meant
//! for futures that never park: the fixture transport does its work synchronously, so a single poll
//! completes it and no reactor is needed. This keeps the transport-free protocol crates from taking a
//! tokio dev-dependency just to await a fake.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Poll `future` to completion on the current thread.
///
/// A no-op waker means a genuinely-parking future would spin here, so use this only for futures that
/// resolve without yielding (the fixture transport is the intended input).
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}
