#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
//! Time-based one-time-password codes for an account, and the local listener a companion can
//! deliver one to.
//!
//! [`TotpParams::parse`] turns an `otpauth` URI or a bare base32 secret into a validated profile,
//! [`TotpParams::into_secret`] renders it in the one form this crate stores, and [`Otp`] is the
//! handle that reads it back and remembers what was last submitted so the same digits are not sent
//! twice. A [`Minted`] carries the code and how long to wait before sending it: nothing here sleeps
//! on a human, because only a caller holds the runtime and the cancellation token. [`Listener`] is the
//! one thing here that owns anything for a stretch of time, and what it owns is a socket whose whole
//! life is one login's wait; it still holds no token, and it spawns nothing it does not also abort.
//!
//! Reading the secret and deriving a code are two calls, not one. [`Otp::prepare`] is the call that
//! raises the platform's unlock prompt and is bounded only by how long the user takes to notice it;
//! [`Prepared::mint`] names a thirty-second window and has to run once the caller knows which window
//! the login server is in. Fusing them would put an unbounded wait between those two facts.
//!
//! [`ClockSkew`] is a signed offset, not a tolerance window. This crate is a generator, not a
//! verifier: it has to produce the one code the login server expects, so "the clock is seven seconds
//! fast" is the case that has to be representable.
//!
//! # Blocking
//! [`Otp::prepare_blocking`] reads the secret store, which blocks and may raise the platform's unlock
//! prompt. On Linux the credential client cannot be driven from an async runtime's worker at all, so
//! a caller on a runtime uses [`Otp::prepare`], which runs the read off the workers.
//!
//! # Layout
//! - [`Otp`] the handle: read the secret, record what was submitted.
//! - [`Prepared`] one account's secret, in hand and waiting for the clock it derives against.
//! - [`TotpParams`] the validated profile, and the import grammar behind it.
//! - [`Code`] and [`Minted`] a live code and when it may be sent.
//! - [`ClockSkew`] the offset between this host's clock and the login server's.
//! - [`OtpSource`] where a login's code comes from.
//! - [`Listener`] the local delivery endpoint, and [`Received`] what one wait took off it.
//! - [`ListenerConfig`] where it sits, [`SourceFilter`] who may reach it, [`ListenerConsent`] the
//!   token that says a user asked for a port on their network at all.

mod code;
mod error;
mod guard;
mod listener;
mod otp;
mod params;
mod skew;
mod source;
mod window;

pub use code::{Code, Minted};
pub use error::{OtpError, Rejected};
pub use listener::{
    COMPAT_PORT, Listener, ListenerConfig, ListenerConsent, Pinned, Received, SourceFilter,
};
pub use otp::{Otp, Prepared};
pub use params::{Algorithm, Deviation, TotpParams};
pub use skew::ClockSkew;
pub use source::OtpSource;

/// The import grammar, for the fuzz workspace and nothing else.
///
/// The property: any text at all produces a clean answer, allocates nothing it did not first bound,
/// and never takes the process down.
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_import(offered: &str) {
    let _ = TotpParams::parse(offered);
}

/// The listener's request grammar, for the fuzz workspace and nothing else.
///
/// The property: any bytes at all produce a clean answer, allocate nothing that was not bounded before
/// the read, and never take the process down. Pure, so the fuzz binary reaches it without linking a
/// socket or a runtime.
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_request(offered: &[u8]) {
    listener::fuzz_parse_request(offered);
}

/// The listener's framing, driven at an arbitrary chunk size.
///
/// The property is an equality rather than an absence: feeding `offered` in `stride`-sized pieces
/// reaches the same verdict as feeding it whole. Framing is where the reference silently drops a
/// legitimate code off a flaky link, and a target that only asserts "does not abort" cannot see it.
#[cfg(feature = "fuzzing")]
pub fn fuzz_framing_agrees(offered: &[u8], stride: usize) -> bool {
    listener::fuzz_framing_agrees(offered, stride)
}

/// The handle is held by the composition root, cloned onto blocking tasks and shared across them,
/// and the error is wrapped by the launcher's top-level error. A code, a profile and a secret read
/// back out of the store are moved into one task and dropped there; none may become
/// `Sync`-by-accident shared state, and none may become `Clone`, because a clone is a second buffer
/// with its own lifetime.
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_sync_static::<Otp>();
    assert_send_sync_static::<OtpError>();
    assert_send_static::<Code>();
    assert_send_static::<Minted>();
    assert_send_static::<TotpParams>();
    assert_send_static::<Prepared>();
    // Both are held across an await inside a spawned flow task. Neither is asserted `Sync`: nothing
    // shares one, and a listener that could be shared is a port two logins could both be waiting on.
    assert_send_static::<Listener>();
    assert_send_static::<Received>();
};
