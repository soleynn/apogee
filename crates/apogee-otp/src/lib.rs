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
//! - [`TotpParams`] the validated profile, and the import grammar behind it. [`Algorithm`] is the
//!   hash it derives with, and [`Deviation`] is each parameter the login server will not take a code
//!   derived from, reported rather than rewritten.
//! - [`Code`] and [`Minted`] a live code and when it may be sent.
//! - [`ClockSkew`] the offset between this host's clock and the login server's.
//! - [`OtpSource`] where a login's code comes from.
//! - [`Listener`] the local delivery endpoint, and [`Received`] what one wait took off it.
//! - [`ListenerConfig`] where it sits, [`SourceFilter`] (and the [`Pinned`] set it may carry) who may
//!   reach it, [`COMPAT_PORT`] the port the companion app dials, [`ListenerConsent`] the token that
//!   says a user asked for a port on their network at all.
//! - [`OtpError`] is the single error type every fallible surface returns, and [`Rejected`] names
//!   which rule a refused import broke.
//!
//! # Features
//! `fuzzing` exposes the two grammars that take hostile input, the secret import and the listener's
//! request line, plus the listener's framing, as plain functions a fuzz target can call. It is off by
//! default and switched on by the fuzz workspace and by nothing else, so no shipping build has a
//! parser entry point in its public API.
//!
//! # Examples
//! Importing a secret, and the two calls a login makes against it:
//! ```
//! use std::sync::Arc;
//! use std::time::{Duration, UNIX_EPOCH};
//!
//! use apogee_otp::{ClockSkew, Otp, TotpParams};
//! use apogee_secrets::{MemoryStore, SecretKind, SecretStore};
//! use uuid::Uuid;
//!
//! // What a user pastes, in the one form this crate stores.
//! let imported = TotpParams::parse("otpauth://totp/Apogee?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")?;
//! assert!(imported.deviations().is_empty());
//!
//! let account = Uuid::from_u128(0x5eed);
//! let store = Arc::new(MemoryStore::new());
//! store.set(account, SecretKind::TotpSecret, imported.into_secret())?;
//!
//! let otp = Otp::new(store as Arc<dyn SecretStore + Send + Sync>);
//!
//! // The read, which may sit on an unlock prompt for as long as the user takes.
//! let prepared = otp.prepare_blocking(account)?;
//!
//! // The derive, once the login server's clock is known.
//! let minted = prepared.mint_at(
//!     UNIX_EPOCH + Duration::from_secs(1_234_567_905),
//!     ClockSkew::from_seconds(2),
//! )?;
//! assert_eq!(minted.wait(), Duration::ZERO);
//! assert_eq!(minted.code().len(), 6);
//! # Ok::<(), apogee_otp::OtpError>(())
//! ```

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
