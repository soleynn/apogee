#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
//! Time-based one-time-password codes for an account, and the local listener a companion can
//! deliver one to.
//!
//! [`TotpParams::parse`] turns an `otpauth` URI or a bare base32 secret into a validated profile,
//! [`TotpParams::into_secret`] renders it in the one form this crate stores, and [`Otp`] is the
//! handle that reads it back, derives a [`Code`] and remembers what was last submitted so the same
//! digits are not sent twice. A [`Minted`] carries the code and how long to wait before sending it:
//! nothing here sleeps, because only a caller holds the runtime and the cancellation token.
//!
//! [`ClockSkew`] is a signed offset, not a tolerance window. This crate is a generator, not a
//! verifier: it has to produce the one code the login server expects, so "the clock is seven seconds
//! fast" is the case that has to be representable.
//!
//! # Blocking
//! [`Otp::mint_blocking`] reads the secret store, which blocks and may raise the platform's unlock
//! prompt. On Linux the credential client cannot be driven from an async runtime's worker at all, so
//! a caller on a runtime uses [`Otp::mint`], which runs the read off the workers.
//!
//! # Layout
//! - [`Otp`] the handle: read the secret, derive a code, record what was submitted.
//! - [`TotpParams`] the validated profile, and the import grammar behind it.
//! - [`Code`] and [`Minted`] a live code and when it may be sent.
//! - [`ClockSkew`] the offset between this host's clock and the login server's.
//! - [`OtpSource`] where a login's code comes from.
//! - [`Listener`] the local delivery endpoint (not built).

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
pub use listener::{Listener, ListenerConfig};
pub use otp::Otp;
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

/// The handle is held by the composition root, cloned onto blocking tasks and shared across them,
/// and the error is wrapped by the launcher's top-level error. A code and a profile are moved into
/// one task and dropped there; neither may become `Sync`-by-accident shared state, and neither may
/// become `Clone`, because a clone is a second buffer with its own lifetime.
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_sync_static::<Otp>();
    assert_send_sync_static::<OtpError>();
    assert_send_static::<Code>();
    assert_send_static::<Minted>();
    assert_send_static::<TotpParams>();
};
