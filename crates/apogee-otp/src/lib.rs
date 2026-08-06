#![forbid(unsafe_code)]
//! TOTP generation and the local one-time-password listener.
//!
//! STUB: public shape only (error taxonomy, [`import`]/[`generate`], the [`Listener`], and the
//! [`Otp`] handle the composition root holds); TOTP math and the local listener are not yet built.

use std::fmt;
use std::time::SystemTime;

use apogee_secrets::Secret;
use thiserror::Error;
use uuid::Uuid;

/// One-time-password failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OtpError {
    #[error("invalid otp import: {reason}")]
    ImportInvalid { reason: String },
    #[error("no otp secret stored")]
    NoSecret,
    #[error("failed to bind the otp listener")]
    ListenerBind,
    #[error("timed out waiting for a code")]
    Timeout,
    #[error("io error")]
    Io(#[from] std::io::Error),
}

/// Where a login's one-time password comes from.
///
/// A typed code is a [`Secret`], not a `String`: the buffer is erased when it drops, and the type
/// carries no `Clone`, so a caller cannot leave a second copy behind on the heap. That is why the
/// enum is neither `Clone` nor derived-`Debug` either.
pub enum OtpSource {
    Totp,
    Manual(Secret),
    Listener(ListenerConfig),
}

/// The variant name, never the code. A rendered `OtpSource` is one of the few ways a live code could
/// reach a log, so there is nothing else to render.
impl fmt::Debug for OtpSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl OtpSource {
    /// The variant's name, for a caller rendering a redacted view of something holding one.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Totp => "Totp",
            Self::Manual(_) => "Manual",
            Self::Listener(_) => "Listener",
        }
    }
}

/// Parsed TOTP parameters (secret + period + digits), from an otpauth URI or a base32 secret.
#[derive(Debug, Clone, Default)]
pub struct TotpParams {/* secret + period + digits not yet modeled */}

/// A generated one-time-password code.
#[derive(Debug, Clone)]
pub struct Code(pub String);

/// Allowed clock drift, in periods, when generating a code.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClockSkew {
    pub steps: u8,
}

/// Configuration for the local listener that receives a code from a companion.
#[derive(Debug, Clone, Default)]
pub struct ListenerConfig {
    pub port: u16,
}

/// The local one-time-password listener.
#[derive(Debug)]
pub struct Listener {/* socket not yet modeled */}

impl Listener {
    /// Bind the listener per `cfg`.
    pub fn bind(_cfg: ListenerConfig) -> Result<Self, OtpError> {
        todo!("bind the local OTP listener")
    }
}

/// Import a TOTP secret from an otpauth URI or a raw base32 secret.
pub fn import(_uri_or_base32: &str) -> Result<TotpParams, OtpError> {
    todo!("parse a TOTP secret from an otpauth URI or base32")
}

/// Generate the current code for `account`.
pub fn generate(_account: Uuid, _now: SystemTime, _skew: ClockSkew) -> Result<Code, OtpError> {
    todo!("generate the current TOTP code")
}

/// The concrete OTP service the composition root holds (`apogee-core`'s `otp` field).
#[derive(Debug, Default)]
pub struct Otp;

impl Otp {
    /// Create the OTP service.
    pub fn new() -> Self {
        Self
    }
}
