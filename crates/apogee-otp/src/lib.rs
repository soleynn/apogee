#![forbid(unsafe_code)]
//! TOTP generation and the local one-time-password listener.
//!
//! STUB: public shape only (error taxonomy, [`import`]/[`generate`], the [`Listener`], and the
//! [`Otp`] handle the composition root holds); TOTP math and the local listener are not yet built.

use std::time::SystemTime;

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
#[derive(Debug, Clone)]
pub enum OtpSource {
    Totp,
    Manual(String),
    Listener(ListenerConfig),
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
