//! The local listener a companion delivers a code to.
//!
//! Not built. The shape is here so the error taxonomy and [`crate::OtpSource`] do not churn when it
//! is, and so a caller can already say that a code will arrive this way.

use crate::error::OtpError;

/// Configuration for the local listener that receives a code from a companion.
#[derive(Debug, Clone, Default)]
pub struct ListenerConfig {
    /// The loopback port to take.
    pub port: u16,
}

/// The local one-time-password listener.
#[derive(Debug)]
pub struct Listener {/* socket not yet modeled */}

impl Listener {
    /// Bind the listener per `cfg`.
    ///
    /// # Errors
    /// [`OtpError::ListenerBind`] if the port cannot be taken.
    pub fn bind(_cfg: ListenerConfig) -> Result<Self, OtpError> {
        todo!("bind the local one-time-password listener")
    }
}
