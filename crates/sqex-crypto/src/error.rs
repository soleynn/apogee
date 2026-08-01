//! The crate's error taxonomy. Deliberately tiny: the primitives are infallible by construction, so
//! these variants surface only on the paths where SE's format admits bad input.

use thiserror::Error;

/// Cryptography failures.
///
/// One variant, and it is the only refusal any of these transforms makes. The argument builder cannot
/// fail at all: its checksum character is selected by a masked nibble, so the index is in range by
/// construction and there is no out-of-range case to report.
///
/// # Examples
///
/// ```
/// use sqex_crypto::{CryptoError, ObfuscatedTicket, ServerTime};
///
/// let result = ObfuscatedTicket::from_auth_ticket(&[], ServerTime(0));
/// assert!(matches!(result, Err(CryptoError::EmptyTicket)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A raw ticket had zero length.
    #[error("ticket was empty")]
    EmptyTicket,
}
