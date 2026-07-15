//! The crate's error taxonomy. Deliberately tiny: the primitives are infallible by construction, so
//! these variants surface only on the paths where SE's format admits bad input.

use thiserror::Error;

/// Cryptography failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A raw ticket had zero length.
    #[error("ticket was empty")]
    EmptyTicket,
    /// A checksum index fell outside the 16-entry table.
    #[error("checksum index out of range")]
    ChecksumIndexOutOfRange,
}
