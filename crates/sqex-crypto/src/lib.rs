#![forbid(unsafe_code)]
//! SE launcher cryptography: Blowfish variants, launch-argument obfuscation, MSVCRT RNG.

mod blowfish;
mod bytes;
mod crtrand;
mod error;
pub mod sqex_base64;

pub use blowfish::{Blowfish, LegacyBlowfish};
pub use crtrand::CrtRand;
pub use error::CryptoError;
