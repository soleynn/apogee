#![forbid(unsafe_code)]
//! SE launcher cryptography: Blowfish variants, launch-argument obfuscation, MSVCRT RNG.

mod args;
mod blowfish;
mod bytes;
mod crtrand;
mod error;
pub mod sqex_base64;

pub use args::{ArgKey, ArgumentBuilder, TickCount};
pub use blowfish::{Blowfish, LegacyBlowfish};
pub use crtrand::CrtRand;
pub use error::CryptoError;
