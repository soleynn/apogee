#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! A reimplementation of Square Enix's launcher cryptography.
//!
//! Before a credential reaches TLS, the SE launcher wraps it in one of a handful of home-grown
//! obfuscation schemes: an encrypted command-line argument string, an obfuscated Steam
//! authentication ticket, and the primitives both are built from. This crate reproduces those
//! schemes byte-for-byte, including implementation-specific behavior such as a signed-byte
//! Blowfish key schedule, wrapping clock arithmetic, and a sign-extended checksum.
//!
//! # Layout
//!
//! - [`ArgumentBuilder`] serializes and encrypts the launcher's `sqex0003` argument string, keyed
//!   by an [`ArgKey`] derived from a [`TickCount`].
//! - [`ObfuscatedTicket`] obfuscates a raw Steam authentication ticket against a [`ServerTime`] for
//!   the login query.
//! - [`Blowfish`] and [`LegacyBlowfish`] are the two zero-padded ECB Blowfish variants both schemes
//!   build on: textbook big-endian, and the launcher's signed-key-schedule little-endian variant.
//! - [`sqex_base64`] is SE's mangled base64 alphabet (`+`/`/`/`=` swapped for `-`/`_`/`*`).
//! - [`CrtRand`] is the MSVCRT `rand()` sequence the ticket obfuscation draws its padding from.
//!
//! Every primitive here is a pure, synchronous transform: none of them read a clock, source
//! randomness, or perform I/O. Callers supply the tick or the server time; this crate only
//! reproduces what SE's code does with it.
//!
//! # Examples
//!
//! Building an encrypted launch-argument string:
//!
//! ```
//! use sqex_crypto::{ArgKey, ArgumentBuilder, TickCount};
//!
//! let key = ArgKey::from_tick(TickCount::from_raw(0x1234_5678));
//! let encrypted = ArgumentBuilder::new()
//!     .add("DEV.UseSqPack", "1")
//!     .add("language", "1")
//!     .build_encrypted(&key);
//!
//! assert!(encrypted.starts_with("//**sqex0003"));
//! assert!(encrypted.ends_with("**//"));
//! ```
//!
//! Obfuscating a Steam authentication ticket:
//!
//! ```
//! # fn main() -> Result<(), sqex_crypto::CryptoError> {
//! use sqex_crypto::{ObfuscatedTicket, ServerTime};
//!
//! let ticket = ObfuscatedTicket::from_auth_ticket(&[0xab], ServerTime(100))?;
//! assert_eq!(ticket.text(), "l9frZA-zmLg*");
//! assert_eq!(ticket.length(), 12);
//! # Ok(())
//! # }
//! ```

mod args;
mod blowfish;
mod bytes;
mod crtrand;
mod error;
mod hex;
pub mod sqex_base64;
mod ticket;

pub use args::{ArgKey, ArgumentBuilder, TickCount};
pub use blowfish::{Blowfish, LegacyBlowfish};
pub use crtrand::CrtRand;
pub use error::CryptoError;
pub use ticket::{ObfuscatedTicket, ServerTime};
