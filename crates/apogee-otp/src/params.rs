//! The validated generator profile: a key plus the three parameters a code depends on.

mod uri;

#[cfg(test)]
mod tests;

use std::fmt;
use std::time::SystemTime;

use apogee_secrets::Secret;
use zeroize::Zeroizing;

use crate::code::Code;
use crate::error::{OtpError, Rejected};
use crate::skew::ClockSkew;
use crate::window;

/// The shortest key a code may be derived from, in bytes. RFC 4226 sets 128 bits as the floor and
/// the generator refuses anything under it, so the check lives here where the reason can be named.
const MIN_KEY_BYTES: usize = 16;

/// The longest key accepted. Nothing legitimate approaches it; the cap is what keeps a pasted
/// megabyte of base32 from being decoded and then held.
const MAX_KEY_BYTES: usize = 256;

const MIN_DIGITS: u8 = 6;
const MAX_DIGITS: u8 = 8;
const MIN_PERIOD: u32 = 1;
const MAX_PERIOD: u32 = 300;

/// What the login server accepts, and therefore what everything else is measured against.
const USABLE_ALGORITHM: Algorithm = Algorithm::Sha1;
const USABLE_DIGITS: u8 = 6;
const USABLE_PERIOD: u32 = 30;

/// The fixed text of the canonical form plus the widest the three parameters render to: the four
/// literals total fifty-six bytes, the longest algorithm name is six, and three digits each cover a
/// digit count and a period. Nothing here grows with the key.
const CANONICAL_OVERHEAD: usize = 56 + 6 + 3 + 3;

/// A hash a code can be derived with.
///
/// Owned here rather than re-exported from the generator this crate builds on: that enum grows a
/// variant under a feature flag, and this one is what the stored form is written against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Algorithm {
    /// What every community flow uses, and the only one the login server takes.
    #[default]
    Sha1,
    /// Legal in the format, and a code derived with it is refused.
    Sha256,
    /// Legal in the format, and a code derived with it is refused.
    Sha512,
}

impl Algorithm {
    /// The name the stored form and the import grammar both spell it with.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn generator(self) -> totp_rs::Algorithm {
        match self {
            Self::Sha1 => totp_rs::Algorithm::SHA1,
            Self::Sha256 => totp_rs::Algorithm::SHA256,
            Self::Sha512 => totp_rs::Algorithm::SHA512,
        }
    }
}

/// A parameter the login server will not accept a code derived from.
///
/// Reported as data so a shell writes the sentence. The value is stored exactly as it was given and
/// never rewritten to the accepted defaults: a user with a genuinely unusual secret gets wrong codes
/// with an explanation rather than wrong codes without one.
///
/// Each variant carries both halves of the comparison. A shell that knew only what was offered would
/// have to spell the accepted value out as a literal of its own, which is a second copy of a rule
/// this crate owns and the copy nothing updates when the rule moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Deviation {
    /// A hash other than the one the login server takes.
    Algorithm {
        /// What the secret asks for.
        offered: Algorithm,
        /// What a code has to be derived with to be accepted.
        accepted: Algorithm,
    },
    /// A digit count other than the one the login server takes.
    Digits {
        /// What the secret asks for.
        offered: u8,
        /// How many digits an accepted code has.
        accepted: u8,
    },
    /// A period other than the one the login server expects.
    Period {
        /// What the secret asks for, in seconds.
        offered: u32,
        /// How many seconds an accepted code stays current for.
        accepted: u32,
    },
}

/// A validated generator profile: the key plus the three parameters a code depends on.
///
/// Not `Clone` (a clone is a second key buffer with its own lifetime), no derived `Debug`, no
/// `serde::Serialize`, no `PartialEq`, no `Default`. The key is erased when it drops.
pub struct TotpParams {
    key: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
}

impl TotpParams {
    /// Parse an `otpauth://totp/...` URI or a raw base32 secret.
    ///
    /// Everything here is hostile input: the text arrives from a paste, a clipboard, or a file
    /// another program wrote. Nothing is forwarded to a general-purpose URL parser, and no reason
    /// carries a fragment of what was offered.
    ///
    /// # Errors
    /// [`OtpError::Import`], carrying the [`Rejected`] rule the text broke.
    pub fn parse(offered: &str) -> Result<Self, OtpError> {
        uri::parse(offered).map_err(|reason| OtpError::Import { reason })
    }

    /// Parse the canonical form this crate stores.
    ///
    /// The same grammar as [`TotpParams::parse`], deliberately: there is one parser in the crate, it
    /// is the one that gets fuzzed, and a value read back from a credential store is not
    /// integrity-protected, so treating it as hostile costs nothing.
    ///
    /// # Errors
    /// [`OtpError::Stored`], carrying the [`Rejected`] rule the stored value broke.
    pub fn from_secret(stored: &Secret) -> Result<Self, OtpError> {
        let text = std::str::from_utf8(stored.expose()).map_err(|_| OtpError::Stored {
            reason: Rejected::SecretAlphabet,
        })?;
        uri::parse(text).map_err(|reason| OtpError::Stored { reason })
    }

    /// The canonical form, ready for the store.
    ///
    /// Consumes `self` so no un-erased copy of the key stays behind at the call site. All four
    /// parameters are written explicitly and the label is a fixed literal, so nothing a user typed
    /// rides along into the store.
    #[must_use]
    pub fn into_secret(self) -> Secret {
        let mut text = self.canonical();
        // Moves the buffer rather than copying it, and what stays behind is the empty `String` the
        // take left. `Secret` erases the one it is handed, which is now the only one there is.
        Secret::from_string(std::mem::take(&mut *text))
    }

    /// The canonical text, in a buffer sized for the whole of it before a key byte is written.
    ///
    /// Sized up front because a buffer that grows moves what it already holds, and the block it
    /// leaves behind goes back to the allocator with the key still in it: only the final buffer is
    /// the one [`Secret`] erases. The `Zeroizing` covers a growth step a later edit reintroduces.
    fn canonical(&self) -> Zeroizing<String> {
        let encoded = Zeroizing::new(base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &self.key,
        ));
        let mut text = Zeroizing::new(String::with_capacity(canonical_capacity(encoded.len())));
        text.push_str("otpauth://totp/apogee?secret=");
        text.push_str(encoded.as_str());
        text.push_str("&algorithm=");
        text.push_str(self.algorithm.label());
        text.push_str("&digits=");
        text.push_str(&self.digits.to_string());
        text.push_str("&period=");
        text.push_str(&self.period.to_string());
        text
    }

    /// The hash codes are derived with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// How many digits a code has.
    #[must_use]
    pub const fn digits(&self) -> u8 {
        self.digits
    }

    /// How many seconds a code stays current for.
    #[must_use]
    pub const fn period(&self) -> u32 {
        self.period
    }

    /// Every parameter that departs from what the login server accepts, in a fixed order. An empty
    /// answer is the usable case.
    #[must_use]
    pub fn deviations(&self) -> Vec<Deviation> {
        let mut found = Vec::new();
        if self.algorithm != USABLE_ALGORITHM {
            found.push(Deviation::Algorithm {
                offered: self.algorithm,
                accepted: USABLE_ALGORITHM,
            });
        }
        if self.digits != USABLE_DIGITS {
            found.push(Deviation::Digits {
                offered: self.digits,
                accepted: USABLE_DIGITS,
            });
        }
        if self.period != USABLE_PERIOD {
            found.push(Deviation::Period {
                offered: self.period,
                accepted: USABLE_PERIOD,
            });
        }
        found
    }

    /// The code for `at`, shifted by `skew`. Pure: no store, no reuse guard.
    ///
    /// # Errors
    /// [`OtpError::Clock`] if `at` plus `skew` is not an instant a counter is defined for.
    pub fn code(&self, at: SystemTime, skew: ClockSkew) -> Result<Code, OtpError> {
        let seconds = window::shifted_seconds(at, skew)?;
        self.code_for_counter(window::counter(seconds, self.period)?)
    }

    /// The code for one counter, which is how the reuse guard walks forward a window at a time.
    ///
    /// # Errors
    /// [`OtpError::Clock`] if the counter's window starts past what a second count holds.
    pub(crate) fn code_for_counter(&self, counter: u64) -> Result<Code, OtpError> {
        let start = window::window_start(counter, self.period)?;
        // Built per call rather than held: the generator wants the key by value, and a field would
        // be a second copy of it living as long as this profile does. `new_unchecked` skips the
        // dependency's own digit and key-length checks, which `assemble` has already made
        // invariants of this type, and in exchange the call cannot fail.
        let generator = totp_rs::TOTP::new_unchecked(
            self.algorithm.generator(),
            usize::from(self.digits),
            1,
            u64::from(self.period),
            self.key.to_vec(),
        );
        Ok(Code::new(Zeroizing::new(generator.generate(start))))
    }

    /// Build a profile from parts the grammar has already separated, applying every range rule in
    /// one place so the two import paths cannot drift apart.
    fn assemble(
        key: Zeroizing<Vec<u8>>,
        algorithm: Algorithm,
        digits: u8,
        period: u32,
    ) -> Result<Self, Rejected> {
        if key.len() < MIN_KEY_BYTES {
            return Err(Rejected::SecretTooShort);
        }
        if key.len() > MAX_KEY_BYTES {
            return Err(Rejected::TooLong);
        }
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(Rejected::Digits);
        }
        if !(MIN_PERIOD..=MAX_PERIOD).contains(&period) {
            return Err(Rejected::Period);
        }
        Ok(Self {
            key,
            algorithm,
            digits,
            period,
        })
    }
}

/// How much room the canonical form needs for a key that encodes to `encoded` characters.
const fn canonical_capacity(encoded: usize) -> usize {
    encoded + CANONICAL_OVERHEAD
}

/// The parameters, never the key. A profile is the one thing in this crate holding a long-lived
/// shared secret, so there is nothing else to render.
impl fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpParams")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}
