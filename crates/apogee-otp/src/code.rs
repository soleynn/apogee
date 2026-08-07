//! A live code, and when it may be sent.

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

/// A live one-time-password code.
///
/// There is no public constructor: only this crate mints one, so a code in a caller's hands came
/// from a secret this crate holds. It implements no `Clone` (a clone is a second buffer of digits
/// with its own lifetime), no `Display`, no `PartialEq`, no `Default` and no `serde::Serialize`, and
/// the `Debug` renders the digit count and never the digits. The buffer is erased when it drops.
pub struct Code(Zeroizing<String>);

impl Code {
    /// The digits, for the one call that submits them. Use and drop: never log, persist, or copy
    /// into a longer-lived buffer.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// How many digits the code holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the code holds no digits at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Wrap freshly generated digits. Takes the buffer by value so no un-erased copy stays behind.
    pub(crate) fn new(digits: Zeroizing<String>) -> Self {
        Self(digits)
    }
}

/// The length, never the digits. A rendered `Code` is the shortest route a live code has to a log.
impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code({} digits)", self.0.len())
    }
}

/// A code and when it may be sent.
///
/// The wait is the whole of what the reuse guard does to a caller: this crate never sleeps and never
/// spawns anything, because only the caller holds the runtime, the cancellation token and the
/// channel a progress event goes down.
pub struct Minted {
    code: Code,
    wait: Duration,
    valid_for: Duration,
}

impl Minted {
    /// How long to wait before submitting.
    ///
    /// `Duration::ZERO` unless the mint moved the code to a later window, which happens when the
    /// current one has almost no life left in it or when the reuse guard recognizes the code. Never
    /// more than the period times one more than the number of windows the guard will scan, since
    /// those are the two things that step it forward.
    #[must_use]
    pub fn wait(&self) -> Duration {
        self.wait
    }

    /// How long the code stays current once [`Minted::wait`] has elapsed.
    #[must_use]
    pub fn valid_for(&self) -> Duration {
        self.valid_for
    }

    /// Borrow the code.
    #[must_use]
    pub fn code(&self) -> &Code {
        &self.code
    }

    /// Take the code, dropping the timing.
    #[must_use]
    pub fn into_code(self) -> Code {
        self.code
    }

    pub(crate) fn new(code: Code, wait: Duration, valid_for: Duration) -> Self {
        Self {
            code,
            wait,
            valid_for,
        }
    }
}

/// The timing, never the code. `Code`'s own `Debug` would redact it anyway; this spells it out so a
/// field added later does not quietly start printing one.
impl fmt::Debug for Minted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Minted")
            .field("wait", &self.wait)
            .field("valid_for", &self.valid_for)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seal, checked from inside the crate where a constructor is reachable: a rendered code is
    /// the one way six live digits reach a CI log, and no assertion downstream would catch it.
    #[test]
    fn a_rendered_code_never_shows_its_digits() {
        let code = Code::new(Zeroizing::new("123456".to_owned()));
        let rendered = format!("{code:?}");
        assert!(!rendered.contains("123456"), "{rendered}");
        assert_eq!(rendered, "Code(6 digits)");
        assert_eq!(code.len(), 6);
        assert!(!code.is_empty());
    }

    #[test]
    fn a_rendered_mint_shows_only_its_timing() {
        let minted = Minted::new(
            Code::new(Zeroizing::new("005924".to_owned())),
            Duration::from_secs(12),
            Duration::from_secs(30),
        );
        let rendered = format!("{minted:?}");
        assert!(!rendered.contains("005924"), "{rendered}");
        assert_eq!(minted.wait(), Duration::from_secs(12));
        assert_eq!(minted.valid_for(), Duration::from_secs(30));
        assert_eq!(minted.into_code().expose(), "005924");
    }
}
