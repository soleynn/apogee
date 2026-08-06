//! Where a login's one-time password comes from.

use std::fmt;

use apogee_secrets::Secret;

use crate::listener::ListenerConfig;

/// Where a login's one-time password comes from.
///
/// A typed code is a [`Secret`], not a `String`: the buffer is erased when it drops, and the type
/// carries no `Clone`, so a caller cannot leave a second copy behind on the heap. That is why the
/// enum is neither `Clone` nor derived-`Debug` either.
#[non_exhaustive]
pub enum OtpSource {
    /// Generate one from the secret stored for the account.
    Totp,
    /// A code the user typed.
    Manual(Secret),
    /// A code a companion will deliver to the local listener.
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
