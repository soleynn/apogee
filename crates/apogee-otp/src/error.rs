//! The one-time-password error taxonomy.

use std::fmt;

use thiserror::Error;

/// One-time-password failures.
///
/// Each variant is a condition a caller answers differently: [`Import`](Self::Import) is text a user
/// just offered and is answered by correcting the paste, [`Stored`](Self::Stored) is a value already
/// in the store and is answered by importing again, and [`NoSecret`](Self::NoSecret) is a store that
/// answered cleanly with nothing at all.
///
/// No variant carries a fragment of a secret or of a code. The enum is wrapped by the launcher's
/// top-level error and rendered by a shell, so anything a caller passed in would reach a log line
/// through a route this crate does not choose.
///
/// There is no passthrough variant for a socket or filesystem failure, and the absence is the
/// contract rather than an omission. Every IO failure this crate can reach is already named as the
/// thing it means to a login: a bind that lost the race is [`ListenerBind`](Self::ListenerBind), and
/// a failure on one connection is that connection's outcome rather than the wait's. A
/// `From<std::io::Error>` conversion would let a `?` added later route one of those past its own
/// variant and reach a caller as an untriageable line.
///
/// # Examples
/// ```
/// use apogee_otp::{OtpError, Rejected, TotpParams};
///
/// let refused = TotpParams::parse("not base32 at all!")
///     .expect_err("the alphabet rule refuses this");
/// assert!(matches!(
///     refused,
///     OtpError::Import { reason: Rejected::SecretAlphabet }
/// ));
/// assert_eq!(
///     refused.to_string(),
///     "the offered one-time-password secret is not usable: the secret is not base32"
/// );
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OtpError {
    /// Text offered for import is neither an `otpauth` URI nor a base32 secret.
    #[error("the offered one-time-password secret is not usable: {reason}")]
    Import {
        /// Which rule the text broke. One of a fixed set this crate owns.
        reason: Rejected,
    },
    /// Nothing is stored for this account under the one-time-password kind.
    ///
    /// Distinct from [`Secrets`](Self::Secrets): the store answered, and the answer was that there
    /// is nothing here. Answered by importing a secret or by typing a code, never by retrying.
    #[error("no one-time-password secret is stored for this account")]
    NoSecret,
    /// A secret came back from the store and does not parse.
    ///
    /// Distinct from [`Import`](Self::Import), which is text a user just offered: this one is
    /// already stored, so a caller answers it by importing again rather than by correcting a paste.
    #[error("the stored one-time-password secret is not usable: {reason}")]
    Stored {
        /// Which rule the stored value broke. One of a fixed set this crate owns.
        reason: Rejected,
    },
    /// The secret store failed, was locked, or refused. Its own taxonomy says which, and a locked
    /// store is the one case where the same call can succeed after the user unlocks.
    #[error("secret store: {0}")]
    Secrets(#[from] apogee_secrets::SecretsError),
    /// The instant a code was asked for is outside the range a counter can be derived from: before
    /// the epoch, or pushed there by the skew offset.
    #[error("the clock is outside the range a code can be generated for")]
    Clock,
    /// The blocking task that would have produced the code was dropped before it answered.
    #[error("the task generating the code was dropped")]
    Interrupted,
    /// The local listener could not take its port.
    ///
    /// Carries the port because that is the one fact that makes the answer actionable: something else
    /// already holds it, which on this port is almost always a running reference launcher. There is no
    /// fallback port, so this is terminal for the login rather than a condition anything retries. A
    /// port is not a secret and not a caller-supplied value in the sense the rest of this taxonomy
    /// refuses.
    #[error("failed to bind the one-time-password listener on port {port}")]
    ListenerBind {
        /// The port that could not be taken.
        port: u16,
    },
    /// Nothing delivered a code inside the deadline.
    #[error("timed out waiting for a code")]
    Timeout,
}

/// Why text offered as a one-time-password secret was refused.
///
/// Carries nothing, deliberately. Every field a reason could carry is a fragment of the secret or of
/// the label, and this enum is rendered by [`OtpError`], which the launcher's top-level error wraps
/// and a shell prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejected {
    /// The text, or the key it decoded to, is longer than anything a shared secret needs.
    TooLong,
    /// Nothing but whitespace was offered.
    Empty,
    /// The text names a scheme, and it is not `otpauth`.
    Scheme,
    /// A multi-account export from another authenticator, not a single secret.
    MigrationBundle,
    /// The authority is not `totp`, or a counter parameter marks this as a counter-based profile.
    Type,
    /// The authority carries userinfo or a port, or the scheme was not followed by `//`.
    Authority,
    /// The label holds a bad percent-escape, a control character, or bytes that are not text.
    Label,
    /// The same query key appears more than once, so two parsers could disagree about which value
    /// was imported.
    DuplicateParameter,
    /// No secret parameter was given.
    SecretMissing,
    /// The secret is not base32 once case, padding, spacing and hyphens are normalized away.
    SecretAlphabet,
    /// The key the secret decodes to is under the length a code may be derived from.
    SecretTooShort,
    /// The digit count is absent from the accepted range, or is not a number at all.
    Digits,
    /// The period is absent from the accepted range, or is not a number at all.
    Period,
    /// The named hash is not one a code can be derived with.
    Algorithm,
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "it is longer than a shared secret can be",
            Self::Empty => "it is empty",
            Self::Scheme => "it is a link of some other kind",
            Self::MigrationBundle => "it is a multi-account export, not one secret",
            Self::Type => "it is a counter-based profile, not a time-based one",
            Self::Authority => "the link is malformed",
            Self::Label => "the label is not readable text",
            Self::DuplicateParameter => "a setting is given more than once",
            Self::SecretMissing => "it carries no secret",
            Self::SecretAlphabet => "the secret is not base32",
            Self::SecretTooShort => "the secret is too short",
            Self::Digits => "the digit count is not one that can be used",
            Self::Period => "the period is not one that can be used",
            Self::Algorithm => "the hash is not one that can be used",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The enum is wrapped into the launcher's top-level error and carried across task boundaries,
    /// so it has to stay `Send + Sync + 'static`. Nothing else pins it: a boxed platform error
    /// smuggled into a future variant would otherwise be caught at the first caller rather than here.
    const _: fn() = || {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<OtpError>();
    };

    /// Freeze the taxonomy: every variant as a pattern, a value built from it, and the line it
    /// renders as. The match is exhaustive with no wildcard, so a new variant stops this compiling
    /// until it gains an entry, and an entry is a pattern *and* a sample *and* an expected string.
    #[test]
    fn every_error_renders_as_recorded() {
        #[allow(dead_code)]
        fn every_variant_has_an_entry(value: &OtpError) {
            match value {
                OtpError::Import { .. } => (),
                OtpError::NoSecret => (),
                OtpError::Stored { .. } => (),
                OtpError::Secrets(_) => (),
                OtpError::Clock => (),
                OtpError::Interrupted => (),
                OtpError::ListenerBind { .. } => (),
                OtpError::Timeout => (),
            }
        }

        let cases: Vec<(OtpError, &str)> = vec![
            (
                OtpError::Import {
                    reason: Rejected::SecretAlphabet,
                },
                "the offered one-time-password secret is not usable: the secret is not base32",
            ),
            (
                OtpError::NoSecret,
                "no one-time-password secret is stored for this account",
            ),
            (
                OtpError::Stored {
                    reason: Rejected::Period,
                },
                "the stored one-time-password secret is not usable: the period is not one that can \
                 be used",
            ),
            (
                OtpError::Secrets(apogee_secrets::SecretsError::Locked),
                "secret store: the secret store is locked",
            ),
            (
                OtpError::Clock,
                "the clock is outside the range a code can be generated for",
            ),
            (
                OtpError::Interrupted,
                "the task generating the code was dropped",
            ),
            (
                OtpError::ListenerBind { port: 4646 },
                "failed to bind the one-time-password listener on port 4646",
            ),
            (OtpError::Timeout, "timed out waiting for a code"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    /// Every reason renders, and none of them is empty. The set is what a shell turns into a
    /// sentence, so a variant added without a phrase would print nothing at all.
    #[test]
    fn every_reason_renders_a_phrase() {
        #[allow(dead_code)]
        fn every_variant_has_an_entry(value: Rejected) {
            match value {
                Rejected::TooLong => (),
                Rejected::Empty => (),
                Rejected::Scheme => (),
                Rejected::MigrationBundle => (),
                Rejected::Type => (),
                Rejected::Authority => (),
                Rejected::Label => (),
                Rejected::DuplicateParameter => (),
                Rejected::SecretMissing => (),
                Rejected::SecretAlphabet => (),
                Rejected::SecretTooShort => (),
                Rejected::Digits => (),
                Rejected::Period => (),
                Rejected::Algorithm => (),
            }
        }

        for reason in [
            Rejected::TooLong,
            Rejected::Empty,
            Rejected::Scheme,
            Rejected::MigrationBundle,
            Rejected::Type,
            Rejected::Authority,
            Rejected::Label,
            Rejected::DuplicateParameter,
            Rejected::SecretMissing,
            Rejected::SecretAlphabet,
            Rejected::SecretTooShort,
            Rejected::Digits,
            Rejected::Period,
            Rejected::Algorithm,
        ] {
            assert!(!reason.to_string().is_empty(), "{reason:?}");
        }
    }

    /// The rendered strings are the whole public surface of these errors, so none of them may echo a
    /// value a caller passed in. A regression here is a leak, not a wording change.
    ///
    /// Driven through the parser rather than over a hand-built variant, so what it covers is the
    /// route a real secret takes: the text goes in, a reason comes back, and the reason is a closed
    /// enum this crate owns with nowhere in it for a fragment of the input to sit.
    #[test]
    fn no_error_renders_a_caller_supplied_value() {
        const OFFERED: &str = "otpauth://totp/JBSWY3DPEHPK3PXP?secret=JBSWY3DPEHPK3PXP";

        let rendered = crate::TotpParams::parse(OFFERED)
            .expect_err("a ten-byte key is under the floor and has to be refused")
            .to_string();
        assert!(!rendered.contains("JBSWY3DP"), "{rendered}");
    }
}
