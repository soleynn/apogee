//! The secret-backend error taxonomy.

use std::fmt;

use thiserror::Error;

/// Secret-backend failures.
///
/// Each variant is a condition a caller answers differently: [`Locked`](Self::Locked) can still
/// succeed once the user unlocks, [`NoBackend`](Self::NoBackend) never will, and
/// [`Denied`](Self::Denied) needs the sandbox or platform rules changed.
///
/// Nothing a variant carries that could identify a caller's data is rendered. [`Corrupt`](Self::Corrupt)
/// and [`Backend`](Self::Backend) do interpolate their `detail`/`step` fields, but both are drawn from
/// a fixed set of `&'static str`s this crate owns, never a value a caller passed in. The
/// credential-store error types this crate talks to interpolate entry attributes and, in one case, the
/// raw secret bytes into their own `Debug`/`Display`, and this enum is wrapped by the launcher's
/// top-level error, so any of that printed anywhere would be the leak the crate exists to prevent.
/// Those errors are matched and dropped rather than carried.
///
/// [`Io`](Self::Io) is the one variant that keeps a foreign error, because a caller answers a
/// missing file differently from a full disk and only the [`ErrorKind`](std::io::ErrorKind) says
/// which. It is fenced rather than dropped, on all three surfaces an error is read through:
/// `Display` renders a fixed line, the hand-written `Debug` below prints the kind alone, and no
/// variant offers a `source()`. Reaching the payload takes a match on the variant, which is a
/// deliberate read rather than a log line.
#[derive(Error)]
#[non_exhaustive]
pub enum SecretsError {
    /// The store answered, but the collection or item is locked and the unlock prompt was not
    /// completed.
    #[error("the secret store is locked")]
    Locked,
    /// No store answered: no session bus, nothing owning the credential-store name on it, or a
    /// sandbox that hides the name.
    #[error("no secret backend is available")]
    NoBackend,
    /// The store was reachable and refused. A sandbox bus policy, or a platform access rule.
    #[error("the secret backend denied access")]
    Denied,
    /// The store answered, but it holds no collection to store into and cannot make one. A keyring
    /// that has never been initialized, which is what a passwordless or autologin session leaves
    /// behind. Distinct from [`Locked`](Self::Locked): there is nothing to unlock, so waiting for
    /// the user to type a password never resolves it.
    #[error("the secret backend has no collection to store into")]
    NoCollection,
    /// More than one stored item matches this account and kind, so a read has no single answer.
    /// Reachable whenever another program has written a matching item.
    #[error("more than one stored secret matches this account and kind")]
    Ambiguous,
    /// The passphrase did not open the encrypted store.
    ///
    /// Distinct from [`Locked`](Self::Locked), which is a store nobody has tried to unlock yet: this
    /// is an attempt that was made and failed, and it is answered by typing it again rather than by
    /// going off to unlock something. Also what a store reports when its salt or its work parameters
    /// have been edited, because a key derived from edited parameters is a wrong key and no check can
    /// tell the two apart.
    #[error("the passphrase did not open the secret store")]
    WrongPassphrase,
    /// The stored secrets are damaged, or were written by a build this one cannot read.
    ///
    /// Separate from [`Backend`](Self::Backend) because it is neither transient nor retryable: the
    /// file on disk will not start opening. A caller answers it by restoring a copy or by starting
    /// over, and starting over destroys secrets, so it must never be offered for a store that merely
    /// failed once.
    #[error("the stored secrets are unreadable: {detail}")]
    Corrupt {
        /// Which part of the file did not hold up, for triage. One of a fixed set this crate owns,
        /// never a value a caller passed in.
        detail: &'static str,
    },
    /// The store keeps nothing by the user's choice, so the write was refused. Distinct from
    /// [`Denied`](Self::Denied), which is a sandbox or platform rule the user did not set and would
    /// send them off to change a permission: this one is answered by asking for the secret again
    /// next time.
    #[error("the secret store keeps nothing")]
    NotStoring,
    /// The value handed in held no bytes, so there was nothing to store.
    ///
    /// Refused rather than written, for the same reason [`NotStoring`](Self::NotStoring) is: a
    /// caller that believed it had saved a password stops asking for one. An empty value stores and
    /// reads back perfectly well, so nothing downstream notices until the login itself fails at the
    /// far end with an error that says nothing about the store.
    #[error("the value to store held no bytes")]
    Empty,
    /// The store failed for a reason outside the classified set. `step` names what was being done.
    #[error("the secret backend failed to {step}")]
    Backend {
        /// What the store was being asked to do, for triage.
        step: &'static str,
    },
    /// A local filesystem or process failure below the store.
    ///
    /// The conversion is written out below rather than derived: a `#[from]` field is also a
    /// `#[source]` field, and a source edge hands the payload to every reporter that walks a chain.
    #[error("io error")]
    Io(std::io::Error),
}

impl From<std::io::Error> for SecretsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// The variant and the fields this crate owns, never a payload from outside it.
///
/// Hand-written for [`SecretsError::Io`], whose derived form prints the inner error: for one built
/// by [`std::io::Error::other`] that is whatever string was handed in, and for one from the standard
/// library it is an errno and a C library message. The kind is what a caller triages on and it is a
/// closed set, so it is the only part kept.
///
/// Exhaustive with no wildcard, so a variant added later has to say here what it shows.
impl fmt::Debug for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("Locked"),
            Self::NoBackend => f.write_str("NoBackend"),
            Self::Denied => f.write_str("Denied"),
            Self::NoCollection => f.write_str("NoCollection"),
            Self::Ambiguous => f.write_str("Ambiguous"),
            Self::WrongPassphrase => f.write_str("WrongPassphrase"),
            Self::Corrupt { detail } => f.debug_struct("Corrupt").field("detail", detail).finish(),
            Self::NotStoring => f.write_str("NotStoring"),
            Self::Empty => f.write_str("Empty"),
            Self::Backend { step } => f.debug_struct("Backend").field("step", step).finish(),
            Self::Io(err) => f.debug_tuple("Io").field(&err.kind()).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The enum is wrapped into the launcher's top-level error and carried across task boundaries,
    /// so it has to stay `Send + Sync + 'static`. Nothing else pins it: a boxed platform error smuggled
    /// into a future variant would otherwise be caught at the first caller rather than here.
    const _: fn() = || {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<SecretsError>();
    };

    /// Every variant as a pattern, a value built from it, and the line it renders as. The match is
    /// exhaustive with no wildcard, so a new variant stops this compiling until it gains an entry,
    /// and an entry is a pattern *and* a sample *and* an expected string.
    ///
    /// Shared by the two tests below so a new variant reaches both: the freeze checks what it says,
    /// the leak guard checks what else it exposes.
    fn every_variant() -> Vec<(SecretsError, &'static str)> {
        #[allow(dead_code)]
        fn every_variant_has_an_entry(value: &SecretsError) {
            match value {
                SecretsError::Locked => (),
                SecretsError::NoBackend => (),
                SecretsError::Denied => (),
                SecretsError::NoCollection => (),
                SecretsError::Ambiguous => (),
                SecretsError::WrongPassphrase => (),
                SecretsError::Corrupt { .. } => (),
                SecretsError::NotStoring => (),
                SecretsError::Empty => (),
                SecretsError::Backend { .. } => (),
                SecretsError::Io(_) => (),
            }
        }

        vec![
            (SecretsError::Locked, "the secret store is locked"),
            (SecretsError::NoBackend, "no secret backend is available"),
            (SecretsError::Denied, "the secret backend denied access"),
            (
                SecretsError::NoCollection,
                "the secret backend has no collection to store into",
            ),
            (
                SecretsError::Ambiguous,
                "more than one stored secret matches this account and kind",
            ),
            (
                SecretsError::WrongPassphrase,
                "the passphrase did not open the secret store",
            ),
            (
                SecretsError::Corrupt {
                    detail: "file magic",
                },
                "the stored secrets are unreadable: file magic",
            ),
            (SecretsError::NotStoring, "the secret store keeps nothing"),
            (SecretsError::Empty, "the value to store held no bytes"),
            (
                SecretsError::Backend { step: "read" },
                "the secret backend failed to read",
            ),
            (SecretsError::Io(std::io::Error::other("disk")), "io error"),
        ]
    }

    /// Freeze what each variant says.
    #[test]
    fn every_error_renders_as_recorded() {
        for (err, expected) in every_variant() {
            assert_eq!(err.to_string(), expected);
        }
    }

    /// An error is read through three surfaces, so a value hidden from one of them is not hidden. A
    /// caller that writes `{err:?}` in a log line gets `Debug`, and anything that walks a chain, the
    /// launcher's own reporting included, gets `source()`. Only [`SecretsError::Io`] holds an error
    /// from outside this crate, so it is the one poisoned here.
    ///
    /// The `source()` half runs over every variant rather than that one: the edge a chain walker
    /// follows is opened by an attribute, so the variant that opens it next is by definition not
    /// this one. Deleting either the hand-written `Debug` or the hand-written `From` turns this red.
    ///
    /// A regression here is a leak, not a wording change.
    #[test]
    fn no_error_exposes_a_caller_supplied_value() {
        const PAYLOAD: &str = "hunter2";

        let poisoned = SecretsError::Io(std::io::Error::other(PAYLOAD));
        let display = poisoned.to_string();
        let debug = format!("{poisoned:?}");
        assert!(!display.contains(PAYLOAD), "Display: {display}");
        assert!(!debug.contains(PAYLOAD), "Debug: {debug}");

        for (err, _) in every_variant() {
            assert!(
                std::error::Error::source(&err).is_none(),
                "{err:?} offers a source to walk"
            );
        }
        assert!(
            std::error::Error::source(&poisoned).is_none(),
            "{debug} offers a source to walk"
        );
    }
}
