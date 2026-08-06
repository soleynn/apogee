//! The secret-backend error taxonomy.

use thiserror::Error;

/// Secret-backend failures.
///
/// Each variant is a condition a caller answers differently: [`Locked`](Self::Locked) can still
/// succeed once the user unlocks, [`NoBackend`](Self::NoBackend) never will, and
/// [`Denied`](Self::Denied) needs the sandbox or platform rules changed.
///
/// No variant carries the underlying platform error. The credential-store error types interpolate
/// entry attributes and, in one case, the raw secret bytes into their own `Debug`/`Display`, and
/// this enum is wrapped by the launcher's top-level error, so any of it printed anywhere would be
/// the leak the crate exists to prevent. The backend error is matched and dropped.
#[derive(Debug, Error)]
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
    #[error("io error")]
    Io(#[from] std::io::Error),
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

    /// Freeze the taxonomy: every variant as a pattern, a value built from it, and the line it
    /// renders as. The match is exhaustive with no wildcard, so a new variant stops this compiling
    /// until it gains an entry, and an entry is a pattern *and* a sample *and* an expected string.
    #[test]
    fn every_error_renders_as_recorded() {
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

        let cases: Vec<(SecretsError, &str)> = vec![
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
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    /// The rendered strings are the whole public surface of these errors, so none of them may echo
    /// a value a caller passed in. A regression here is a leak, not a wording change.
    #[test]
    fn no_error_renders_a_caller_supplied_value() {
        let rendered = SecretsError::Io(std::io::Error::other("hunter2")).to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }
}
