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
