//! What a probe of the credential store found.
//!
//! Codes, not prose. The shell composes the sentence and the fix from these; a library that shipped
//! the advice string would be shipping untranslatable UI text below the layer that owns it.

/// Which store answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Backend {
    /// The freedesktop Secret Service: GNOME Keyring, KWallet, KeePassXC.
    SecretService,
    /// The Windows Credential Manager.
    WindowsCredentialManager,
    /// The macOS or iOS Keychain.
    AppleKeychain,
    /// The opt-in encrypted-file store.
    EncryptedFile,
    /// The store that keeps nothing.
    Null,
    /// The in-memory double, which nothing shipping constructs.
    ///
    /// It has a name of its own so that no real store's report can be confused with a test's. The
    /// double used to answer [`Backend::Null`] while holding items and handing them back, which is a
    /// combination the real [`crate::Null`] cannot produce, so a consumer's test could assert
    /// behaviour no store has.
    Memory,
}

/// What condition the store is in.
///
/// Each variant is a distinct thing for a caller to do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendState {
    /// Reachable and unlocked. Reads and writes will not prompt.
    Ready,
    /// Reachable but locked. The next read or write raises the platform's unlock prompt.
    Locked,
    /// Reachable, with no collection to store into. A keyring that has never been initialized does
    /// this.
    NoDefaultCollection,
    /// No session bus to reach at all: a TTY login, an SSH session, a bare game-mode session.
    NoSessionBus,
    /// A session bus, but nothing owns the credential-store name on it. Either nothing is
    /// installed, or a sandbox is hiding it; [`BackendReport::sandbox`] is what tells those apart.
    NoProvider,
    /// The sandbox's bus policy refused the name outright.
    SandboxDenied,
    /// The store keeps nothing, by the user's choice. Reads answer nothing and writes are refused.
    /// Nothing here is broken and there is nothing to fix: refusing is what this store is for, so a
    /// caller answers it by asking for the secret every time instead.
    NotStoring,
    /// The store failed in a way this crate does not classify.
    Unreachable,
}

/// The sandbox the process is running inside, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sandbox {
    /// A Flatpak sandbox.
    Flatpak {
        /// The application id the sandbox reports, when it reports one.
        app_id: Option<String>,
        /// Whether the sandbox's own bus policy withholds calls to the credential-store name. This
        /// is the only signal that separates a sandbox permission problem from a machine with no
        /// keyring installed: from inside the sandbox the two look identical on the bus.
        bus_filtered: bool,
    },
    /// A container. Says nothing about the bus on its own.
    Container,
}

/// What a [`SecretStore::probe`](crate::SecretStore::probe) found.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BackendReport {
    /// Which store this is.
    pub backend: Backend,
    /// The condition it is in.
    pub state: BackendState,
    /// The sandbox the process is inside, if it is inside one.
    pub sandbox: Option<Sandbox>,
}

impl BackendReport {
    /// Report `backend` in `state`, reached from outside any sandbox.
    ///
    /// The struct is `#[non_exhaustive]`, so this is the only way to build one from another crate,
    /// and without it [`SecretStore`](crate::SecretStore) could not be implemented outside this one
    /// at all: every method but the probe can be written by anybody, and the probe has to return a
    /// value only this module could make. The one implementation in this workspace that lives
    /// elsewhere had to hold a backend of this crate's and forward to its probe, which is a
    /// workaround for the gap rather than a use of the seam.
    ///
    /// Sandbox detection is left out rather than defaulted to a guess: this crate reads
    /// `/.flatpak-info` for its own backends, and a store somebody else wrote knows its own answer
    /// or has none. [`BackendReport::in_sandbox`] is how it says so.
    ///
    /// # Examples
    /// ```
    /// use apogee_secrets::{Backend, BackendReport, BackendState};
    ///
    /// let report = BackendReport::new(Backend::Null, BackendState::NotStoring);
    /// assert!(!report.is_usable());
    /// assert!(report.sandbox.is_none());
    /// ```
    #[must_use]
    pub fn new(backend: Backend, state: BackendState) -> Self {
        Self {
            backend,
            state,
            sandbox: None,
        }
    }

    /// The same report, taken from inside `sandbox`.
    ///
    /// # Examples
    /// ```
    /// use apogee_secrets::{Backend, BackendReport, BackendState, Sandbox};
    ///
    /// let report = BackendReport::new(Backend::SecretService, BackendState::SandboxDenied)
    ///     .in_sandbox(Sandbox::Flatpak {
    ///         app_id: Some("dev.apogee.Launcher".to_owned()),
    ///         bus_filtered: true,
    ///     });
    /// assert!(report.sandbox.is_some());
    /// ```
    #[must_use]
    pub fn in_sandbox(mut self, sandbox: Sandbox) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    /// Whether the store is locked.
    #[must_use]
    pub fn locked(&self) -> bool {
        matches!(self.state, BackendState::Locked)
    }

    /// Whether storing is possible at all, prompt or no prompt.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self.state, BackendState::Ready | BackendState::Locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(state: BackendState) -> BackendReport {
        BackendReport::new(Backend::SecretService, state)
    }

    /// The constructor is the only way another crate can answer
    /// [`SecretStore::probe`](crate::SecretStore::probe), so what it leaves out matters as much as
    /// what it takes: a report that arrived carrying a sandbox nobody named would be this crate's
    /// guess standing in for a caller's fact.
    #[test]
    fn a_built_report_carries_what_it_was_given_and_nothing_else() {
        let plain = BackendReport::new(Backend::WindowsCredentialManager, BackendState::Ready);
        assert_eq!(plain.backend, Backend::WindowsCredentialManager);
        assert_eq!(plain.state, BackendState::Ready);
        assert!(plain.sandbox.is_none());

        let sandboxed = BackendReport::new(Backend::SecretService, BackendState::SandboxDenied)
            .in_sandbox(Sandbox::Container);
        assert_eq!(sandboxed.sandbox, Some(Sandbox::Container));
        assert_eq!(sandboxed.state, BackendState::SandboxDenied);
    }

    /// Both accessors are answered for every state, so a state added later cannot silently inherit
    /// "not locked, not usable" from a `matches!` nobody revisited.
    #[test]
    fn every_state_answers_both_questions() {
        let expected = [
            (BackendState::Ready, false, true),
            (BackendState::Locked, true, true),
            (BackendState::NoDefaultCollection, false, false),
            (BackendState::NoSessionBus, false, false),
            (BackendState::NoProvider, false, false),
            (BackendState::SandboxDenied, false, false),
            (BackendState::NotStoring, false, false),
            (BackendState::Unreachable, false, false),
        ];
        for (state, locked, usable) in expected {
            let report = report(state);
            assert_eq!(report.locked(), locked, "{state:?}");
            assert_eq!(report.is_usable(), usable, "{state:?}");
        }
    }

    /// A locked store is still a store worth writing to: the write raises the unlock prompt and
    /// then succeeds. Treating it as unusable would push a caller to the fallback for no reason.
    #[test]
    fn a_locked_store_is_still_usable() {
        assert!(report(BackendState::Locked).is_usable());
    }
}
