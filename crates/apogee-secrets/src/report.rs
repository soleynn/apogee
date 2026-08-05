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
}

/// What condition the store is in. Each variant is a distinct thing for a caller to do about it.
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
        BackendReport {
            backend: Backend::SecretService,
            state,
            sandbox: None,
        }
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
