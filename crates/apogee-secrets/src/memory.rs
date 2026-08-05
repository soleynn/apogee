//! An in-memory store, for tests that need one without a bus.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use uuid::Uuid;

use crate::{Backend, BackendReport, BackendState, Secret, SecretKind, SecretStore, SecretsError};

/// One call the store received.
///
/// It records what was asked and of what, never the value. A [`Secret`] field would make this enum
/// underivable, which is the seal doing its job rather than an inconvenience: a test that wants to
/// check a stored value asks [`MemoryStore::stored`] for it, and that call is as feature-gated as
/// the rest of this module.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Call {
    /// A read of one account's kind.
    Get(Uuid, SecretKind),
    /// A write of one account's kind.
    Set(Uuid, SecretKind),
    /// A delete of one account's kind.
    Delete(Uuid, SecretKind),
    /// A report of the store's condition.
    Probe,
}

/// Which calls a scripted store fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailAt {
    /// Every fallible call.
    Everything,
    /// Reads only.
    Get,
    /// Writes only.
    Set,
    /// Deletes of one kind, leaving the others working. This is the shape that catches a sweep
    /// which gives up after its first failure.
    Delete(SecretKind),
}

impl FailAt {
    fn matches(self, call: &Call) -> bool {
        match (self, call) {
            (Self::Everything, _) => true,
            (Self::Get, Call::Get(..)) | (Self::Set, Call::Set(..)) => true,
            (Self::Delete(kind), Call::Delete(_, other)) => kind == *other,
            _ => false,
        }
    }
}

/// A [`SecretStore`] that keeps its items in this process: no bus, no prompt, no unlock, nothing on
/// disk.
///
/// Behind the `mock` feature because a shipping build must not carry a store that holds secrets in
/// process memory and hands them back verbatim. That feature is separate from `testing` on purpose:
/// `testing` gates tests that drive whatever keyring is really on the bus, and a crate that
/// dev-depended on it to reach this double would pull those into every workspace test run.
///
/// It records what it was asked and can be scripted to fail, so a test can assert the *sequence* a
/// caller performed rather than only the state it left behind. Those are different properties: a
/// sweep that stops early and a sweep that never ran leave the same empty store.
#[derive(Debug)]
pub struct MemoryStore {
    items: Mutex<BTreeMap<(Uuid, &'static str), Vec<u8>>>,
    calls: Mutex<Vec<Call>>,
    state: BackendState,
    fail: Option<FailAt>,
    /// Built fresh per failure rather than stored: [`SecretsError`] is deliberately not `Clone`, and
    /// which condition a store reports is exactly what a caller branches on.
    error: fn() -> SecretsError,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// An empty store that reports itself ready and fails nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Mutex::new(BTreeMap::new()),
            calls: Mutex::new(Vec::new()),
            state: BackendState::Ready,
            fail: None,
            error: || SecretsError::Backend { step: "pretend" },
        }
    }

    /// Report `state` from [`SecretStore::probe`] instead of `Ready`.
    #[must_use]
    pub fn in_state(mut self, state: BackendState) -> Self {
        self.state = state;
        self
    }

    /// Fail the calls `fail` selects, leaving the rest working.
    #[must_use]
    pub fn failing(mut self, fail: FailAt) -> Self {
        self.fail = Some(fail);
        self
    }

    /// Fail the calls `fail` selects with the condition `error` builds.
    ///
    /// Which condition matters: a caller deciding whether a store may still be holding a secret
    /// branches on the variant, so a mock that always reported the same one could not exercise both
    /// sides of that decision.
    #[must_use]
    pub fn failing_with(mut self, fail: FailAt, error: fn() -> SecretsError) -> Self {
        self.fail = Some(fail);
        self.error = error;
        self
    }

    /// What the store was asked, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.locked(&self.calls).clone()
    }

    /// The bytes held for `account` and `kind`, for a test that must assert the value that was
    /// written rather than only that a write happened.
    #[must_use]
    pub fn stored(&self, account: Uuid, kind: SecretKind) -> Option<Vec<u8>> {
        self.locked(&self.items)
            .get(&(account, kind.slug()))
            .cloned()
    }

    /// How many items the store holds, across every account.
    #[must_use]
    pub fn len(&self) -> usize {
        self.locked(&self.items).len()
    }

    /// Whether the store holds nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A poisoned lock is another test's panic, not a condition this store models, so the data is
    /// taken back rather than turned into a second panic that would bury the first.
    fn locked<'a, T>(&self, lock: &'a Mutex<T>) -> std::sync::MutexGuard<'a, T> {
        lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record `call`, and answer whether it was scripted to fail.
    fn record(&self, call: Call) -> Result<(), SecretsError> {
        let failed = self.fail.is_some_and(|fail| fail.matches(&call));
        self.locked(&self.calls).push(call);
        if failed {
            return Err((self.error)());
        }
        Ok(())
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, account: Uuid, kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        self.record(Call::Get(account, kind))?;
        Ok(self
            .locked(&self.items)
            .get(&(account, kind.slug()))
            .map(|bytes| Secret::new(bytes.clone())))
    }

    fn set(&self, account: Uuid, kind: SecretKind, value: Secret) -> Result<(), SecretsError> {
        self.record(Call::Set(account, kind))?;
        self.locked(&self.items)
            .insert((account, kind.slug()), value.expose().to_vec());
        Ok(())
    }

    fn delete(&self, account: Uuid, kind: SecretKind) -> Result<(), SecretsError> {
        self.record(Call::Delete(account, kind))?;
        self.locked(&self.items).remove(&(account, kind.slug()));
        Ok(())
    }

    fn probe(&self) -> BackendReport {
        self.locked(&self.calls).push(Call::Probe);
        BackendReport {
            backend: Backend::Null,
            state: self.state,
            sandbox: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);
    const OTHER: Uuid = Uuid::from_u128(2);

    #[test]
    fn a_written_secret_reads_back_and_a_missing_one_is_absent() {
        let store = MemoryStore::new();
        store
            .set(ACCOUNT, SecretKind::Password, Secret::new(b"pw".to_vec()))
            .expect("write");
        let read = store.get(ACCOUNT, SecretKind::Password).expect("read");
        assert_eq!(read.expect("present").expose(), b"pw");
        assert!(
            store
                .get(ACCOUNT, SecretKind::TotpSecret)
                .expect("read")
                .is_none()
        );
    }

    /// The keys are per account *and* per kind, which is the property a caller sweeping one account
    /// depends on: another account's secrets must survive.
    #[test]
    fn a_sweep_takes_one_account_and_leaves_the_others() {
        let store = MemoryStore::new();
        for kind in SecretKind::ALL {
            store
                .set(ACCOUNT, kind, Secret::new(b"a".to_vec()))
                .expect("write");
            store
                .set(OTHER, kind, Secret::new(b"b".to_vec()))
                .expect("write");
        }
        store.forget_account(ACCOUNT).expect("sweep");
        assert_eq!(store.len(), 2);
        for kind in SecretKind::ALL {
            assert!(store.stored(ACCOUNT, kind).is_none());
            assert!(store.stored(OTHER, kind).is_some());
        }
    }

    /// The reason the recorder exists. A sweep that gave up after the password would leave the TOTP
    /// secret behind, and the resulting store looks the same as a clean one from the outside: only
    /// the call sequence tells them apart.
    #[test]
    fn a_failed_delete_does_not_stop_the_sweep() {
        let store = MemoryStore::new().failing(FailAt::Delete(SecretKind::Password));
        let err = store.forget_account(ACCOUNT);
        assert!(err.is_err());
        assert_eq!(
            store.calls(),
            vec![
                Call::Delete(ACCOUNT, SecretKind::Password),
                Call::Delete(ACCOUNT, SecretKind::TotpSecret),
            ]
        );
    }

    #[test]
    fn a_scripted_state_is_what_the_report_says() {
        let store = MemoryStore::new().in_state(BackendState::Locked);
        assert!(store.probe().locked());
        assert_eq!(store.calls(), vec![Call::Probe]);
    }
}
