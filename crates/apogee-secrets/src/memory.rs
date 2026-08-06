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
///
/// Every verb selects by kind, not just [`FailAt::Delete`]. Reads and writes used to fail for every
/// kind at once, which left the two states a real store reaches most often unscriptable: an account
/// half written, where the password stored and the one-time secret was refused, and a read where one
/// kind comes back and the other does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailAt {
    /// Every fallible call.
    Everything,
    /// Reads, of one kind or of all of them.
    Get(Option<SecretKind>),
    /// Writes, of one kind or of all of them.
    Set(Option<SecretKind>),
    /// Deletes, of one kind or of all of them. Naming one kind is the shape that catches a sweep
    /// which gives up after its first failure.
    Delete(Option<SecretKind>),
}

impl FailAt {
    fn matches(self, call: &Call) -> bool {
        let selected = |chosen: Option<SecretKind>, actual: &SecretKind| {
            chosen.is_none_or(|kind| kind == *actual)
        };
        match (self, call) {
            (Self::Everything, _) => true,
            (Self::Get(kind), Call::Get(_, actual))
            | (Self::Set(kind), Call::Set(_, actual))
            | (Self::Delete(kind), Call::Delete(_, actual)) => selected(kind, actual),
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
pub struct MemoryStore {
    items: Mutex<BTreeMap<(Uuid, &'static str), Vec<u8>>>,
    calls: Mutex<Vec<Call>>,
    backend: Backend,
    state: BackendState,
    fail: Mutex<Option<FailAt>>,
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
            backend: Backend::Memory,
            state: BackendState::Ready,
            fail: Mutex::new(None),
            error: || SecretsError::Backend { step: "pretend" },
        }
    }

    /// Report `state` from [`SecretStore::probe`], and behave like a store in it.
    ///
    /// The state is not decoration. A real store in any state but `Ready` refuses a write, so a
    /// double that moved only its report while going on accepting writes taught a consumer's test
    /// that a locked keyring stores secrets. Every call but the report now answers the condition
    /// that state implies, and a case that wants a store which reports one thing and does another
    /// says so with [`MemoryStore::failing_with`].
    #[must_use]
    pub fn in_state(mut self, state: BackendState) -> Self {
        self.state = state;
        self
    }

    /// Report `backend` instead of [`Backend::Memory`], for a test that has to stand in for a
    /// named platform store.
    #[must_use]
    pub fn as_backend(mut self, backend: Backend) -> Self {
        self.backend = backend;
        self
    }

    /// Fail the calls `fail` selects, leaving the rest working.
    #[must_use]
    pub fn failing(self, fail: FailAt) -> Self {
        self.now_failing(Some(fail));
        self
    }

    /// Fail the calls `fail` selects with the condition `error` builds.
    ///
    /// Which condition matters: a caller deciding whether a store may still be holding a secret
    /// branches on the variant, so a mock that always reported the same one could not exercise both
    /// sides of that decision.
    #[must_use]
    pub fn failing_with(mut self, fail: FailAt, error: fn() -> SecretsError) -> Self {
        self.error = error;
        self.now_failing(Some(fail));
        self
    }

    /// Change what fails, or stop failing, on a store a caller is already holding.
    ///
    /// The builders take `self` by value, and a consumer holds the double behind an `Arc`, so a
    /// scripted failure could be set up and never lifted. That left the defining property of
    /// [`SecretsError::Locked`] and [`SecretsError::WrongPassphrase`] with no double at all: both
    /// mean *this retry fails and the one after the unlock succeeds*, and a store that can only fail
    /// forever cannot express the second half.
    pub fn now_failing(&self, fail: Option<FailAt>) {
        *self.locked(&self.fail) = fail;
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

    /// Record `call`, and answer whether the store is in any condition to serve it.
    ///
    /// The scripted state is consulted before the scripted failure, because it is the coarser fact:
    /// a store that is locked or has nothing to store into refuses everything, and only a store that
    /// would otherwise have worked needs a per-call script.
    fn record(&self, call: Call) -> Result<(), SecretsError> {
        let refused = refusal_for(self.state);
        let failed = self
            .locked(&self.fail)
            .is_some_and(|fail| fail.matches(&call));
        self.locked(&self.calls).push(call);
        if let Some(refused) = refused {
            return Err(refused);
        }
        if failed {
            return Err((self.error)());
        }
        Ok(())
    }
}

/// What a store in `state` answers to a call that is not a report, or `None` if it serves it.
///
/// One arm per state, with no wildcard, so a state added later stops this compiling until somebody
/// decides what a store in it does rather than defaulting it to working.
fn refusal_for(state: BackendState) -> Option<SecretsError> {
    match state {
        BackendState::Ready => None,
        BackendState::Locked => Some(SecretsError::Locked),
        BackendState::NoDefaultCollection => Some(SecretsError::NoCollection),
        BackendState::NoSessionBus | BackendState::NoProvider => Some(SecretsError::NoBackend),
        BackendState::SandboxDenied => Some(SecretsError::Denied),
        BackendState::NotStoring => Some(SecretsError::NotStoring),
        BackendState::Unreachable => Some(SecretsError::Backend {
            step: "reach the secret store",
        }),
    }
}

/// Written out rather than derived: a derive prints `items` as the raw byte arrays it holds, which
/// is every stored secret, and one `dbg!` or one assertion message in a consumer's test puts them in
/// a CI log where grepping for the plaintext would not find them.
impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held: Vec<String> = self
            .locked(&self.items)
            .iter()
            .map(|((account, slug), value)| format!("{account}/{slug} ({} bytes)", value.len()))
            .collect();
        f.debug_struct("MemoryStore")
            .field("items", &held)
            .field("calls", &*self.locked(&self.calls))
            .field("backend", &self.backend)
            .field("state", &self.state)
            .field("fail", &*self.locked(&self.fail))
            .finish()
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
        // Before the call is recorded: a value with no bytes never reached a real store either, so a
        // double that logged the attempt would let a consumer assert a write that cannot happen.
        crate::store::refuse_empty(&value)?;
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
            backend: self.backend,
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
        let store = MemoryStore::new().failing(FailAt::Delete(Some(SecretKind::Password)));
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

    /// The double refuses an empty value the way every real backend does, and does not record the
    /// attempt: a write that no store could have taken must not read back as one that happened.
    #[test]
    fn the_double_refuses_a_value_with_no_bytes_in_it() {
        let store = MemoryStore::new();
        assert!(matches!(
            store.set(ACCOUNT, SecretKind::Password, Secret::new(Vec::new())),
            Err(SecretsError::Empty)
        ));
        assert!(store.is_empty());
        assert!(store.calls().is_empty());
    }

    /// The double must not print what it holds. A derive renders `items` as raw byte arrays, so one
    /// `dbg!` or one assertion message in a consumer's test puts every stored secret in a CI log,
    /// and it would not be found by grepping for the plaintext.
    #[test]
    fn the_double_prints_what_it_holds_without_printing_the_values() {
        let store = MemoryStore::new();
        store
            .set(
                ACCOUNT,
                SecretKind::Password,
                Secret::new(b"hunter2".to_vec()),
            )
            .expect("write");

        let rendered = format!("{store:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        // The byte array a derive would have produced, which a plaintext grep would miss.
        assert!(!rendered.contains("104, 117, 110"), "{rendered}");
        assert!(rendered.contains("password"), "{rendered}");
        assert!(rendered.contains("7 bytes"), "{rendered}");
    }

    /// The report has to be one a real store could produce. The double answered `Null` while holding
    /// items and handing them back, and the real `Null` refuses every write, so a consumer could
    /// assert behaviour no store has.
    #[test]
    fn the_double_reports_a_backend_no_real_store_claims() {
        assert_eq!(MemoryStore::new().probe().backend, Backend::Memory);
        assert_eq!(
            MemoryStore::new()
                .as_backend(Backend::SecretService)
                .probe()
                .backend,
            Backend::SecretService
        );
    }

    /// A scripted state has to reach the calls, not just the report. A store that reported itself
    /// locked and went on taking writes taught a consumer's test that a locked keyring saves
    /// secrets.
    #[test]
    fn a_store_that_is_not_ready_refuses_the_calls_too() {
        let cases = [
            (BackendState::Locked, SecretsError::Locked),
            (
                BackendState::NoDefaultCollection,
                SecretsError::NoCollection,
            ),
            (BackendState::NotStoring, SecretsError::NotStoring),
            (BackendState::SandboxDenied, SecretsError::Denied),
            (BackendState::NoProvider, SecretsError::NoBackend),
        ];
        for (state, expected) in cases {
            let store = MemoryStore::new().in_state(state);
            let err = store
                .set(ACCOUNT, SecretKind::Password, Secret::new(b"pw".to_vec()))
                .expect_err("a store in this state refuses a write");
            assert_eq!(
                std::mem::discriminant(&err),
                std::mem::discriminant(&expected),
                "{state:?}"
            );
            assert!(store.is_empty(), "{state:?} took the write anyway");
            assert!(
                store.get(ACCOUNT, SecretKind::Password).is_err(),
                "{state:?}"
            );
        }
    }

    /// Every verb selects by kind. Without it the half-written account, which is the state a caller
    /// most needs to handle, could not be set up at all.
    #[test]
    fn a_failure_can_name_one_kind_on_every_verb() {
        let store = MemoryStore::new().failing(FailAt::Set(Some(SecretKind::TotpSecret)));
        store
            .set(ACCOUNT, SecretKind::Password, Secret::new(b"pw".to_vec()))
            .expect("the kind that was not named still writes");
        assert!(
            store
                .set(ACCOUNT, SecretKind::TotpSecret, Secret::new(b"s".to_vec()))
                .is_err()
        );
        assert!(store.stored(ACCOUNT, SecretKind::Password).is_some());
        assert!(store.stored(ACCOUNT, SecretKind::TotpSecret).is_none());

        let store = MemoryStore::new().failing(FailAt::Get(Some(SecretKind::Password)));
        assert!(store.get(ACCOUNT, SecretKind::Password).is_err());
        assert!(store.get(ACCOUNT, SecretKind::TotpSecret).is_ok());
    }

    /// The property that defines `Locked` and `WrongPassphrase`: this attempt fails and the one
    /// after the unlock succeeds. The builders take `self` by value and a consumer holds the double
    /// behind an `Arc`, so without a way to lift the script the second half had no double.
    #[test]
    fn a_scripted_failure_can_be_lifted_on_a_store_already_handed_out() {
        let store = std::sync::Arc::new(
            MemoryStore::new().failing_with(FailAt::Everything, || SecretsError::Locked),
        );
        let held: &dyn SecretStore = &*store;
        assert!(matches!(
            held.set(ACCOUNT, SecretKind::Password, Secret::new(b"pw".to_vec())),
            Err(SecretsError::Locked)
        ));

        store.now_failing(None);
        held.set(ACCOUNT, SecretKind::Password, Secret::new(b"pw".to_vec()))
            .expect("the retry after the unlock succeeds");
        assert_eq!(
            store.stored(ACCOUNT, SecretKind::Password),
            Some(b"pw".to_vec())
        );
    }
}
