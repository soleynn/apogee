//! The per-account record of the last code that was submitted.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::code::Code;

/// What was last sent to the login server, per account.
///
/// Instance state on a handle the composition root owns, never a process global. Never persisted
/// either: a code expires in about half a minute, so writing one to disk buys nothing and leaves a
/// record of when the account signed in.
#[derive(Default)]
pub(crate) struct Guard {
    submitted: Mutex<HashMap<Uuid, Zeroizing<String>>>,
}

impl Guard {
    /// Whether `candidate` is the code this account last submitted.
    pub(crate) fn repeats(&self, account: Uuid, candidate: &Code) -> bool {
        // A plain comparison. Both sides are strings this process produced moments ago, so there is
        // no remote party whose timing could be measured and nothing constant time would buy.
        self.lock()
            .get(&account)
            .is_some_and(|last| last.as_str() == candidate.expose())
    }

    /// Record that `code` went to the login server for this account.
    pub(crate) fn record(&self, account: Uuid, code: &Code) {
        self.lock()
            .insert(account, Zeroizing::new(code.expose().to_owned()));
    }

    /// Drop what is remembered for this account.
    pub(crate) fn forget(&self, account: Uuid) {
        self.lock().remove(&account);
    }

    /// How many accounts are being tracked, for a redacted rendering of the handle.
    pub(crate) fn tracked(&self) -> usize {
        self.lock().len()
    }

    /// A poisoned lock is taken back rather than propagated: the map holds no invariant a panicking
    /// writer could have broken, and panicking here is denied besides.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Zeroizing<String>>> {
        self.submitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(digits: &str) -> Code {
        Code::new(Zeroizing::new(digits.to_owned()))
    }

    #[test]
    fn a_code_repeats_only_for_the_account_that_submitted_it() {
        let guard = Guard::default();
        let one = Uuid::from_u128(1);
        let two = Uuid::from_u128(2);

        assert!(!guard.repeats(one, &code("123456")));
        guard.record(one, &code("123456"));
        assert!(guard.repeats(one, &code("123456")));
        assert!(!guard.repeats(one, &code("654321")));
        assert!(!guard.repeats(two, &code("123456")));
        assert_eq!(guard.tracked(), 1);

        guard.forget(one);
        assert!(!guard.repeats(one, &code("123456")));
        assert_eq!(guard.tracked(), 0);
    }

    /// What the guard keeps is erased when it drops.
    ///
    /// Asserted by a helper that will not compile against a plain `String`, because nothing else in
    /// the crate can see this field: the record is the one place a live code is deliberately held
    /// past the request that sent it, and dropping the wrapper leaves the last code every account
    /// submitted in freed heap for as long as the process runs, with every test still green.
    #[test]
    fn what_the_guard_remembers_is_erased_when_it_drops() {
        const fn erased(_: &Mutex<HashMap<Uuid, Zeroizing<String>>>) {}

        let guard = Guard::default();
        guard.record(Uuid::from_u128(4), &code("424242"));
        erased(&guard.submitted);
    }

    /// Only the most recent submission is remembered. An older code that has already expired is not
    /// worth holding, and a growing per-account history would be a record of sign-in times.
    #[test]
    fn only_the_last_code_is_remembered() {
        let guard = Guard::default();
        let account = Uuid::from_u128(3);
        guard.record(account, &code("111111"));
        guard.record(account, &code("222222"));
        assert!(!guard.repeats(account, &code("111111")));
        assert!(guard.repeats(account, &code("222222")));
    }
}
