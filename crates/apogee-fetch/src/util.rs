//! Small shared helpers.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock a mutex, recovering the guard from a poisoned lock rather than propagating a panic. Every
/// mutex in the crate guards a brief, panic-free critical section, so a poisoned lock is never a
/// meaningful state to fail a download on.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
