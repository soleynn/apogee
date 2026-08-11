//! Small shared helpers.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock a mutex, recovering the guard from a poisoned lock instead of propagating the panic. Every
/// mutex in the crate guards a brief, panic-free section, so a poisoned lock is never meaningful to
/// fail a download on.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
