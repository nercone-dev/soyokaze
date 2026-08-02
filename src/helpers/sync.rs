//! Locking that treats a poisoned mutex as an ordinary one.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks `mutex`, ignoring poisoning.
///
/// A panic while another thread held the lock poisons it, and the state behind
/// it may be halfway through an update. Every mutex in this crate guards a
/// bounded cache — a cookie jar, an HSTS store, a connection tally — where a
/// half-finished update costs at most one wrong entry, so refusing to lock
/// afterwards would take down a connection over nothing.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
