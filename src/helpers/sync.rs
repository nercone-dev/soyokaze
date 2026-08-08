//! Locking and deadlines.
//!
//! [`Lock`] treats a poisoned mutex as an ordinary one, and [`Timeout`] runs an
//! operation under a deadline, reporting [`Elapsed`] when it passes. Nothing
//! here knows what the deadline was for: a caller that wants its own error
//! converts, as [`Error`] does.
//!
//! [`Error`]: crate::errors::Error

use std::fmt;
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::Poll;
use std::time::Duration;

/// An operation did not finish within the seconds it was given.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Elapsed {
    /// The deadline that passed, in seconds.
    pub seconds: f64,
}

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nothing arrived within {}s", self.seconds)
    }
}

impl std::error::Error for Elapsed {}

/// Taking a mutex the way this crate takes one.
pub struct Lock;

impl Lock {
    /// Locks `mutex`, ignoring poisoning.
    ///
    /// A panic while another thread held the lock poisons it, and the state
    /// behind it may be halfway through an update. Every mutex in this crate
    /// guards a bounded cache — a cookie jar, an HSTS store, a connection
    /// tally — where a half-finished update costs at most one wrong entry, so
    /// refusing to lock afterwards would take down a connection over nothing.
    pub fn on<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The deadlines the [`Limits`] fields describe.
///
/// [`Limits`]: crate::models::Limits
pub struct Timeout;

impl Timeout {
    /// Whether a timeout in seconds asks for a deadline at all.
    ///
    /// Zero, negative and non-finite values all disable the timeout, which is
    /// what the [`Limits`] fields are documented to do.
    ///
    /// [`Limits`]: crate::models::Limits
    #[inline]
    pub fn armed(seconds: f64) -> bool {
        seconds.is_finite() && seconds > 0.0
    }

    /// A timeout in seconds as a [`Duration`], or `None` when it means "wait
    /// forever".
    ///
    /// Values [`Timeout::armed`] rejects yield `None`. A value too large for a
    /// [`Duration`] is capped at [`Duration::MAX`] rather than panicking — a
    /// deadline that far out and no deadline at all are the same thing to a
    /// connection.
    pub fn duration(seconds: f64) -> Option<Duration> {
        Self::armed(seconds).then(|| Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX))
    }

    /// Runs an operation under a deadline.
    ///
    /// A `seconds` that [`Timeout::duration`] rejects means no deadline at all,
    /// and the operation is simply awaited. The operation is polled once before
    /// the timer is armed, so work that is already finished never pays for one.
    ///
    /// The operation is taken by value, so a caller whose operation is a large
    /// future — one whole message going out or coming in, rather than a single
    /// read — should hand over a `Pin<&mut _>` from [`std::pin::pin!`] instead.
    /// That leaves the state machine where the caller built it rather than
    /// copying it into this one, which for a message-sized future is kilobytes
    /// a message.
    ///
    /// # Errors
    ///
    /// Returns [`Elapsed`] when the deadline passes first.
    pub async fn within<T>(seconds: f64, operation: impl Future<Output = T>) -> Result<T, Elapsed> {
        if !Self::armed(seconds) {
            return Ok(operation.await);
        }

        let mut operation = std::pin::pin!(operation);

        if let Poll::Ready(value) = std::future::poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx))).await {
            return Ok(value);
        }

        let wait = Self::duration(seconds).unwrap_or(Duration::MAX);

        tokio::time::timeout(wait, operation).await.map_err(|_| Elapsed { seconds })
    }
}
