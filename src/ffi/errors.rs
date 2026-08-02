//! Carrying [`Error`] across the boundary.
//!
//! A fallible call returns a [`Status`], which says what kind of failure it was
//! and nothing more. Passing an `error` out parameter as well hands back an
//! [`Error`] handle, which carries the message that goes with it.

use crate::errors::Error;
use crate::ffi::Slice;

/// What a call did, as a C enum.
///
/// [`Status::Ok`] is zero and every failure is non-zero, so a call may be
/// tested with `if (soyokaze_...(...))`. The variants past [`Status::Io`] have
/// no [`Error`] behind them: they are raised by the boundary itself, before the
/// crate is reached.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// The call succeeded.
    Ok = 0,
    /// The peer closed the connection, or it was closed under us.
    Closed = 1,
    /// The peer broke the protocol.
    Protocol = 2,
    /// The peer went past one of the ceilings in [`Limits`].
    ///
    /// [`Limits`]: crate::api::common::Limits
    Limit = 3,
    /// One stream failed; the connection itself stays usable.
    Stream = 4,
    /// An operation ran past its deadline.
    Timeout = 5,
    /// The TLS handshake failed, or a TLS object could not be built.
    Tls = 6,
    /// No usable HTTP version could be agreed on.
    Version = 7,
    /// The transport underneath failed.
    Io = 8,
    /// An argument was null where it may not be, or was not UTF-8.
    Invalid = 9,
    /// The runtime could not be built, or the call was made without one.
    Runtime = 10,
}

impl Status {
    /// The status that stands for `error`.
    pub fn of(error: &Error) -> Self {
        match error {
            Error::Closed => Self::Closed,
            Error::Protocol(_) => Self::Protocol,
            Error::Limit(_) => Self::Limit,
            Error::Stream { .. } => Self::Stream,
            Error::Timeout(_) => Self::Timeout,
            Error::Tls(_) => Self::Tls,
            Error::Version(_) => Self::Version,
            Error::Io(_) => Self::Io,
        }
    }

    /// A fixed description of the status, for a caller that has no [`Error`].
    pub fn message(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Closed => "connection closed",
            Self::Protocol => "protocol violation",
            Self::Limit => "limit exceeded",
            Self::Stream => "stream failed",
            Self::Timeout => "timed out",
            Self::Tls => "tls error",
            Self::Version => "version negotiation failed",
            Self::Io => "io error",
            Self::Invalid => "invalid argument",
            Self::Runtime => "runtime unavailable",
        }
    }
}

/// A failure, with the message that goes with it.
///
/// Produced through the `error` out parameter of a fallible call, and freed
/// with [`soyokaze_error_free`]. The message is rendered once, when the handle
/// is built, so [`soyokaze_error_message`] borrows rather than allocates.
pub struct ErrorHandle {
    /// What kind of failure it was.
    pub status: Status,
    /// What went wrong, as [`Error`] renders it.
    pub message: String,
}

impl ErrorHandle {
    /// The handle that stands for `error`.
    pub fn new(error: &Error) -> Self {
        Self { status: Status::of(error), message: error.to_string() }
    }

    /// Writes `error` through an out parameter, and returns its status.
    ///
    /// A null `out` drops the handle rather than leaking it, so a caller that
    /// does not want the message may pass null and read only the status.
    ///
    /// # Safety
    ///
    /// `out` must either be null or point to a writable handle pointer.
    pub unsafe fn report(out: *mut *mut ErrorHandle, error: &Error) -> Status {
        let status = Status::of(error);

        if !out.is_null() {
            unsafe { *out = Box::into_raw(Box::new(Self::new(error))) };
        }

        status
    }

    /// Writes a boundary failure through an out parameter, and returns it.
    ///
    /// For the statuses that have no [`Error`] behind them — a null argument,
    /// text that is not UTF-8, a missing runtime.
    ///
    /// # Safety
    ///
    /// As [`ErrorHandle::report`].
    pub unsafe fn raise(out: *mut *mut ErrorHandle, status: Status) -> Status {
        if !out.is_null() {
            unsafe { *out = Box::into_raw(Box::new(Self { status, message: status.message().to_owned() })) };
        }

        status
    }
}

/// Releases an [`ErrorHandle`].
///
/// # Safety
///
/// `error` must come from an `error` out parameter and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_free(error: *mut ErrorHandle) {
    if !error.is_null() {
        drop(unsafe { Box::from_raw(error) });
    }
}

/// What kind of failure `error` was.
///
/// A null `error` reads as [`Status::Invalid`].
///
/// # Safety
///
/// `error` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_status(error: *const ErrorHandle) -> Status {
    match unsafe { error.as_ref() } {
        Some(error) => error.status,
        None => Status::Invalid,
    }
}

/// What went wrong, borrowed from `error` and valid until it is freed.
///
/// # Safety
///
/// As [`soyokaze_error_status`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_message(error: *const ErrorHandle) -> Slice {
    match unsafe { error.as_ref() } {
        Some(error) => Slice::text(&error.message),
        None => Slice::ABSENT,
    }
}

/// A fixed description of `status`, for a caller that has no [`ErrorHandle`].
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_status_message(status: Status) -> Slice {
    Slice::text(status.message())
}
