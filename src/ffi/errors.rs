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
/// tested with `if (soyokaze_...(...))`. The variants past [`Status::IO`] have
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
    /// [`Limits`]: crate::models::Limits
    Limit = 3,
    /// One stream failed; the connection itself stays usable.
    Stream = 4,
    /// An operation ran past its deadline.
    Timeout = 5,
    /// The TLS handshake failed, or a TLS object could not be built.
    TLS = 6,
    /// No usable HTTP version could be agreed on.
    Version = 7,
    /// The transport underneath failed.
    IO = 8,
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
            Error::TLS(_) => Self::TLS,
            Error::Version(_) => Self::Version,
            Error::IO(_) => Self::IO,
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
            Self::TLS => "tls error",
            Self::Version => "version negotiation failed",
            Self::IO => "io error",
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
///
/// [`Error::Stream`] is the one failure that carries more than a message, so
/// the stream it names and the code to reset it by are kept alongside rather
/// than left to be read out of the text.
pub struct ErrorHandle {
    /// What kind of failure it was.
    pub status: Status,
    /// What went wrong, as [`Error`] renders it.
    pub message: String,
    /// What went wrong, without the prefix the rendering adds.
    ///
    /// This is the payload the [`Error`] variant carries, which is what a
    /// caller narrowing a failure to one stream has to keep.
    pub reason: String,
    /// The stream that failed, on an [`Error::Stream`].
    pub stream_id: Option<crate::models::StreamID>,
    /// The protocol error code to reset that stream with.
    pub code: Option<u64>,
}

impl ErrorHandle {
    /// The handle that stands for `error`.
    pub fn new(error: &Error) -> Self {
        let (stream_id, code) = match error {
            Error::Stream { id, code, .. } => (Some(*id), Some(*code)),
            _ => (None, None),
        };

        Self { status: Status::of(error), message: error.to_string(), reason: Self::reason(error), stream_id, code }
    }

    /// The payload `error` carries, without the prefix its rendering adds.
    pub fn reason(error: &Error) -> String {
        match error {
            Error::Closed => String::new(),
            Error::Protocol(reason) | Error::Limit(reason) | Error::Timeout(reason) | Error::TLS(reason) | Error::Version(reason) => reason.clone(),
            Error::Stream { reason, .. } => reason.clone(),
            Error::IO(failure) => failure.to_string(),
        }
    }

    /// The [`Error`] a status and a reason stand for.
    ///
    /// The statuses raised by the boundary itself — [`Status::Invalid`] and
    /// [`Status::Runtime`] — have no [`Error`] behind them and read as
    /// [`Error::Protocol`], since a caller that builds one is describing a
    /// failure the crate would have called a protocol violation.
    pub fn build(status: Status, reason: String) -> Error {
        match status {
            Status::Ok | Status::Closed => Error::Closed,
            Status::Protocol | Status::Invalid | Status::Runtime => Error::Protocol(reason),
            Status::Limit => Error::Limit(reason),
            Status::Stream => Error::stream(crate::models::StreamID(0), 0, reason),
            Status::Timeout => Error::Timeout(reason),
            Status::TLS => Error::TLS(reason),
            Status::Version => Error::Version(reason),
            Status::IO => Error::IO(std::io::Error::other(reason)),
        }
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
            let handle = Self { status, message: status.message().to_owned(), reason: status.message().to_owned(), stream_id: None, code: None };
            unsafe { *out = Box::into_raw(Box::new(handle)) };
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

/// The stream that failed, or `-1` when the failure names none.
///
/// Only a [`Status::Stream`] failure names one; everything else took the whole
/// connection with it. This is the stream identifier a message carries, so it
/// matches what `soyokaze_message_stream_id` reports.
///
/// # Safety
///
/// As [`soyokaze_error_status`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_stream_id(error: *const ErrorHandle) -> i64 {
    match unsafe { error.as_ref() }.and_then(|error| error.stream_id) {
        Some(stream_id) => stream_id.0 as i64,
        None => -1,
    }
}

/// The protocol error code the stream was reset with, or `-1` when there is
/// none.
///
/// Reads as the HTTP/2 or HTTP/3 error code, whichever version raised it.
///
/// # Safety
///
/// As [`soyokaze_error_status`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_code(error: *const ErrorHandle) -> i64 {
    match unsafe { error.as_ref() }.and_then(|error| error.code) {
        Some(code) => code as i64,
        None => -1,
    }
}

/// A fixed description of `status`, for a caller that has no [`ErrorHandle`].
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_status_message(status: Status) -> Slice {
    Slice::text(status.message())
}

/// Builds an [`ErrorHandle`] for a status and the reason that goes with it.
///
/// For a caller that raises a failure of its own — a request handler refusing
/// a message, most of all — and wants it to read exactly like one the crate
/// raised. A [`Status::Stream`] built this way names stream zero and code
/// zero; [`soyokaze_error_stream`] names them properly.
///
/// # Safety
///
/// `reason` must either be null or point to `reason_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_new(status: Status, reason: *const u8, reason_len: usize) -> *mut ErrorHandle {
    let reason = unsafe { Slice::borrow_text(reason, reason_len) }.unwrap_or_default().to_owned();
    Box::into_raw(Box::new(ErrorHandle::new(&ErrorHandle::build(status, reason))))
}

/// Builds an [`ErrorHandle`] for one stream that failed.
///
/// The connection itself stays usable; `code` is the HTTP/2 or HTTP/3 error
/// code the stream is reset with.
///
/// # Safety
///
/// As [`soyokaze_error_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_stream(stream_id: u64, code: u64, reason: *const u8, reason_len: usize) -> *mut ErrorHandle {
    let reason = unsafe { Slice::borrow_text(reason, reason_len) }.unwrap_or_default();
    Box::into_raw(Box::new(ErrorHandle::new(&Error::stream(crate::models::StreamID(stream_id), code, reason))))
}

/// Narrows a connection-wide failure to one stream, consuming `error`.
///
/// A [`Status::Protocol`] or [`Status::Limit`] failure becomes a
/// [`Status::Stream`] one, so the stream is reset instead of the connection;
/// everything else comes back unchanged, because it is not something one
/// stream can absorb. `error` must not be freed afterwards.
///
/// # Safety
///
/// `error` must come from an `error` out parameter or one of the constructors
/// here, and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_on_stream(error: *mut ErrorHandle, stream_id: u64, code: u64) -> *mut ErrorHandle {
    if error.is_null() {
        return std::ptr::null_mut();
    }

    let handle = *unsafe { Box::from_raw(error) };
    let narrowed = ErrorHandle::build(handle.status, handle.reason).on_stream(crate::models::StreamID(stream_id), code);

    Box::into_raw(Box::new(ErrorHandle::new(&narrowed)))
}

/// What went wrong without the prefix the message carries, borrowed from
/// `error`.
///
/// # Safety
///
/// As [`soyokaze_error_status`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_reason(error: *const ErrorHandle) -> Slice {
    match unsafe { error.as_ref() } {
        Some(error) => Slice::text(&error.reason),
        None => Slice::ABSENT,
    }
}

/// Builds an [`ErrorHandle`] for a TLS failure.
///
/// # Safety
///
/// As [`soyokaze_error_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_tls(reason: *const u8, reason_len: usize) -> *mut ErrorHandle {
    let reason = unsafe { Slice::borrow_text(reason, reason_len) }.unwrap_or_default();
    Box::into_raw(Box::new(ErrorHandle::new(&Error::tls(reason))))
}

/// Builds an [`ErrorHandle`] for a failure from the QUIC layer.
///
/// QUIC failures read as [`Status::IO`], since what they mean to a caller is
/// that the transport underneath gave way.
///
/// # Safety
///
/// As [`soyokaze_error_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_error_quic(reason: *const u8, reason_len: usize) -> *mut ErrorHandle {
    let reason = unsafe { Slice::borrow_text(reason, reason_len) }.unwrap_or_default();
    Box::into_raw(Box::new(ErrorHandle::new(&Error::quic(reason))))
}
