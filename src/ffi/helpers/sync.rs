//! Deadlines, from C.
//!
//! [`crate::helpers::sync`] holds two pieces: taking a mutex the way this
//! crate takes one, which has no meaning outside Rust, and reading the
//! timeouts the [`Limits`] fields describe, which does. What a timeout in
//! seconds means — when it arms a deadline at all, and how long that deadline
//! is — crosses here, so a caller filling in a [`Limits`] reads the same rules
//! the crate does.
//!
//! [`Limits`]: crate::models::Limits
//!
//! [`Lock`] has no counterpart here: it hands back a guard, which is a Rust
//! lifetime and nothing a C caller could hold.
//!
//! [`Lock`]: crate::helpers::sync::Lock

/// Whether a timeout in seconds asks for a deadline at all.
///
/// Zero, negative and non-finite values all disable the timeout, which is what
/// the [`Limits`] fields are documented to do.
///
/// [`Limits`]: crate::models::Limits
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_timeout_armed(seconds: f64) -> bool {
    crate::helpers::sync::Timeout::armed(seconds)
}

/// How long a timeout in seconds is, in nanoseconds, or `-1` when it arms no
/// deadline.
///
/// A value too large to hold saturates rather than wrapping.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_timeout_nanos(seconds: f64) -> i64 {
    match crate::helpers::sync::Timeout::duration(seconds) {
        Some(duration) => duration.as_nanos().min(i64::MAX as u128) as i64,
        None => -1,
    }
}

/// How an elapsed deadline reads, as [`Elapsed`] renders it.
///
/// Owned by the caller, and freed with `soyokaze_buffer_free`.
///
/// [`Elapsed`]: crate::helpers::sync::Elapsed
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_elapsed_message(seconds: f64) -> crate::ffi::Buffer {
    crate::ffi::Buffer::new(crate::helpers::sync::Elapsed { seconds }.to_string().into_bytes())
}

/// The status an elapsed deadline is reported as.
///
/// Always [`Status::Timeout`], since [`Elapsed`] converts to [`Error::Timeout`]
/// and nothing else.
///
/// [`Status::Timeout`]: crate::ffi::Status::Timeout
/// [`Elapsed`]: crate::helpers::sync::Elapsed
/// [`Error::Timeout`]: crate::errors::Error::Timeout
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_elapsed_status() -> crate::ffi::Status {
    crate::ffi::Status::Timeout
}
