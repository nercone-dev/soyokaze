//! Content codings, from C.
//!
//! The codings a message body may be carried in, as
//! [`crate::helpers::compression`] implements them. Every piece the Rust
//! module offers crosses: the tokens either way, the preference order, the
//! field value this end advertises, what an `Accept-Encoding` permits and what
//! a `Content-Encoding` applied, and the encoder and decoder themselves.
//!
//! A coding crosses as its own code, and `-1` stands for "no coding" wherever
//! one may be absent.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Slice};
use crate::helpers::compression::{Coding, Compression};
use crate::models::Headers;

/// The coding a code names, or `None` when it names none.
///
/// The one place a code from C becomes a [`Compression`], so that every entry
/// point refuses the same set and a coding added to the enum is reachable from
/// C without another arm being written by hand.
pub fn coding(code: i32) -> Option<Compression> {
    let codings = std::iter::once(Compression::Auto).chain(Compression::CODINGS.iter().copied());
    codings.into_iter().find(|compression| *compression as i32 == code)
}

/// The coding's token, as `Content-Encoding` spells it.
///
/// Empty for `SOYOKAZE_COMPRESSION_AUTO`, which names no coding, and for a
/// code that names none at all. Borrowed from the library and valid for its
/// lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_compression_name(compression: i32) -> Slice {
    match coding(compression) {
        Some(compression) => Slice::text(compression.as_str()),
        None => Slice::text(""),
    }
}

/// The coding a token names, ignoring case, or `-1` when it names none.
///
/// Never answers `SOYOKAZE_COMPRESSION_AUTO`.
///
/// # Safety
///
/// `token` must either be null or point to `token_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_compression_parse(token: *const u8, token_len: usize) -> i32 {
    match unsafe { Slice::borrow_text(token, token_len) }.and_then(Compression::parse) {
        Some(compression) => compression as i32,
        None => -1,
    }
}

/// How many codings name something, which is what
/// [`soyokaze_compression_coding`] indexes.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_compression_count() -> usize {
    Compression::CODINGS.len()
}

/// The coding at `index` in preference order, or `-1` past the end.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_compression_coding(index: usize) -> i32 {
    match Compression::CODINGS.get(index) {
        Some(compression) => *compression as i32,
        None => -1,
    }
}

/// The `Accept-Encoding` value naming every coding this library decodes.
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_compression_accepted_field() -> Slice {
    Slice::text(Compression::ACCEPTED)
}

/// The best coding a field section's `Accept-Encoding` permits, or `-1`.
///
/// # Safety
///
/// `headers` must be a section that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_compression_accepted(headers: *const Headers) -> i32 {
    let Some(headers) = (unsafe { headers.as_ref() }) else {
        return -1;
    };

    match Compression::accepted(headers.get_all("accept-encoding")) {
        Some(compression) => compression as i32,
        None => -1,
    }
}

/// The coding a field section's `Content-Encoding` applied, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_compression_accepted`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_compression_applied(headers: *const Headers) -> i32 {
    let Some(headers) = (unsafe { headers.as_ref() }) else {
        return -1;
    };

    match Compression::applied(headers.get_all("content-encoding")) {
        Some(compression) => compression as i32,
        None => -1,
    }
}

/// Whether a field section's `Content-Encoding` says the body is coded at all.
///
/// Answers true for a coding this library does not implement.
///
/// # Safety
///
/// As [`soyokaze_compression_accepted`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_compression_encoded(headers: *const Headers) -> bool {
    match unsafe { headers.as_ref() } {
        Some(headers) => Compression::encoded(headers.get_all("content-encoding")),
        None => false,
    }
}

/// The quality one entry of a coding list carries, or `-1` when it is unreadable.
///
/// An entry with no `q` parameter is fully acceptable and reads as 1.
///
/// # Safety
///
/// `entry` must either be null or point to `entry_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_compression_quality(entry: *const u8, entry_len: usize) -> f32 {
    match unsafe { Slice::borrow_text(entry, entry_len) } {
        Some(entry) => Coding::parse(entry).quality,
        None => -1.0,
    }
}

/// Encodes octets in `compression` through `out`.
///
/// Refuses `SOYOKAZE_COMPRESSION_AUTO`, which names no coding to encode in.
/// Free the result with [`soyokaze_buffer_free`].
///
/// [`soyokaze_buffer_free`]: crate::ffi::soyokaze_buffer_free
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` and `error` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_compression_encode(compression: i32, data: *const u8, data_len: usize, out: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let (Some(compression), Some(data)) = (coding(compression), unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match compression.encode(data) {
        Ok(encoded) => {
            if !out.is_null() {
                unsafe { *out = Buffer::new(encoded.to_vec()) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure.into()) },
    }
}

/// Decodes octets from `compression` through `out`, producing at most `max`.
///
/// Passing `max` is [`Status::Limit`] and produces nothing.
///
/// # Safety
///
/// As [`soyokaze_compression_encode`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_compression_decode(compression: i32, data: *const u8, data_len: usize, max: u64, out: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let (Some(compression), Some(data)) = (coding(compression), unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match compression.decode(data, max) {
        Ok(decoded) => {
            if !out.is_null() {
                unsafe { *out = Buffer::new(decoded.to_vec()) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure.into()) },
    }
}
