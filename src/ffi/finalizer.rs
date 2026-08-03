//! Date formatting, from C.
//!
//! The one piece of [`crate::finalizer`] a caller outside Rust reaches for:
//! rendering an HTTP-date. The `Date` field itself is stamped onto server
//! responses by the library, so nothing here needs calling for that.

use crate::ffi::Buffer;

/// The IMF-fixdate for a Unix timestamp, owned by the caller.
///
/// Always 29 octets: `Sun, 06 Nov 1994 08:49:37 GMT`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_http_date(unix_seconds: u64) -> Buffer {
    Buffer::new(crate::finalizer::DateCache::format(unix_seconds).into_bytes())
}
