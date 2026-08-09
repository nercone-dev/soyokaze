//! Filling in the fields a message is expected to carry, from C.
//!
//! [`DateCache`] renders the `Date` field, caching the rendering for a whole
//! second because a busy server stamps one on every response.
//! [`ResponseFinalizer`] and [`RequestFinalizer`] are the two halves that put
//! the finishing fields on a message before it goes out — the same pair as
//! [`crate::finalizer`]. A connection runs both itself, so nothing here needs
//! calling for an ordinary exchange; it is here for a caller driving one by
//! hand.

use crate::ffi::{Buffer, Slice};
use crate::models::{Message, Role};

pub use crate::finalizer::{DateCache, RequestFinalizer, ResponseFinalizer};

/// How many octets an HTTP-date is: `Sun, 06 Nov 1994 08:49:37 GMT`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_date_length() -> usize {
    crate::finalizer::DATE_LENGTH
}

/// The abbreviated day name at `index`, Sunday first, borrowed from the
/// library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_day_name(index: usize) -> Slice {
    Slice::maybe(crate::finalizer::DAY_NAMES.get(index).copied())
}

/// The abbreviated month name at `index`, January first, borrowed from the
/// library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_month_name(index: usize) -> Slice {
    Slice::maybe(crate::finalizer::MONTH_NAMES.get(index).copied())
}

/// The year, month and day a count of days since the epoch falls on.
///
/// # Safety
///
/// `year`, `month` and `day` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_civil_from_days(days: i64, year: *mut i64, month: *mut u32, day: *mut u32) {
    let (civil_year, civil_month, civil_day) = DateCache::civil_from_days(days);

    if !year.is_null() {
        unsafe { *year = civil_year };
    }

    if !month.is_null() {
        unsafe { *month = civil_month };
    }

    if !day.is_null() {
        unsafe { *day = civil_day };
    }
}

/// The IMF-fixdate for a Unix timestamp, owned by the caller.
///
/// Always 29 octets: `Sun, 06 Nov 1994 08:49:37 GMT`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_http_date(unix_seconds: u64) -> Buffer {
    Buffer::new(DateCache::format(unix_seconds).into_bytes())
}

/// Builds a [`DateCache`], which renders at most once a second.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_date_cache_new() -> *mut DateCache {
    Box::into_raw(Box::new(DateCache::new()))
}

/// Releases a [`DateCache`].
///
/// # Safety
///
/// `cache` must come from [`soyokaze_date_cache_new`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_date_cache_free(cache: *mut DateCache) {
    if !cache.is_null() {
        drop(unsafe { Box::from_raw(cache) });
    }
}

/// The IMF-fixdate for now, owned by the caller.
///
/// Rendered once a second and handed back unchanged in between, which is what
/// a cache is for.
///
/// # Safety
///
/// `cache` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_date_cache_now(cache: *const DateCache) -> Buffer {
    match unsafe { cache.as_ref() } {
        Some(cache) => Buffer::new(cache.now().into_bytes()),
        None => Buffer::new(DateCache::shared().now().into_bytes()),
    }
}

/// Builds a [`ResponseFinalizer`].
///
/// A null `hsts` finalizes without stamping a `Strict-Transport-Security`
/// field, which is what a server that does not insist on TLS wants.
///
/// # Safety
///
/// `hsts` must either be null or point to a readable [`HSTSPolicy`].
///
/// [`HSTSPolicy`]: crate::ffi::hsts::HSTSPolicy
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_finalizer_new(hsts: *const crate::ffi::hsts::HSTSPolicy) -> *mut ResponseFinalizer {
    let hsts = unsafe { hsts.as_ref() }.map(|hsts| hsts.parse());
    Box::into_raw(Box::new(ResponseFinalizer::new(hsts)))
}

/// Releases a [`ResponseFinalizer`].
///
/// # Safety
///
/// `finalizer` must come from [`soyokaze_response_finalizer_new`] and not have
/// been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_finalizer_free(finalizer: *mut ResponseFinalizer) {
    if !finalizer.is_null() {
        drop(unsafe { Box::from_raw(finalizer) });
    }
}

/// Puts the finishing fields on a message about to go out.
///
/// Does nothing unless `role` answers requests and the message is a response.
/// `secure` says whether the connection carrying it is one an HSTS policy may
/// be stamped on.
///
/// # Safety
///
/// `finalizer` and `message` must either be null or be handles that have not
/// been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_finalizer_finalize(finalizer: *const ResponseFinalizer, role: Role, secure: bool, message: *mut Message) -> bool {
    let (Some(finalizer), Some(message)) = (unsafe { finalizer.as_ref() }, unsafe { message.as_mut() }) else {
        return false;
    };

    finalizer.finalize(role, secure, message);
    true
}

/// Builds a [`RequestFinalizer`] for `authority`.
///
/// A null `authority` finalizes without filling one in, which is what a caller
/// that has already set `Host` or `:authority` wants.
///
/// # Safety
///
/// `authority` must either be null or point to `authority_len` readable
/// octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_request_finalizer_new(authority: *const u8, authority_len: usize) -> *mut RequestFinalizer {
    Box::into_raw(Box::new(RequestFinalizer::new(unsafe { Slice::borrow_text(authority, authority_len) })))
}

/// Releases a [`RequestFinalizer`].
///
/// # Safety
///
/// `finalizer` must come from [`soyokaze_request_finalizer_new`] and not have
/// been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_request_finalizer_free(finalizer: *mut RequestFinalizer) {
    if !finalizer.is_null() {
        drop(unsafe { Box::from_raw(finalizer) });
    }
}

/// The authority the finalizer fills in, borrowed from it.
///
/// # Safety
///
/// `finalizer` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_request_finalizer_authority(finalizer: *const RequestFinalizer) -> Slice {
    Slice::maybe(unsafe { finalizer.as_ref() }.and_then(|finalizer| finalizer.authority.as_deref()))
}

/// Puts the finishing fields on a request about to go out.
///
/// Does nothing unless `role` sends requests and the message is a request.
///
/// # Safety
///
/// As [`soyokaze_response_finalizer_finalize`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_request_finalizer_finalize(finalizer: *const RequestFinalizer, role: Role, message: *mut Message) -> bool {
    let (Some(finalizer), Some(message)) = (unsafe { finalizer.as_ref() }, unsafe { message.as_mut() }) else {
        return false;
    };

    finalizer.finalize(role, message);
    true
}

/// Stamps the fields a response is expected to carry onto `message`.
///
/// The `Date` field comes from `cache`, or from the shared one when `cache` is
/// null; a null `hsts` stamps no `Strict-Transport-Security`.
///
/// # Safety
///
/// `message` must be a handle that has not been freed, and `cache` and `hsts`
/// must either be null or be readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_finalize_response(message: *mut Message, cache: *const DateCache, hsts: *const crate::ffi::hsts::HSTSPolicy) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    let policy = unsafe { hsts.as_ref() }.map(|hsts| hsts.parse());
    let cache = unsafe { cache.as_ref() }.unwrap_or_else(|| DateCache::shared());

    message.finalize_response(cache, policy.as_ref());
    true
}

/// Fills in the authority a request is expected to carry.
///
/// Writes `Host` for HTTP/1.x and `:authority` above it, and leaves whichever
/// is already there alone.
///
/// # Safety
///
/// `message` must be a handle that has not been freed, and `authority` must
/// point to `authority_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_finalize_request(message: *mut Message, authority: *const u8, authority_len: usize) -> bool {
    let (Some(message), Some(authority)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(authority, authority_len) }) else {
        return false;
    };

    message.finalize_request(authority);
    true
}
