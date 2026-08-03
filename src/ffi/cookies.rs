//! Cookies, from C.
//!
//! [`Cookie`] and [`SetCookie`] are the two sides of the exchange — what a
//! client sends and what a server sets — and [`CookieJar`] is the client-side
//! store that turns one into the other across requests, exactly as
//! [`crate::cookies`] arranges them. The jar reads the clock itself, so the
//! caller never passes a timestamp.

use std::time::Instant;

use crate::ffi::models::Limits;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{borrow_text, Buffer, Slice};
use crate::cookies::{Cookie, CookieJar, SameSite, SetCookie};
use crate::models::Url;

/// Builds an empty `Cookie` field: no pairs yet.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_cookie_new() -> *mut Cookie {
    Box::into_raw(Box::new(Cookie::new()))
}

/// Reads a `Cookie` field value.
///
/// Parsing never fails — a malformed field yields whatever pairs could be read
/// from it. Returns null only when `value` is null or not UTF-8.
///
/// # Safety
///
/// `value` must either be null or point to `value_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookie_parse(value: *const u8, value_len: usize) -> *mut Cookie {
    match unsafe { borrow_text(value, value_len) } {
        Some(value) => Box::into_raw(Box::new(Cookie::parse(value))),
        None => std::ptr::null_mut(),
    }
}

/// Releases a [`Cookie`].
///
/// # Safety
///
/// `cookie` must come from `soyokaze_cookie_new` or `soyokaze_cookie_parse`
/// and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookie_free(cookie: *mut Cookie) {
    if !cookie.is_null() {
        drop(unsafe { Box::from_raw(cookie) });
    }
}

/// How many pairs the field holds.
///
/// # Safety
///
/// `cookie` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookie_count(cookie: *const Cookie) -> usize {
    unsafe { cookie.as_ref() }.map_or(0, |cookie| cookie.pairs.len())
}

/// The name of the pair at `index`, borrowed from `cookie`.
///
/// # Safety
///
/// As [`soyokaze_cookie_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookie_name(cookie: *const Cookie, index: usize) -> Slice {
    Slice::maybe(unsafe { cookie.as_ref() }.and_then(|cookie| cookie.pairs.get(index)).map(|(name, _)| name.as_str()))
}

/// The value of the pair at `index`, borrowed from `cookie`.
///
/// # Safety
///
/// As [`soyokaze_cookie_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookie_value(cookie: *const Cookie, index: usize) -> Slice {
    Slice::maybe(unsafe { cookie.as_ref() }.and_then(|cookie| cookie.pairs.get(index)).map(|(_, value)| value.as_str()))
}

/// The value stored under this exact name, borrowed from `cookie`.
///
/// Absent when no pair carries the name.
///
/// # Safety
///
/// `cookie` must either be null or be a handle that has not been freed, and
/// `name` must point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookie_get(cookie: *const Cookie, name: *const u8, name_len: usize) -> Slice {
    let Some(name) = (unsafe { borrow_text(name, name_len) }) else {
        return Slice::ABSENT;
    };

    Slice::maybe(unsafe { cookie.as_ref() }.and_then(|cookie| cookie.get(name)))
}

/// Adds a pair at the end.
///
/// Returns whether it was added; it is refused when an argument is null or is
/// not UTF-8.
///
/// # Safety
///
/// `cookie` must either be null or be a handle that has not been freed, and
/// `name` and `value` must point to their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookie_append(cookie: *mut Cookie, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(cookie), Some(name), Some(value)) = (unsafe { cookie.as_mut() }, unsafe { borrow_text(name, name_len) }, unsafe { borrow_text(value, value_len) })
    else {
        return false;
    };

    cookie.pairs.push((name.to_owned(), value.to_owned()));
    true
}

/// Writes the pairs back out as a `Cookie` field value, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_cookie_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookie_build(cookie: *const Cookie) -> Buffer {
    match unsafe { cookie.as_ref() } {
        Some(cookie) => Buffer::new(cookie.build().into_bytes()),
        None => Buffer::EMPTY,
    }
}

/// Builds a cookie with no attributes set.
///
/// Returns null when an argument is null or not UTF-8.
///
/// # Safety
///
/// `name` and `value` must point to their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_new(name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> *mut SetCookie {
    let (Some(name), Some(value)) = (unsafe { borrow_text(name, name_len) }, unsafe { borrow_text(value, value_len) }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(SetCookie::new(name, value)))
}

/// Reads a `Set-Cookie` field value.
///
/// # Safety
///
/// `value` must point to `value_len` readable octets, and `out` must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_parse(value: *const u8, value_len: usize, out: *mut *mut SetCookie, error: *mut *mut ErrorHandle) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(value) = (unsafe { borrow_text(value, value_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match SetCookie::parse(value) {
        Ok(cookie) => {
            unsafe { *out = Box::into_raw(Box::new(cookie)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Releases a [`SetCookie`].
///
/// # Safety
///
/// `cookie` must come from `soyokaze_setcookie_new` or
/// `soyokaze_setcookie_parse` and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_free(cookie: *mut SetCookie) {
    if !cookie.is_null() {
        drop(unsafe { Box::from_raw(cookie) });
    }
}

/// The cookie name, borrowed from `cookie`.
///
/// # Safety
///
/// `cookie` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_name(cookie: *const SetCookie) -> Slice {
    Slice::maybe(unsafe { cookie.as_ref() }.map(|cookie| cookie.name.as_str()))
}

/// The cookie value, borrowed from `cookie`.
///
/// # Safety
///
/// As [`soyokaze_setcookie_name`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_value(cookie: *const SetCookie) -> Slice {
    Slice::maybe(unsafe { cookie.as_ref() }.map(|cookie| cookie.value.as_str()))
}

/// The `Expires` attribute, verbatim, or absent when there is none.
///
/// # Safety
///
/// As [`soyokaze_setcookie_name`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_expires(cookie: *const SetCookie) -> Slice {
    Slice::maybe(unsafe { cookie.as_ref() }.and_then(|cookie| cookie.expires.as_deref()))
}

/// Reads the `Max-Age` attribute through `out`, returning whether it is set.
///
/// `out` is written only when the attribute is there, so a caller may pass
/// null just to test for its presence.
///
/// # Safety
///
/// `cookie` must either be null or be a handle that has not been freed, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_max_age(cookie: *const SetCookie, out: *mut i64) -> bool {
    let Some(max_age) = unsafe { cookie.as_ref() }.and_then(|cookie| cookie.max_age) else {
        return false;
    };

    if !out.is_null() {
        unsafe { *out = max_age };
    }

    true
}

/// The `Domain` attribute, or absent when the cookie is host-only.
///
/// # Safety
///
/// As [`soyokaze_setcookie_name`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_domain(cookie: *const SetCookie) -> Slice {
    Slice::maybe(unsafe { cookie.as_ref() }.and_then(|cookie| cookie.domain.as_deref()))
}

/// The `Path` attribute, or absent when the default path applies.
///
/// # Safety
///
/// As [`soyokaze_setcookie_name`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_path(cookie: *const SetCookie) -> Slice {
    Slice::maybe(unsafe { cookie.as_ref() }.and_then(|cookie| cookie.path.as_deref()))
}

/// Whether the `Secure` attribute is set.
///
/// # Safety
///
/// As [`soyokaze_setcookie_name`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_secure(cookie: *const SetCookie) -> bool {
    unsafe { cookie.as_ref() }.is_some_and(|cookie| cookie.secure)
}

/// Whether the `HttpOnly` attribute is set.
///
/// # Safety
///
/// As [`soyokaze_setcookie_name`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_httponly(cookie: *const SetCookie) -> bool {
    unsafe { cookie.as_ref() }.is_some_and(|cookie| cookie.httponly)
}

/// The `SameSite` attribute: `0` Strict, `1` Lax, `2` None, `-1` unset.
///
/// # Safety
///
/// As [`soyokaze_setcookie_name`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_samesite(cookie: *const SetCookie) -> i32 {
    match unsafe { cookie.as_ref() }.and_then(|cookie| cookie.samesite) {
        Some(SameSite::Strict) => 0,
        Some(SameSite::Lax) => 1,
        Some(SameSite::None) => 2,
        None => -1,
    }
}

/// Replaces the cookie value.
///
/// # Safety
///
/// `cookie` must either be null or be a handle that has not been freed, and
/// `value` must point to `value_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_set_value(cookie: *mut SetCookie, value: *const u8, value_len: usize) -> bool {
    let (Some(cookie), Some(value)) = (unsafe { cookie.as_mut() }, unsafe { borrow_text(value, value_len) }) else {
        return false;
    };

    cookie.value = value.to_owned();
    true
}

/// Sets the `Expires` attribute, or clears it with a null `value`.
///
/// # Safety
///
/// As [`soyokaze_setcookie_set_value`], except that a null `value` is allowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_set_expires(cookie: *mut SetCookie, value: *const u8, value_len: usize) -> bool {
    let Some(cookie) = (unsafe { cookie.as_mut() }) else {
        return false;
    };

    if value.is_null() {
        cookie.expires = None;
        return true;
    }

    let Some(value) = (unsafe { borrow_text(value, value_len) }) else {
        return false;
    };

    cookie.expires = Some(value.to_owned());
    true
}

/// Sets the `Max-Age` attribute, or clears it when `present` is false.
///
/// # Safety
///
/// `cookie` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_set_max_age(cookie: *mut SetCookie, present: bool, max_age: i64) -> bool {
    let Some(cookie) = (unsafe { cookie.as_mut() }) else {
        return false;
    };

    cookie.max_age = present.then_some(max_age);
    true
}

/// Sets the `Domain` attribute, or clears it with a null `value`.
///
/// # Safety
///
/// As [`soyokaze_setcookie_set_expires`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_set_domain(cookie: *mut SetCookie, value: *const u8, value_len: usize) -> bool {
    let Some(cookie) = (unsafe { cookie.as_mut() }) else {
        return false;
    };

    if value.is_null() {
        cookie.domain = None;
        return true;
    }

    let Some(value) = (unsafe { borrow_text(value, value_len) }) else {
        return false;
    };

    cookie.domain = Some(value.to_owned());
    true
}

/// Sets the `Path` attribute, or clears it with a null `value`.
///
/// # Safety
///
/// As [`soyokaze_setcookie_set_expires`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_set_path(cookie: *mut SetCookie, value: *const u8, value_len: usize) -> bool {
    let Some(cookie) = (unsafe { cookie.as_mut() }) else {
        return false;
    };

    if value.is_null() {
        cookie.path = None;
        return true;
    }

    let Some(value) = (unsafe { borrow_text(value, value_len) }) else {
        return false;
    };

    cookie.path = Some(value.to_owned());
    true
}

/// Sets or clears the `Secure` attribute.
///
/// # Safety
///
/// As [`soyokaze_setcookie_set_max_age`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_set_secure(cookie: *mut SetCookie, secure: bool) -> bool {
    let Some(cookie) = (unsafe { cookie.as_mut() }) else {
        return false;
    };

    cookie.secure = secure;
    true
}

/// Sets or clears the `HttpOnly` attribute.
///
/// # Safety
///
/// As [`soyokaze_setcookie_set_max_age`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_set_httponly(cookie: *mut SetCookie, httponly: bool) -> bool {
    let Some(cookie) = (unsafe { cookie.as_mut() }) else {
        return false;
    };

    cookie.httponly = httponly;
    true
}

/// Sets the `SameSite` attribute: `0` Strict, `1` Lax, `2` None, `-1` unset.
///
/// Any other number is refused.
///
/// # Safety
///
/// As [`soyokaze_setcookie_set_max_age`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_set_samesite(cookie: *mut SetCookie, samesite: i32) -> bool {
    let Some(cookie) = (unsafe { cookie.as_mut() }) else {
        return false;
    };

    cookie.samesite = match samesite {
        0 => Some(SameSite::Strict),
        1 => Some(SameSite::Lax),
        2 => Some(SameSite::None),
        -1 => None,
        _ => return false,
    };

    true
}

/// Writes the cookie out as a `Set-Cookie` field value, owned by the caller.
///
/// # Safety
///
/// `cookie` must be a handle that has not been freed, and `out` must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_setcookie_build(cookie: *const SetCookie, out: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let Some(cookie) = (unsafe { cookie.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match cookie.build() {
        Ok(value) => {
            unsafe { *out = Buffer::new(value.into_bytes()) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Builds an empty [`CookieJar`].
///
/// A null `limits` takes every default. The jar reads the clock itself, so
/// lifetimes count from the moment a cookie is learned.
///
/// # Safety
///
/// `limits` must either be null or point to a readable [`Limits`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookiejar_new(limits: *const Limits) -> *mut CookieJar {
    Box::into_raw(Box::new(CookieJar::new().with_limits(unsafe { Limits::or_default(limits) })))
}

/// Releases a [`CookieJar`].
///
/// # Safety
///
/// `jar` must come from `soyokaze_cookiejar_new` and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookiejar_free(jar: *mut CookieJar) {
    if !jar.is_null() {
        drop(unsafe { Box::from_raw(jar) });
    }
}

/// Takes in the `Set-Cookie` values a response for `url` carried.
///
/// Values that do not parse are skipped rather than failing the whole batch.
/// Returns whether the arguments were usable at all.
///
/// # Safety
///
/// `jar` and `url` must be handles that have not been freed, and `values`
/// must point to `value_count` readable slices whose own pointers are valid
/// UTF-8 text.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookiejar_learn(jar: *const CookieJar, url: *const Url, values: *const Slice, value_count: usize) -> bool {
    let (Some(jar), Some(url)) = (unsafe { jar.as_ref() }, unsafe { url.as_ref() }) else {
        return false;
    };

    if values.is_null() && value_count > 0 {
        return false;
    }

    let mut parsed = Vec::with_capacity(value_count);
    for index in 0..value_count {
        let slice = unsafe { *values.add(index) };
        let Some(value) = (unsafe { borrow_text(slice.data, slice.len) }) else {
            return false;
        };
        parsed.push(value);
    }

    jar.learn(url, &parsed, Instant::now());
    true
}

/// The `Cookie` field value for a request to `url`, owned by the caller.
///
/// An empty buffer with a null pointer means no cookie matched.
///
/// # Safety
///
/// `jar` and `url` must each either be null or be handles that have not been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookiejar_cookie(jar: *const CookieJar, url: *const Url) -> Buffer {
    let (Some(jar), Some(url)) = (unsafe { jar.as_ref() }, unsafe { url.as_ref() }) else {
        return Buffer::EMPTY;
    };

    match jar.cookie(url, Instant::now()) {
        Some(value) => Buffer::new(value.into_bytes()),
        None => Buffer::EMPTY,
    }
}

/// Drops every cookie that has expired.
///
/// # Safety
///
/// `jar` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cookiejar_prune(jar: *const CookieJar) {
    if let Some(jar) = unsafe { jar.as_ref() } {
        jar.prune(Instant::now());
    }
}
