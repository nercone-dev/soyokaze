//! The response constructors a handler reaches for most, from C.
//!
//! Each call builds a [`Message`] with its `Content-Type` already set, so a
//! callback can answer in a line, mirroring the constructors in
//! [`crate::responses`]. The result is an ordinary message handle that can be
//! adjusted further before it is returned.

use bytes::Bytes;

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::Slice;
use crate::cookies::SetCookie;
use crate::models::{Body, Message, Version};

/// The response a callback returns to answer with a body it holds in memory.
///
/// A shorthand for building a response and setting its body, since that is what
/// most callbacks do.
///
/// # Safety
///
/// `body` must either be null or point to `body_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_with_body(status_code: u16, version: Version, body: *const u8, body_len: usize) -> *mut Message {
    let mut response = Message::response(status_code, version);

    if let Some(body) = unsafe { Slice::borrow(body, body_len) } {
        response.body = Some(Body::Data(Bytes::copy_from_slice(body)));
    }

    Box::into_raw(Box::new(response))
}

/// A `200 OK` carrying `body` under the given media type.
///
/// Returns null when `content_type` is null or not UTF-8; a null `body` sends
/// an empty one.
///
/// # Safety
///
/// `content_type` and `body` must each either be null or point to their stated
/// number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_content(content_type: *const u8, content_type_len: usize, body: *const u8, body_len: usize, version: Version) -> *mut Message {
    let Some(content_type) = (unsafe { Slice::borrow_text(content_type, content_type_len) }) else {
        return std::ptr::null_mut();
    };

    let body = Body::Data(Bytes::copy_from_slice(unsafe { Slice::borrow(body, body_len) }.unwrap_or_default()));
    Box::into_raw(Box::new(Message::content(content_type, body, version)))
}

/// A `200 OK` of `text/plain`.
///
/// Returns null when `content` is null or not UTF-8.
///
/// # Safety
///
/// `content` must either be null or point to `content_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_text(content: *const u8, content_len: usize, version: Version) -> *mut Message {
    match unsafe { Slice::borrow_text(content, content_len) } {
        Some(content) => Box::into_raw(Box::new(Message::text(content, version))),
        None => std::ptr::null_mut(),
    }
}

/// A `200 OK` of `text/html`.
///
/// # Safety
///
/// As [`soyokaze_response_text`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_html(content: *const u8, content_len: usize, version: Version) -> *mut Message {
    match unsafe { Slice::borrow_text(content, content_len) } {
        Some(content) => Box::into_raw(Box::new(Message::html(content, version))),
        None => std::ptr::null_mut(),
    }
}

/// A `200 OK` of `text/markdown`.
///
/// # Safety
///
/// As [`soyokaze_response_text`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_markdown(content: *const u8, content_len: usize, version: Version) -> *mut Message {
    match unsafe { Slice::borrow_text(content, content_len) } {
        Some(content) => Box::into_raw(Box::new(Message::markdown(content, version))),
        None => std::ptr::null_mut(),
    }
}

/// A `200 OK` of `application/json`.
///
/// The content is sent as given; nothing checks that it is valid JSON.
///
/// # Safety
///
/// As [`soyokaze_response_text`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_json(content: *const u8, content_len: usize, version: Version) -> *mut Message {
    match unsafe { Slice::borrow_text(content, content_len) } {
        Some(content) => Box::into_raw(Box::new(Message::json(content, version))),
        None => std::ptr::null_mut(),
    }
}

/// A `200 OK` serving a file, typed by its extension.
///
/// The file is not opened here — a missing or unreadable file surfaces when
/// the body is sent.
///
/// # Safety
///
/// `path` must either be null or point to `path_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_file(path: *const u8, path_len: usize, version: Version) -> *mut Message {
    match unsafe { Slice::borrow_text(path, path_len) } {
        Some(path) => Box::into_raw(Box::new(Message::file(path, version))),
        None => std::ptr::null_mut(),
    }
}

/// A `307 Temporary Redirect` to `target`, which preserves the method.
///
/// # Safety
///
/// `target` must either be null or point to `target_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_redirect(target: *const u8, target_len: usize, version: Version) -> *mut Message {
    match unsafe { Slice::borrow_text(target, target_len) } {
        Some(target) => Box::into_raw(Box::new(Message::redirect(target, version))),
        None => std::ptr::null_mut(),
    }
}

/// Adds a `Set-Cookie` field, keeping any already on the message.
///
/// The cookie handle is borrowed, not consumed.
///
/// # Safety
///
/// `message` and `cookie` must be handles that have not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_cookie(message: *mut Message, cookie: *const SetCookie, error: *mut *mut ErrorHandle) -> Status {
    let (Some(message), Some(cookie)) = (unsafe { message.as_mut() }, unsafe { cookie.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match message.set_cookie(cookie) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Adds a `Set-Cookie` field that deletes the cookie.
///
/// The value is emptied and `Max-Age=0` replaces any lifetime, so the client
/// drops the cookie. The cookie handle is borrowed, not consumed.
///
/// # Safety
///
/// As [`soyokaze_message_set_cookie`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_delete_cookie(message: *mut Message, cookie: *const SetCookie, error: *mut *mut ErrorHandle) -> Status {
    let (Some(message), Some(cookie)) = (unsafe { message.as_mut() }, unsafe { cookie.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match message.delete_cookie(cookie.clone()) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The reason phrase a status code is conventionally sent with, borrowed from
/// the library.
///
/// A code outside the ranges the library knows reads as the phrase for the
/// class it falls in.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_status_reason(status_code: u16) -> Slice {
    Slice::text(crate::responses::Status::reason(status_code))
}

/// The media type a path's extension names, borrowed from the library.
///
/// An extension the library does not know reads as
/// `application/octet-stream`.
///
/// # Safety
///
/// `path` must either be null or point to `path_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_content_type(path: *const u8, path_len: usize) -> Slice {
    match unsafe { Slice::borrow_text(path, path_len) } {
        Some(path) => Slice::text(crate::models::Message::content_type(path)),
        None => Slice::ABSENT,
    }
}

/// The `426 Upgrade Required` a server answers with when it will not speak the
/// version a request came in on.
///
/// `request` is read, not consumed.
///
/// # Safety
///
/// `request` must either be null or be a handle that has not been freed, and
/// `protocol` must point to `protocol_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_upgrade_required(request: *const Message, version: Version, protocol: *const u8, protocol_len: usize) -> *mut Message {
    let (Some(request), Some(protocol)) = (unsafe { request.as_ref() }, unsafe { Slice::borrow_text(protocol, protocol_len) }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(Message::upgrade_required(request, version, protocol)))
}
