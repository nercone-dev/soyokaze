//! Carrying [`Url`] and [`Message`] across the boundary.
//!
//! A [`Message`] is reached as a handle, and its field section and body are
//! reached through it rather than as handles of their own — there is no way to
//! hold a section apart from the message it belongs to, and so no way to free
//! one twice.

use bytes::Bytes;

use crate::errors::Error;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{borrow, borrow_text, Buffer, Runtime, Slice};
use crate::models::{Body, Message, Method, Url, Version};

/// Which transport a port names, and so which versions it can carry.
///
/// The C half of [`Port`], which cannot cross as an enum because one of its
/// variants carries a path.
///
/// [`Port`]: crate::models::Port
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortKind {
    /// A Unix domain socket, named by `path`.
    UDS = 0,
    /// A TCP port, named by `number`.
    TCP = 1,
    /// A UDP port carrying QUIC, named by `number`.
    QUIC = 2,
}

/// A port to dial or bind.
///
/// `number` is read for [`PortKind::TCP`] and [`PortKind::QUIC`], and `path`
/// and `path_len` for [`PortKind::UDS`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Port {
    /// Which transport the port names.
    pub kind: PortKind,
    /// The port number, for a TCP or QUIC port.
    pub number: u16,
    /// The socket path, for a Unix domain socket.
    pub path: *const u8,
    /// How long the socket path is.
    pub path_len: usize,
}

impl Port {
    /// The [`Port`] this names.
    ///
    /// Returns `None` when a Unix socket path is absent or is not UTF-8.
    ///
    /// [`Port`]: crate::models::Port
    ///
    /// # Safety
    ///
    /// `path` must either be null or point to `path_len` readable octets.
    pub unsafe fn parse(&self) -> Option<crate::models::Port> {
        match self.kind {
            PortKind::TCP => Some(crate::models::Port::TCP(self.number)),
            PortKind::QUIC => Some(crate::models::Port::QUIC(self.number)),
            PortKind::UDS => Some(crate::models::Port::UDS(unsafe { borrow_text(self.path, self.path_len) }?.to_owned())),
        }
    }
}

/// Parses an absolute URL.
///
/// # Safety
///
/// `url` must point to `url_len` readable octets, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_parse(
    url: *const u8,
    url_len: usize,
    out: *mut *mut Url,
    error: *mut *mut ErrorHandle,
) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(text) = (unsafe { borrow_text(url, url_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Url::parse(text) {
        Ok(url) => {
            unsafe { *out = Box::into_raw(Box::new(url)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Releases a [`Url`].
///
/// # Safety
///
/// `url` must come from [`soyokaze_url_parse`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_free(url: *mut Url) {
    if !url.is_null() {
        drop(unsafe { Box::from_raw(url) });
    }
}

/// The scheme, lowercased, borrowed from `url`.
///
/// # Safety
///
/// `url` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_scheme(url: *const Url) -> Slice {
    Slice::maybe(unsafe { url.as_ref() }.map(|url| url.scheme.as_str()))
}

/// The host, borrowed from `url`.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_host(url: *const Url) -> Slice {
    Slice::maybe(unsafe { url.as_ref() }.map(|url| url.host.as_str()))
}

/// The request target — path, query and fragment — borrowed from `url`.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_target(url: *const Url) -> Slice {
    Slice::maybe(unsafe { url.as_ref() }.map(|url| url.target.as_str()))
}

/// The port, or zero when `url` is null.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_port(url: *const Url) -> u16 {
    unsafe { url.as_ref() }.map_or(0, |url| url.port)
}

/// Whether the scheme is a secure one.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_secure(url: *const Url) -> bool {
    unsafe { url.as_ref() }.is_some_and(|url| url.secure())
}

/// The authority — host, and port when it is not the default for the scheme.
///
/// Owned by the caller, since it is assembled rather than stored. An empty
/// buffer comes back when `url` is null.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_authority(url: *const Url) -> Buffer {
    match unsafe { url.as_ref() } {
        Some(url) => Buffer::new(url.authority().into_bytes()),
        None => Buffer::EMPTY,
    }
}

/// Builds a request.
///
/// # Safety
///
/// `target` must point to `target_len` readable octets. Returns null when it is
/// not UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_request(
    method: Method,
    target: *const u8,
    target_len: usize,
    version: Version,
) -> *mut Message {
    match unsafe { borrow_text(target, target_len) } {
        Some(target) => Box::into_raw(Box::new(Message::request(method, target, version))),
        None => std::ptr::null_mut(),
    }
}

/// Builds a response.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_message_response(status_code: u16, version: Version) -> *mut Message {
    Box::into_raw(Box::new(Message::response(status_code, version)))
}

/// Releases a [`Message`].
///
/// # Safety
///
/// `message` must be a handle the caller owns and has not freed. A message
/// handed to a call documented as consuming it must not be freed again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_free(message: *mut Message) {
    if !message.is_null() {
        drop(unsafe { Box::from_raw(message) });
    }
}

/// The version that framed the message.
///
/// A null `message` reads as [`Version::V1_1`].
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_version(message: *const Message) -> Version {
    unsafe { message.as_ref() }.map_or(Version::V1_1, |message| message.version)
}

/// The method, or `-1` on a response.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_method(message: *const Message) -> i32 {
    match unsafe { message.as_ref() }.and_then(|message| message.method) {
        Some(method) => method as i32,
        None => -1,
    }
}

/// The status code, or `-1` on a request.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_status_code(message: *const Message) -> i32 {
    match unsafe { message.as_ref() }.and_then(|message| message.status_code) {
        Some(status_code) => status_code as i32,
        None => -1,
    }
}

/// The request target, borrowed from `message`, or absent on a response.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_target(message: *const Message) -> Slice {
    Slice::maybe(unsafe { message.as_ref() }.and_then(|message| message.target.as_deref()))
}

/// Whether the message is a request.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_is_request(message: *const Message) -> bool {
    unsafe { message.as_ref() }.is_some_and(|message| message.is_request())
}

/// Whether the message is a response.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_is_response(message: *const Message) -> bool {
    unsafe { message.as_ref() }.is_some_and(|message| message.is_response())
}

/// Whether the message is an informational (1xx) response.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_is_informational(message: *const Message) -> bool {
    unsafe { message.as_ref() }.is_some_and(|message| message.is_informational())
}

/// Whether the message travelled over a secure transport.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_secure(message: *const Message) -> bool {
    unsafe { message.as_ref() }.is_some_and(|message| message.secure)
}

/// How many fields the message's section holds.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_header_count(message: *const Message) -> usize {
    unsafe { message.as_ref() }.and_then(|message| message.headers.as_ref()).map_or(0, |headers| headers.len())
}

/// The name of the field at `index`, borrowed from `message`.
///
/// Absent when there is no such field. Names are stored lowercase.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_header_name(message: *const Message, index: usize) -> Slice {
    Slice::maybe(
        unsafe { message.as_ref() }
            .and_then(|message| message.headers.as_ref())
            .and_then(|headers| headers.iter().nth(index))
            .map(|(name, _)| name),
    )
}

/// The value of the field at `index`, borrowed from `message`.
///
/// Absent when there is no such field.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_header_value(message: *const Message, index: usize) -> Slice {
    Slice::maybe(
        unsafe { message.as_ref() }
            .and_then(|message| message.headers.as_ref())
            .and_then(|headers| headers.iter().nth(index))
            .map(|(_, value)| value),
    )
}

/// The first value stored under `name`, borrowed from `message`.
///
/// Absent when the field is not there, which is not the same as a field that is
/// there and empty. The name is matched case-insensitively.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `name` must point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_header(message: *const Message, name: *const u8, name_len: usize) -> Slice {
    let Some(name) = (unsafe { borrow_text(name, name_len) }) else {
        return Slice::ABSENT;
    };

    Slice::maybe(unsafe { message.as_ref() }.and_then(|message| message.headers.as_ref()).and_then(|headers| headers.get(name)))
}

/// Adds a field, keeping any field already stored under the same name.
///
/// Returns whether it was added; it is refused when an argument is null or is
/// not UTF-8.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `name` and `value` must point to their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_append_header(
    message: *mut Message,
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
) -> bool {
    let (Some(message), Some(name), Some(value)) =
        (unsafe { message.as_mut() }, unsafe { borrow_text(name, name_len) }, unsafe { borrow_text(value, value_len) })
    else {
        return false;
    };

    message.headers.get_or_insert_default().append(name, value);
    true
}

/// Adds a field, dropping any field already stored under the same name.
///
/// Returns whether it was set, as [`soyokaze_message_append_header`].
///
/// # Safety
///
/// As [`soyokaze_message_append_header`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_insert_header(
    message: *mut Message,
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
) -> bool {
    let (Some(message), Some(name), Some(value)) =
        (unsafe { message.as_mut() }, unsafe { borrow_text(name, name_len) }, unsafe { borrow_text(value, value_len) })
    else {
        return false;
    };

    message.headers.get_or_insert_default().insert(name, value);
    true
}

/// Drops every field stored under `name`.
///
/// Returns whether anything was there to drop.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `name` must point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_remove_header(message: *mut Message, name: *const u8, name_len: usize) -> bool {
    let (Some(message), Some(name)) = (unsafe { message.as_mut() }, unsafe { borrow_text(name, name_len) }) else {
        return false;
    };

    message.headers.as_mut().is_some_and(|headers| headers.remove(name))
}

/// Sets the body to octets held in memory, copied out of `data`.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `data` must point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_body_data(message: *mut Message, data: *const u8, data_len: usize) -> bool {
    let (Some(message), Some(data)) = (unsafe { message.as_mut() }, unsafe { borrow(data, data_len) }) else {
        return false;
    };

    message.body = Some(Body::Data(Bytes::copy_from_slice(data)));
    true
}

/// Sets the body to UTF-8 text held in memory, copied out of `text`.
///
/// Refused when the octets are not UTF-8; [`soyokaze_message_set_body_data`]
/// takes octets that are not.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `text` must point to `text_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_body_text(message: *mut Message, text: *const u8, text_len: usize) -> bool {
    let (Some(message), Some(text)) = (unsafe { message.as_mut() }, unsafe { borrow_text(text, text_len) }) else {
        return false;
    };

    message.body = Some(Body::Text(text.to_owned()));
    true
}

/// Sets the body to a path, read only when the body is actually sent.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `path` must point to `path_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_body_file(message: *mut Message, path: *const u8, path_len: usize) -> bool {
    let (Some(message), Some(path)) = (unsafe { message.as_mut() }, unsafe { borrow_text(path, path_len) }) else {
        return false;
    };

    message.body = Some(Body::File(path.to_owned()));
    true
}

/// How long the body is, or `-1` when there is none or it is a file that has
/// not been read.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_body_len(message: *const Message) -> i64 {
    match unsafe { message.as_ref() }.and_then(|message| message.body.as_ref()).and_then(|body| body.len()) {
        Some(len) => len as i64,
        None => -1,
    }
}

/// Reads the body, reading the file behind it if there is one.
///
/// Writes an empty buffer when the message has no body. Needs a runtime because
/// a [`Body::File`] is read from the filesystem.
///
/// # Safety
///
/// `runtime` and `message` must be handles that have not been freed, and `out`
/// must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_body(
    runtime: *mut Runtime,
    message: *const Message,
    out: *mut Buffer,
    error: *mut *mut ErrorHandle,
) -> Status {
    let (Some(runtime), Some(message)) = (unsafe { runtime.as_ref() }, unsafe { message.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(body) = message.body.as_ref() else {
        unsafe { *out = Buffer::EMPTY };
        return Status::Ok;
    };

    match runtime.0.block_on(body.bytes()) {
        Ok(octets) => {
            unsafe { *out = Buffer::new(octets.to_vec()) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &Error::Io(failure)) },
    }
}
