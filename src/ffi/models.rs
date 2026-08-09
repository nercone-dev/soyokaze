//! Carrying [`URL`] and [`Message`] across the boundary.
//!
//! A [`Message`] is reached as a handle, and its field section and body are
//! reached through it rather than as handles of their own — there is no way to
//! hold a section apart from the message it belongs to, and so no way to free
//! one twice.

use bytes::Bytes;

use crate::errors::Error;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Runtime, Slice};
use crate::models::{Body, Message, Method, Role, URL, Version};

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
            PortKind::UDS => Some(crate::models::Port::UDS(unsafe { Slice::borrow_text(self.path, self.path_len) }?.to_owned())),
        }
    }

    /// Reads `count` ports out of a C array.
    ///
    /// `None` when the array is null or any entry will not parse.
    ///
    /// # Safety
    ///
    /// `ports` must either be null or point to `count` readable [`Port`]
    /// values whose own pointers are valid.
    pub unsafe fn parse_all(ports: *const Port, count: usize) -> Option<Vec<crate::models::Port>> {
        if ports.is_null() {
            return None;
        }

        let mut parsed = Vec::with_capacity(count);
        for index in 0..count {
            parsed.push(unsafe { (*ports.add(index)).parse() }?);
        }

        Some(parsed)
    }
}

/// Parses an absolute URL.
///
/// # Safety
///
/// `url` must point to `url_len` readable octets, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_parse(url: *const u8, url_len: usize, out: *mut *mut URL, error: *mut *mut ErrorHandle) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(text) = (unsafe { Slice::borrow_text(url, url_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match URL::parse(text) {
        Ok(url) => {
            unsafe { *out = Box::into_raw(Box::new(url)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Releases a [`URL`].
///
/// # Safety
///
/// `url` must come from [`soyokaze_url_parse`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_free(url: *mut URL) {
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
pub unsafe extern "C" fn soyokaze_url_scheme(url: *const URL) -> Slice {
    Slice::maybe(unsafe { url.as_ref() }.map(|url| url.scheme.as_str()))
}

/// The host, borrowed from `url`.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_host(url: *const URL) -> Slice {
    Slice::maybe(unsafe { url.as_ref() }.map(|url| url.host.as_str()))
}

/// The request target — path, query and fragment — borrowed from `url`.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_target(url: *const URL) -> Slice {
    Slice::maybe(unsafe { url.as_ref() }.map(|url| url.target.as_str()))
}

/// The port, or zero when `url` is null.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_port(url: *const URL) -> u16 {
    unsafe { url.as_ref() }.map_or(0, |url| url.port)
}

/// Whether the scheme is a secure one.
///
/// # Safety
///
/// As [`soyokaze_url_scheme`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_secure(url: *const URL) -> bool {
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
pub unsafe extern "C" fn soyokaze_url_authority(url: *const URL) -> Buffer {
    match unsafe { url.as_ref() } {
        Some(url) => Buffer::new(url.authority().into_bytes()),
        None => Buffer::EMPTY,
    }
}

/// Builds an empty message, neither a request nor a response yet.
///
/// [`soyokaze_message_request`] and [`soyokaze_message_response`] are the
/// usual entry points; this is for the rare caller assembling one by hand.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_message_new(version: Version) -> *mut Message {
    Box::into_raw(Box::new(Message::new(version)))
}

/// Builds a request.
///
/// # Safety
///
/// `target` must point to `target_len` readable octets. Returns null when it is
/// not UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_request(method: Method, target: *const u8, target_len: usize, version: Version) -> *mut Message {
    match unsafe { Slice::borrow_text(target, target_len) } {
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
    unsafe { message.as_ref() }.is_some_and(|message| message.security.secure)
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
    let field = unsafe { message.as_ref() }.and_then(|message| message.headers.as_ref()).and_then(|headers| headers.iter().nth(index)).map(|(name, _)| name);

    Slice::maybe(field)
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
    let field = unsafe { message.as_ref() }.and_then(|message| message.headers.as_ref()).and_then(|headers| headers.iter().nth(index)).map(|(_, value)| value);

    Slice::maybe(field)
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
    let Some(name) = (unsafe { Slice::borrow_text(name, name_len) }) else {
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
pub unsafe extern "C" fn soyokaze_message_append_header(message: *mut Message, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(message), Some(name), Some(value)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) })
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
pub unsafe extern "C" fn soyokaze_message_insert_header(message: *mut Message, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(message), Some(name), Some(value)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) })
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
    let (Some(message), Some(name)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return false;
    };

    message.headers.as_mut().is_some_and(|headers| headers.remove(name))
}

/// How many fields the message's trailer section holds.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_trailer_count(message: *const Message) -> usize {
    unsafe { message.as_ref() }.and_then(|message| message.trailers.as_ref()).map_or(0, |trailers| trailers.len())
}

/// The name of the trailer field at `index`, borrowed from `message`.
///
/// Absent when there is no such field. Names are stored lowercase.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_trailer_name(message: *const Message, index: usize) -> Slice {
    let field = unsafe { message.as_ref() }.and_then(|message| message.trailers.as_ref()).and_then(|trailers| trailers.iter().nth(index)).map(|(name, _)| name);

    Slice::maybe(field)
}

/// The value of the trailer field at `index`, borrowed from `message`.
///
/// Absent when there is no such field.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_trailer_value(message: *const Message, index: usize) -> Slice {
    let field = unsafe { message.as_ref() }.and_then(|message| message.trailers.as_ref()).and_then(|trailers| trailers.iter().nth(index)).map(|(_, value)| value);

    Slice::maybe(field)
}

/// The first trailer value stored under `name`, borrowed from `message`.
///
/// Absent when the field is not there. The name is matched case-insensitively.
///
/// # Safety
///
/// As [`soyokaze_message_header`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_trailer(message: *const Message, name: *const u8, name_len: usize) -> Slice {
    let Some(name) = (unsafe { Slice::borrow_text(name, name_len) }) else {
        return Slice::ABSENT;
    };

    Slice::maybe(unsafe { message.as_ref() }.and_then(|message| message.trailers.as_ref()).and_then(|trailers| trailers.get(name)))
}

/// Adds a trailer field, keeping any field already stored under the same name.
///
/// Returns whether it was added, as [`soyokaze_message_append_header`].
///
/// # Safety
///
/// As [`soyokaze_message_append_header`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_append_trailer(message: *mut Message, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(message), Some(name), Some(value)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) })
    else {
        return false;
    };

    message.trailers.get_or_insert_default().append(name, value);
    true
}

/// Adds a trailer field, dropping any field already stored under the same name.
///
/// Returns whether it was set, as [`soyokaze_message_append_header`].
///
/// # Safety
///
/// As [`soyokaze_message_append_header`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_insert_trailer(message: *mut Message, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(message), Some(name), Some(value)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) })
    else {
        return false;
    };

    message.trailers.get_or_insert_default().insert(name, value);
    true
}

/// Drops every trailer field stored under `name`.
///
/// Returns whether anything was there to drop.
///
/// # Safety
///
/// As [`soyokaze_message_remove_header`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_remove_trailer(message: *mut Message, name: *const u8, name_len: usize) -> bool {
    let (Some(message), Some(name)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return false;
    };

    message.trailers.as_mut().is_some_and(|trailers| trailers.remove(name))
}

/// The stream the message belongs to, or `-1` when it belongs to none.
///
/// HTTP/1.x has no streams; HTTP/2 and HTTP/3 stamp this on every message they
/// hand over.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_stream_id(message: *const Message) -> i64 {
    match unsafe { message.as_ref() }.and_then(|message| message.stream_id) {
        Some(stream_id) => stream_id.0 as i64,
        None => -1,
    }
}

/// Stamps the message with a stream, or clears it with a negative `stream_id`.
///
/// A server sending responses through `soyokaze_connection_send` must echo the
/// request's stream identifier this way; the serve callbacks do it themselves.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_stream_id(message: *mut Message, stream_id: i64) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    message.stream_id = u64::try_from(stream_id).ok().map(crate::models::StreamID);
    true
}

/// The identifier of the connection the message arrived on, borrowed from
/// `message`.
///
/// Absent when the message has not crossed a connection.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_connection_id(message: *const Message) -> Slice {
    match unsafe { message.as_ref() }.and_then(|message| message.connection_id.as_ref()) {
        Some(id) => Slice::new(&id.0),
        None => Slice::ABSENT,
    }
}

/// Marks the message as travelling over a secure transport, or not.
///
/// This is what the `:scheme` pseudo-header reflects on HTTP/2 and HTTP/3.
/// [`soyokaze_client_fetch`] sets it from the URL itself; this is for requests
/// sent through `soyokaze_connection_send`.
///
/// [`soyokaze_client_fetch`]: crate::ffi::api::client::soyokaze_client_fetch
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_secure(message: *mut Message, secure: bool) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    message.security.secure = secure;
    true
}

/// Whether the request arrived in TLS early data, and so may be a replay.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_early_data(message: *const Message) -> bool {
    unsafe { message.as_ref() }.is_some_and(|message| message.security.early_data)
}

/// Whether the transport underneath was TLS.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_tls(message: *const Message) -> bool {
    unsafe { message.as_ref() }.is_some_and(|message| message.security.tls)
}

/// The negotiated TLS version as its two-octet wire code, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_tls_version(message: *const Message) -> i32 {
    match unsafe { message.as_ref() }.and_then(|message| message.security.tls_version) {
        Some(version) => version.0 as i32,
        None => -1,
    }
}

/// The negotiated TLS named group as its two-octet wire code, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_tls_group(message: *const Message) -> i32 {
    match unsafe { message.as_ref() }.and_then(|message| message.security.tls_group) {
        Some(group) => group.0 as i32,
        None => -1,
    }
}

/// The negotiated TLS cipher suite as its two-octet wire code, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_tls_cipher(message: *const Message) -> i32 {
    match unsafe { message.as_ref() }.and_then(|message| message.security.tls_cipher) {
        Some(cipher) => cipher.0 as i32,
        None => -1,
    }
}

/// Whether the transport underneath was QUIC.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_quic(message: *const Message) -> bool {
    unsafe { message.as_ref() }.is_some_and(|message| message.security.quic)
}

/// The negotiated QUIC version, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_message_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_quic_version(message: *const Message) -> i64 {
    match unsafe { message.as_ref() }.and_then(|message| message.security.quic_version) {
        Some(version) => version as i64,
        None => -1,
    }
}

/// Sets the body to octets held in memory, copied out of `data`.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `data` must point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_body_data(message: *mut Message, data: *const u8, data_len: usize) -> bool {
    let (Some(message), Some(data)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow(data, data_len) }) else {
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
    let (Some(message), Some(text)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(text, text_len) }) else {
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
    let (Some(message), Some(path)) = (unsafe { message.as_mut() }, unsafe { Slice::borrow_text(path, path_len) }) else {
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
pub unsafe extern "C" fn soyokaze_message_body(runtime: *mut Runtime, message: *const Message, out: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
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
        Err(failure) => unsafe { ErrorHandle::report(error, &Error::IO(failure)) },
    }
}

/// What one connection is allowed to spend on the peer's behalf.
///
/// The C half of [`Limits`], field for field. Passing null wherever one of
/// these is asked for takes every default; a caller that wants to change one
/// ceiling starts from [`soyokaze_limits_default`] and adjusts it.
///
/// [`Limits`]: crate::models::Limits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Limits {
    /// In bytes, the total size of the HTTP message allowed for reception.
    pub max_message_size: u64,
    /// In bytes, the size of the HTTP message body allowed for reception.
    pub max_message_body_size: u64,

    /// In bytes, the request/status line ceiling.
    pub max_startline_size: u32,
    /// In bytes, the whole header (or trailer) block.
    pub max_headers_size: u64,
    /// The number of header fields allowed in one block.
    pub max_header_count: u16,
    /// In bytes, the chunk-size line ceiling for chunked transfer encoding.
    pub max_chunk_header_size: u32,

    /// In bytes, how much room each read from a transport is given.
    pub read_chunk_size: u64,
    /// In bytes, the buffer size above which an idle connection gives memory back.
    pub idle_capacity: u64,

    /// The number of connections a listener may negotiate at once.
    pub max_pending_handshakes: u32,

    /// In seconds, how long one read may wait. Zero waits forever.
    pub read_timeout: f64,
    /// In seconds, how long one write may wait. Zero waits forever.
    pub write_timeout: f64,
    /// In seconds, how long one whole message may take to arrive. Zero waits forever.
    pub receive_timeout: f64,
    /// In seconds, how long one whole message may take to send. Zero waits forever.
    pub send_timeout: f64,

    /// In bytes, the body size up to which an HTTP/1.x head and body go out as one write.
    pub inline_body_size: u64,

    /// The number of streams a peer may have open at once, per connection.
    pub max_concurrent_streams: u32,
    /// In bytes, the unread message data one connection may hold.
    pub max_connection_buffer_size: u64,
    /// The number of streams a peer may reset before a response was sent.
    pub max_premature_resets: u32,
    /// In bytes, the largest field compression encoder table this end will keep.
    pub max_encoder_table_size: u64,

    /// The number of frames a peer may send without advancing a stream.
    pub max_idle_frames: u32,
    /// In bytes, the buffered output size at which a body write flushes rather than growing.
    pub output_high_water: u64,

    /// The number of requests one connection may serve over its lifetime. Zero serves forever.
    pub max_requests_per_connection: u64,
    /// In seconds, how long to wait for a blocking QPACK reference.
    pub qpack_block_timeout: f64,
    /// The number of unidirectional streams a peer may open at once.
    pub max_peer_uni_streams: u32,
    /// The number of unacknowledged QPACK field sections the encoder may track.
    pub max_outstanding_sections: u32,
    /// The number of streams that may wait QPACK-blocked at once.
    pub max_blocked_streams: u32,
    /// The number of reads or writes a tunnel will hold before it applies back pressure.
    pub tunnel_backlog: u32,
    pub command_backlog: u32,

    /// In seconds, how long a WebSocket close waits for the peer's echo.
    pub ws_linger_timeout: f64,
    /// The number of continuation frames allowed in one WebSocket message.
    pub ws_max_fragments: u16,

    /// The number of cookies one jar may hold across all origins.
    pub max_cookies: u32,
    /// The number of cookies one jar may hold for a single domain.
    pub max_cookies_per_domain: u16,
    /// The number of hosts one HSTS store may remember.
    pub max_hsts_entries: u32,
}

impl Limits {
    /// The [`Limits`] this stands for.
    ///
    /// [`Limits`]: crate::models::Limits
    pub fn parse(&self) -> crate::models::Limits {
        crate::models::Limits {
            max_message_size: self.max_message_size,
            max_message_body_size: self.max_message_body_size,
            max_startline_size: self.max_startline_size,
            max_headers_size: self.max_headers_size,
            max_header_count: self.max_header_count,
            max_chunk_header_size: self.max_chunk_header_size,
            read_chunk_size: self.read_chunk_size,
            idle_capacity: self.idle_capacity,
            max_pending_handshakes: self.max_pending_handshakes,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            receive_timeout: self.receive_timeout,
            send_timeout: self.send_timeout,
            inline_body_size: self.inline_body_size,
            max_concurrent_streams: self.max_concurrent_streams,
            max_connection_buffer_size: self.max_connection_buffer_size,
            max_premature_resets: self.max_premature_resets,
            max_encoder_table_size: self.max_encoder_table_size,
            max_idle_frames: self.max_idle_frames,
            output_high_water: self.output_high_water,
            max_requests_per_connection: self.max_requests_per_connection,
            qpack_block_timeout: self.qpack_block_timeout,
            max_peer_uni_streams: self.max_peer_uni_streams,
            max_outstanding_sections: self.max_outstanding_sections,
            max_blocked_streams: self.max_blocked_streams,
            tunnel_backlog: self.tunnel_backlog,
            command_backlog: self.command_backlog,
            ws_linger_timeout: self.ws_linger_timeout,
            ws_max_fragments: self.ws_max_fragments,
            max_cookies: self.max_cookies,
            max_cookies_per_domain: self.max_cookies_per_domain,
            max_hsts_entries: self.max_hsts_entries,
        }
    }

    /// The C half of `limits`.
    pub fn build(limits: &crate::models::Limits) -> Self {
        Self {
            max_message_size: limits.max_message_size,
            max_message_body_size: limits.max_message_body_size,
            max_startline_size: limits.max_startline_size,
            max_headers_size: limits.max_headers_size,
            max_header_count: limits.max_header_count,
            max_chunk_header_size: limits.max_chunk_header_size,
            read_chunk_size: limits.read_chunk_size,
            idle_capacity: limits.idle_capacity,
            max_pending_handshakes: limits.max_pending_handshakes,
            read_timeout: limits.read_timeout,
            write_timeout: limits.write_timeout,
            receive_timeout: limits.receive_timeout,
            send_timeout: limits.send_timeout,
            inline_body_size: limits.inline_body_size,
            max_concurrent_streams: limits.max_concurrent_streams,
            max_connection_buffer_size: limits.max_connection_buffer_size,
            max_premature_resets: limits.max_premature_resets,
            max_encoder_table_size: limits.max_encoder_table_size,
            max_idle_frames: limits.max_idle_frames,
            output_high_water: limits.output_high_water,
            max_requests_per_connection: limits.max_requests_per_connection,
            qpack_block_timeout: limits.qpack_block_timeout,
            max_peer_uni_streams: limits.max_peer_uni_streams,
            max_outstanding_sections: limits.max_outstanding_sections,
            max_blocked_streams: limits.max_blocked_streams,
            tunnel_backlog: limits.tunnel_backlog,
            command_backlog: limits.command_backlog,
            ws_linger_timeout: limits.ws_linger_timeout,
            ws_max_fragments: limits.ws_max_fragments,
            max_cookies: limits.max_cookies,
            max_cookies_per_domain: limits.max_cookies_per_domain,
            max_hsts_entries: limits.max_hsts_entries,
        }
    }

    /// The [`Limits`] a pointer stands for: what it points at, or the defaults
    /// when it is null.
    ///
    /// [`Limits`]: crate::models::Limits
    ///
    /// # Safety
    ///
    /// `limits` must either be null or point to a readable [`Limits`].
    pub unsafe fn or_default(limits: *const Limits) -> crate::models::Limits {
        match unsafe { limits.as_ref() } {
            Some(limits) => limits.parse(),
            None => crate::models::Limits::default(),
        }
    }
}

/// The default [`Limits`], to be adjusted and passed back.
///
/// [`Limits`]: crate::models::Limits
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_limits_default() -> Limits {
    Limits::build(&crate::models::Limits::default())
}

impl Version {
    /// Reads a version list out of a C array of `soyokaze_version_t` values.
    ///
    /// A null `versions` means take the default list. `None` when an entry
    /// names no version.
    ///
    /// # Safety
    ///
    /// `versions` must either be null or point to `count` readable numbers.
    pub unsafe fn parse_all(versions: *const i32, count: usize) -> Option<Vec<Version>> {
        if versions.is_null() {
            return Some(Vec::new());
        }

        let mut parsed = Vec::with_capacity(count);

        for index in 0..count {
            parsed.push(match unsafe { *versions.add(index) } {
                0 => Version::V1_0,
                1 => Version::V1_1,
                2 => Version::V2_0,
                3 => Version::V3_0,
                _ => return None,
            });
        }

        Some(parsed)
    }
}

impl Role {
    /// The `soyokaze_role_t` number for a [`Role`].
    ///
    /// The two enums are kept in the same order, so this is the crate's own
    /// grading rather than a narrowing of it: a caller can still tell a proxy
    /// from a user agent, and a tunnel from either.
    pub fn build(role: Role) -> u32 {
        match role {
            Role::UserAgent => 0,
            Role::Origin => 1,
            Role::Proxy => 2,
            Role::Gateway => 3,
            Role::Tunnel => 4,
        }
    }
}

/// What a port or a version runs over.
///
/// The C half of [`TransportKind`]. Nothing keys on a particular version
/// number: a port carries exactly the versions whose transport matches its
/// own, so a future version is routed by what it runs over rather than by
/// name.
///
/// [`TransportKind`]: crate::models::TransportKind
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportKind {
    /// An ordered byte stream: TCP, or a Unix domain socket.
    Stream = 0,
    /// QUIC, over UDP.
    QUIC = 1,
}

impl TransportKind {
    /// The C half of `transport`.
    pub fn build(transport: crate::models::TransportKind) -> Self {
        match transport {
            crate::models::TransportKind::Stream => Self::Stream,
            crate::models::TransportKind::QUIC => Self::QUIC,
        }
    }
}

/// The transport family a port carries.
///
/// A null `port`, or one whose socket path will not read, reads as
/// [`TransportKind::Stream`].
///
/// # Safety
///
/// `port` must either be null or point to a readable [`Port`] whose own
/// pointers are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_port_transport(port: *const Port) -> TransportKind {
    match unsafe { port.as_ref() }.and_then(|port| unsafe { port.parse() }) {
        Some(port) => TransportKind::build(port.transport()),
        None => TransportKind::Stream,
    }
}

/// Whether a port can carry a version at all.
///
/// # Safety
///
/// As [`soyokaze_port_transport`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_port_carries(port: *const Port, version: Version) -> bool {
    unsafe { port.as_ref() }.and_then(|port| unsafe { port.parse() }).is_some_and(|port| port.carries(version))
}

/// Which of `versions` a port can carry, in the order they were given.
///
/// Writes at most `count` versions through `out` and returns how many there
/// were. A null `out` counts without writing.
///
/// # Safety
///
/// As [`soyokaze_port_transport`], `versions` must point to `count` readable
/// versions, and `out` must either be null or be writable for `count` of them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_port_offers(port: *const Port, versions: *const Version, count: usize, out: *mut Version) -> usize {
    let (Some(port), Some(versions)) = (unsafe { port.as_ref() }.and_then(|port| unsafe { port.parse() }), unsafe { Version::borrow_all(versions, count) }) else {
        return 0;
    };

    let offered = port.offers(&versions);

    if !out.is_null() {
        for (index, version) in offered.iter().take(count).enumerate() {
            unsafe { *out.add(index) = *version };
        }
    }

    offered.len()
}

impl Version {
    /// Borrows `count` versions from a C array.
    ///
    /// A null array borrows nothing, which is how an absent argument is
    /// passed.
    ///
    /// # Safety
    ///
    /// `versions` must either be null or point to `count` readable versions.
    pub unsafe fn borrow_all<'a>(versions: *const Version, count: usize) -> Option<&'a [Version]> {
        if versions.is_null() {
            return (count == 0).then_some(&[][..]);
        }

        Some(unsafe { std::slice::from_raw_parts(versions, count) })
    }
}

/// The port a scheme is reached on when the URL does not say.
///
/// Zero for a scheme with no default.
///
/// # Safety
///
/// `scheme` must either be null or point to `scheme_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_default_port(scheme: *const u8, scheme_len: usize) -> u16 {
    match unsafe { Slice::borrow_text(scheme, scheme_len) } {
        Some(scheme) => URL::default_port(scheme),
        None => 0,
    }
}

/// The authority a scheme, host and port spell out, owned by the caller.
///
/// The port is left off when it is the scheme's default, which is what an
/// origin expects to see in `Host` or `:authority`.
///
/// # Safety
///
/// `scheme` and `host` must either be null or point to their stated number of
/// readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_url_authority_of(scheme: *const u8, scheme_len: usize, host: *const u8, host_len: usize, port: u16) -> Buffer {
    let (Some(scheme), Some(host)) = (unsafe { Slice::borrow_text(scheme, scheme_len) }, unsafe { Slice::borrow_text(host, host_len) }) else {
        return Buffer::EMPTY;
    };

    Buffer::new(URL::authority_of(scheme, host, port).into_bytes())
}

/// The ALPN identifier a version is negotiated under, borrowed from the
/// library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_version_alpn(version: Version) -> Slice {
    Slice::text(version.alpn())
}

/// The version an ALPN identifier names, or `-1` when it names none.
///
/// # Safety
///
/// `alpn` must either be null or point to `alpn_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_version_from_alpn(alpn: *const u8, alpn_len: usize) -> i32 {
    match unsafe { Slice::borrow(alpn, alpn_len) }.and_then(Version::from_alpn) {
        Some(version) => version as i32,
        None => -1,
    }
}

/// The major version number.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_version_major(version: Version) -> u8 {
    version.major()
}

/// What the version runs over.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_version_transport(version: Version) -> TransportKind {
    TransportKind::build(version.transport())
}

/// How the version is written out, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_version_name(version: Version) -> Slice {
    Slice::text(version.as_str())
}

/// The version a name spells out, or `-1` when it spells none.
///
/// Accepts what [`soyokaze_version_name`] produces, and the bare `1.0`, `1.1`,
/// `2` and `3` forms alongside them.
///
/// # Safety
///
/// `name` must either be null or point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_version_parse(name: *const u8, name_len: usize) -> i32 {
    match unsafe { Slice::borrow_text(name, name_len) }.and_then(|name| name.parse::<Version>().ok()) {
        Some(version) => version as i32,
        None => -1,
    }
}

/// The ALPN protocol list for `versions`, in the wire format a handshake
/// carries: each identifier preceded by its length.
///
/// # Safety
///
/// `versions` must either be null or point to `count` readable versions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_alpn_wire(versions: *const Version, count: usize) -> Buffer {
    match unsafe { Version::borrow_all(versions, count) } {
        Some(versions) => Buffer::new(crate::models::ALPN::wire(versions)),
        None => Buffer::EMPTY,
    }
}

/// Picks the first identifier a client offered that this end also offers.
///
/// Both lists are in the wire format [`soyokaze_alpn_wire`] produces. The
/// answer is borrowed from `client`, and is absent when nothing matched.
///
/// # Safety
///
/// `versions` must either be null or point to `count` readable versions, and
/// `client` must either be null or point to `client_len` readable octets that
/// outlive the returned slice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_alpn_select(versions: *const Version, count: usize, client: *const u8, client_len: usize) -> Slice {
    let (Some(versions), Some(client)) = (unsafe { Version::borrow_all(versions, count) }, unsafe { Slice::borrow(client, client_len) }) else {
        return Slice::ABSENT;
    };

    match crate::models::ALPN::select(&crate::models::ALPN::list(versions), client) {
        Some(chosen) => Slice::new(chosen),
        None => Slice::ABSENT,
    }
}

/// The version an agreed ALPN identifier settles on.
///
/// A null `alpn` stands for a handshake that agreed on nothing, which settles
/// on HTTP/1.1 when it is offered and fails otherwise.
///
/// # Safety
///
/// As [`soyokaze_alpn_select`], and `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_alpn_negotiated(alpn: *const u8, alpn_len: usize, versions: *const Version, count: usize, out: *mut Version, error: *mut *mut ErrorHandle) -> Status {
    let Some(versions) = (unsafe { Version::borrow_all(versions, count) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match crate::models::ALPN::negotiated(unsafe { Slice::borrow(alpn, alpn_len) }, versions) {
        Ok(version) => {
            if !out.is_null() {
                unsafe { *out = version };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The method as it is written on the wire, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_method_name(method: Method) -> Slice {
    Slice::text(method.as_str())
}

/// The method a name spells out, or `-1` when it spells none.
///
/// # Safety
///
/// `name` must either be null or point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_method_parse(name: *const u8, name_len: usize) -> i32 {
    match unsafe { Slice::borrow_text(name, name_len) }.and_then(|name| name.parse::<Method>().ok()) {
        Some(method) => method as i32,
        None => -1,
    }
}

/// Whether the method is read-only, so that issuing it changes nothing.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_method_safe(method: Method) -> bool {
    method.safe()
}

/// Whether repeating the method has the same effect as issuing it once.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_method_idempotent(method: Method) -> bool {
    method.idempotent()
}

/// Whether this role sends requests and reads responses.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_role_is_client(role: Role) -> bool {
    role.is_client()
}

/// Whether this role reads requests and sends responses.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_role_is_server(role: Role) -> bool {
    role.is_server()
}

/// How field names are cased on the way out.
///
/// The C half of [`HeaderCase`]. Names are always stored lowercase and
/// re-cased as they are written.
///
/// [`HeaderCase`]: crate::models::HeaderCase
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderCase {
    /// `Content-Length`: each dash-separated word capitalised.
    Title = 0,
    /// `content-length`: entirely lowercase.
    Lower = 1,
}

impl HeaderCase {
    /// The [`HeaderCase`] this stands for.
    ///
    /// [`HeaderCase`]: crate::models::HeaderCase
    pub fn parse(self) -> crate::models::HeaderCase {
        match self {
            Self::Title => crate::models::HeaderCase::Title,
            Self::Lower => crate::models::HeaderCase::Lower,
        }
    }

    /// The C half of `case`.
    pub fn build(case: crate::models::HeaderCase) -> Self {
        match case {
            crate::models::HeaderCase::Title => Self::Title,
            crate::models::HeaderCase::Lower => Self::Lower,
        }
    }
}

/// The casing a version expects: title case for HTTP/1.x, lowercase above.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_header_case_from_version(version: Version) -> HeaderCase {
    HeaderCase::build(crate::models::HeaderCase::from_version(version))
}

/// A field name in this casing, owned by the caller.
///
/// # Safety
///
/// `name` must either be null or point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_header_case_apply(case: HeaderCase, name: *const u8, name_len: usize) -> Buffer {
    match unsafe { Slice::borrow_text(name, name_len) } {
        Some(name) => Buffer::new(case.parse().apply(name).into_bytes()),
        None => Buffer::EMPTY,
    }
}

/// Re-cases a field name already written into `name`, in place.
///
/// # Safety
///
/// `name` must either be null or point to `name_len` writable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_header_case_apply_in_place(case: HeaderCase, name: *mut u8, name_len: usize) -> bool {
    if name.is_null() {
        return false;
    }

    case.parse().apply_in_place(unsafe { std::slice::from_raw_parts_mut(name, name_len) });
    true
}

pub use crate::models::Headers;

/// The presence bit that stands for a well-known field name, or zero.
///
/// A [`Headers`] keeps the bitwise or of these over every field it holds,
/// which lets a lookup for one of these names rule itself out without walking
/// the list. The name must already be lowercase.
///
/// # Safety
///
/// `name` must either be null or point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_well_known(name: *const u8, name_len: usize) -> u32 {
    match unsafe { Slice::borrow_text(name, name_len) } {
        Some(name) => Headers::well_known(name),
        None => 0,
    }
}

/// `1 << index` when `matched`, and zero otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_headers_bit(matched: bool, index: u32) -> u32 {
    Headers::bit(matched, index)
}

/// Whether a stored lowercase name is the field `name` asks for.
///
/// # Safety
///
/// `stored` and `name` must either be null or point to their stated number of
/// readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_named(stored: *const u8, stored_len: usize, name: *const u8, name_len: usize) -> bool {
    let (Some(stored), Some(name)) = (unsafe { Slice::borrow_text(stored, stored_len) }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return false;
    };

    Headers::named(stored, name)
}

/// Builds an empty field section.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_headers_new() -> *mut Headers {
    Box::into_raw(Box::new(Headers::new()))
}

/// Builds an empty field section with room for `fields` entries.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_headers_with_capacity(fields: usize) -> *mut Headers {
    Box::into_raw(Box::new(Headers::with_capacity(fields)))
}

/// Releases a [`Headers`].
///
/// Only one built by [`soyokaze_headers_new`] or
/// [`soyokaze_headers_with_capacity`] is freed this way; one borrowed from a
/// message belongs to that message.
///
/// # Safety
///
/// `headers` must come from one of those two calls and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_free(headers: *mut Headers) {
    if !headers.is_null() {
        drop(unsafe { Box::from_raw(headers) });
    }
}

/// How many fields the section holds.
///
/// # Safety
///
/// `headers` must either be null or be a section that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_len(headers: *const Headers) -> usize {
    unsafe { headers.as_ref() }.map_or(0, |headers| headers.len())
}

/// Whether the section holds nothing.
///
/// # Safety
///
/// As [`soyokaze_headers_len`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_is_empty(headers: *const Headers) -> bool {
    unsafe { headers.as_ref() }.is_none_or(|headers| headers.is_empty())
}

/// The name of the field at `index`, borrowed from the section.
///
/// # Safety
///
/// As [`soyokaze_headers_len`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_name(headers: *const Headers, index: usize) -> Slice {
    Slice::maybe(unsafe { headers.as_ref() }.and_then(|headers| headers.fields().get(index)).map(|(name, _)| name.as_str()))
}

/// The value of the field at `index`, borrowed from the section.
///
/// # Safety
///
/// As [`soyokaze_headers_len`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_value(headers: *const Headers, index: usize) -> Slice {
    Slice::maybe(unsafe { headers.as_ref() }.and_then(|headers| headers.fields().get(index)).map(|(_, value)| value.as_str()))
}

/// Whether the section carries `name` at all.
///
/// # Safety
///
/// As [`soyokaze_headers_len`], and `name` must either be null or point to
/// `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_contains(headers: *const Headers, name: *const u8, name_len: usize) -> bool {
    let (Some(headers), Some(name)) = (unsafe { headers.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return false;
    };

    headers.contains(name)
}

/// Whether the section carries no field named `name`.
///
/// # Safety
///
/// As [`soyokaze_headers_contains`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_absent(headers: *const Headers, name: *const u8, name_len: usize) -> bool {
    let (Some(headers), Some(name)) = (unsafe { headers.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return true;
    };

    headers.absent(name)
}

/// The first value stored under `name`, borrowed from the section.
///
/// # Safety
///
/// As [`soyokaze_headers_contains`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_get(headers: *const Headers, name: *const u8, name_len: usize) -> Slice {
    let (Some(headers), Some(name)) = (unsafe { headers.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return Slice::ABSENT;
    };

    Slice::maybe(headers.get(name))
}

/// How many values are stored under `name`.
///
/// # Safety
///
/// As [`soyokaze_headers_contains`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_get_all_count(headers: *const Headers, name: *const u8, name_len: usize) -> usize {
    let (Some(headers), Some(name)) = (unsafe { headers.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return 0;
    };

    headers.get_all(name).count()
}

/// The `index`th value stored under `name`, borrowed from the section.
///
/// # Safety
///
/// As [`soyokaze_headers_contains`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_get_all(headers: *const Headers, name: *const u8, name_len: usize, index: usize) -> Slice {
    let (Some(headers), Some(name)) = (unsafe { headers.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return Slice::ABSENT;
    };

    Slice::maybe(headers.get_all(name).nth(index))
}

/// Appends a field, keeping whatever is already stored under the name.
///
/// # Safety
///
/// As [`soyokaze_headers_contains`], and `value` must either be null or point
/// to `value_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_append(headers: *mut Headers, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(headers), Some(name), Some(value)) = (unsafe { headers.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    headers.append(name, value);
    true
}

/// Appends a field whose name is already lowercase.
///
/// Skips the lowercasing [`soyokaze_headers_append`] does. A name that is not
/// already lowercase will never be found by a lookup.
///
/// # Safety
///
/// As [`soyokaze_headers_append`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_append_lowercase(headers: *mut Headers, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(headers), Some(name), Some(value)) = (unsafe { headers.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    headers.append_lowercase(name, value);
    true
}

/// Stores a field, dropping whatever was already under the name.
///
/// # Safety
///
/// As [`soyokaze_headers_append`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_insert(headers: *mut Headers, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(headers), Some(name), Some(value)) = (unsafe { headers.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    headers.insert(name, value);
    true
}

/// Drops every field stored under `name`, returning whether any was there.
///
/// # Safety
///
/// As [`soyokaze_headers_contains`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_headers_remove(headers: *mut Headers, name: *const u8, name_len: usize) -> bool {
    let (Some(headers), Some(name)) = (unsafe { headers.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }) else {
        return false;
    };

    headers.remove(name)
}

/// The message's field section, borrowed from it.
///
/// Built empty when the message has none yet, so the pointer is null only when
/// `message` is. It belongs to the message and must not be freed; it stays
/// valid until the message is freed or its section is replaced.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_headers(message: *mut Message) -> *mut Headers {
    match unsafe { message.as_mut() } {
        Some(message) => message.headers.get_or_insert_with(Headers::new),
        None => std::ptr::null_mut(),
    }
}

/// The message's trailer section, borrowed from it.
///
/// As [`soyokaze_message_headers`], for the fields that follow the body.
///
/// # Safety
///
/// As [`soyokaze_message_headers`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_trailers(message: *mut Message) -> *mut Headers {
    match unsafe { message.as_mut() } {
        Some(message) => message.trailers.get_or_insert_with(Headers::new),
        None => std::ptr::null_mut(),
    }
}

/// Whether the message opens a tunnel rather than carrying a body.
///
/// `method` is the request method a response is being read against, and is
/// ignored on a request; pass `-1` when there is none.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_tunneling(message: *const Message, method: i32) -> bool {
    let Some(message) = (unsafe { message.as_ref() }) else {
        return false;
    };

    message.tunneling(Method::from_code(method))
}

impl Method {
    /// The method a wire code names, or `None` when it names none.
    ///
    /// A negative code stands for an absent method, which is how a caller says
    /// it does not know which request a response answers.
    pub fn from_code(code: i32) -> Option<Self> {
        Some(match code {
            0 => Self::GET,
            1 => Self::HEAD,
            2 => Self::POST,
            3 => Self::PUT,
            4 => Self::DELETE,
            5 => Self::CONNECT,
            6 => Self::OPTIONS,
            7 => Self::TRACE,
            8 => Self::PATCH,
            _ => return None,
        })
    }
}

/// Sets which version framed the message.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_version(message: *mut Message, version: Version) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    message.version = version;
    true
}

/// Sets the request method, or clears it with a negative `method`.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_method(message: *mut Message, method: i32) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    message.method = Method::from_code(method);
    true
}

/// Sets the request target, or clears it with a null `target`.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`], and `target` must either be null or point
/// to `target_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_target(message: *mut Message, target: *const u8, target_len: usize) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    if target.is_null() {
        message.target = None;
        return true;
    }

    let Some(target) = (unsafe { Slice::borrow_text(target, target_len) }) else {
        return false;
    };

    message.target = Some(target.to_owned());
    true
}

/// Sets the response status code, or clears it with a negative `status_code`.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_status_code(message: *mut Message, status_code: i32) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    message.status_code = u16::try_from(status_code).ok();
    true
}

/// Sets the connection the message belongs to, or clears it with a null `id`.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`], and `id` must either be null or point to
/// `id_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_set_connection_id(message: *mut Message, id: *const u8, id_len: usize) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    message.connection_id = unsafe { Slice::borrow(id, id_len) }.map(|id| crate::models::ConnectionID(Bytes::copy_from_slice(id)));
    true
}

/// Which kind of body a message carries.
///
/// The C half of [`Body`], with [`BodyKind::None`] added for the message that
/// carries none.
///
/// [`Body`]: crate::models::Body
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BodyKind {
    /// No body at all.
    None = 0,
    /// Octets held in memory.
    Data = 1,
    /// A UTF-8 string held in memory.
    Text = 2,
    /// A filesystem path, read when the body is needed.
    File = 3,
}

/// Which kind of body the message carries.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_body_kind(message: *const Message) -> BodyKind {
    match unsafe { message.as_ref() }.and_then(|message| message.body.as_ref()) {
        Some(Body::Data(_)) => BodyKind::Data,
        Some(Body::Text(_)) => BodyKind::Text,
        Some(Body::File(_)) => BodyKind::File,
        None => BodyKind::None,
    }
}

/// Whether the body is known to be empty.
///
/// A file that has not been read counts as non-empty, since its length is not
/// known until it is.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_body_is_empty(message: *const Message) -> bool {
    unsafe { message.as_ref() }.and_then(|message| message.body.as_ref()).is_none_or(|body| body.is_empty())
}

/// The body's octets when they are already in memory, borrowed from the
/// message.
///
/// Absent for a file that has not been read, which
/// `soyokaze_message_body` reads instead.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_body_inline(message: *const Message) -> Slice {
    match unsafe { message.as_ref() }.and_then(|message| message.body.as_ref()) {
        Some(Body::Data(data)) => Slice::new(data),
        Some(Body::Text(text)) => Slice::text(text),
        _ => Slice::ABSENT,
    }
}

/// The path a file body names, borrowed from the message.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_body_path(message: *const Message) -> Slice {
    match unsafe { message.as_ref() }.and_then(|message| message.body.as_ref()) {
        Some(Body::File(path)) => Slice::text(path),
        _ => Slice::ABSENT,
    }
}

/// Clears the body, returning whether there was a message.
///
/// # Safety
///
/// As [`soyokaze_message_tunneling`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_clear_body(message: *mut Message) -> bool {
    let Some(message) = (unsafe { message.as_mut() }) else {
        return false;
    };

    message.body = None;
    true
}
