//! Carrying [`Url`] and [`Message`] across the boundary.
//!
//! A [`Message`] is reached as a handle, and its field section and body are
//! reached through it rather than as handles of their own — there is no way to
//! hold a section apart from the message it belongs to, and so no way to free
//! one twice.

use bytes::Bytes;

use crate::errors::Error;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Runtime, Slice};
use crate::models::{Body, Message, Method, Role, Url, Version};

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
pub unsafe extern "C" fn soyokaze_url_parse(url: *const u8, url_len: usize, out: *mut *mut Url, error: *mut *mut ErrorHandle) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(text) = (unsafe { Slice::borrow_text(url, url_len) }) else {
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
    Slice::maybe(
        unsafe { message.as_ref() }
            .and_then(|message| message.trailers.as_ref())
            .and_then(|trailers| trailers.iter().nth(index))
            .map(|(name, _)| name),
    )
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
    Slice::maybe(
        unsafe { message.as_ref() }
            .and_then(|message| message.trailers.as_ref())
            .and_then(|trailers| trailers.iter().nth(index))
            .map(|(_, value)| value),
    )
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
        Err(failure) => unsafe { ErrorHandle::report(error, &Error::Io(failure)) },
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
