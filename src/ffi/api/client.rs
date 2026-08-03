//! Dialling an origin and issuing requests, from C.
//!
//! [`soyokaze_client_fetch`] and its shorthands each dial, exchange one
//! message, and close. [`soyokaze_client_open`] hands back the connection
//! instead, so several messages may go over one.

use crate::api::client::Client;
use crate::ffi::api::common::Limits;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::models::Port;
use crate::ffi::websocket::WebSocket;
use crate::ffi::{borrow, borrow_text, Buffer, Runtime, Slice};
use crate::models::{Message, Method, Role, Url, Version};
use crate::protocol::base::{AnyConnection, Connection};

/// Reads a version list out of a C array of `soyokaze_version_t` values.
///
/// A null `versions` means take the default list. `None` when an entry names
/// no version.
///
/// # Safety
///
/// `versions` must either be null or point to `count` readable numbers.
pub unsafe fn parse_versions(versions: *const i32, count: usize) -> Option<Vec<Version>> {
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

/// The limits a client applies on top of the per-message [`Limits`].
///
/// The C half of [`ClientLimits`], field for field.
///
/// [`ClientLimits`]: crate::api::client::ClientLimits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClientLimits {
    /// The limits each connection holds itself to.
    pub message: Limits,
    /// In seconds, how long establishing one connection may take, TLS
    /// handshake included. Zero waits forever.
    pub connection_timeout: f64,
}

impl ClientLimits {
    /// The [`ClientLimits`] this stands for.
    ///
    /// [`ClientLimits`]: crate::api::client::ClientLimits
    pub fn parse(&self) -> crate::api::client::ClientLimits {
        crate::api::client::ClientLimits { message: self.message.parse(), connection_timeout: self.connection_timeout }
    }
}

/// The default [`ClientLimits`], to be adjusted and passed back.
///
/// [`ClientLimits`]: crate::api::client::ClientLimits
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_client_limits_default() -> ClientLimits {
    let limits = crate::api::client::ClientLimits::default();
    ClientLimits { message: Limits::build(&limits.message), connection_timeout: limits.connection_timeout }
}

/// One host's ECH configuration list.
///
/// A host of `*` applies wherever no exact entry matches, as
/// [`ClientConfig::ech`] documents.
///
/// [`ClientConfig::ech`]: crate::api::client::ClientConfig::ech
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EchEntry {
    /// The host the list applies to.
    pub host: Slice,
    /// The `ECHConfigList`, as `soyokaze_ech_keys_config_list` produces it.
    pub config_list: Slice,
}

/// How a [`Client`] is configured.
///
/// Passing null wherever one of these is asked for takes every default:
/// negotiate the version, default limits, TLS on, the platform trust store,
/// no ECH, cookies kept, HSTS remembered. A null pointer inside the struct
/// takes that field's default the same way.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClientConfig {
    /// The versions to offer, most preferred first, as `soyokaze_version_t`
    /// numbers. Null offers every supported version; exactly one entry pins
    /// the version instead of negotiating one.
    pub versions: *const i32,
    /// How many entries `versions` holds.
    pub version_count: usize,

    /// The limits every connection this client makes will hold itself to.
    pub limits: *const ClientLimits,

    /// Whether a stream transport is wrapped in TLS.
    pub secure: bool,
    /// Whether a cookie jar is kept across requests.
    pub cookies: bool,
    /// Whether an HSTS store is kept across requests.
    pub hsts: bool,

    /// The certificates to trust instead of the platform store, each DER or
    /// PEM. Null keeps the platform store.
    pub roots: *const Slice,
    /// How many entries `roots` holds.
    pub root_count: usize,

    /// The ECH configuration lists to use when dialling each host.
    pub ech: *const EchEntry,
    /// How many entries `ech` holds.
    pub ech_count: usize,
}

impl ClientConfig {
    /// The configuration a null pointer stands for.
    pub const DEFAULT: Self = Self {
        versions: std::ptr::null(),
        version_count: 0,
        limits: std::ptr::null(),
        secure: true,
        cookies: true,
        hsts: true,
        roots: std::ptr::null(),
        root_count: 0,
        ech: std::ptr::null(),
        ech_count: 0,
    };

    /// The [`Client`] this configures.
    ///
    /// `None` when an entry is unusable: a number that names no version, a
    /// null root, or an ECH host that is null or not UTF-8.
    ///
    /// # Safety
    ///
    /// Every pointer in the struct must either be null or point to its stated
    /// number of readable elements, themselves valid.
    pub unsafe fn build(&self) -> Option<Client> {
        let mut config = crate::api::client::ClientConfig {
            secure: self.secure,
            cookies: self.cookies,
            hsts: self.hsts,
            ..crate::api::client::ClientConfig::default()
        };

        let versions = unsafe { parse_versions(self.versions, self.version_count) }?;
        if !versions.is_empty() {
            config.versions = versions;
        }

        if let Some(limits) = unsafe { self.limits.as_ref() } {
            config.limits = limits.parse();
        }

        if !self.roots.is_null() {
            let mut roots = Vec::with_capacity(self.root_count);
            for index in 0..self.root_count {
                let slice = unsafe { *self.roots.add(index) };
                roots.push(unsafe { borrow(slice.data, slice.len) }?.to_vec());
            }
            config.roots = Some(roots);
        }

        if !self.ech.is_null() {
            for index in 0..self.ech_count {
                let entry = unsafe { *self.ech.add(index) };
                let host = unsafe { borrow_text(entry.host.data, entry.host.len) }?;
                let list = unsafe { borrow(entry.config_list.data, entry.config_list.len) }?;
                config.ech.insert(host.to_owned(), list.to_vec());
            }
        }

        Some(Client::new(config))
    }
}

/// Builds a [`Client`].
///
/// A null `config` takes [`ClientConfig::DEFAULT`]. Returns null when the
/// configuration holds an unusable entry.
///
/// # Safety
///
/// `config` must either be null or point to a readable [`ClientConfig`] whose
/// own pointers are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_new(config: *const ClientConfig) -> *mut Client {
    let config = unsafe { config.as_ref() }.copied().unwrap_or(ClientConfig::DEFAULT);

    match unsafe { config.build() } {
        Some(client) => Box::into_raw(Box::new(client)),
        None => std::ptr::null_mut(),
    }
}

/// Releases a [`Client`].
///
/// # Safety
///
/// `client` must come from [`soyokaze_client_new`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_free(client: *mut Client) {
    if !client.is_null() {
        drop(unsafe { Box::from_raw(client) });
    }
}

/// Makes one request and hands back the response.
///
/// Dials, exchanges, and closes. HSTS is applied to the URL first; `Host` and
/// `Cookie` are filled in unless `request` already carries them; and any
/// `Set-Cookie` and `Strict-Transport-Security` on the response are taken into
/// the client's state. Redirects are not followed.
///
/// `request` may be null. When it is not, its field section and body are used
/// for the request and the handle is consumed — the caller must not free it.
///
/// # Safety
///
/// `runtime` and `client` must be handles that have not been freed, `url` must
/// point to `url_len` readable octets, `request` must either be null or be a
/// message handle the caller owns, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_fetch(runtime: *mut Runtime, client: *const Client, method: Method, url: *const u8, url_len: usize, request: *mut Message, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    let request = (!request.is_null()).then(|| *unsafe { Box::from_raw(request) });

    let (Some(runtime), Some(client), Some(url)) = (unsafe { runtime.as_ref() }, unsafe { client.as_ref() }, unsafe { borrow_text(url, url_len) })
    else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let (headers, body) = match request {
        Some(request) => (request.headers, request.body),
        None => (None, None),
    };

    match runtime.0.block_on(client.fetch(method, url, headers, body)) {
        Ok(response) => {
            unsafe { *out = Box::into_raw(Box::new(response)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// A `GET`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_get(runtime: *mut Runtime, client: *const Client, url: *const u8, url_len: usize, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::GET, url, url_len, std::ptr::null_mut(), out, error) }
}

/// A `HEAD`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_head(runtime: *mut Runtime, client: *const Client, url: *const u8, url_len: usize, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::HEAD, url, url_len, std::ptr::null_mut(), out, error) }
}

/// A `POST`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_post(runtime: *mut Runtime, client: *const Client, url: *const u8, url_len: usize, request: *mut Message, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::POST, url, url_len, request, out, error) }
}

/// A `PUT`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_put(runtime: *mut Runtime, client: *const Client, url: *const u8, url_len: usize, request: *mut Message, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::PUT, url, url_len, request, out, error) }
}

/// A `DELETE`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_delete(runtime: *mut Runtime, client: *const Client, url: *const u8, url_len: usize, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::DELETE, url, url_len, std::ptr::null_mut(), out, error) }
}

/// Opens a connection for a URL, taking the transport from its scheme.
///
/// # Safety
///
/// `runtime`, `client` and `url` must be handles that have not been freed, and
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_open(runtime: *mut Runtime, client: *const Client, url: *const Url, out: *mut *mut AnyConnection, error: *mut *mut ErrorHandle) -> Status {
    let (Some(runtime), Some(client), Some(url)) = (unsafe { runtime.as_ref() }, unsafe { client.as_ref() }, unsafe { url.as_ref() })
    else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match runtime.0.block_on(client.open(url)) {
        Ok(connection) => {
            unsafe { *out = Box::into_raw(Box::new(connection)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Opens a connection to a host on a given port.
///
/// The port decides the transport, and so which versions are available.
///
/// # Safety
///
/// `runtime` and `client` must be handles that have not been freed, `host` must
/// point to `host_len` readable octets, `port` must point to a readable [`Port`]
/// whose own pointers are valid, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_connect(runtime: *mut Runtime, client: *const Client, host: *const u8, host_len: usize, port: *const Port, out: *mut *mut AnyConnection, error: *mut *mut ErrorHandle) -> Status {
    let (Some(runtime), Some(client), Some(host), Some(port)) = (
        unsafe { runtime.as_ref() },
        unsafe { client.as_ref() },
        unsafe { borrow_text(host, host_len) },
        unsafe { port.as_ref() },
    ) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let Some(port) = (unsafe { port.parse() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match runtime.0.block_on(client.connect(host, port)) {
        Ok(connection) => {
            unsafe { *out = Box::into_raw(Box::new(connection)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Sends a request over an open connection and waits for the response.
///
/// Informational (1xx) responses are read past. `request` is consumed — the
/// caller must not free it.
///
/// # Safety
///
/// `runtime`, `client`, `connection` and `request` must be handles that have not
/// been freed, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_request(runtime: *mut Runtime, client: *const Client, connection: *mut AnyConnection, request: *mut Message, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    if request.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let request = *unsafe { Box::from_raw(request) };

    let (Some(runtime), Some(client), Some(connection)) = (unsafe { runtime.as_ref() }, unsafe { client.as_ref() }, unsafe { connection.as_mut() })
    else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match runtime.0.block_on(client.request(connection, request)) {
        Ok(response) => {
            unsafe { *out = Box::into_raw(Box::new(response)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Opens a WebSocket connection.
///
/// The handshake follows whichever version is negotiated: an HTTP/1.1
/// upgrade, or extended CONNECT over HTTP/2 and HTTP/3. The socket carries
/// its runtime with it, so the WebSocket calls take none — but `runtime`
/// must outlive the socket.
///
/// # Safety
///
/// `runtime` and `client` must be handles that have not been freed, `url`
/// must point to `url_len` readable octets, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_websocket(runtime: *mut Runtime, client: *const Client, url: *const u8, url_len: usize, out: *mut *mut WebSocket, error: *mut *mut ErrorHandle) -> Status {
    let (Some(runtime), Some(client), Some(url)) = (unsafe { runtime.as_ref() }, unsafe { client.as_ref() }, unsafe { borrow_text(url, url_len) })
    else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match runtime.0.block_on(client.websocket(url)) {
        Ok(connection) => {
            unsafe { *out = Box::into_raw(Box::new(WebSocket { connection, handle: runtime.0.handle().clone() })) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The version the connection settled on.
///
/// A null `connection` reads as [`Version::V1_1`].
///
/// # Safety
///
/// `connection` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_version(connection: *const AnyConnection) -> Version {
    unsafe { connection.as_ref() }.map_or(Version::V1_1, |connection| connection.version())
}

/// What this end of the connection is doing on it.
///
/// One of the `soyokaze_role_t` numbers; a null `connection` reads as
/// [`Role::UserAgent`], which is what a connection this library hands a C
/// caller from the client side is.
///
/// # Safety
///
/// As [`soyokaze_connection_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_role(connection: *const AnyConnection) -> u32 {
    match unsafe { connection.as_ref() } {
        Some(connection) => role(connection.role()),
        None => role(Role::UserAgent),
    }
}

/// The `soyokaze_role_t` number for a [`Role`].
///
/// The two enums are kept in the same order, so this is the crate's own
/// grading rather than a narrowing of it: a caller can still tell a proxy from
/// a user agent, and a tunnel from either.
pub fn role(role: Role) -> u32 {
    match role {
        Role::UserAgent => 0,
        Role::Origin => 1,
        Role::Proxy => 2,
        Role::Gateway => 3,
        Role::Tunnel => 4,
    }
}

/// The connection's identifier, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_connection_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_id(connection: *const AnyConnection) -> Buffer {
    match unsafe { connection.as_ref() } {
        Some(connection) => Buffer::new(connection.id().0.to_vec()),
        None => Buffer::EMPTY,
    }
}

/// Sends one message over an open connection, without waiting for anything
/// back.
///
/// This is the raw half of [`soyokaze_client_request`], for pipelining
/// requests or streaming responses by hand. On HTTP/2 and HTTP/3 a response
/// must carry the stream identifier of the request it answers, set with
/// `soyokaze_message_set_stream_id`. `message` is consumed — the caller must
/// not free it.
///
/// # Safety
///
/// `runtime` and `connection` must be handles that have not been freed, and
/// `message` must be a message handle the caller owns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_send(runtime: *mut Runtime, connection: *mut AnyConnection, message: *mut Message, error: *mut *mut ErrorHandle) -> Status {
    if message.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let message = *unsafe { Box::from_raw(message) };

    let (Some(runtime), Some(connection)) = (unsafe { runtime.as_ref() }, unsafe { connection.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match runtime.0.block_on(connection.send(message)) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Receives the next message from an open connection.
///
/// Unlike [`soyokaze_client_request`], informational (1xx) responses are
/// handed over rather than read past.
///
/// # Safety
///
/// `runtime` and `connection` must be handles that have not been freed, and
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_receive(runtime: *mut Runtime, connection: *mut AnyConnection, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    let (Some(runtime), Some(connection)) = (unsafe { runtime.as_ref() }, unsafe { connection.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match runtime.0.block_on(connection.receive()) {
        Ok(message) => {
            unsafe { *out = Box::into_raw(Box::new(message)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Opens a WebSocket over an already-open connection and takes it over.
///
/// The client-side counterpart of a server accepting one. The connection is
/// consumed whether the handshake succeeds or not — the caller must not free
/// or use it again. The socket carries its runtime with it, but `runtime`
/// must outlive the socket.
///
/// # Safety
///
/// `runtime` must be a handle that has not been freed, `connection` must be
/// one the caller owns, `authority` and `target` must point to their stated
/// number of readable octets, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_open_websocket(runtime: *mut Runtime, connection: *mut AnyConnection, authority: *const u8, authority_len: usize, target: *const u8, target_len: usize, out: *mut *mut WebSocket, error: *mut *mut ErrorHandle) -> Status {
    if connection.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let connection = *unsafe { Box::from_raw(connection) };

    let (Some(runtime), Some(authority), Some(target)) = (
        unsafe { runtime.as_ref() },
        unsafe { borrow_text(authority, authority_len) },
        unsafe { borrow_text(target, target_len) },
    ) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match runtime.0.block_on(connection.open_websocket(authority, target)) {
        Ok(socket) => {
            unsafe { *out = Box::into_raw(Box::new(WebSocket { connection: socket, handle: runtime.0.handle().clone() })) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Whether another message may go over the connection.
///
/// # Safety
///
/// As [`soyokaze_connection_version`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_reusable(connection: *const AnyConnection) -> bool {
    unsafe { connection.as_ref() }.is_some_and(|connection| connection.reusable())
}

/// Closes the connection, leaving the handle to be freed.
///
/// # Safety
///
/// `runtime` and `connection` must be handles that have not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_close(runtime: *mut Runtime, connection: *mut AnyConnection) {
    if let (Some(runtime), Some(connection)) = (unsafe { runtime.as_ref() }, unsafe { connection.as_mut() }) {
        runtime.0.block_on(connection.close());
    }
}

/// Releases a connection.
///
/// Does not close it; call [`soyokaze_connection_close`] first to shut it down
/// in an orderly way.
///
/// # Safety
///
/// `connection` must be a handle the caller owns and has not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_free(connection: *mut AnyConnection) {
    if !connection.is_null() {
        drop(unsafe { Box::from_raw(connection) });
    }
}
