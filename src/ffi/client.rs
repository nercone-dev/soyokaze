//! Dialling an origin and issuing requests, from C.
//!
//! [`soyokaze_client_fetch`] and its shorthands each dial, exchange one
//! message, and close. [`soyokaze_client_open`] hands back the connection
//! instead, so several messages may go over one.

use crate::api::client::Client;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::models::Port;
use crate::ffi::{borrow_text, Runtime};
use crate::models::{Message, Method, Url, Version};
use crate::protocol::common::{AnyConnection, Connection};

/// How a [`Client`] is configured.
///
/// Passing null wherever one of these is asked for takes every default:
/// negotiate the version, TLS on, cookies kept, HSTS remembered.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClientConfig {
    /// The version to pin, or `-1` to negotiate one.
    pub version: i32,
    /// Whether a stream transport is wrapped in TLS.
    pub secure: bool,
    /// Whether a cookie jar is kept across requests.
    pub cookies: bool,
    /// Whether an HSTS store is kept across requests.
    pub hsts: bool,
}

impl ClientConfig {
    /// The configuration a null pointer stands for.
    pub const DEFAULT: Self = Self { version: -1, secure: true, cookies: true, hsts: true };

    /// The version this pins, if it pins one.
    pub fn version(&self) -> Option<Version> {
        match self.version {
            0 => Some(Version::V1_0),
            1 => Some(Version::V1_1),
            2 => Some(Version::V2_0),
            3 => Some(Version::V3_0),
            _ => None,
        }
    }

    /// The [`Client`] this configures.
    pub fn build(&self) -> Client {
        let mut builder = Client::builder().secure(self.secure).cookies(self.cookies).hsts(self.hsts);

        if let Some(version) = self.version() {
            builder = builder.version(version);
        }

        builder.build()
    }
}

/// Builds a [`Client`].
///
/// A null `config` takes [`ClientConfig::DEFAULT`].
///
/// # Safety
///
/// `config` must either be null or point to a readable [`ClientConfig`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_new(config: *const ClientConfig) -> *mut Client {
    let config = unsafe { config.as_ref() }.copied().unwrap_or(ClientConfig::DEFAULT);
    Box::into_raw(Box::new(config.build()))
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
pub unsafe extern "C" fn soyokaze_client_fetch(
    runtime: *mut Runtime,
    client: *const Client,
    method: Method,
    url: *const u8,
    url_len: usize,
    request: *mut Message,
    out: *mut *mut Message,
    error: *mut *mut ErrorHandle,
) -> Status {
    let request = (!request.is_null()).then(|| *unsafe { Box::from_raw(request) });

    let (Some(runtime), Some(client), Some(url)) =
        (unsafe { runtime.as_ref() }, unsafe { client.as_ref() }, unsafe { borrow_text(url, url_len) })
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
pub unsafe extern "C" fn soyokaze_client_get(
    runtime: *mut Runtime,
    client: *const Client,
    url: *const u8,
    url_len: usize,
    out: *mut *mut Message,
    error: *mut *mut ErrorHandle,
) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::GET, url, url_len, std::ptr::null_mut(), out, error) }
}

/// A `HEAD`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_head(
    runtime: *mut Runtime,
    client: *const Client,
    url: *const u8,
    url_len: usize,
    out: *mut *mut Message,
    error: *mut *mut ErrorHandle,
) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::HEAD, url, url_len, std::ptr::null_mut(), out, error) }
}

/// A `POST`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_post(
    runtime: *mut Runtime,
    client: *const Client,
    url: *const u8,
    url_len: usize,
    request: *mut Message,
    out: *mut *mut Message,
    error: *mut *mut ErrorHandle,
) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::POST, url, url_len, request, out, error) }
}

/// A `PUT`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_put(
    runtime: *mut Runtime,
    client: *const Client,
    url: *const u8,
    url_len: usize,
    request: *mut Message,
    out: *mut *mut Message,
    error: *mut *mut ErrorHandle,
) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::PUT, url, url_len, request, out, error) }
}

/// A `DELETE`; see [`soyokaze_client_fetch`].
///
/// # Safety
///
/// As [`soyokaze_client_fetch`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_delete(
    runtime: *mut Runtime,
    client: *const Client,
    url: *const u8,
    url_len: usize,
    out: *mut *mut Message,
    error: *mut *mut ErrorHandle,
) -> Status {
    unsafe { soyokaze_client_fetch(runtime, client, Method::DELETE, url, url_len, std::ptr::null_mut(), out, error) }
}

/// Opens a connection for a URL, taking the transport from its scheme.
///
/// # Safety
///
/// `runtime`, `client` and `url` must be handles that have not been freed, and
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_client_open(
    runtime: *mut Runtime,
    client: *const Client,
    url: *const Url,
    out: *mut *mut AnyConnection,
    error: *mut *mut ErrorHandle,
) -> Status {
    let (Some(runtime), Some(client), Some(url)) =
        (unsafe { runtime.as_ref() }, unsafe { client.as_ref() }, unsafe { url.as_ref() })
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
pub unsafe extern "C" fn soyokaze_client_connect(
    runtime: *mut Runtime,
    client: *const Client,
    host: *const u8,
    host_len: usize,
    port: *const Port,
    out: *mut *mut AnyConnection,
    error: *mut *mut ErrorHandle,
) -> Status {
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
pub unsafe extern "C" fn soyokaze_client_request(
    runtime: *mut Runtime,
    client: *const Client,
    connection: *mut AnyConnection,
    request: *mut Message,
    out: *mut *mut Message,
    error: *mut *mut ErrorHandle,
) -> Status {
    if request.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let request = *unsafe { Box::from_raw(request) };

    let (Some(runtime), Some(client), Some(connection)) =
        (unsafe { runtime.as_ref() }, unsafe { client.as_ref() }, unsafe { connection.as_mut() })
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
