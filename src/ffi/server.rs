//! Binding ports and answering requests, from C.
//!
//! [`soyokaze_server_serve`] binds every port and returns as soon as they are
//! bound; the accept loops keep running on the runtime. Each request is handed
//! to the [`OnRequest`] callback, which answers it.

use bytes::Bytes;

use crate::api::server::{Handler, Server, ServerHandle};
use crate::api::tls::Identity;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::models::Port;
use crate::ffi::{borrow, Runtime};
use crate::models::{Body, Message, Version};
use crate::protocol::common::{AnyConnection, Connection};

/// Answers one request.
///
/// Called with whatever `context` [`soyokaze_server_serve`] was given, and with
/// a request the callback takes ownership of — it frees the handle with
/// `soyokaze_message_free`, or hands it back as the response. The response it
/// returns is taken over by the library, which frees it once sent.
///
/// Returning null answers with a bare `500`. The callback runs on a runtime
/// thread and may block; the connection it belongs to waits, but the rest keep
/// running.
pub type OnRequest = extern "C" fn(context: *mut std::ffi::c_void, request: *mut Message) -> *mut Message;

/// A [`Handler`] that answers each request through a C callback.
///
/// Holds `context` untouched and hands it back on every call, which is how a C
/// caller reaches its own state from inside the callback.
pub struct CallbackHandler {
    /// The callback each request is handed to.
    pub on_request: OnRequest,
    /// What the callback is given alongside the request.
    pub context: *mut std::ffi::c_void,
}

// The context is opaque to this library, which only ever hands it back to the
// callback that supplied it. Making it shareable is the caller's undertaking,
// stated on `soyokaze_server_serve`.
unsafe impl Send for CallbackHandler {}
unsafe impl Sync for CallbackHandler {}

impl CallbackHandler {
    /// The response the callback gives for `request`.
    ///
    /// A callback that returns null answers with a bare `500`, and the response
    /// is always stamped with the request's stream so that HTTP/2 and HTTP/3
    /// match the two up.
    pub fn answer(&self, request: Message, version: Version) -> Message {
        let stream_id = request.stream_id;
        let response = (self.on_request)(self.context, Box::into_raw(Box::new(request)));

        let mut response = match std::ptr::NonNull::new(response) {
            Some(response) => *unsafe { Box::from_raw(response.as_ptr()) },
            None => Message::response(500, version),
        };

        response.stream_id = stream_id;
        response
    }
}

impl Handler for CallbackHandler {
    async fn on_connection(&self, connection: AnyConnection) {
        let mut connection = connection;
        let version = connection.version();

        loop {
            let Ok(request) = connection.receive().await else {
                break;
            };

            if connection.send(self.answer(request, version)).await.is_err() {
                break;
            }

            if !connection.reusable() {
                break;
            }
        }

        connection.close().await;
    }
}

/// How a [`Server`] is configured.
///
/// Passing null wherever one of these is asked for takes every default: every
/// version on offer, no ceilings, `SO_REUSEPORT` on, and no identity, which
/// leaves a TCP port in plaintext and a QUIC port unservable.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServerConfig {
    /// The certificate chain to serve, as DER or PEM.
    pub certificate: *const u8,
    /// How long the certificate chain is.
    pub certificate_len: usize,
    /// The private key to serve, as DER or PEM.
    pub key: *const u8,
    /// How long the private key is.
    pub key_len: usize,
    /// How many connections may be open at once. Zero is unbounded.
    pub max_connections: u32,
    /// How many connections one address may have open. Zero is unbounded.
    pub max_connections_per_ip: u32,
    /// Whether sockets are opened with `SO_REUSEPORT`.
    pub reuseport: bool,
}

impl ServerConfig {
    /// The configuration a null pointer stands for.
    pub const DEFAULT: Self = Self {
        certificate: std::ptr::null(),
        certificate_len: 0,
        key: std::ptr::null(),
        key_len: 0,
        max_connections: 0,
        max_connections_per_ip: 0,
        reuseport: true,
    };

    /// The [`Server`] this configures.
    ///
    /// # Safety
    ///
    /// The certificate and key pointers must each either be null or point to
    /// their stated number of readable octets.
    pub unsafe fn build(&self) -> Server {
        let mut builder = Server::builder()
            .max_connections(self.max_connections)
            .max_connections_per_ip(self.max_connections_per_ip)
            .reuseport(self.reuseport);

        if let (Some(certificate), Some(key)) =
            (unsafe { borrow(self.certificate, self.certificate_len) }, unsafe { borrow(self.key, self.key_len) })
        {
            builder = builder.with_identity(Identity::new(vec![certificate.to_vec()], key.to_vec()));
        }

        builder.build()
    }
}

/// Builds a [`Server`].
///
/// A null `config` takes [`ServerConfig::DEFAULT`].
///
/// # Safety
///
/// `config` must either be null or point to a readable [`ServerConfig`] whose
/// own pointers are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_new(config: *const ServerConfig) -> *mut Server {
    let config = unsafe { config.as_ref() }.copied().unwrap_or(ServerConfig::DEFAULT);
    Box::into_raw(Box::new(unsafe { config.build() }))
}

/// Releases a [`Server`].
///
/// A server that is already serving may be released; the [`ServerHandle`] keeps
/// what it needs.
///
/// # Safety
///
/// `server` must come from [`soyokaze_server_new`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_free(server: *mut Server) {
    if !server.is_null() {
        drop(unsafe { Box::from_raw(server) });
    }
}

/// Binds every port and starts serving.
///
/// Returns as soon as the ports are bound; the accept loops keep running on
/// `runtime`, which must outlive the returned handle. Every request is handed
/// to `on_request` along with `context`.
///
/// `context` is passed between threads, so whatever it points at has to stand
/// being reached from more than one at a time.
///
/// # Safety
///
/// `runtime` and `server` must be handles that have not been freed, `ports`
/// must point to `port_count` readable [`Port`] values whose own pointers are
/// valid, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_serve(
    runtime: *mut Runtime,
    server: *const Server,
    on_request: OnRequest,
    context: *mut std::ffi::c_void,
    ports: *const Port,
    port_count: usize,
    out: *mut *mut ServerHandle,
    error: *mut *mut ErrorHandle,
) -> Status {
    let (Some(runtime), Some(server)) = (unsafe { runtime.as_ref() }, unsafe { server.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if ports.is_null() || out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let mut bound = Vec::with_capacity(port_count);
    for index in 0..port_count {
        let Some(port) = (unsafe { (*ports.add(index)).parse() }) else {
            return unsafe { ErrorHandle::raise(error, Status::Invalid) };
        };
        bound.push(port);
    }

    let handler = CallbackHandler { on_request, context };

    match runtime.0.block_on(server.serve(handler, &bound)) {
        Ok(handle) => {
            unsafe { *out = Box::into_raw(Box::new(handle)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The port the first listener actually bound.
///
/// This is how to find a port the kernel chose, when zero was asked for.
/// Returns zero when nothing is bound, or when the first listener is a Unix
/// socket.
///
/// # Safety
///
/// `handle` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_handle_port(handle: *const ServerHandle) -> u16 {
    unsafe { handle.as_ref() }.and_then(|handle| handle.address()).map_or(0, |address| address.port())
}

/// Stops accepting, waits for connections to finish, and releases the handle.
///
/// `timeout` bounds the wait in seconds; connections still running when it
/// passes are aborted. A negative `timeout` waits as long as it takes. The
/// handle is consumed either way — the caller must not free it.
///
/// # Safety
///
/// `runtime` must be a handle that has not been freed, and `handle` must be one
/// the caller owns and has not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_handle_close(runtime: *mut Runtime, handle: *mut ServerHandle, timeout: f64) {
    if handle.is_null() {
        return;
    }

    let handle = *unsafe { Box::from_raw(handle) };

    if let Some(runtime) = unsafe { runtime.as_ref() } {
        runtime.0.block_on(handle.close((timeout >= 0.0).then_some(timeout)));
    }
}

/// The response a callback returns to answer with a body it holds in memory.
///
/// A shorthand for building a response and setting its body, since that is what
/// most callbacks do.
///
/// # Safety
///
/// `body` must either be null or point to `body_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_response_with_body(
    status_code: u16,
    version: Version,
    body: *const u8,
    body_len: usize,
) -> *mut Message {
    let mut response = Message::response(status_code, version);

    if let Some(body) = unsafe { borrow(body, body_len) } {
        response.body = Some(Body::Data(Bytes::copy_from_slice(body)));
    }

    Box::into_raw(Box::new(response))
}
