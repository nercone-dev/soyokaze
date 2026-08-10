//! Binding ports and answering requests, from C.
//!
//! [`soyokaze_server_serve`] binds every port and returns as soon as they are
//! bound; the accept loops keep running on the runtime.
//! [`soyokaze_server_run`] spreads the same work across worker threads, each
//! with its own runtime, the way [`Server::run`] does. Each request is handed
//! to the [`OnRequest`] callback, which answers it, and each accepted
//! WebSocket to the [`OnWebSocket`] callback, when one was given.

use crate::api::cluster::Cluster;
use crate::api::server::{Handler, Server, ServerHandle};
use crate::ffi::SendPtr;
use crate::ffi::models::Limits;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::hsts::HSTSPolicy;
use crate::ffi::models::Port;
use crate::ffi::tls::TLSConfig;
use crate::ffi::websocket::WebSocket;
use crate::ffi::{Runtime, Slice};
use crate::models::{Message, Version};
use crate::protocol::base::{AnyConnection, Connection, Transport};
use crate::tls::{ECHKeys, Identity};

/// Answers one request.
///
/// Called with whatever `context` [`soyokaze_server_serve`] was given, and with
/// a request the callback takes ownership of — it frees the handle with
/// `soyokaze_message_free`, or hands it back as the response. The response it
/// returns is taken over by the library, which frees it once sent.
///
/// Returning null answers with a bare `500`. The callback runs on its own
/// blocking thread, so it may block and may make blocking `soyokaze_` calls;
/// the connection it belongs to waits, but the rest keep running.
pub type OnRequest = extern "C" fn(context: *mut std::ffi::c_void, request: *mut Message) -> *mut Message;

/// Runs one accepted WebSocket to completion.
///
/// Called with whatever `context` [`soyokaze_server_serve`] was given, and
/// with a socket the callback takes ownership of — it drives it with the
/// `soyokaze_websocket_` calls and frees it with `soyokaze_websocket_free`.
/// The callback runs on its own blocking thread, so it may block as long as
/// the connection lives.
pub type OnWebSocket = extern "C" fn(context: *mut std::ffi::c_void, socket: *mut WebSocket);

/// A [`Handler`] that answers each request through a C callback.
///
/// Holds `context` untouched and hands it back on every call, which is how a C
/// caller reaches its own state from inside the callback. WebSocket upgrades
/// are routed to `on_websocket` when one was given, and are otherwise handed
/// to `on_request` like any other request.
pub struct CallbackHandler {
    /// The callback each request is handed to.
    pub on_request: OnRequest,
    /// The callback each accepted WebSocket is handed to, if any.
    pub on_websocket: Option<OnWebSocket>,
    /// What the callbacks are given alongside their argument.
    pub context: *mut std::ffi::c_void,
    /// The ceilings an accepted WebSocket holds itself to.
    pub limits: crate::websocket::WebSocketLimits,
}

unsafe impl Send for CallbackHandler {}
unsafe impl Sync for CallbackHandler {}

impl CallbackHandler {
    pub async fn answer(&self, request: Message, version: Version) -> Message {
        let stream_id = request.stream_id;
        let callback = self.on_request;
        let context = SendPtr(self.context);
        let request = SendPtr(Box::into_raw(Box::new(request)));

        let answered = tokio::task::spawn_blocking(move || {
            let (context, request) = (context, request);
            SendPtr(callback(context.0, request.0))
        })
        .await;

        let mut response = match answered.ok().and_then(|response| std::ptr::NonNull::new(response.0)) {
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

            if self.on_websocket.is_some() && crate::websocket::Handshake::requested(&request) {
                match crate::websocket::Handshake::answer(connection, &request, self.limits).await {
                    crate::websocket::Answer::Accepted(socket) => {
                        self.on_websocket(socket).await;
                        return;
                    }
                    crate::websocket::Answer::Refused(kept) => {
                        connection = kept;
                        continue;
                    }
                    crate::websocket::Answer::Failed => return,
                }
            }

            if connection.send(self.answer(request, version).await).await.is_err() {
                break;
            }

            if !connection.reusable() {
                break;
            }
        }

        connection.close().await;
    }

    async fn on_websocket(&self, socket: crate::websocket::WebSocketConnection<Box<dyn Transport>>) {
        let Some(callback) = self.on_websocket else {
            let mut socket = socket;
            socket.close(crate::websocket::CloseCode::InternalError, "WebSocket is not configured").await;
            return;
        };

        let handle = tokio::runtime::Handle::current();
        let socket = SendPtr(Box::into_raw(Box::new(WebSocket { connection: socket, handle })));
        let context = SendPtr(self.context);

        let _ = tokio::task::spawn_blocking(move || {
            let (context, socket) = (context, socket);
            callback(context.0, socket.0)
        })
        .await;
    }
}

/// One sliding-window rate limit.
///
/// The C half of one [`ServerLimits::max_connection_rate`] entry.
///
/// [`ServerLimits::max_connection_rate`]: crate::api::server::ServerLimits::max_connection_rate
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rate {
    /// The window, in seconds.
    pub period: f64,
    /// How many connections one address may open within it.
    pub count: u32,
}

/// The limits a server applies on top of the per-message [`Limits`].
///
/// The C half of [`ServerLimits`], field for field.
///
/// [`ServerLimits`]: crate::api::server::ServerLimits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServerLimits {
    /// The limits each connection holds itself to.
    pub message: Limits,

    /// The listen backlog for a TCP socket.
    pub backlog: u32,
    /// The number of connections that may be open at once. Zero is unbounded.
    pub max_connections: u32,
    /// The number of connections one address may have open. Zero is unbounded.
    pub max_connections_per_ip: u32,
    /// Rate limits, every one of which must be satisfied. Null means none.
    pub max_connection_rate: *const Rate,
    /// How many entries `max_connection_rate` holds.
    pub rate_count: usize,
    /// The number of addresses whose connection history is remembered.
    pub max_connection_history: usize,
    /// The stack size for a worker thread.
    pub worker_stack_size: usize,
}

impl ServerLimits {
    /// The [`ServerLimits`] this stands for.
    ///
    /// [`ServerLimits`]: crate::api::server::ServerLimits
    ///
    /// # Safety
    ///
    /// `max_connection_rate` must either be null or point to `rate_count`
    /// readable [`Rate`] values.
    pub unsafe fn parse(&self) -> crate::api::server::ServerLimits {
        let mut rate = Vec::new();

        if !self.max_connection_rate.is_null() {
            for index in 0..self.rate_count {
                let entry = unsafe { *self.max_connection_rate.add(index) };
                rate.push((entry.period, entry.count));
            }
        }

        crate::api::server::ServerLimits {
            message: self.message.parse(),
            backlog: self.backlog,
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            max_connection_rate: rate,
            max_connection_history: self.max_connection_history,
            worker_stack_size: self.worker_stack_size,
        }
    }

    /// The C half of `limits`, field for field.
    ///
    /// The rate list cannot cross without a caller-owned array to point into,
    /// so it comes back empty.
    pub fn build(limits: &crate::api::server::ServerLimits) -> Self {
        Self {
            message: Limits::build(&limits.message),
            backlog: limits.backlog,
            max_connections: limits.max_connections,
            max_connections_per_ip: limits.max_connections_per_ip,
            max_connection_rate: std::ptr::null(),
            rate_count: 0,
            max_connection_history: limits.max_connection_history,
            worker_stack_size: limits.worker_stack_size,
        }
    }
}

/// The default [`ServerLimits`], to be adjusted and passed back.
///
/// [`ServerLimits`]: crate::api::server::ServerLimits
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_server_limits_default() -> ServerLimits {
    ServerLimits::build(&crate::api::server::ServerLimits::default())
}

/// How a [`Server`] is configured.
///
/// Passing null wherever one of these is asked for takes every default: every
/// version on offer, no ceilings, `SO_REUSEPORT` on, a Unix socket anyone may
/// connect to, and no identity, which leaves a TCP port in plaintext and a
/// QUIC port unservable. A null pointer inside the struct takes that field's
/// default the same way.
///
/// The identity and ECH handles are borrowed: the server copies what it needs,
/// so they may be freed once the server is built.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServerConfig {
    /// The versions to offer, as `soyokaze_version_t` numbers. Null offers
    /// every supported version; each port narrows this to what it can carry.
    pub versions: *const i32,
    /// How many entries `versions` holds.
    pub version_count: usize,

    /// The limits this server and every connection it accepts hold themselves
    /// to.
    pub limits: *const ServerLimits,

    /// The identity to serve, from `soyokaze_identity_new` or
    /// `soyokaze_identity_from_pkcs12`. Takes precedence over `certificate`
    /// and `key`.
    pub identity: *const Identity,
    /// The certificate chain to serve, as DER or PEM, when `identity` is null.
    pub certificate: Slice,
    /// The private key to serve, as DER or PEM, when `identity` is null.
    pub key: Slice,

    /// The TLS details every context is built with. Null takes every default,
    /// as `soyokaze_tls_config_default` hands them out.
    pub tls: *const TLSConfig,

    /// The keys to offer Encrypted Client Hello with, from
    /// `soyokaze_ech_keys_generate` or `soyokaze_ech_keys_new`.
    pub ech: *const ECHKeys,

    /// The HSTS policy to attach to every secure response.
    pub hsts: *const HSTSPolicy,

    /// Whether sockets are opened with `SO_REUSEPORT`.
    pub reuseport: bool,

    /// The filesystem mode a Unix socket is bound at. Zero leaves it the mode
    /// the process umask gave it.
    pub uds_mode: u32,
}

impl ServerConfig {
    /// The configuration a null pointer stands for.
    pub const DEFAULT: Self = Self {
        versions: std::ptr::null(),
        version_count: 0,
        limits: std::ptr::null(),
        identity: std::ptr::null(),
        certificate: Slice::ABSENT,
        key: Slice::ABSENT,
        tls: std::ptr::null(),
        ech: std::ptr::null(),
        hsts: std::ptr::null(),
        reuseport: true,
        uds_mode: 0o666,
    };

    /// The [`Server`] this configures.
    ///
    /// `None` when a version number names no version.
    ///
    /// # Safety
    ///
    /// Every pointer in the struct must either be null or point to its stated
    /// number of readable elements, themselves valid; `identity` and `ech`
    /// must be handles that have not been freed.
    pub unsafe fn build(&self) -> Option<Server> {
        let mut config = crate::api::server::ServerConfig { reuseport: self.reuseport, uds_mode: self.uds_mode, ..Default::default() };

        let versions = unsafe { Version::parse_all(self.versions, self.version_count) }?;
        if !versions.is_empty() {
            config.versions = versions;
        }

        if let Some(limits) = unsafe { self.limits.as_ref() } {
            config.limits = unsafe { limits.parse() };
        }

        if let Some(identity) = unsafe { self.identity.as_ref() } {
            config.identity = Some(identity.clone());
        } else if let (Some(certificate), Some(key)) = (
            unsafe { Slice::borrow(self.certificate.data, self.certificate.len) },
            unsafe { Slice::borrow(self.key.data, self.key.len) },
        ) {
            config.identity = Some(Identity::new(vec![certificate.to_vec()], key.to_vec()));
        }

        if let Some(tls) = unsafe { self.tls.as_ref() } {
            config.tls = unsafe { tls.parse() }?;
        }

        if let Some(ech) = unsafe { self.ech.as_ref() } {
            config.ech = Some(ech.clone());
        }

        if let Some(hsts) = unsafe { self.hsts.as_ref() } {
            config.hsts = Some(hsts.parse());
        }

        Some(Server::new(config))
    }
}

/// Builds a [`Server`].
///
/// A null `config` takes [`ServerConfig::DEFAULT`]. Returns null when the
/// configuration holds an unusable entry.
///
/// # Safety
///
/// `config` must either be null or point to a readable [`ServerConfig`] whose
/// own pointers are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_new(config: *const ServerConfig) -> *mut Server {
    let config = unsafe { config.as_ref() }.copied().unwrap_or(ServerConfig::DEFAULT);

    match unsafe { config.build() } {
        Some(server) => Box::into_raw(Box::new(server)),
        None => std::ptr::null_mut(),
    }
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
/// to `on_request` along with `context`, and every accepted WebSocket to
/// `on_websocket` when it is not null — a null `on_websocket` hands upgrade
/// requests to `on_request` like any other.
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
pub unsafe extern "C" fn soyokaze_server_serve(runtime: *mut Runtime, server: *const Server, on_request: OnRequest, on_websocket: Option<OnWebSocket>, context: *mut std::ffi::c_void, ports: *const Port, port_count: usize, out: *mut *mut ServerHandle, error: *mut *mut ErrorHandle,) -> Status {
    let (Some(runtime), Some(server)) = (unsafe { runtime.as_ref() }, unsafe { server.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(bound) = (unsafe { Port::parse_all(ports, port_count) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let handler = CallbackHandler { on_request, on_websocket, context, limits: server.config.limits.message.into() };

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

/// How many addresses the handle bound.
///
/// A Unix socket has no address, so this may be fewer than the ports served.
///
/// # Safety
///
/// As [`soyokaze_server_handle_port`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_handle_address_count(handle: *const ServerHandle) -> usize {
    unsafe { handle.as_ref() }.map_or(0, |handle| handle.addresses.len())
}

/// The port of the address at `index`, or zero when there is no such address.
///
/// # Safety
///
/// As [`soyokaze_server_handle_port`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_handle_port_at(handle: *const ServerHandle, index: usize) -> u16 {
    unsafe { handle.as_ref() }
        .and_then(|handle| handle.addresses.get(index))
        .map_or(0, |address| address.port())
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

/// Runs the server across several threads, each with its own runtime.
///
/// The multi-worker counterpart of [`soyokaze_server_serve`]: no runtime is
/// passed in, because each worker brings its own, and the callbacks are the
/// same. A `workers` of zero takes one per core. Returns once every worker is
/// ready, so a bind failure surfaces here.
///
/// # Safety
///
/// `server` must be a handle that has not been freed, `ports` must point to
/// `port_count` readable [`Port`] values whose own pointers are valid, and
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_run(server: *const Server, on_request: OnRequest, on_websocket: Option<OnWebSocket>, context: *mut std::ffi::c_void, ports: *const Port, port_count: usize, workers: u32, out: *mut *mut Cluster, error: *mut *mut ErrorHandle,) -> Status {
    let Some(server) = (unsafe { server.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(bound) = (unsafe { Port::parse_all(ports, port_count) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let workers = match workers {
        0 => Cluster::cores(),
        count => count as usize,
    };

    let handler = CallbackHandler { on_request, on_websocket, context, limits: server.config.limits.message.into() };

    match server.run(handler, &bound, workers) {
        Ok(cluster) => {
            unsafe { *out = Box::into_raw(Box::new(cluster)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// A bound socket that no runtime has adopted yet.
///
/// Sockets are opened before worker threads start, so this is deliberately
/// runtime-free. A caller that wants to bind its ports itself — to drop
/// privileges after binding, or to hand a socket to another process — opens
/// one with [`soyokaze_server_open`] and reads the descriptor off it.
pub use crate::api::server::RawSocket;

/// Binds one port without starting anything on it.
///
/// The socket is bound and, for a stream port, listening, but nothing accepts
/// from it until a server adopts it. Freed with
/// [`soyokaze_raw_socket_free`].
///
/// # Safety
///
/// `server` must either be null or be a handle that has not been freed, and
/// `target` must point to a readable [`Port`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_open(server: *const Server, target: *const Port, out: *mut *mut RawSocket, error: *mut *mut ErrorHandle) -> Status {
    let (Some(server), Some(target)) = (unsafe { server.as_ref() }, unsafe { target.as_ref() }.and_then(|target| unsafe { target.parse() })) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match server.open(&target) {
        Ok(socket) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(socket)) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Releases a [`RawSocket`], closing it.
///
/// # Safety
///
/// `socket` must come from [`soyokaze_server_open`] or
/// [`soyokaze_raw_socket_share`], and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_raw_socket_free(socket: *mut RawSocket) {
    if !socket.is_null() {
        drop(unsafe { Box::from_raw(socket) });
    }
}

/// The address the socket is bound to, as text, owned by the caller.
///
/// An empty buffer with a null pointer means the address cannot be read, which
/// is what a Unix socket always reports.
///
/// # Safety
///
/// `socket` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_raw_socket_address(socket: *const RawSocket) -> crate::ffi::Buffer {
    match unsafe { socket.as_ref() }.and_then(|socket| socket.address().ok()) {
        Some(address) => crate::ffi::Buffer::new(address.to_string().into_bytes()),
        None => crate::ffi::Buffer::EMPTY,
    }
}

/// The port the socket is bound to, or zero when it has none.
///
/// # Safety
///
/// As [`soyokaze_raw_socket_address`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_raw_socket_port(socket: *const RawSocket) -> u16 {
    unsafe { socket.as_ref() }.and_then(|socket| socket.address().ok()).map_or(0, |address| address.port())
}

/// Duplicates the descriptor, so several workers may accept from one socket.
///
/// This is the fallback when `SO_REUSEPORT` is off, and the only way for a
/// Unix socket, which cannot be bound twice.
///
/// # Safety
///
/// As [`soyokaze_raw_socket_address`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_raw_socket_share(socket: *const RawSocket, out: *mut *mut RawSocket, error: *mut *mut ErrorHandle) -> Status {
    let Some(socket) = (unsafe { socket.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match socket.share() {
        Ok(shared) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(shared)) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The descriptor underneath, for a caller handing the socket elsewhere.
///
/// The socket still owns the descriptor: freeing the handle closes it, so a
/// caller that passes this on must keep the handle alive for as long as the
/// descriptor is in use.
///
/// # Safety
///
/// As [`soyokaze_raw_socket_address`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_raw_socket_descriptor(socket: *const RawSocket) -> i32 {
    use std::os::fd::AsRawFd;

    match unsafe { socket.as_ref() } {
        Some(RawSocket::UDS(listener)) => listener.as_raw_fd(),
        Some(RawSocket::TCP(listener)) => listener.as_raw_fd(),
        Some(RawSocket::QUIC(socket)) => socket.as_raw_fd(),
        None => -1,
    }
}

/// How many versions the server accepts.
///
/// # Safety
///
/// `server` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_version_count(server: *const Server) -> usize {
    unsafe { server.as_ref() }.map_or(0, |server| server.config.versions.len())
}

/// The version at `index` among those the server accepts, or `-1` past the
/// end.
///
/// # Safety
///
/// As [`soyokaze_server_version_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_version_at(server: *const Server, index: usize) -> i32 {
    match unsafe { server.as_ref() }.and_then(|server| server.config.versions.get(index)) {
        Some(&version) => version as i32,
        None => -1,
    }
}

/// Whether the server binds each worker's socket with `SO_REUSEPORT`.
///
/// # Safety
///
/// As [`soyokaze_server_version_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_reuseport(server: *const Server) -> bool {
    unsafe { server.as_ref() }.is_some_and(|server| server.config.reuseport)
}

/// The filesystem mode the server binds a Unix socket at, or zero for the one
/// the process umask gives it.
///
/// # Safety
///
/// As [`soyokaze_server_version_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_uds_mode(server: *const Server) -> u32 {
    unsafe { server.as_ref() }.map_or(0, |server| server.config.uds_mode)
}

/// Builds the admission gate a [`ServerLimits`] describes.
///
/// The same gate a server built from those limits would admit connections
/// through. Freed with `soyokaze_gate_free`.
///
/// # Safety
///
/// `limits` must either be null or point to a readable [`ServerLimits`] whose
/// own pointers are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_limits_gate(limits: *const ServerLimits) -> *mut crate::ffi::api::gate::GateHandle {
    let limits = match unsafe { limits.as_ref() } {
        Some(limits) => unsafe { limits.parse() },
        None => crate::api::server::ServerLimits::default(),
    };

    Box::into_raw(Box::new(crate::ffi::api::gate::GateHandle(limits.gate())))
}

/// The address at `index` a running server bound, as text, owned by the
/// caller.
///
/// # Safety
///
/// `handle` must either be null or be a handle that has not been closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_server_handle_address_at(handle: *const ServerHandle, index: usize) -> crate::ffi::Buffer {
    match unsafe { handle.as_ref() }.and_then(|handle| handle.addresses().get(index)) {
        Some(address) => crate::ffi::Buffer::new(address.to_string().into_bytes()),
        None => crate::ffi::Buffer::EMPTY,
    }
}
