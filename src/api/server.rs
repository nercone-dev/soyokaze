//! Binding ports, accepting connections and dispatching to a handler.
//!
//! [`Server`] holds a [`ServerConfig`]; [`Server::serve`] binds ports and runs
//! an accept loop on the current runtime, and [`Server::run`] runs
//! one runtime per thread instead, each with its own listener under
//! `SO_REUSEPORT` so the kernel spreads connections between them.
//!
//! Which version a connection speaks is settled before a handler sees it: by
//! ALPN over TLS, by sniffing the HTTP/2 preface on a plaintext port, and by
//! the port itself for QUIC. Handlers are written against
//! [`AnyConnection`], so they do not need to care which it was.
//!
//! Admission control lives in [`Gate`], and runs before the handler is
//! reached: a total connection count, a per-address count, and a set of
//! sliding-window rate limits. Handshakes negotiate concurrently, bounded by
//! [`Limits::max_pending_handshakes`], so a peer that opens a connection and
//! then goes quiet cannot hold up the accept loop.

use std::net::{Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::{TcpListener, UnixListener};

use crate::api::common::VERSIONS;
use crate::models::{ConnectionID, Limits, Port, Version};
use crate::protocol::base::{AnyConnection, Connection, Transport};
use crate::protocol::common::Error;
use crate::api::cluster::Cluster;
use crate::api::gate::Gate;
use crate::protocol::handler::{Incoming, Negotiation};
use crate::protocol::quic::{self, QUICIncoming};
use crate::tls::Identity;
use crate::helpers::sync;

/// How a [`Server`] is configured.
///
/// Every field has a working default: every supported version offered, no
/// admission limits, `SO_REUSEPORT` on, a Unix socket anyone may connect to,
/// and no identity, which leaves a TCP port in plaintext and a QUIC port
/// unservable.
#[derive(Clone)]
pub struct ServerConfig {
    /// The versions to offer. Each port narrows this to what it can carry.
    pub versions: Vec<Version>,

    /// The limits this server and every connection it accepts hold themselves
    /// to.
    pub limits: ServerLimits,

    /// The certificate chain and key to serve.
    ///
    /// Required for TLS and for any QUIC port; without one, a TCP port is
    /// served in plaintext.
    ///
    /// Each blob [`Identity::new`] takes is DER or PEM, so the chain may be
    /// one PEM bundle or one certificate per entry, and the key PKCS#8, PKCS#1
    /// or SEC1. A PKCS#12 archive goes through [`Identity::from_pkcs12`].
    pub identity: Option<Identity>,

    /// The TLS details every context is built with: cipher suites, groups,
    /// signature algorithms, suite preference, session tickets, early data
    /// and certificate compression.
    pub tls: crate::tls::TLSConfig,

    /// The keys to offer Encrypted Client Hello with.
    pub ech: Option<crate::tls::ECHKeys>,

    /// The HSTS policy to attach to every secure response.
    pub hsts: Option<crate::hsts::HSTSPolicy>,

    /// Whether sockets are opened with `SO_REUSEPORT`.
    ///
    /// On by default, and needed for [`Server::run`] to give each
    /// worker its own listener. Turning it off makes a QUIC port single-worker.
    pub reuseport: bool,

    /// The filesystem mode a Unix socket is bound at.
    ///
    /// `0o666` by default, since connecting to a Unix socket asks for write
    /// permission on it and a reverse proxy in front usually runs as another
    /// user. Zero leaves the socket the mode the process umask gave it, which
    /// is what a server that keeps its socket in a directory of its own wants.
    pub uds_mode: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            versions: VERSIONS.to_vec(),
            limits: ServerLimits::default(),
            identity: None,
            tls: crate::tls::TLSConfig::default(),
            ech: None,
            hsts: None,
            reuseport: true,
            uds_mode: 0o666,
        }
    }
}

/// An HTTP server.
///
/// Holds the [`ServerConfig`] a listener is built from. Cheap to clone, since
/// each worker in [`Server::run`] needs its own copy.
#[derive(Clone, Default)]
pub struct Server {
    /// How this server is configured.
    pub config: ServerConfig,
}

impl Server {
    /// A server with this configuration.
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    /// Opens a port and makes a listener over it.
    ///
    /// # Errors
    ///
    /// As [`Server::open`] and [`Server::attach`].
    pub async fn bind(&self, target: Port) -> Result<Listener, Error> {
        let socket = self.open(&target)?;
        self.attach(&target, socket).await
    }

    /// Opens the socket for a port, without building a listener over it.
    ///
    /// Splitting this out lets several worker threads open the same port under
    /// `SO_REUSEPORT` before any of them starts a runtime.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the socket cannot be created, bound, or, for
    /// a Unix socket, given [`ServerConfig::uds_mode`].
    pub fn open(&self, target: &Port) -> Result<RawSocket, Error> {
        Ok(match target {
            Port::UDS(path) => {
                let listener = std::os::unix::net::UnixListener::bind(path)?;
                listener.set_nonblocking(true)?;

                if self.config.uds_mode != 0 {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(self.config.uds_mode))?;
                }

                RawSocket::UDS(listener)
            }

            Port::TCP(port) => RawSocket::TCP(self.socket(*port, socket2::Type::STREAM)?.into()),
            Port::QUIC(port) => RawSocket::QUIC(self.socket(*port, socket2::Type::DGRAM)?.into()),
        })
    }

    /// Creates and binds one socket.
    ///
    /// Bound to the IPv6 unspecified address, which on the usual dual-stack
    /// configuration accepts IPv4 as well.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the socket cannot be created, configured or
    /// bound.
    pub fn socket(&self, port: u16, kind: socket2::Type) -> Result<socket2::Socket, Error> {
        let socket = socket2::Socket::new(socket2::Domain::IPV6, kind, None)?;

        if self.config.reuseport {
            socket.set_reuse_port(true)?;
        }

        socket.set_nonblocking(true)?;

        if kind == socket2::Type::STREAM {
            socket.set_reuse_address(true)?;
        }

        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;

        if kind == socket2::Type::STREAM {
            socket.listen(self.config.limits.backlog.min(i32::MAX as u32) as i32)?;
        }

        Ok(socket)
    }

    /// Builds a listener over an already-open socket.
    ///
    /// This is where the version list is narrowed to what the port offers, per
    /// [`Port::offers`], and where the TLS acceptor is built, if there is an
    /// identity to build one from. The same narrowed list is what goes out by
    /// ALPN and what the connection is then negotiated against, so a peer is
    /// never offered a version the port would go on to turn away.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] when the port is offered no version it can
    /// carry, [`Error::IO`] when the socket cannot be adopted, and
    /// [`Error::TLS`] when a QUIC port has no identity or a TLS context
    /// cannot be built.
    pub async fn attach(&self, target: &Port, socket: RawSocket) -> Result<Listener, Error> {
        let versions = target.offers(&self.config.versions);
        if versions.is_empty() {
            return Err(Error::Version(format!("no configured version runs over {:?}", target.transport())));
        }

        let socket = match socket {
            RawSocket::UDS(listener) => Socket::UDS(UnixListener::from_std(listener)?),

            RawSocket::TCP(listener) => Socket::TCP(TcpListener::from_std(listener)?),

            RawSocket::QUIC(udp) => {
                let identity = self
                    .config
                    .identity
                    .as_ref()
                    .ok_or_else(|| Error::TLS("a QUIC port needs a certificate and a key".into()))?;

                let config = quic::QUICConfig {
                    versions: versions.clone(),
                    idle_timeout: self.config.limits.message.read_timeout,
                    max_streams_bidi: Some(self.config.limits.message.max_concurrent_streams as u64),
                    enable_dgram: false,
                };
                let hook = std::sync::Arc::new(quic::QUICServerTLS {
                    identity: identity.clone(),
                    ech: self.config.ech.clone(),
                    tls: self.config.tls.clone(),
                });

                let (incoming, address) = quic::QUICListener::bind(udp, &config, hook)?;
                Socket::QUIC { incoming: tokio::sync::Mutex::new(incoming), address }
            }
        };

        let acceptor = match (&self.config.identity, &socket) {
            (Some(identity), Socket::TCP(_)) => Some(Arc::new(self.config.tls.server(identity, &versions, self.config.ech.as_ref())?)),
            _ => None,
        };

        let response_finalizer = crate::finalizer::ResponseFinalizer::new(self.config.hsts);
        let negotiation = Negotiation { versions, limits: self.config.limits.message, acceptor, response_finalizer };
        let (negotiating, negotiated) = tokio::sync::mpsc::channel(negotiation.limits.max_pending_handshakes.max(1) as usize);

        Ok(Listener { socket, negotiation: Arc::new(negotiation), negotiating, negotiated })
    }
}

/// A bound socket that no runtime has adopted yet.
///
/// Sockets are opened before worker threads start, so this is deliberately
/// runtime-free; [`Server::attach`] turns one into a [`Socket`].
pub enum RawSocket {
    /// A bound Unix domain socket.
    UDS(std::os::unix::net::UnixListener),
    /// A bound and listening TCP socket.
    TCP(std::net::TcpListener),
    /// A bound UDP socket, for QUIC.
    QUIC(std::net::UdpSocket),
}

impl RawSocket {
    /// The address the socket is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] for a Unix socket, which has no address, and when
    /// the address cannot be read.
    pub fn address(&self) -> Result<SocketAddr, Error> {
        match self {
            Self::TCP(listener) => Ok(listener.local_addr()?),
            Self::QUIC(socket) => Ok(socket.local_addr()?),
            Self::UDS(_) => Err(Error::IO(std::io::Error::other("a unix socket has no address"))),
        }
    }

    /// Duplicates the descriptor, so several workers accept from one socket.
    ///
    /// This is the fallback when `SO_REUSEPORT` is off, or for a Unix socket,
    /// which cannot be bound twice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the descriptor cannot be duplicated.
    pub fn share(&self) -> Result<Self, Error> {
        Ok(match self {
            Self::UDS(listener) => Self::UDS(listener.try_clone()?),
            Self::TCP(listener) => Self::TCP(listener.try_clone()?),
            Self::QUIC(socket) => Self::QUIC(socket.try_clone()?),
        })
    }
}

/// A listening socket a runtime has adopted.
pub enum Socket {
    /// A Unix domain socket.
    UDS(UnixListener),
    /// A TCP socket.
    TCP(TcpListener),
    /// A QUIC endpoint.
    ///
    /// `tokio-quiche` owns the UDP socket and demultiplexes datagrams into
    /// connections, so what arrives here is a queue of connections rather than
    /// a socket to accept on.
    QUIC {
        /// Connections `tokio-quiche` has completed the handshake for.
        incoming: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<std::io::Result<QUICIncoming>>>,
        /// The address the UDP socket is bound to.
        address: std::net::SocketAddr,
    },
}

impl Socket {
    /// The address the socket is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] for a Unix socket, which has no address, and when
    /// the address cannot be read.
    pub fn address(&self) -> Result<SocketAddr, Error> {
        match self {
            Self::TCP(listener) => Ok(listener.local_addr()?),
            Self::QUIC { address, .. } => Ok(*address),
            Self::UDS(_) => Err(Error::IO(std::io::Error::other("a unix socket has no address"))),
        }
    }

    /// Waits for the next connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when a QUIC endpoint has shut down, and
    /// [`Error::IO`] when accepting fails.
    pub async fn accept(&self) -> Result<Incoming, Error> {
        match self {
            Self::QUIC { incoming, .. } => {
                let incoming = incoming.lock().await.recv().await.ok_or(Error::Closed)?.map_err(Error::IO)?;
                Ok(Incoming::QUIC(incoming))
            }

            Self::TCP(listener) => {
                let (transport, address) = listener.accept().await?;
                let _ = transport.set_nodelay(true);
                let id = ConnectionID(Bytes::from(address.to_string()));
                Ok(Incoming::Stream { transport: Box::new(transport), id, client: Some(address) })
            }

            Self::UDS(listener) => {
                let (transport, _) = listener.accept().await?;
                let id = ConnectionID(Bytes::from_static(b"unix"));
                Ok(Incoming::Stream { transport: Box::new(transport), id, client: None })
            }
        }
    }
}

/// One bound port, accepting and negotiating connections.
///
/// Handshakes run concurrently in their own tasks rather than in the accept
/// loop, so one slow peer does not hold up the rest. The channel between them
/// is what bounds that concurrency to
/// [`Limits::max_pending_handshakes`].
pub struct Listener {
    socket: Socket,
    negotiation: Arc<Negotiation>,
    negotiating: tokio::sync::mpsc::Sender<Result<AnyConnection, Error>>,
    negotiated: tokio::sync::mpsc::Receiver<Result<AnyConnection, Error>>,
}

impl Listener {
    /// The versions this port offers.
    pub fn versions(&self) -> &[Version] {
        &self.negotiation.versions
    }

    /// The limits each connection holds itself to.
    pub fn limits(&self) -> &Limits {
        &self.negotiation.limits
    }

    /// The socket underneath.
    pub fn socket(&self) -> &Socket {
        &self.socket
    }

    /// What this port negotiates with.
    pub fn negotiation(&self) -> &Negotiation {
        &self.negotiation
    }

    /// How many handshakes are in flight.
    pub fn pending(&self) -> usize {
        self.negotiating.max_capacity() - self.negotiating.capacity()
    }

    /// The address this port is bound to.
    ///
    /// Useful when the port was bound to zero and the kernel chose one.
    ///
    /// # Errors
    ///
    /// As [`Socket::address`].
    pub fn address(&self) -> Result<SocketAddr, Error> {
        self.socket.address()
    }

    /// Waits for the next connection that has finished negotiating.
    ///
    /// Accepting and negotiating go on in the background while this waits, so
    /// a caller that is slow to take connections still lets handshakes
    /// progress. Handshakes that fail are dropped rather than returned — one
    /// peer failing to negotiate is not the listener's failure.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] or [`Error::Closed`] when accepting itself fails.
    pub async fn accept(&mut self) -> Result<AnyConnection, Error> {
        loop {
            tokio::select! {
                biased;

                Some(negotiated) = self.negotiated.recv() => {
                    if let Ok(connection) = negotiated {
                        return Ok(connection);
                    }
                }

                incoming = self.socket.accept(), if self.negotiating.capacity() > 0 => {
                    let incoming = incoming?;

                    let Ok(permit) = self.negotiating.clone().try_reserve_owned() else {
                        continue;
                    };

                    let negotiation = Arc::clone(&self.negotiation);
                    tokio::spawn(async move { permit.send(negotiation.accept(incoming).await) });
                }
            }
        }
    }
}

/// The limits a server applies on top of the per-message [`Limits`].
///
/// These are what the admission [`Gate`] enforces. The defaults leave
/// admission unbounded, so a server limits nothing it was not asked to.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    /// The limits each connection holds itself to.
    pub message: Limits,

    /// The listen backlog for a TCP socket.
    pub backlog: u32,
    /// The number of connections that may be open at once. Zero is unbounded.
    pub max_connections: u32,
    /// The number of connections one address may have open. Zero is unbounded.
    pub max_connections_per_ip: u32,
    /// Rate limits as `[(period in seconds, count), ...]`; every entry must be
    /// satisfied, so several together shape both bursts and sustained rate.
    pub max_connection_rate: Vec<(f64, u32)>,
    /// The number of addresses whose connection history is remembered.
    pub max_connection_history: usize,
    /// The stack size for a [`Server::run`] worker thread.
    ///
    /// Handlers run on the worker's own runtime, so every future they nest is
    /// polled on this stack. The platform default for spawned threads
    /// (commonly 2 MiB) is too tight for handlers with deeply nested futures,
    /// so workers get the same 8 MiB a main thread usually has.
    pub worker_stack_size: usize,
}

impl ServerLimits {
    /// The admission [`Gate`] these limits describe.
    pub fn gate(&self) -> Arc<Gate> {
        Gate::new(self.max_connections, self.max_connections_per_ip, self.max_connection_rate.clone(), self.max_connection_history)
    }
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            message: Limits::default(),
            backlog: 1024,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_connection_rate: Vec::new(),
            max_connection_history: 1024,
            worker_stack_size: 8 * 1024 * 1024,
        }
    }
}

/// What a server does with the connections it accepts.
///
/// Both methods have defaults, so `impl Handler for MyHandler {}` compiles and
/// answers every request with a placeholder — useful to get a server running
/// before deciding what it should say.
///
/// A handler is used from many tasks at once, so it takes `&self` and must be
/// `Send + Sync`.
pub trait Handler: Send + Sync + 'static {
    /// The ceilings a WebSocket accepted by this handler holds itself to.
    ///
    /// A handler is what turns an HTTP connection into a WebSocket, so it is
    /// what says how that socket is bounded — an HTTP connection has no
    /// WebSocket settings to hand on, and does not carry any. Override this to
    /// pass on what [`ServerConfig::limits`] was configured with, which
    /// converts: `self.config.limits.message.into()`.
    fn websocket_limits(&self) -> crate::websocket::WebSocketLimits {
        crate::websocket::WebSocketLimits::default()
    }

    /// Runs one connection to completion.
    ///
    /// The default reads requests in a loop and answers each with a
    /// placeholder `200`, hands a valid WebSocket upgrade to
    /// [`Handler::on_websocket`], and answers an invalid one with `426`. It
    /// stops when the peer is done or the connection is no longer reusable,
    /// and closes on the way out.
    ///
    /// An override must send a response carrying the request's
    /// [`Message::stream_id`], or HTTP/2 and HTTP/3 will not match the two up.
    ///
    /// [`Message::stream_id`]: crate::models::Message::stream_id
    fn on_connection(&self, connection: AnyConnection) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let mut connection = connection;

            loop {
                let Ok(request) = connection.receive().await else {
                    break;
                };

                if crate::websocket::Handshake::requested(&request) {
                    match crate::websocket::Handshake::answer(connection, &request, self.websocket_limits()).await {
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

                let mut response = crate::models::Message::response(200, connection.version());
                response.stream_id = request.stream_id;
                response.body = Some(crate::models::Body::Data(Bytes::from_static(b"This is the default response from Soyokaze.")));

                if connection.send(response).await.is_err() {
                    break;
                }

                if !connection.reusable() {
                    break;
                }
            }

            connection.close().await;
        }
    }

    /// Runs one WebSocket connection to completion.
    ///
    /// The default closes it with `1011`, since a server that has not
    /// overridden this has nothing to say over a WebSocket.
    fn on_websocket(&self, socket: crate::websocket::WebSocketConnection<Box<dyn Transport>>) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let mut socket = socket;
            socket.close(crate::websocket::CloseCode::InternalError, "WebSocket is not configured").await;
        }
    }
}

/// A running server, as [`Server::serve`] returns it.
///
/// Everything runs on the current runtime. Dropping this leaves the server
/// running; call [`ServerHandle::close`] to wind it down.
pub struct ServerHandle {
    /// Tells the accept loops to stop.
    pub shutdown: tokio::sync::watch::Sender<bool>,
    /// The tasks running connections.
    pub tasks: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
    /// One accept loop per bound port.
    pub accept_loops: Vec<tokio::task::JoinHandle<()>>,
    /// The addresses actually bound, which is how to find a port chosen by the
    /// kernel.
    pub addresses: Vec<std::net::SocketAddr>,
}

impl ServerHandle {
    /// The first bound address, if any port has one.
    pub fn address(&self) -> Option<std::net::SocketAddr> {
        self.addresses.first().copied()
    }

    /// Every bound address.
    pub fn addresses(&self) -> &[std::net::SocketAddr] {
        &self.addresses
    }

    /// Stops accepting and waits for connections to finish.
    ///
    /// `timeout` bounds the wait; connections still running when it passes are
    /// aborted. `None` waits as long as it takes.
    pub async fn close(self, timeout: Option<f64>) {
        let _ = self.shutdown.send(true);
        for accept_loop in self.accept_loops {
            let _ = accept_loop.await;
        }

        let mut tasks = self.tasks.lock().await;
        let drain = async {
            while tasks.join_next().await.is_some() {}
        };

        match timeout.and_then(sync::Timeout::duration) {
            Some(wait) => {
                if tokio::time::timeout(wait, drain).await.is_err() {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                }
            }
            None => drain.await,
        }
    }
}

impl Server {
    /// Binds every port and starts serving on the current runtime.
    ///
    /// Returns as soon as the ports are bound; the accept loops keep running
    /// in the background. Use [`Server::run`] to spread the work
    /// across threads instead.
    ///
    /// # Errors
    ///
    /// As [`Server::bind`]. Ports bound before the failure are closed when the
    /// error unwinds.
    pub async fn serve<H: Handler>(&self, handler: H, ports: &[Port]) -> Result<ServerHandle, Error> {
        let gate = self.config.limits.gate();

        let mut listeners = Vec::with_capacity(ports.len());
        for port in ports {
            listeners.push(self.bind(port.clone()).await?);
        }

        Ok(self.launch(Arc::new(handler), listeners, gate))
    }

    /// Starts an accept loop for each listener.
    ///
    /// Each accepted connection is put to the gate before a task is spawned
    /// for it; one that is refused is closed at once. The permit is held for
    /// as long as the connection runs.
    pub fn launch<H: Handler>(&self, handler: Arc<H>, listeners: Vec<Listener>, gate: Arc<Gate>) -> ServerHandle {
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let tasks = Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));

        let mut accept_loops = Vec::new();
        let mut addresses = Vec::new();

        for mut listener in listeners {
            if let Ok(address) = listener.address() {
                addresses.push(address);
            }

            let handler = handler.clone();
            let gate = gate.clone();
            let tasks = tasks.clone();
            let mut receiver = receiver.clone();

            accept_loops.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = receiver.changed() => break,

                        result = listener.accept() => {
                            let Ok(mut connection) = result else {
                                break;
                            };

                            let ip = connection.client().map(|address| address.ip());

                            let Some(permit) = gate.admit(ip, std::time::Instant::now()) else {
                                connection.close().await;
                                continue;
                            };

                            let handler = handler.clone();
                            let mut set = tasks.lock().await;

                            while set.try_join_next().is_some() {}

                            set.spawn(async move {
                                handler.on_connection(connection).await;
                                drop(permit);
                            });
                        }
                    }
                }
            }));
        }

        ServerHandle { shutdown, tasks, accept_loops, addresses }
    }

    /// Runs the server across several threads, each with its own runtime.
    ///
    /// Under `SO_REUSEPORT` each worker binds the port independently and the
    /// kernel spreads connections between them, which avoids the single accept
    /// loop that one shared listener would make. Where that is not possible —
    /// a Unix socket, or reuseport turned off — the descriptor is duplicated
    /// and the workers accept from the one socket.
    ///
    /// Every port is opened before any thread starts, and this waits for all
    /// the workers to report ready, so a bind failure surfaces here rather
    /// than in a thread nobody is watching.
    ///
    /// The admission [`Gate`] is shared, so its limits apply to the cluster as
    /// a whole.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when a QUIC port is asked for more than one
    /// worker without reuseport, when a socket cannot be opened, or when a
    /// thread or runtime cannot be created, [`Error::Closed`] when a worker
    /// dies before reporting, and otherwise as [`Server::attach`], whose
    /// failure on any worker is returned here. On failure every thread
    /// already started is wound down first.
    pub fn run<H: Handler>(&self, handler: H, ports: &[Port], workers: usize) -> Result<Cluster, Error> {
        let workers = workers.max(1);

        if workers > 1 && !self.config.reuseport && ports.iter().any(|port| matches!(port, Port::QUIC(_))) {
            let reason = "a QUIC port needs reuseport to run on more than one worker";
            return Err(Error::IO(std::io::Error::other(reason)));
        }

        let handler = Arc::new(handler);
        let gate = self.config.limits.gate();

        let mut targets = Vec::with_capacity(ports.len());
        let mut queues: Vec<Vec<RawSocket>> = Vec::with_capacity(ports.len());
        let mut addresses = Vec::new();

        for port in ports {
            let opened = self.open(port)?;
            let address = opened.address().ok();

            let target = match (port, address) {
                (Port::TCP(_), Some(address)) => Port::TCP(address.port()),
                (Port::QUIC(_), Some(address)) => Port::QUIC(address.port()),
                _ => port.clone(),
            };

            addresses.extend(address);

            let independent = self.config.reuseport && !matches!(target, Port::UDS(_));

            let mut queue = Vec::with_capacity(workers);
            queue.push(opened);

            while queue.len() < workers {
                queue.push(if independent { self.open(&target)? } else { queue[0].share()? });
            }

            targets.push(target);
            queues.push(queue);
        }

        let (shutdown, receiver) = tokio::sync::watch::channel(None::<f64>);
        let (ready, started) = std::sync::mpsc::channel();

        let mut threads = Vec::with_capacity(workers);
        let mut failure = None;

        for index in 0..workers {
            let sockets: Vec<RawSocket> = queues.iter_mut().filter_map(Vec::pop).collect();
            let targets = targets.clone();

            let server = self.clone();
            let handler = handler.clone();
            let gate = gate.clone();
            let mut receiver = receiver.clone();
            let ready = ready.clone();

            let worker = move || {
                let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(Error::IO(error)));
                        return;
                    }
                };

                runtime.block_on(async move {
                    let mut listeners = Vec::with_capacity(targets.len());

                    for (target, socket) in targets.iter().zip(sockets) {
                        match server.attach(target, socket).await {
                            Ok(listener) => listeners.push(listener),
                            Err(error) => {
                                let _ = ready.send(Err(error));
                                return;
                            }
                        }
                    }

                    let handle = server.launch(handler, listeners, gate);
                    if ready.send(Ok(())).is_err() {
                        return;
                    }
                    drop(ready);

                    let _ = receiver.changed().await;
                    let timeout = *receiver.borrow_and_update();

                    handle.close(timeout).await;
                });
            };

            match std::thread::Builder::new().name(format!("soyokaze-{index}")).stack_size(self.config.limits.worker_stack_size).spawn(worker) {
                Ok(thread) => threads.push(thread),
                Err(error) => {
                    failure = Some(Error::IO(error));
                    break;
                }
            }
        }

        drop(ready);

        for _ in 0..threads.len() {
            match started.recv() {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => failure = failure.or(Some(error)),
                Err(_) => failure = failure.or(Some(Error::Closed)),
            }
        }

        if let Some(error) = failure {
            let _ = shutdown.send(None);
            for thread in threads {
                let _ = thread.join();
            }
            return Err(error);
        }

        Ok(Cluster::new(shutdown, threads, addresses))
    }
}

