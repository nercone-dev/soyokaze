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
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::{TcpListener, UnixListener};

use crate::api::common::{Limits, VERSIONS};
use crate::helpers::sync::lock;
use crate::models::{ConnectionID, Port, Version};
use crate::protocol::base::{AnyConnection, Connection, Transport};
use crate::protocol::common::{self, Error};
use crate::protocol::handler::{Incoming, Negotiation, QuicIncoming};
use crate::tls::{self, Identity};

/// The listen backlog for a TCP socket.
pub const BACKLOG: i32 = 1024;

/// How many threads the machine can run at once, or 1 if that cannot be found.
///
/// Useful as the worker count for [`Server::run`].
pub fn cores() -> usize {
    std::thread::available_parallelism().map(|count| count.get()).unwrap_or(1)
}

/// How a [`Server`] is configured.
///
/// Every field has a working default: every supported version offered, no
/// admission limits, `SO_REUSEPORT` on, and no identity, which leaves a TCP
/// port in plaintext and a QUIC port unservable.
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

    /// The keys to offer Encrypted Client Hello with.
    pub ech: Option<crate::tls::EchKeys>,

    /// The HSTS policy to attach to every secure response.
    pub hsts: Option<crate::helpers::hsts::HstsPolicy>,

    /// Whether sockets are opened with `SO_REUSEPORT`.
    ///
    /// On by default, and needed for [`Server::run`] to give each
    /// worker its own listener. Turning it off makes a QUIC port single-worker.
    pub reuseport: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            versions: VERSIONS.to_vec(),
            limits: ServerLimits::default(),
            identity: None,
            ech: None,
            hsts: None,
            reuseport: true,
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
    /// Returns [`Error::Io`] when the socket cannot be created or bound.
    pub fn open(&self, target: &Port) -> Result<RawSocket, Error> {
        Ok(match target {
            Port::UDS(path) => {
                let listener = std::os::unix::net::UnixListener::bind(path)?;
                listener.set_nonblocking(true)?;
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
    /// Returns [`Error::Io`] when the socket cannot be created, configured or
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
            socket.listen(BACKLOG)?;
        }

        Ok(socket)
    }

    /// Builds a listener over an already-open socket.
    ///
    /// This is where the version list is narrowed to what the port can carry —
    /// HTTP/3 on a QUIC port, everything else elsewhere — and where the TLS
    /// acceptor is built, if there is an identity to build one from.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when a QUIC port has no identity or a TLS
    /// context cannot be built, [`Error::Version`] when a QUIC port is offered
    /// no HTTP/3, and [`Error::Io`] when the socket cannot be adopted.
    pub async fn attach(&self, target: &Port, socket: RawSocket) -> Result<Listener, Error> {
        let socket = match socket {
            RawSocket::UDS(listener) => Socket::UDS(UnixListener::from_std(listener)?),

            RawSocket::TCP(listener) => Socket::TCP(TcpListener::from_std(listener)?),

            RawSocket::QUIC(udp) => {
                let identity = self
                    .config
                    .identity
                    .as_ref()
                    .ok_or_else(|| Error::Tls("a QUIC port needs a certificate and a key".into()))?;

                let versions: Vec<Version> = self.config.versions.iter().copied().filter(|version| version.major() == 3).collect();
                if versions.is_empty() {
                    return Err(Error::Version("a QUIC port only carries HTTP/3".into()));
                }

                let address = udp.local_addr()?;

                let mut settings = tokio_quiche::settings::QuicSettings::default();
                settings.alpn = versions.iter().map(|version| version.alpn().as_bytes().to_vec()).collect();
                settings.max_idle_timeout = common::duration(self.config.limits.message.read_timeout);
                settings.initial_max_streams_bidi = self.config.limits.message.max_concurrent_streams as u64;
                settings.enable_dgram = false;

                let hooks = tokio_quiche::settings::Hooks {
                    connection_hook: Some(std::sync::Arc::new(tls::QuicServerTls { identity: identity.clone(), ech: self.config.ech.clone() })),
                };

                let params = tokio_quiche::ConnectionParams::new_server(
                    settings,
                    tokio_quiche::settings::TlsCertificatePaths { cert: "", private_key: "", kind: tokio_quiche::settings::CertificateKind::X509 },
                    hooks,
                );

                let listeners = tokio_quiche::listen([udp], params, tokio_quiche::metrics::DefaultMetrics).map_err(Error::Io)?;
                let incoming = listeners.into_iter().next().ok_or(Error::Closed)?.into_inner();

                Socket::QUIC { incoming: tokio::sync::Mutex::new(incoming), address }
            }
        };

        let versions: Vec<Version> = match target {
            Port::QUIC(_) => self.config.versions.iter().copied().filter(|version| version.major() == 3).collect(),
            _ => self.config.versions.iter().copied().filter(|version| version.major() != 3).collect(),
        };

        let acceptor = match (&self.config.identity, &socket) {
            (Some(identity), Socket::TCP(_)) => Some(Arc::new(tls::server_config(identity, &versions, self.config.ech.as_ref())?)),
            _ => None,
        };

        let negotiation = Negotiation { versions, limits: self.config.limits.message, acceptor, hsts: self.config.hsts };
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
    /// Returns [`Error::Io`] for a Unix socket, which has no address, and when
    /// the address cannot be read.
    pub fn address(&self) -> Result<SocketAddr, Error> {
        match self {
            Self::TCP(listener) => Ok(listener.local_addr()?),
            Self::QUIC(socket) => Ok(socket.local_addr()?),
            Self::UDS(_) => Err(Error::Io(std::io::Error::other("a unix socket has no address"))),
        }
    }

    /// Duplicates the descriptor, so several workers accept from one socket.
    ///
    /// This is the fallback when `SO_REUSEPORT` is off, or for a Unix socket,
    /// which cannot be bound twice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the descriptor cannot be duplicated.
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
        incoming: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<std::io::Result<QuicIncoming>>>,
        /// The address the UDP socket is bound to.
        address: std::net::SocketAddr,
    },
}

impl Socket {
    /// Waits for the next connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when a QUIC endpoint has shut down, and
    /// [`Error::Io`] when accepting fails.
    pub async fn accept(&self) -> Result<Incoming, Error> {
        match self {
            Self::QUIC { incoming, .. } => {
                let incoming = incoming.lock().await.recv().await.ok_or(Error::Closed)?.map_err(Error::Io)?;
                Ok(Incoming::QUIC(incoming))
            }

            Self::TCP(listener) => {
                let (transport, address) = listener.accept().await?;
                Ok(Incoming::Stream { transport: Box::new(transport), id: ConnectionID(Bytes::from(address.to_string())) })
            }

            Self::UDS(listener) => {
                let (transport, _) = listener.accept().await?;
                Ok(Incoming::Stream { transport: Box::new(transport), id: ConnectionID(Bytes::from_static(b"unix")) })
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
    /// Returns [`Error::Io`] for a Unix socket, which has no address.
    pub fn address(&self) -> Result<std::net::SocketAddr, Error> {
        match &self.socket {
            Socket::TCP(listener) => Ok(listener.local_addr()?),
            Socket::QUIC { address, .. } => Ok(*address),
            Socket::UDS(_) => Err(Error::Io(std::io::Error::other("a unix socket has no address"))),
        }
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
    /// Returns [`Error::Io`] or [`Error::Closed`] when accepting itself fails.
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

    /// The number of connections that may be open at once. Zero is unbounded.
    pub max_connections: u32,
    /// The number of connections one address may have open. Zero is unbounded.
    pub max_connections_per_ip: u32,
    /// Rate limits as `[(period in seconds, count), ...]`; every entry must be
    /// satisfied, so several together shape both bursts and sustained rate.
    pub max_connection_rate: Vec<(f64, u32)>,
    /// The number of addresses whose connection history is remembered.
    pub max_connection_history: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            message: Limits::default(),
            max_connections: 0,
            max_connections_per_ip: 0,
            max_connection_rate: Vec::new(),
            max_connection_history: 1024,
        }
    }
}

/// The per-address bookkeeping a [`Gate`] keeps behind its lock.
pub struct GateState {
    /// How many connections each address currently holds.
    pub per_ip: std::collections::HashMap<std::net::IpAddr, u32>,
    /// When each address last connected, within the rate window.
    pub history: std::collections::HashMap<std::net::IpAddr, std::collections::VecDeque<std::time::Instant>>,
}

/// Admission control for incoming connections.
///
/// Checked before a handler is reached, so a refused connection costs a
/// handshake and nothing more. Shared across every listener and worker, so the
/// totals are for the server as a whole rather than per port.
///
/// The total count is an atomic, since every connection touches it; the
/// per-address tallies sit behind a lock, since they are only consulted for a
/// connection whose address is known.
pub struct Gate {
    /// The connections that may be open at once. Zero is unbounded.
    pub max_connections: u32,
    /// The connections one address may have open. Zero is unbounded.
    pub max_connections_per_ip: u32,
    /// Rate limits as `[(period in seconds, count), ...]`.
    pub max_connection_rate: Vec<(f64, u32)>,
    /// The addresses whose history is remembered.
    pub max_connection_history: usize,

    /// The longest period in [`Gate::max_connection_rate`], which is how far
    /// back history has to be kept.
    pub window: f64,

    /// How many connections are open right now.
    pub connections: std::sync::atomic::AtomicU32,
    /// The per-address bookkeeping.
    pub state: std::sync::Mutex<GateState>,
}

impl Gate {
    /// A gate with these limits.
    pub fn new(max_connections: u32, max_connections_per_ip: u32, max_connection_rate: Vec<(f64, u32)>, max_connection_history: usize) -> Arc<Self> {
        Arc::new(Self {
            window: max_connection_rate.iter().map(|(period, _)| *period).fold(0.0, f64::max),
            max_connections,
            max_connections_per_ip,
            max_connection_rate,
            max_connection_history,
            connections: std::sync::atomic::AtomicU32::new(0),
            state: std::sync::Mutex::new(GateState {
                per_ip: std::collections::HashMap::new(),
                history: std::collections::HashMap::new(),
            }),
        })
    }

    /// A gate taking its limits from a [`ServerLimits`].
    pub fn from_limits(limits: &ServerLimits) -> Arc<Self> {
        Self::new(
            limits.max_connections,
            limits.max_connections_per_ip,
            limits.max_connection_rate.clone(),
            limits.max_connection_history,
        )
    }

    /// How many connections are open right now.
    pub fn count(&self) -> u32 {
        self.connections.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The longest rate limit period, and so how far back history is kept.
    pub fn window(&self) -> f64 {
        self.window
    }

    /// Admits a connection, or refuses it.
    ///
    /// `None` means turn the connection away. A [`Permit`] means it may
    /// proceed, and releases its slot when dropped — so holding the permit for
    /// as long as the connection lives is what keeps the count honest.
    ///
    /// An `ip` of `None` skips the per-address checks; a Unix socket has no
    /// address to limit by.
    pub fn admit(self: &Arc<Self>, ip: Option<std::net::IpAddr>, now: std::time::Instant) -> Option<Permit> {
        use std::sync::atomic::Ordering;

        loop {
            let current = self.connections.load(Ordering::Acquire);
            if self.max_connections != 0 && current >= self.max_connections {
                return None;
            }
            if self
                .connections
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        if let Some(ip) = ip {
            let mut state = lock(&self.state);

            let count = state.per_ip.get(&ip).copied().unwrap_or(0);
            let over_ip = self.max_connections_per_ip != 0 && count >= self.max_connections_per_ip;

            if over_ip || !self.rate(&mut state, ip, now) {
                drop(state);
                self.connections.fetch_sub(1, Ordering::AcqRel);
                return None;
            }

            self.bound_history(&mut state, ip);
            *state.per_ip.entry(ip).or_insert(0) += 1;
        }

        Some(Permit { gate: Arc::clone(self), ip })
    }

    /// Whether an address is within every rate limit, recording the attempt
    /// when it is.
    ///
    /// Entries older than the longest window are dropped as they are found.
    pub fn rate(&self, state: &mut GateState, ip: std::net::IpAddr, now: std::time::Instant) -> bool {
        let window = self.window();
        let record = state.history.entry(ip).or_default();

        while record.front().is_some_and(|front| now.duration_since(*front).as_secs_f64() > window) {
            record.pop_front();
        }

        for &(period, count) in &self.max_connection_rate {
            let recent = record.iter().filter(|at| now.duration_since(**at).as_secs_f64() <= period).count() as u32;
            if recent >= count {
                return false;
            }
        }

        record.push_back(now);
        true
    }

    /// Bounds how many addresses are remembered, never evicting `keep`.
    ///
    /// Without this, a flood from many addresses would grow the history
    /// without bound — the rate limiter itself becoming the way in.
    pub fn bound_history(&self, state: &mut GateState, keep: std::net::IpAddr) {
        let cap = self.max_connection_history.max(self.max_connections as usize);

        while state.history.len() > cap {
            let Some(victim) = state.history.keys().find(|address| **address != keep).copied() else {
                break;
            };
            state.history.remove(&victim);
        }
    }

    /// Gives a connection's slot back.
    ///
    /// Called by [`Permit`] on drop; there is rarely a reason to call it
    /// directly, and doing so alongside a live permit would double-count.
    pub fn release(&self, ip: Option<std::net::IpAddr>) {
        self.connections.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);

        if let Some(ip) = ip {
            let mut state = lock(&self.state);
            if let Some(count) = state.per_ip.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_ip.remove(&ip);
                }
            }
        }
    }

    /// Drops rate history that has aged out.
    ///
    /// [`Gate::admit`] prunes as it goes, so this is only needed to reclaim
    /// memory on a server that has gone quiet.
    pub fn sweep(&self, now: std::time::Instant) {
        let window = self.window();
        let mut state = lock(&self.state);

        state.history.retain(|_, record| {
            while record.front().is_some_and(|front| now.duration_since(*front).as_secs_f64() > window) {
                record.pop_front();
            }
            !record.is_empty()
        });
    }
}

/// A connection's claim on a [`Gate`] slot.
///
/// Holding it is what keeps the connection counted; dropping it gives the slot
/// back. Keep it alive for as long as the connection is.
pub struct Permit {
    /// The gate the slot belongs to.
    pub gate: Arc<Gate>,
    /// The address the slot was counted against, if any.
    pub ip: Option<std::net::IpAddr>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.release(self.ip);
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

                if crate::websocket::upgrade_requested(&request) {
                    if crate::websocket::verify_upgrade(&request).is_err() {
                        if connection.send(upgrade_required(&request, connection.version())).await.is_err() {
                            break;
                        }
                        continue;
                    }

                    if let Ok(socket) = connection.accept_websocket(&request).await {
                        self.on_websocket(socket).await;
                    }
                    return;
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

/// The `426 Upgrade Required` sent when a WebSocket handshake does not check out.
///
/// Tells the client which version is expected, so it can retry correctly. The
/// `Upgrade` and `Connection` fields only belong on HTTP/1.x, where they mean
/// anything.
pub fn upgrade_required(request: &crate::models::Message, version: Version) -> crate::models::Message {
    let mut headers = crate::models::Headers::new();
    if version.major() == 1 {
        headers.append("upgrade", crate::websocket::PROTOCOL);
        headers.append("connection", "Upgrade");
    }
    headers.append("sec-websocket-version", crate::websocket::VERSION);

    let mut response = crate::models::Message::response(426, version);
    response.stream_id = request.stream_id;
    response.headers = Some(headers);
    response
}

/// A [`Handler`] that does nothing beyond the trait's defaults.
///
/// Useful for bringing a server up before deciding what it should answer.
pub struct DefaultHandler;
impl Handler for DefaultHandler {}

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

        match timeout.and_then(common::duration) {
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
        let gate = Gate::from_limits(&self.config.limits);

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

                            let ip = std::str::from_utf8(&connection.id().0)
                                .ok()
                                .and_then(|address| address.parse::<std::net::SocketAddr>().ok())
                                .map(|address| address.ip());

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
    /// Returns [`Error::Io`] when a QUIC port is asked for more than one
    /// worker without reuseport, when a socket cannot be opened, or when a
    /// thread or runtime cannot be created. On failure every thread already
    /// started is wound down first.
    pub fn run<H: Handler>(&self, handler: H, ports: &[Port], workers: usize) -> Result<Cluster, Error> {
        let workers = workers.max(1);

        if workers > 1 && !self.config.reuseport && ports.iter().any(|port| matches!(port, Port::QUIC(_))) {
            let reason = "a QUIC port needs reuseport to run on more than one worker";
            return Err(Error::Io(std::io::Error::other(reason)));
        }

        let handler = Arc::new(handler);
        let gate = Gate::from_limits(&self.config.limits);

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
                        let _ = ready.send(Err(Error::Io(error)));
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

            match std::thread::Builder::new().name(format!("soyokaze-{index}")).spawn(worker) {
                Ok(thread) => threads.push(thread),
                Err(error) => {
                    failure = Some(Error::Io(error));
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

        Ok(Cluster { shutdown, threads, addresses })
    }
}

/// A server running across several threads, as [`Server::run`]
/// returns it.
///
/// Dropping this leaves the workers running; call [`Cluster::close`] to wind
/// them down.
pub struct Cluster {
    shutdown: tokio::sync::watch::Sender<Option<f64>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    addresses: Vec<std::net::SocketAddr>,
}

impl Cluster {
    /// The first bound address, if any port has one.
    pub fn address(&self) -> Option<std::net::SocketAddr> {
        self.addresses.first().copied()
    }

    /// Every bound address.
    pub fn addresses(&self) -> &[std::net::SocketAddr] {
        &self.addresses
    }

    /// How many worker threads are running.
    pub fn workers(&self) -> usize {
        self.threads.len()
    }

    /// Stops every worker and waits for the threads to finish.
    ///
    /// `timeout` is passed to each worker's [`ServerHandle::close`], bounding
    /// how long it waits for its connections. This blocks, so do not call it
    /// from inside an async context.
    pub fn close(self, timeout: Option<f64>) {
        let _ = self.shutdown.send(timeout);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}
