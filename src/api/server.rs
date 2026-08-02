use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::{TcpListener, UnixListener};

use crate::api::tls::{self, Identity};
use crate::helpers::sync::lock;
use crate::models::{ConnectionID, Limits, Port, Role, Version};
use crate::protocol::common::{self, AnyConnection, Buffer, Connection, Error, Transport};
use crate::protocol::h1::H1Connection;
use crate::protocol::h2::{self, H2Connection};
use crate::protocol::h3::{H3Connection, H3Session};

pub type QuicIncoming = tokio_quiche::InitialQuicConnection<tokio::net::UdpSocket, tokio_quiche::metrics::DefaultMetrics>;

pub const SUPPORTED: &[Version] = &[Version::V3_0, Version::V2_0, Version::V1_1];

pub const BACKLOG: i32 = 1024;

pub fn cores() -> usize {
    std::thread::available_parallelism().map(|count| count.get()).unwrap_or(1)
}

pub struct ServerBuilder {
    versions: Vec<Version>,
    limits: Option<Limits>,
    identity: Option<Identity>,
    ech: Option<crate::api::tls::EchKeys>,
    max_connections: u32,
    max_connections_per_ip: u32,
    max_connection_rate: Vec<(f64, u32)>,
    hsts: Option<crate::helpers::hsts::HstsPolicy>,
    reuseport: bool,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            versions: Vec::new(),
            limits: None,
            identity: None,
            ech: None,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_connection_rate: Vec::new(),
            hsts: None,
            reuseport: true,
        }
    }

    pub fn version(mut self, version: Version) -> Self {
        self.versions.push(version);
        self
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    pub fn identity(mut self, certificates: Vec<Vec<u8>>, key: Vec<u8>) -> Self {
        self.identity = Some(Identity::new(certificates, key));
        self
    }

    pub fn ech(mut self, ech: crate::api::tls::EchKeys) -> Self {
        self.ech = Some(ech);
        self
    }

    pub fn max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub fn max_connections_per_ip(mut self, max_connections_per_ip: u32) -> Self {
        self.max_connections_per_ip = max_connections_per_ip;
        self
    }

    pub fn max_connection_rate(mut self, max_connection_rate: Vec<(f64, u32)>) -> Self {
        self.max_connection_rate = max_connection_rate;
        self
    }

    pub fn hsts(mut self, hsts: crate::helpers::hsts::HstsPolicy) -> Self {
        self.hsts = Some(hsts);
        self
    }

    pub fn reuseport(mut self, reuseport: bool) -> Self {
        self.reuseport = reuseport;
        self
    }

    pub fn build(self) -> Server {
        Server {
            versions: if self.versions.is_empty() { SUPPORTED.to_vec() } else { self.versions },
            limits: self.limits.unwrap_or_default(),
            identity: self.identity,
            ech: self.ech,
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            max_connection_rate: self.max_connection_rate,
            hsts: self.hsts,
            reuseport: self.reuseport,
        }
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct Server {
    versions: Vec<Version>,
    limits: Limits,
    identity: Option<Identity>,
    ech: Option<crate::api::tls::EchKeys>,
    max_connections: u32,
    max_connections_per_ip: u32,
    max_connection_rate: Vec<(f64, u32)>,
    hsts: Option<crate::helpers::hsts::HstsPolicy>,
    reuseport: bool,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    pub fn versions(&self) -> &[Version] {
        &self.versions
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn reuseport(&self) -> bool {
        self.reuseport
    }

    pub async fn bind(&self, target: Port) -> Result<Listener, Error> {
        let socket = self.open(&target)?;
        self.attach(&target, socket).await
    }

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

    pub fn socket(&self, port: u16, kind: socket2::Type) -> Result<socket2::Socket, Error> {
        let socket = socket2::Socket::new(socket2::Domain::IPV6, kind, None)?;

        if self.reuseport {
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

    pub async fn attach(&self, target: &Port, socket: RawSocket) -> Result<Listener, Error> {
        let socket = match socket {
            RawSocket::UDS(listener) => Socket::UDS(UnixListener::from_std(listener)?),

            RawSocket::TCP(listener) => Socket::TCP(TcpListener::from_std(listener)?),

            RawSocket::QUIC(udp) => {
                let identity = self
                    .identity
                    .as_ref()
                    .ok_or_else(|| Error::Tls("a QUIC port needs a certificate and a key".into()))?;

                let versions: Vec<Version> = self.versions.iter().copied().filter(|version| version.major() == 3).collect();
                if versions.is_empty() {
                    return Err(Error::Version("a QUIC port only carries HTTP/3".into()));
                }

                let address = udp.local_addr()?;

                let mut settings = tokio_quiche::settings::QuicSettings::default();
                settings.alpn = versions.iter().map(|version| version.alpn().as_bytes().to_vec()).collect();
                settings.max_idle_timeout = common::duration(self.limits.read_timeout);
                settings.initial_max_streams_bidi = self.limits.max_concurrent_streams as u64;
                settings.enable_dgram = false;

                let hooks = tokio_quiche::settings::Hooks {
                    connection_hook: Some(std::sync::Arc::new(tls::QuicServerTls { identity: identity.clone(), ech: self.ech.clone() })),
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
            Port::QUIC(_) => self.versions.iter().copied().filter(|version| version.major() == 3).collect(),
            _ => self.versions.iter().copied().filter(|version| version.major() != 3).collect(),
        };

        let acceptor = match (&self.identity, &socket) {
            (Some(identity), Socket::TCP(_)) => Some(Arc::new(tls::server_config(identity, &versions, self.ech.as_ref())?)),
            _ => None,
        };

        let negotiation = Negotiation { versions, limits: self.limits, acceptor, hsts: self.hsts };
        let (negotiating, negotiated) = tokio::sync::mpsc::channel(negotiation.limits.max_pending_handshakes.max(1) as usize);

        Ok(Listener { socket, negotiation: Arc::new(negotiation), negotiating, negotiated })
    }
}

pub enum RawSocket {
    UDS(std::os::unix::net::UnixListener),
    TCP(std::net::TcpListener),
    QUIC(std::net::UdpSocket),
}

impl RawSocket {
    pub fn address(&self) -> Result<SocketAddr, Error> {
        match self {
            Self::TCP(listener) => Ok(listener.local_addr()?),
            Self::QUIC(socket) => Ok(socket.local_addr()?),
            Self::UDS(_) => Err(Error::Io(std::io::Error::other("a unix socket has no address"))),
        }
    }

    pub fn share(&self) -> Result<Self, Error> {
        Ok(match self {
            Self::UDS(listener) => Self::UDS(listener.try_clone()?),
            Self::TCP(listener) => Self::TCP(listener.try_clone()?),
            Self::QUIC(socket) => Self::QUIC(socket.try_clone()?),
        })
    }
}

pub enum Socket {
    UDS(UnixListener),
    TCP(TcpListener),
    QUIC {
        incoming: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<std::io::Result<QuicIncoming>>>,
        address: std::net::SocketAddr,
    },
}

impl Socket {
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

#[allow(clippy::large_enum_variant)]
pub enum Incoming {
    Stream { transport: Box<dyn Transport>, id: ConnectionID },
    QUIC(QuicIncoming),
}

#[derive(Clone)]
pub struct Negotiation {
    pub versions: Vec<Version>,
    pub limits: Limits,
    pub acceptor: Option<Arc<boring::ssl::SslAcceptor>>,
    pub hsts: Option<crate::helpers::hsts::HstsPolicy>,
}

impl Negotiation {
    pub async fn accept(&self, incoming: Incoming) -> Result<AnyConnection, Error> {
        match incoming {
            Incoming::Stream { transport, id } => {
                common::within(self.limits.read_timeout, self.assemble(transport, id)).await?
            }

            Incoming::QUIC(incoming) => {
                let id = ConnectionID(Bytes::from(incoming.peer_addr().to_string()));

                let session = H3Session::new(Role::Origin, id, self.limits);
                let (mut connection, worker) = H3Connection::pair(session, self.hsts);
                let quic = incoming.start(worker);
                connection.guard = Some(std::sync::Arc::new(quic));

                Ok(AnyConnection::H3(connection))
            }
        }
    }

    pub async fn assemble(&self, transport: Box<dyn Transport>, id: ConnectionID) -> Result<AnyConnection, Error> {
        let Some(acceptor) = &self.acceptor else {
            return self.assemble_plain(transport, id).await;
        };

        let stream = tokio_boring::accept(acceptor, transport).await.map_err(|err| Error::Tls(err.to_string()))?;
        let version = tls::negotiated(stream.ssl().selected_alpn_protocol(), &self.versions)?;

        let transport = Box::new(stream) as Box<dyn Transport>;
        Ok(match version {
            Version::V2_0 => AnyConnection::H2(H2Connection::new(transport, Role::Origin, id, self.limits).with_hsts(self.hsts)),
            _ => AnyConnection::H1(H1Connection::new(transport, Role::Origin, id, self.limits).with_hsts(self.hsts)),
        })
    }

    pub async fn assemble_plain(&self, mut transport: Box<dyn Transport>, id: ConnectionID) -> Result<AnyConnection, Error> {
        let mut buffer = Buffer::new();

        let probe = h2::PREFACE.len().min(4);
        while buffer.len() < probe && buffer.fill(&mut transport, self.limits.read_timeout).await? {}

        let sniffed = buffer.len().min(probe);
        let h2 = self.versions.contains(&Version::V2_0)
            && sniffed > 0
            && buffer.as_slice()[..sniffed] == h2::PREFACE[..sniffed];

        if h2 {
            return Ok(AnyConnection::H2(H2Connection::resume(transport, Role::Origin, id, self.limits, buffer)));
        }

        Ok(AnyConnection::H1(H1Connection::resume(transport, Role::Origin, id, self.limits, buffer)))
    }
}

pub struct Listener {
    socket: Socket,
    negotiation: Arc<Negotiation>,
    negotiating: tokio::sync::mpsc::Sender<Result<AnyConnection, Error>>,
    negotiated: tokio::sync::mpsc::Receiver<Result<AnyConnection, Error>>,
}

impl Listener {
    pub fn versions(&self) -> &[Version] {
        &self.negotiation.versions
    }

    pub fn limits(&self) -> &Limits {
        &self.negotiation.limits
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }

    pub fn negotiation(&self) -> &Negotiation {
        &self.negotiation
    }

    pub fn pending(&self) -> usize {
        self.negotiating.max_capacity() - self.negotiating.capacity()
    }

    pub fn address(&self) -> Result<std::net::SocketAddr, Error> {
        match &self.socket {
            Socket::TCP(listener) => Ok(listener.local_addr()?),
            Socket::QUIC { address, .. } => Ok(*address),
            Socket::UDS(_) => Err(Error::Io(std::io::Error::other("a unix socket has no address"))),
        }
    }

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

#[derive(Debug, Clone)]
pub struct ServerLimits {
    pub message: Limits,

    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub max_connection_rate: Vec<(f64, u32)>, // [(period in seconds, count), ...]
    pub max_connection_history: usize,

    pub max_pending_handshakes: u32,
    pub handshake_timeout: f64,
    pub idle_timeout: f64,
    pub shutdown_timeout: f64,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            message: Limits::default(),
            max_connections: 16384,
            max_connections_per_ip: 0,
            max_connection_rate: vec![(1.0, 25), (5.0, 50), (60.0, 75)],
            max_connection_history: 1024,
            max_pending_handshakes: 256,
            handshake_timeout: 30.0,
            idle_timeout: 60.0,
            shutdown_timeout: 30.0,
        }
    }
}

pub struct GateState {
    pub per_ip: std::collections::HashMap<std::net::IpAddr, u32>,
    pub history: std::collections::HashMap<std::net::IpAddr, std::collections::VecDeque<std::time::Instant>>,
}

pub struct Gate {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub max_connection_rate: Vec<(f64, u32)>,
    pub max_connection_history: usize,

    pub window: f64,

    pub connections: std::sync::atomic::AtomicU32,
    pub state: std::sync::Mutex<GateState>,
}

impl Gate {
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

    pub fn from_limits(limits: &ServerLimits) -> Arc<Self> {
        Self::new(
            limits.max_connections,
            limits.max_connections_per_ip,
            limits.max_connection_rate.clone(),
            limits.max_connection_history,
        )
    }

    pub fn count(&self) -> u32 {
        self.connections.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn window(&self) -> f64 {
        self.window
    }

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

    pub fn bound_history(&self, state: &mut GateState, keep: std::net::IpAddr) {
        let cap = self.max_connection_history.max(self.max_connections as usize);

        while state.history.len() > cap {
            let Some(victim) = state.history.keys().find(|address| **address != keep).copied() else {
                break;
            };
            state.history.remove(&victim);
        }
    }

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

pub struct Permit {
    pub gate: Arc<Gate>,
    pub ip: Option<std::net::IpAddr>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.release(self.ip);
    }
}

pub trait Handler: Send + Sync + 'static {
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

    fn on_websocket(&self, socket: crate::websocket::WebSocketConnection<Box<dyn Transport>>) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let mut socket = socket;
            socket.close(crate::websocket::CloseCode::InternalError, "WebSocket is not configured").await;
        }
    }
}

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

pub struct DefaultHandler;
impl Handler for DefaultHandler {}

pub struct ServerHandle {
    pub shutdown: tokio::sync::watch::Sender<bool>,
    pub tasks: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
    pub accept_loops: Vec<tokio::task::JoinHandle<()>>,
    pub addresses: Vec<std::net::SocketAddr>,
}

impl ServerHandle {
    pub fn address(&self) -> Option<std::net::SocketAddr> {
        self.addresses.first().copied()
    }

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
    pub async fn serve<H: Handler>(&self, handler: H, ports: &[Port]) -> Result<ServerHandle, Error> {
        let gate = Gate::new(self.max_connections, self.max_connections_per_ip, self.max_connection_rate.clone(), 1024);

        let mut listeners = Vec::with_capacity(ports.len());
        for port in ports {
            listeners.push(self.bind(port.clone()).await?);
        }

        Ok(self.launch(Arc::new(handler), listeners, gate))
    }

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

    pub fn serve_workers<H: Handler>(&self, handler: H, ports: &[Port], workers: usize) -> Result<Cluster, Error> {
        let workers = workers.max(1);

        if workers > 1 && !self.reuseport && ports.iter().any(|port| matches!(port, Port::QUIC(_))) {
            let reason = "a QUIC port needs reuseport to run on more than one worker";
            return Err(Error::Io(std::io::Error::other(reason)));
        }

        let handler = Arc::new(handler);
        let gate = Gate::new(self.max_connections, self.max_connections_per_ip, self.max_connection_rate.clone(), 1024);

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

            let independent = self.reuseport && !matches!(target, Port::UDS(_));

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

pub struct Cluster {
    shutdown: tokio::sync::watch::Sender<Option<f64>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    addresses: Vec<std::net::SocketAddr>,
}

impl Cluster {
    pub fn address(&self) -> Option<std::net::SocketAddr> {
        self.addresses.first().copied()
    }

    pub fn addresses(&self) -> &[std::net::SocketAddr] {
        &self.addresses
    }

    pub fn workers(&self) -> usize {
        self.threads.len()
    }

    pub fn close(self, timeout: Option<f64>) {
        let _ = self.shutdown.send(timeout);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}
