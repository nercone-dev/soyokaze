//! Dialling an origin and issuing requests.
//!
//! [`Client`] is the entry point. Build one with [`Client::builder`], then use
//! [`Client::get`] and friends for one-off requests, or [`Client::connect`]
//! when the connection itself is wanted — to pipeline over it, multiplex
//! several streams, or hold it open.
//!
//! Which HTTP version is used follows from where the connection goes: a QUIC
//! port carries HTTP/3, and a TLS handshake negotiates between HTTP/2 and
//! HTTP/1.1 by ALPN. A plaintext connection cannot negotiate, so it takes the
//! version the builder was told or HTTP/1.1.
//!
//! A client keeps a [`CookieJar`] and an [`HstsStore`] unless told not to, and
//! both are consulted by [`Client::fetch`] and updated from what comes back.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::net::{TcpStream, UnixStream};

use crate::api::tls;
use crate::headers::CookieJar;
use crate::helpers::hsts::HstsStore;
use crate::models::{Body, ConnectionID, Headers, Limits, Message, Method, Port, Url, Version};
use crate::protocol::common::{AnyConnection, Connection, Error, Transport};
use crate::protocol::h1::H1Connection;
use crate::protocol::h2::H2Connection;
use crate::protocol::h3::{H3Connection, H3Session};

/// The versions offered when the builder was not told which to use, in the
/// order they are preferred.
pub const PREFERENCE: &[Version] = &[Version::V3_0, Version::V2_0, Version::V1_1];

/// Builds a [`Client`].
///
/// Everything has a working default: TLS on, cookies kept, HSTS remembered,
/// the platform trust store, and version chosen by negotiation.
pub struct ClientBuilder {
    version: Option<Version>,
    limits: Option<Limits>,
    secure: bool,
    roots: Option<Vec<Vec<u8>>>,
    ech: std::collections::HashMap<String, Vec<u8>>,
    cookies: bool,
    hsts: bool,
}

impl ClientBuilder {
    /// A builder with the defaults described on [`ClientBuilder`].
    pub fn new() -> Self {
        Self { version: None, limits: None, secure: true, roots: None, ech: std::collections::HashMap::new(), cookies: true, hsts: true }
    }

    /// Pins the HTTP version instead of negotiating one.
    ///
    /// [`Version::V3_0`] makes [`Client::open`] dial QUIC rather than TCP.
    pub fn version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the limits every connection this client makes will hold itself to.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Whether [`Client::connect`] wraps a stream transport in TLS.
    ///
    /// This does not affect [`Client::open`] and [`Client::fetch`], which
    /// decide from the URL's scheme.
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Trusts exactly these DER certificates instead of the platform store.
    pub fn roots(mut self, roots: Vec<Vec<u8>>) -> Self {
        self.roots = Some(roots);
        self
    }

    /// Uses an ECH configuration list when dialling `host`.
    ///
    /// A host of `*` applies wherever no exact entry matches. The list is what
    /// [`EchKeys::config_list`] produces.
    ///
    /// [`EchKeys::config_list`]: crate::api::tls::EchKeys::config_list
    pub fn ech(mut self, host: &str, config_list: Vec<u8>) -> Self {
        self.ech.insert(host.to_owned(), config_list);
        self
    }

    /// Whether to keep a [`CookieJar`] across requests.
    pub fn cookies(mut self, cookies: bool) -> Self {
        self.cookies = cookies;
        self
    }

    /// Whether to keep an [`HstsStore`] across requests.
    pub fn hsts(mut self, hsts: bool) -> Self {
        self.hsts = hsts;
        self
    }

    /// Builds the client.
    pub fn build(self) -> Client {
        let limits = self.limits.unwrap_or_default();

        Client {
            version: self.version,
            limits,
            secure: self.secure,
            roots: self.roots,
            ech: self.ech,
            jar: self.cookies.then(|| Arc::new(CookieJar::new().with_limits(limits))),
            store: self.hsts.then(|| Arc::new(HstsStore::new().with_limits(limits))),
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// An HTTP client.
///
/// Holds the configuration a connection is made with, and the cookie and HSTS
/// state that outlives one request. It does not pool connections: each
/// [`Client::fetch`] dials, exchanges, and closes. Use [`Client::connect`] or
/// [`Client::open`] to hold a connection open yourself.
pub struct Client {
    version: Option<Version>,
    limits: Limits,
    secure: bool,
    roots: Option<Vec<Vec<u8>>>,
    ech: std::collections::HashMap<String, Vec<u8>>,
    jar: Option<Arc<CookieJar>>,
    store: Option<Arc<HstsStore>>,
}

impl Client {
    /// A builder for a client.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// The ECH configuration list to use for a host, if one was configured.
    ///
    /// Falls back to the `*` entry.
    pub fn ech(&self, host: &str) -> Option<&Vec<u8>> {
        self.ech.get(host).or_else(|| self.ech.get("*"))
    }

    /// The limits every connection this client makes holds itself to.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The versions this client will offer, in order of preference.
    pub fn versions(&self) -> Vec<Version> {
        match self.version {
            Some(version) => vec![version],
            None => PREFERENCE.to_vec(),
        }
    }

    /// The identifier given to a connection to this host and port.
    pub fn id(&self, host: &str, target: &Port) -> ConnectionID {
        ConnectionID(Bytes::from(format!("{host}/{target:?}")))
    }

    /// Opens a connection to a host on a given port.
    ///
    /// The port decides the transport, and so the versions available: QUIC
    /// carries HTTP/3, TCP carries HTTP/1.1 or HTTP/2 over TLS when
    /// [`ClientBuilder::secure`] is set, and a Unix socket is always plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the transport cannot be established,
    /// [`Error::Tls`] when the handshake fails, and [`Error::Version`] when no
    /// usable version is agreed.
    pub async fn connect(&self, host: &str, target: Port) -> Result<AnyConnection, Error> {
        let id = self.id(host, &target);

        match target {
            Port::QUIC(port) => self.connect_quic(host, port, id).await,

            Port::TCP(port) => {
                let transport = TcpStream::connect((host, port)).await?;
                self.connect_stream(host, Box::new(transport), id).await
            }

            Port::UDS(ref path) => {
                let transport = UnixStream::connect(path).await?;
                self.assemble(self.prior_version(), Box::new(transport), id).await
            }
        }
    }

    /// Builds a connection over a transport the caller already has.
    ///
    /// Wraps it in TLS when [`ClientBuilder::secure`] is set.
    ///
    /// # Errors
    ///
    /// As [`Client::connect_stream_tls`] and [`Client::assemble`].
    pub async fn connect_stream(&self, host: &str, transport: Box<dyn Transport>, id: ConnectionID) -> Result<AnyConnection, Error> {
        if !self.secure {
            return self.assemble(self.prior_version(), transport, id).await;
        }

        self.connect_stream_tls(host, transport, id).await
    }

    /// Runs the TLS handshake over a transport and builds the negotiated
    /// connection.
    ///
    /// HTTP/3 is filtered out of what is offered, since it needs QUIC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] when HTTP/3 is the only version configured,
    /// or when nothing usable is negotiated, and [`Error::Tls`] when the
    /// handshake fails.
    pub async fn connect_stream_tls(&self, host: &str, transport: Box<dyn Transport>, id: ConnectionID) -> Result<AnyConnection, Error> {
        let versions: Vec<Version> = self.versions().into_iter().filter(|version| version.major() != 3).collect();
        if versions.is_empty() {
            return Err(Error::Version("HTTP/3 needs a QUIC port".into()));
        }

        let connector = tls::client_config(self.roots.as_deref().unwrap_or(&[]), &versions)?;
        let mut config = connector.configure().map_err(|err| Error::Tls(err.to_string()))?;

        if let Some(list) = self.ech(host) {
            config.set_ech_config_list(list).map_err(|err| Error::Tls(err.to_string()))?;
        }

        let stream = tokio_boring::connect(config, host, transport).await.map_err(|err| Error::Tls(err.to_string()))?;
        let version = tls::negotiated(stream.ssl().selected_alpn_protocol(), &versions)?;

        self.assemble(version, Box::new(stream), id).await
    }

    /// Opens an HTTP/3 connection over QUIC.
    ///
    /// The local socket is bound to match the address family the host resolved
    /// to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the host resolves to nothing or the socket
    /// cannot be set up, and [`Error::Tls`] when the QUIC handshake fails.
    pub async fn connect_quic(&self, host: &str, port: u16, id: ConnectionID) -> Result<AnyConnection, Error> {
        let address = tokio::net::lookup_host((host, port))
            .await?
            .next()
            .ok_or_else(|| Error::Io(std::io::Error::other(format!("{host} resolved to no address"))))?;

        let bind = match address {
            std::net::SocketAddr::V4(_) => std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            std::net::SocketAddr::V6(_) => std::net::SocketAddr::from(([0u16; 8], 0)),
        };

        let udp = tokio::net::UdpSocket::bind(bind).await?;
        udp.connect(address).await?;
        let socket: tokio_quiche::socket::Socket<std::sync::Arc<tokio::net::UdpSocket>, std::sync::Arc<tokio::net::UdpSocket>> = udp.try_into().map_err(|err: std::io::Error| Error::Io(err))?;

        let mut settings = tokio_quiche::settings::QuicSettings::default();
        settings.alpn = vec![Version::V3_0.alpn().as_bytes().to_vec()];
        settings.max_idle_timeout = crate::protocol::common::duration(self.limits.read_timeout);
        settings.enable_dgram = false;

        let hooks = tokio_quiche::settings::Hooks {
            connection_hook: Some(std::sync::Arc::new(tls::QuicClientTls { roots: self.roots.clone().unwrap_or_default() })),
        };

        let params = tokio_quiche::ConnectionParams::new_client(
            settings,
            Some(tokio_quiche::settings::TlsCertificatePaths { cert: "", private_key: "", kind: tokio_quiche::settings::CertificateKind::X509 }),
            hooks,
        );

        let session = H3Session::new(crate::models::Role::UserAgent, id, self.limits);
        let (mut connection, worker) = H3Connection::pair(session, None);
        let quic = tokio_quiche::quic::connect_with_config(socket, Some(host), &params, worker)
            .await
            .map_err(|err| Error::Tls(err.to_string()))?;
        connection.guard = Some(std::sync::Arc::new(quic));

        Ok(AnyConnection::H3(connection))
    }

    /// The version to use where nothing can be negotiated.
    ///
    /// Whatever the builder was told, or HTTP/1.1.
    pub fn prior_version(&self) -> Version {
        self.version.unwrap_or(Version::V1_1)
    }

    /// Wraps a transport in the connection type for a version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] for [`Version::V3_0`], which cannot run over
    /// a stream transport.
    pub async fn assemble(&self, version: Version, transport: Box<dyn Transport>, id: ConnectionID) -> Result<AnyConnection, Error> {
        let role = crate::models::Role::UserAgent;

        match version {
            Version::V1_0 | Version::V1_1 => {
                Ok(AnyConnection::H1(H1Connection::new(transport, role, id, self.limits)))
            }
            Version::V2_0 => Ok(AnyConnection::H2(H2Connection::new(transport, role, id, self.limits))),
            Version::V3_0 => Err(Error::Version("HTTP/3 needs a QUIC port".into())),
        }
    }

    /// Sends a request and waits for the response.
    ///
    /// Informational (1xx) responses are read past, so what comes back is the
    /// real one.
    ///
    /// # Errors
    ///
    /// Any [`Error`] the connection raises.
    pub async fn request(&self, connection: &mut AnyConnection, request: Message) -> Result<Message, Error> {
        connection.send(request).await?;

        loop {
            let response = connection.receive().await?;

            if !response.is_informational() {
                return Ok(response);
            }
        }
    }

    /// The cookie jar, unless cookies were turned off.
    pub fn jar(&self) -> Option<&Arc<CookieJar>> {
        self.jar.as_ref()
    }

    /// The HSTS store, unless HSTS was turned off.
    pub fn store(&self) -> Option<&Arc<HstsStore>> {
        self.store.as_ref()
    }

    /// Whether this client dials QUIC rather than TCP.
    pub fn prefers_h3(&self) -> bool {
        self.version == Some(Version::V3_0)
    }

    /// Opens a connection for a URL, taking the transport from its scheme.
    ///
    /// A secure scheme dials QUIC when the client is pinned to HTTP/3, and TLS
    /// over TCP otherwise. An insecure scheme dials plain TCP.
    ///
    /// # Errors
    ///
    /// As [`Client::connect`].
    pub async fn open(&self, url: &Url) -> Result<AnyConnection, Error> {
        let id = self.id(&url.host, &Port::TCP(url.port));

        if !url.secure() {
            let transport = TcpStream::connect((url.host.as_str(), url.port)).await?;
            return self.assemble(self.prior_version(), Box::new(transport), id).await;
        }

        if self.prefers_h3() {
            return self.connect_quic(&url.host, url.port, id).await;
        }

        let transport = TcpStream::connect((url.host.as_str(), url.port)).await?;
        self.connect_stream_tls(&url.host, Box::new(transport), id).await
    }

    /// Upgrades a URL to its secure scheme when the store says the host insists.
    ///
    /// `http` becomes `https` and `ws` becomes `wss`, and a default port of 80
    /// moves to 443. Does nothing when HSTS is off or the host is not stored.
    pub fn apply_hsts(&self, url: &mut Url, now: Instant) {
        if let Some(store) = &self.store
            && matches!(url.scheme.as_str(), "http" | "ws")
            && store.secure(&url.host, now)
        {
            url.scheme = if url.scheme == "http" { "https".to_owned() } else { "wss".to_owned() };
            if url.port == 80 {
                url.port = 443;
            }
        }
    }

    /// Makes one request and returns the response.
    ///
    /// Dials, exchanges, and closes the connection. HSTS is applied to the URL
    /// first; `Host` and `Cookie` are filled in unless the caller set them;
    /// and any `Set-Cookie` and `Strict-Transport-Security` on the response
    /// are taken into the client's state.
    ///
    /// Redirects are not followed — the response is returned as it came.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the URL will not parse, and otherwise
    /// as [`Client::open`] and [`Client::request`].
    pub async fn fetch(&self, method: Method, url: &str, headers: Option<Headers>, body: Option<Body>) -> Result<Message, Error> {
        let now = Instant::now();
        let mut url = Url::parse(url)?;
        self.apply_hsts(&mut url, now);

        let mut connection = self.open(&url).await?;

        let mut fields = headers.unwrap_or_default();
        if !fields.contains("host") {
            fields.append("host", url.authority());
        }
        if let Some(jar) = &self.jar
            && !fields.contains("cookie")
            && let Some(cookie) = jar.cookie(&url, now)
        {
            fields.append("cookie", cookie);
        }

        let mut request = Message::request(method, url.target.clone(), connection.version());
        request.secure = url.secure();
        request.headers = Some(fields);
        request.body = body;

        let response = self.request(&mut connection, request).await?;
        connection.close().await;

        if let (Some(jar), Some(headers)) = (&self.jar, response.headers.as_ref()) {
            let set: Vec<&str> = headers.get_all("set-cookie").collect();
            if !set.is_empty() {
                jar.learn(&url, &set, now);
            }
        }
        if let (Some(store), Some(headers)) = (&self.store, response.headers.as_ref())
            && let Some(policy) = headers.get("strict-transport-security")
        {
            store.learn(&url.host, policy, url.secure(), now);
        }

        Ok(response)
    }

    /// A `GET`; see [`Client::fetch`].
    ///
    /// # Errors
    ///
    /// As [`Client::fetch`].
    pub async fn get(&self, url: &str) -> Result<Message, Error> {
        self.fetch(Method::GET, url, None, None).await
    }

    /// A `HEAD`; see [`Client::fetch`].
    ///
    /// # Errors
    ///
    /// As [`Client::fetch`].
    pub async fn head(&self, url: &str) -> Result<Message, Error> {
        self.fetch(Method::HEAD, url, None, None).await
    }

    /// A `POST`; see [`Client::fetch`].
    ///
    /// # Errors
    ///
    /// As [`Client::fetch`].
    pub async fn post(&self, url: &str, body: Body) -> Result<Message, Error> {
        self.fetch(Method::POST, url, None, Some(body)).await
    }

    /// A `PUT`; see [`Client::fetch`].
    ///
    /// # Errors
    ///
    /// As [`Client::fetch`].
    pub async fn put(&self, url: &str, body: Body) -> Result<Message, Error> {
        self.fetch(Method::PUT, url, None, Some(body)).await
    }

    /// A `DELETE`; see [`Client::fetch`].
    ///
    /// # Errors
    ///
    /// As [`Client::fetch`].
    pub async fn delete(&self, url: &str) -> Result<Message, Error> {
        self.fetch(Method::DELETE, url, None, None).await
    }

    /// Opens a WebSocket connection.
    ///
    /// The handshake follows whichever version was negotiated: an HTTP/1.1
    /// upgrade, or extended CONNECT over HTTP/2 and HTTP/3.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the URL will not parse or the server's
    /// handshake does not check out, and otherwise as [`Client::open`].
    pub async fn websocket(&self, url: &str) -> Result<crate::websocket::WebSocketConnection<Box<dyn Transport>>, Error> {
        let mut url = Url::parse(url)?;
        self.apply_hsts(&mut url, Instant::now());

        let connection = self.open(&url).await?;
        connection.open_websocket(&url.authority(), &url.target).await
    }
}

/// The limits a client applies on top of the per-message [`Limits`].
#[derive(Debug, Clone)]
pub struct ClientLimits {
    /// The limits each connection holds itself to.
    pub message: Limits,
    /// In seconds, how long to wait for a connection to be established.
    pub connection_timeout: f64,
    /// The number of connections kept for reuse (HTTP/2 sessions, keep-alive).
    pub max_connections: u32,
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self { message: Limits::default(), connection_timeout: 10.0, max_connections: 65536 }
    }
}
