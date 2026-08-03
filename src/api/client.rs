//! Dialling an origin and issuing requests.
//!
//! [`Client`] is the entry point. Build one with [`Client::new`] from a
//! [`ClientConfig`] — or [`Client::default`] to take every default — then use
//! [`Client::get`] and friends for one-off requests, or [`Client::connect`]
//! when the connection itself is wanted — to pipeline over it, multiplex
//! several streams, or hold it open.
//!
//! Which HTTP version is used follows from where the connection goes: a QUIC
//! port carries HTTP/3, and a TLS handshake negotiates between HTTP/2 and
//! HTTP/1.1 by ALPN. A plaintext connection cannot negotiate, so it takes the
//! version [`ClientConfig::versions`] pinned or HTTP/1.1.
//!
//! A client keeps a [`CookieJar`] and an [`HstsStore`] unless told not to, and
//! both are consulted by [`Client::fetch`] and updated from what comes back.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::net::{TcpStream, UnixStream};

use crate::api::common::VERSIONS;
use crate::cookies::CookieJar;
use crate::hsts::HstsStore;
use crate::helpers::text::Text;
use crate::models::{Alpn, Body, ConnectionID, Headers, Limits, Message, Method, Port, TransportKind, Url, Version};
use crate::tls::Security;
use crate::protocol::base::{AnyConnection, Connection, Transport};
use crate::protocol::common::Error;
use crate::protocol::h1::H1Connection;
use crate::protocol::h2::H2Connection;
use crate::protocol::h3::{H3Connection, H3Session};
use crate::protocol::handler::QuicApplication;
use crate::protocol::quic;
use crate::helpers::sync;

/// How a [`Client`] is configured.
///
/// Every field has a working default: every supported version offered, TLS on,
/// cookies kept, HSTS remembered, and the platform trust store.
#[derive(Clone)]
pub struct ClientConfig {
    /// The versions to offer, in the order they are preferred.
    ///
    /// Exactly one entry pins the version instead of negotiating one, and
    /// [`Version::V3_0`] alone makes [`Client::open`] dial QUIC rather than
    /// TCP.
    pub versions: Vec<Version>,

    /// The limits every connection this client makes will hold itself to.
    pub limits: ClientLimits,

    /// Whether [`Client::connect`] wraps a stream transport in TLS.
    ///
    /// This does not affect [`Client::open`] and [`Client::fetch`], which
    /// decide from the URL's scheme.
    pub secure: bool,

    /// The certificates to trust instead of the platform store.
    ///
    /// Each entry is DER or PEM, so a whole bundle of roots may be one entry.
    pub roots: Option<Vec<Vec<u8>>>,

    /// The TLS details every context is built with: cipher suites, groups,
    /// signature algorithms, session tickets, early data and certificate
    /// compression.
    pub tls: crate::tls::TlsConfig,

    /// The ECH configuration list to use when dialling each host.
    ///
    /// A host of `*` applies wherever no exact entry matches. Each list is
    /// what [`EchKeys::config_list`] produces.
    ///
    /// [`EchKeys::config_list`]: crate::tls::EchKeys::config_list
    pub ech: std::collections::HashMap<String, Vec<u8>>,

    /// Whether to keep a [`CookieJar`] across requests.
    pub cookies: bool,

    /// Whether to keep an [`HstsStore`] across requests.
    pub hsts: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            versions: VERSIONS.to_vec(),
            limits: ClientLimits::default(),
            secure: true,
            roots: None,
            tls: crate::tls::TlsConfig::default(),
            ech: std::collections::HashMap::new(),
            cookies: true,
            hsts: true,
        }
    }
}

/// The limits a client applies on top of the per-message [`Limits`].
#[derive(Debug, Clone)]
pub struct ClientLimits {
    /// The limits each connection holds itself to.
    pub message: Limits,
    /// In seconds, how long establishing one connection may take, TLS
    /// handshake included. Zero waits forever.
    pub connection_timeout: f64,
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self { message: Limits::default(), connection_timeout: 10.0 }
    }
}

/// An HTTP client.
///
/// Holds the configuration a connection is made with, and the cookie and HSTS
/// state that outlives one request. It does not pool connections: each
/// [`Client::fetch`] dials, exchanges, and closes. Use [`Client::connect`] or
/// [`Client::open`] to hold a connection open yourself.
pub struct Client {
    /// How this client is configured.
    pub config: ClientConfig,
    /// The cookie jar, unless [`ClientConfig::cookies`] turned it off.
    pub jar: Option<Arc<CookieJar>>,
    /// The HSTS store, unless [`ClientConfig::hsts`] turned it off.
    pub store: Option<Arc<HstsStore>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(ClientConfig::default())
    }
}

impl Client {
    /// A client with this configuration.
    pub fn new(config: ClientConfig) -> Self {
        let jar = config.cookies.then(|| Arc::new(CookieJar::new().with_limits(config.limits.message)));
        let store = config.hsts.then(|| Arc::new(HstsStore::new().with_limits(config.limits.message)));

        Self { config, jar, store }
    }

    /// The ECH configuration list to use for a host, if one was configured.
    ///
    /// Falls back to the `*` entry.
    pub fn ech(&self, host: &str) -> Option<&Vec<u8>> {
        self.config.ech.get(host).or_else(|| self.config.ech.get("*"))
    }

    /// The identifier given to a connection to this host and port.
    pub fn id(&self, host: &str, target: &Port) -> ConnectionID {
        ConnectionID(Bytes::from(format!("{host}/{target:?}")))
    }

    /// The authority a request over a connection to this host and port carries.
    ///
    /// The scheme comes from [`ClientConfig::secure`], since that is what
    /// decides whether the connection is wrapped in TLS, and the port is
    /// omitted when it is the one that scheme implies. A Unix socket has no
    /// port to name, so the host stands alone.
    pub fn authority(&self, host: &str, target: &Port) -> String {
        let scheme = if self.config.secure { "https" } else { "http" };

        match target {
            Port::UDS(_) => host.to_owned(),
            Port::TCP(port) | Port::QUIC(port) => Url::authority_of(scheme, host, *port),
        }
    }

    /// The finalisation every connection this client makes applies to the
    /// requests it sends.
    ///
    /// This is where `Host` — and so, above HTTP/1.1, `:authority` — comes
    /// from: the client knows what it dialled and the connection does not, so
    /// the client is what tells it.
    pub fn request_finalizer(&self, authority: impl Into<Text>) -> crate::finalizer::RequestFinalizer {
        crate::finalizer::RequestFinalizer::new(Some(authority.into()))
    }

    /// Opens a connection to a host on a given port.
    ///
    /// The port decides the transport, and so the versions available: QUIC
    /// carries HTTP/3, TCP carries HTTP/1.1 or HTTP/2 over TLS when
    /// [`ClientConfig::secure`] is set, and a Unix socket is always plaintext.
    /// The whole dial, TLS handshake included, is held to
    /// [`ClientLimits::connection_timeout`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the transport cannot be established,
    /// [`Error::Tls`] when the handshake fails, [`Error::Version`] when no
    /// usable version is agreed, and [`Error::Timeout`] when the dial takes too
    /// long.
    pub async fn connect(&self, host: &str, target: Port) -> Result<AnyConnection, Error> {
        let id = self.id(host, &target);
        let authority = self.authority(host, &target);

        sync::Timeout::within(self.config.limits.connection_timeout, async move {
            match target {
                Port::QUIC(port) => self.connect_quic(host, port, id, &authority).await,

                Port::TCP(port) => {
                    let transport = TcpStream::connect((host, port)).await?;
                    self.connect_stream(host, Box::new(transport), id, &authority).await
                }

                Port::UDS(ref path) => {
                    let transport = UnixStream::connect(path).await?;
                    self.assemble(self.prior_version()?, Box::new(transport), id, &authority).await
                }
            }
        })
        .await?
    }

    /// Builds a connection over a transport the caller already has.
    ///
    /// Wraps it in TLS when [`ClientConfig::secure`] is set.
    ///
    /// # Errors
    ///
    /// As [`Client::connect_stream_tls`] and [`Client::assemble`].
    pub async fn connect_stream(&self, host: &str, transport: Box<dyn Transport>, id: ConnectionID, authority: &str) -> Result<AnyConnection, Error> {
        if !self.config.secure {
            return self.assemble(self.prior_version()?, transport, id, authority).await;
        }

        self.connect_stream_tls(host, transport, id, authority).await
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
    pub async fn connect_stream_tls(&self, host: &str, transport: Box<dyn Transport>, id: ConnectionID, authority: &str) -> Result<AnyConnection, Error> {
        let versions: Vec<Version> = self.config.versions.iter().copied().filter(|version| version.transport() == TransportKind::Stream).collect();
        if versions.is_empty() {
            return Err(Error::Version("no configured version runs over a stream transport".into()));
        }

        let connector = self.config.tls.client(self.config.roots.as_deref().unwrap_or(&[]), &versions)?;
        let mut config = connector.configure().map_err(|err| Error::Tls(err.to_string()))?;

        if let Some(list) = self.ech(host) {
            config.set_ech_config_list(list).map_err(|err| Error::Tls(err.to_string()))?;
        }

        let stream = tokio_boring::connect(config, host, transport).await.map_err(|err| Error::Tls(err.to_string()))?;
        let version = Alpn::negotiated(stream.ssl().selected_alpn_protocol(), &versions)?;
        let security = Security::of(stream.ssl());

        Ok(self.assemble(version, Box::new(stream), id, authority).await?.with_security(security))
    }

    /// Opens a connection over QUIC.
    ///
    /// The local socket is bound to match the address family the host resolved
    /// to. The version is settled before the handshake rather than after it —
    /// the QUIC driver fixes the application first — so a QUIC port offers the
    /// one version it will run, per [`Port::offers`], and the match below is
    /// over every version rather than assuming the one that runs over QUIC
    /// today.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the host resolves to nothing or the socket
    /// cannot be set up, [`Error::Version`] when no configured version runs
    /// over QUIC, and [`Error::Tls`] when the QUIC handshake fails.
    pub async fn connect_quic(&self, host: &str, port: u16, id: ConnectionID, authority: &str) -> Result<AnyConnection, Error> {
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

        let versions = Port::QUIC(port).offers(&self.config.versions);
        let Some(version) = versions.first().copied() else {
            return Err(Error::Version("no configured version runs over QUIC".into()));
        };

        match version {
            Version::V3_0 => {
                let config = quic::QuicConfig {
                    versions: versions.clone(),
                    idle_timeout: self.config.limits.message.read_timeout,
                    max_streams_bidi: None,
                    enable_dgram: false,
                };
                let hook = std::sync::Arc::new(quic::QuicClientTls {
                    roots: self.config.roots.clone().unwrap_or_default(),
                    tls: self.config.tls.clone(),
                });

                let session = H3Session::new(crate::models::Role::UserAgent, id, self.config.limits.message);
                let (connection, worker) = H3Connection::pair(session);
                let connection = connection.with_request_finalizer(self.request_finalizer(authority));
                let application = QuicApplication::new(versions, version, worker);

                let guard = quic::QuicDialer::connect(host, udp, &config, hook, application).await?;
                Ok(AnyConnection::H3(connection.with_guard(std::sync::Arc::new(guard))))
            }

            Version::V1_0 | Version::V1_1 | Version::V2_0 => Err(Error::Version(format!("{version} needs a stream transport"))),
        }
    }

    /// The version to use where nothing can be negotiated.
    ///
    /// A plaintext port and a Unix socket have no ALPN, so the version cannot
    /// be agreed on and has to be settled in advance. One configured version
    /// that runs over a stream is taken as prior knowledge — HTTP/2 that way is
    /// h2c, and [`H2Connection`] sends the preface RFC 9113 §3.4 requires.
    /// Where several are configured, only HTTP/1.x can be assumed of a peer
    /// that was never asked, so the most preferred HTTP/1.x is used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] when no configured version can be spoken
    /// without negotiating — pinning HTTP/3 alone and then dialling a stream,
    /// for instance. A version the caller pinned is never silently exchanged
    /// for another.
    pub fn prior_version(&self) -> Result<Version, Error> {
        let mut stream = self.config.versions.iter().copied().filter(|version| version.transport() == TransportKind::Stream);

        let Some(first) = stream.next() else {
            return Err(Error::Version("no configured version runs over a stream transport".into()));
        };

        if stream.next().is_none() {
            return Ok(first);
        }

        self.config
            .versions
            .iter()
            .copied()
            .find(|version| version.major() == 1)
            .ok_or_else(|| Error::Version("several versions are configured and none of them is HTTP/1.x, which is the only one a peer that cannot negotiate may be assumed to speak".into()))
    }

    /// Wraps a transport in the connection type for a version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] for [`Version::V3_0`], which cannot run over
    /// a stream transport.
    pub async fn assemble(&self, version: Version, transport: Box<dyn Transport>, id: ConnectionID, authority: &str) -> Result<AnyConnection, Error> {
        let role = crate::models::Role::UserAgent;
        let finalizer = self.request_finalizer(authority);

        match version {
            Version::V1_0 | Version::V1_1 => Ok(AnyConnection::H1(
                H1Connection::new(transport, role, id, self.config.limits.message).with_version(version).with_request_finalizer(finalizer),
            )),
            Version::V2_0 => Ok(AnyConnection::H2(
                H2Connection::new(transport, role, id, self.config.limits.message).with_request_finalizer(finalizer),
            )),
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

    /// Whether every version on offer runs over QUIC, and so QUIC is the
    /// only transport to dial.
    pub fn only_quic(&self) -> bool {
        !self.config.versions.is_empty() && self.config.versions.iter().all(|version| version.transport() == TransportKind::Quic)
    }

    /// Opens a connection for a URL, taking the transport from its scheme.
    ///
    /// A secure scheme dials QUIC when the client offers only HTTP/3, and TLS
    /// over TCP otherwise. An insecure scheme dials plain TCP. The whole dial
    /// is held to [`ClientLimits::connection_timeout`].
    ///
    /// # Errors
    ///
    /// As [`Client::connect`].
    pub async fn open(&self, url: &Url) -> Result<AnyConnection, Error> {
        let id = self.id(&url.host, &Port::TCP(url.port));
        let authority = url.authority();

        sync::Timeout::within(self.config.limits.connection_timeout, async move {
            if !url.secure() {
                let transport = TcpStream::connect((url.host.as_str(), url.port)).await?;
                return self.assemble(self.prior_version()?, Box::new(transport), id, &authority).await;
            }

            if self.only_quic() {
                return self.connect_quic(&url.host, url.port, id, &authority).await;
            }

            let transport = TcpStream::connect((url.host.as_str(), url.port)).await?;
            self.connect_stream_tls(&url.host, Box::new(transport), id, &authority).await
        })
        .await?
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
    /// first; `Cookie` is filled in unless the caller set it, and `Host` by the
    /// connection's own [`Client::request_finalizer`]; and any `Set-Cookie` and
    /// `Strict-Transport-Security` on the response are taken into the client's
    /// state.
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
        if let Some(jar) = &self.jar
            && !fields.contains("cookie")
            && let Some(cookie) = jar.cookie(&url, now)
        {
            fields.append("cookie", cookie);
        }

        let mut request = Message::request(method, url.target.clone(), connection.version());
        request.security.secure = url.secure();
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
        connection.open_websocket(&url.authority(), &url.target, self.config.limits.message).await
    }
}
