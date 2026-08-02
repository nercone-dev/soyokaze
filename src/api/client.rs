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

pub const PREFERENCE: &[Version] = &[Version::V3_0, Version::V2_0, Version::V1_1];

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
    pub fn new() -> Self {
        Self { version: None, limits: None, secure: true, roots: None, ech: std::collections::HashMap::new(), cookies: true, hsts: true }
    }

    pub fn version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn roots(mut self, roots: Vec<Vec<u8>>) -> Self {
        self.roots = Some(roots);
        self
    }

    pub fn ech(mut self, host: &str, config_list: Vec<u8>) -> Self {
        self.ech.insert(host.to_owned(), config_list);
        self
    }

    pub fn cookies(mut self, cookies: bool) -> Self {
        self.cookies = cookies;
        self
    }

    pub fn hsts(mut self, hsts: bool) -> Self {
        self.hsts = hsts;
        self
    }

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
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn ech(&self, host: &str) -> Option<&Vec<u8>> {
        self.ech.get(host).or_else(|| self.ech.get("*"))
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn versions(&self) -> Vec<Version> {
        match self.version {
            Some(version) => vec![version],
            None => PREFERENCE.to_vec(),
        }
    }

    pub fn id(&self, host: &str, target: &Port) -> ConnectionID {
        ConnectionID(Bytes::from(format!("{host}/{target:?}")))
    }

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

    pub async fn connect_stream(&self, host: &str, transport: Box<dyn Transport>, id: ConnectionID) -> Result<AnyConnection, Error> {
        if !self.secure {
            return self.assemble(self.prior_version(), transport, id).await;
        }

        self.connect_stream_tls(host, transport, id).await
    }

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

    pub fn prior_version(&self) -> Version {
        self.version.unwrap_or(Version::V1_1)
    }

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

    pub async fn request(&self, connection: &mut AnyConnection, request: Message) -> Result<Message, Error> {
        connection.send(request).await?;

        loop {
            let response = connection.receive().await?;

            if !response.is_informational() {
                return Ok(response);
            }
        }
    }

    pub fn jar(&self) -> Option<&Arc<CookieJar>> {
        self.jar.as_ref()
    }

    pub fn store(&self) -> Option<&Arc<HstsStore>> {
        self.store.as_ref()
    }

    pub fn prefers_h3(&self) -> bool {
        self.version == Some(Version::V3_0)
    }

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

    pub async fn get(&self, url: &str) -> Result<Message, Error> {
        self.fetch(Method::GET, url, None, None).await
    }

    pub async fn head(&self, url: &str) -> Result<Message, Error> {
        self.fetch(Method::HEAD, url, None, None).await
    }

    pub async fn post(&self, url: &str, body: Body) -> Result<Message, Error> {
        self.fetch(Method::POST, url, None, Some(body)).await
    }

    pub async fn put(&self, url: &str, body: Body) -> Result<Message, Error> {
        self.fetch(Method::PUT, url, None, Some(body)).await
    }

    pub async fn delete(&self, url: &str) -> Result<Message, Error> {
        self.fetch(Method::DELETE, url, None, None).await
    }

    pub async fn websocket(&self, url: &str) -> Result<crate::websocket::WebSocketConnection<Box<dyn Transport>>, Error> {
        let mut url = Url::parse(url)?;
        self.apply_hsts(&mut url, Instant::now());

        let connection = self.open(&url).await?;
        connection.open_websocket(&url.authority(), &url.target).await
    }
}

#[derive(Debug, Clone)]
pub struct ClientLimits {
    pub message: Limits,
    pub connection_timeout: f64, // in seconds, how long to wait for a connection to be established
    pub max_connections: u32,    // the number of connections kept for reuse (HTTP/2 sessions, keep-alive)
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self { message: Limits::default(), connection_timeout: 10.0, max_connections: 65536 }
    }
}
