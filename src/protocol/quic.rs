//! The QUIC transport seam every application over QUIC shares.
//!
//! QUIC itself is provided by `quiche` and driven by `tokio-quiche`; what is
//! here is the boundary this crate consumes it through, the way HTTP/1 and
//! HTTP/2 consume a stream transport through [`Transport`]. Nothing in this
//! module knows which application protocol runs on top: [`QUICTransport`] is
//! the stream surface an established connection offers, [`Varint`] and
//! [`QUICStreamID`] are RFC 9000 vocabulary, [`Handshake`] reads back what the
//! handshake settled — including the ALPN that decides the application — and
//! [`QUICListener`] and [`QUICDialer`] stand up an endpoint on either side.
//!
//! An application over QUIC is written against [`QUICApplication`], and reaches
//! the connection only through [`QUICTransport`]. The `tokio-quiche` types that
//! carry all of this are re-exported here — [`QUICApplication`],
//! [`QUICConnection`], [`QUICHandshake`], [`QUICError`] and [`QUICOutcome`] —
//! so nothing above this module has to name the crate underneath, and swapping
//! it out is a change to this file alone.
//!
//! [`Transport`]: crate::protocol::base::Transport

use std::sync::Arc;

use boring::ssl::SslContextBuilder;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::ApplicationOverQuic;

/// What an application driven on a QUIC connection has to implement.
///
/// The seam an application is written against, so `h3` and anything after it
/// never names the QUIC crate itself.
pub use tokio_quiche::ApplicationOverQuic as QUICApplication;
/// A live QUIC connection, as the driver hands it over.
pub use tokio_quiche::quic::QuicheConnection as QUICConnection;
/// What the QUIC handshake reports when it completes.
pub use tokio_quiche::quic::HandshakeInfo as QUICHandshake;
/// The error an application hands back to the QUIC driver.
pub use tokio_quiche::BoxError as QUICError;
/// What an application returns to the QUIC driver.
pub use tokio_quiche::QuicResult as QUICOutcome;
/// The handle that keeps a QUIC connection alive.
pub use tokio_quiche::QuicConnection as QUICGuard;

use crate::models::{ALPN, Role, Version};
use crate::protocol::common::Error;
use crate::tls::{ECHKeys, Identity, Security, TLSConfig};
use crate::helpers::sync;

/// A QUIC variable-length integer.
pub struct Varint;

impl Varint {
    /// The largest value a variable-length integer can hold.
    pub const MAXIMUM: u64 = (1 << 62) - 1;
    /// The largest a variable-length integer can be, in octets.
    pub const MAX_SIZE: usize = 8;

    /// How many octets a variable-length integer takes: 1, 2, 4 or 8.
    pub fn len(value: u64) -> usize {
        match value {
            0..=0x3f => 1,
            0x40..=0x3fff => 2,
            0x4000..=0x3fff_ffff => 4,
            _ => 8,
        }
    }

    /// Appends a variable-length integer, in the shortest form that holds it.
    ///
    /// # Panics
    ///
    /// Debug builds assert that `value` does not go past [`Varint::MAXIMUM`]:
    /// anything larger does not fit the encoding, and the two high bits that
    /// carry the length would overwrite it.
    pub fn encode(out: &mut impl bytes::BufMut, value: u64) {
        debug_assert!(value <= Varint::MAXIMUM, "{value} does not fit a variable-length integer");

        match Varint::len(value) {
            1 => out.put_u8(value as u8),
            2 => out.put_slice(&(value as u16 | 0x4000).to_be_bytes()),
            4 => out.put_slice(&(value as u32 | 0x8000_0000).to_be_bytes()),
            _ => out.put_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
        }
    }

    /// Reads a variable-length integer, returning how many octets it took.
    ///
    /// A consumed count of zero means the integer has not fully arrived; the
    /// caller should wait for more of the stream.
    pub fn decode(input: &[u8]) -> (usize, u64) {
        let Some(first) = input.first() else {
            return (0, 0);
        };

        let length = 1 << (first >> 6);
        if input.len() < length {
            return (0, 0);
        }

        let mut value = (first & 0x3f) as u64;
        for octet in &input[1..length] {
            value = value << 8 | *octet as u64;
        }

        (length, value)
    }

    /// Reads a payload that must be exactly one variable-length integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the integer is incomplete or anything
    /// follows it.
    pub fn only(payload: &[u8], name: &str) -> Result<u64, Error> {
        let (consumed, value) = Varint::decode(payload);

        if consumed == 0 || consumed != payload.len() {
            return Err(Error::Protocol(format!("{name} payload is not a single variable-length integer")));
        }

        Ok(value)
    }
}

/// The stream identifier arithmetic of RFC 9000 §2.1.
///
/// The two low bits carry who opened the stream and in how many directions,
/// so successive streams of one kind step by [`QUICStreamID::STEP`].
pub struct QUICStreamID;

impl QUICStreamID {
    /// How far apart successive streams of one kind are numbered.
    pub const STEP: u64 = 4;

    /// Whether the identifier names a bidirectional stream.
    pub fn is_bidi(id: u64) -> bool {
        id & 0x2 == 0
    }

    /// Whether the identifier names a unidirectional stream.
    pub fn is_uni(id: u64) -> bool {
        id & 0x2 != 0
    }

    /// Whether the client opened the stream.
    pub fn client_initiated(id: u64) -> bool {
        id & 0x1 == 0
    }

    /// The first bidirectional stream a role may open: 0 for a client, 1 for
    /// a server.
    pub fn first_bidi(role: Role) -> u64 {
        if role.is_client() { 0 } else { 1 }
    }

    /// The first unidirectional stream a role may open: 2 for a client, 3 for
    /// a server.
    pub fn first_uni(role: Role) -> u64 {
        if role.is_client() { 2 } else { 3 }
    }
}

/// What one read from a stream produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRead {
    /// Octets arrived, and whether the stream ended with them.
    Data {
        /// How many octets were read.
        len: usize,
        /// Whether the peer finished sending on this stream.
        fin: bool,
    },
    /// Nothing more is readable right now.
    Done,
    /// The peer reset the stream with this error code.
    Reset(u64),
}

/// What one write to a stream produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamWrite {
    /// This many octets were taken; the rest stays with the caller.
    Sent(usize),
    /// The stream cannot take anything right now; try again later.
    Blocked,
    /// The peer stopped the stream with this error code.
    Stopped(u64),
}

/// The stream surface an established QUIC connection offers an application.
///
/// This is the QUIC counterpart of [`Transport`]: whatever runs over QUIC —
/// HTTP/3 today, anything later — drives the connection through this and
/// nothing else, so no application code depends on the QUIC implementation
/// underneath. Stream-level outcomes come back as [`StreamRead`] and
/// [`StreamWrite`] values rather than errors, since a reset or stopped stream
/// leaves the connection running.
///
/// [`Transport`]: crate::protocol::base::Transport
pub trait QUICTransport {
    /// Writes octets to a stream, ending it when `fin` is set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the connection has failed; a stream the
    /// peer stopped is a [`StreamWrite::Stopped`], not an error.
    fn send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<StreamWrite, Error>;

    /// Reads octets from a stream into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the connection has failed; a stream the
    /// peer reset is a [`StreamRead::Reset`], not an error.
    fn receive(&mut self, stream_id: u64, out: &mut [u8]) -> Result<StreamRead, Error>;

    /// Abandons reading a stream, telling the peer to stop sending on it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the connection has failed; a stream already
    /// finished is not an error.
    fn shutdown_read(&mut self, stream_id: u64, code: u64) -> Result<(), Error>;

    /// Abandons writing a stream, resetting it towards the peer.
    ///
    /// # Errors
    ///
    /// As [`QUICTransport::shutdown_read`].
    fn shutdown_write(&mut self, stream_id: u64, code: u64) -> Result<(), Error>;

    /// The streams with octets waiting to be read.
    fn readable(&self) -> impl Iterator<Item = u64>;

    /// Closes the whole connection with an application error code.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the connection has failed; a connection
    /// already closing is not an error.
    fn close(&mut self, code: u64, reason: &[u8]) -> Result<(), Error>;

    /// The ALPN protocol the handshake settled on; empty when none was.
    fn application_protocol(&self) -> &[u8];

    /// The QUIC wire version the connection speaks.
    fn version(&self) -> u32;
}

impl QUICTransport for QuicheConnection {
    fn send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<StreamWrite, Error> {
        match self.stream_send(stream_id, data, fin) {
            Ok(sent) => Ok(StreamWrite::Sent(sent)),
            Err(quiche::Error::Done) => Ok(StreamWrite::Blocked),
            Err(quiche::Error::StreamStopped(code)) => Ok(StreamWrite::Stopped(code)),
            Err(err) => Err(Error::quic(err)),
        }
    }

    fn receive(&mut self, stream_id: u64, out: &mut [u8]) -> Result<StreamRead, Error> {
        match self.stream_recv(stream_id, out) {
            Ok((len, fin)) => Ok(StreamRead::Data { len, fin }),
            Err(quiche::Error::Done) => Ok(StreamRead::Done),
            Err(quiche::Error::StreamReset(code)) => Ok(StreamRead::Reset(code)),
            Err(err) => Err(Error::quic(err)),
        }
    }

    fn shutdown_read(&mut self, stream_id: u64, code: u64) -> Result<(), Error> {
        match self.stream_shutdown(stream_id, quiche::Shutdown::Read, code) {
            Ok(()) | Err(quiche::Error::Done) => Ok(()),
            Err(err) => Err(Error::quic(err)),
        }
    }

    fn shutdown_write(&mut self, stream_id: u64, code: u64) -> Result<(), Error> {
        match self.stream_shutdown(stream_id, quiche::Shutdown::Write, code) {
            Ok(()) | Err(quiche::Error::Done) => Ok(()),
            Err(err) => Err(Error::quic(err)),
        }
    }

    fn readable(&self) -> impl Iterator<Item = u64> {
        QuicheConnection::readable(self)
    }

    fn close(&mut self, code: u64, reason: &[u8]) -> Result<(), Error> {
        match QuicheConnection::close(self, true, code, reason) {
            Ok(()) | Err(quiche::Error::Done) => Ok(()),
            Err(err) => Err(Error::quic(err)),
        }
    }

    fn application_protocol(&self) -> &[u8] {
        self.application_proto()
    }

    /// `quiche` exposes no accessor for the negotiated wire version, and the
    /// version it links speaks QUIC version 1 only, so for an established
    /// connection the compile-time [`quiche::PROTOCOL_VERSION`] is exact.
    fn version(&self) -> u32 {
        quiche::PROTOCOL_VERSION
    }
}

/// What a completed QUIC handshake settled on.
///
/// The counterpart of reading ALPN and [`Security`] off a TLS stream: read
/// once, when the connection is established, and never assumed beforehand.
pub struct Handshake {
    /// The ALPN protocol the handshake settled on; empty when none was.
    pub alpn: Vec<u8>,
    /// The QUIC wire version the connection speaks.
    pub version: u32,
}

impl Handshake {
    /// Reads the handshake facts off an established connection.
    pub fn of(transport: &impl QUICTransport) -> Self {
        Self { alpn: transport.application_protocol().to_vec(), version: transport.version() }
    }

    /// The HTTP version the handshake settled on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] when the peer selected something outside
    /// `versions`, or selected nothing and `versions` offers no HTTP/1.x
    /// fallback.
    pub fn negotiated(&self, versions: &[Version]) -> Result<Version, Error> {
        ALPN::negotiated((!self.alpn.is_empty()).then_some(&self.alpn), versions)
    }

    /// The [`Security`] this connection stands for.
    pub fn security(&self) -> Security {
        Security::quic(Some(self.version))
    }
}

/// How a QUIC endpoint is tuned, on either side.
///
/// The counterpart of what a TLS acceptor or connector is built from: the
/// versions to offer by ALPN and the transport knobs both ends share.
pub struct QUICConfig {
    /// The versions offered by ALPN.
    pub versions: Vec<Version>,
    /// In seconds, how long the connection may sit idle (0 waits forever).
    pub idle_timeout: f64,
    /// How many bidirectional streams the peer may open, when bounded.
    pub max_streams_bidi: Option<u64>,
    /// Whether QUIC datagrams are offered.
    pub enable_dgram: bool,
}

impl QUICConfig {
    /// The `tokio-quiche` settings this configuration stands for.
    pub fn settings(&self) -> tokio_quiche::settings::QuicSettings {
        let mut settings = tokio_quiche::settings::QuicSettings::default();
        settings.alpn = ALPN::list(&self.versions);
        settings.max_idle_timeout = sync::Timeout::duration(self.idle_timeout);
        settings.enable_dgram = self.enable_dgram;

        if let Some(max) = self.max_streams_bidi {
            settings.initial_max_streams_bidi = max;
        }

        settings
    }

    /// The certificate paths handed to `tokio-quiche`, which are never read.
    ///
    /// The TLS context actually used is built by the [`QUICServerTLS`] or
    /// [`QUICClientTLS`] hook, so the paths exist only to satisfy the
    /// signature.
    pub fn placeholder_certificate() -> tokio_quiche::settings::TlsCertificatePaths<'static> {
        tokio_quiche::settings::TlsCertificatePaths { cert: "", private_key: "", kind: tokio_quiche::settings::CertificateKind::X509 }
    }
}

/// A QUIC connection that has arrived but not yet been given an application.
pub type QUICIncoming = tokio_quiche::InitialQuicConnection<tokio::net::UdpSocket, tokio_quiche::metrics::DefaultMetrics>;

/// The queue of connections a bound QUIC endpoint yields.
pub type QUICIncomingStream = tokio::sync::mpsc::Receiver<std::io::Result<QUICIncoming>>;

/// The server side of a QUIC endpoint.
pub struct QUICListener;

impl QUICListener {
    /// Binds a QUIC endpoint over an already-bound UDP socket.
    ///
    /// `tokio-quiche` owns the socket from here on and demultiplexes
    /// datagrams into connections, so what comes back is a queue of
    /// connections rather than a socket to accept on, alongside the address
    /// the socket is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the socket cannot be read or the endpoint
    /// cannot be stood up, and [`Error::Closed`] when no listener comes back.
    pub fn bind(udp: std::net::UdpSocket, config: &QUICConfig, hook: Arc<dyn tokio_quiche::quic::ConnectionHook + Send + Sync>) -> Result<(QUICIncomingStream, std::net::SocketAddr), Error> {
        let address = udp.local_addr()?;

        let hooks = tokio_quiche::settings::Hooks { connection_hook: Some(hook) };
        let params = tokio_quiche::ConnectionParams::new_server(config.settings(), QUICConfig::placeholder_certificate(), hooks);

        let listeners = tokio_quiche::listen([udp], params, tokio_quiche::metrics::DefaultMetrics).map_err(Error::IO)?;
        let incoming = listeners.into_iter().next().ok_or(Error::Closed)?.into_inner();

        Ok((incoming, address))
    }
}

/// The client side of a QUIC endpoint.
pub struct QUICDialer;

impl QUICDialer {
    /// Dials a QUIC connection over an already-connected UDP socket and
    /// drives `application` on it.
    ///
    /// The returned handle keeps the connection alive; the application runs
    /// inside `tokio-quiche`'s worker until the connection ends.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when the socket cannot be adopted and
    /// [`Error::TLS`] when the QUIC handshake fails.
    pub async fn connect(host: &str, udp: tokio::net::UdpSocket, config: &QUICConfig, hook: Arc<dyn tokio_quiche::quic::ConnectionHook + Send + Sync>, application: impl ApplicationOverQuic) -> Result<tokio_quiche::QuicConnection, Error> {
        let socket: tokio_quiche::socket::Socket<Arc<tokio::net::UdpSocket>, Arc<tokio::net::UdpSocket>> = udp.try_into().map_err(Error::IO)?;

        let hooks = tokio_quiche::settings::Hooks { connection_hook: Some(hook) };
        let params = tokio_quiche::ConnectionParams::new_client(config.settings(), Some(QUICConfig::placeholder_certificate()), hooks);

        tokio_quiche::quic::connect_with_config(socket, Some(host), &params, application)
            .await
            .map_err(|err| Error::TLS(err.to_string()))
    }
}

/// Gives a QUIC server its TLS context.
pub struct QUICServerTLS {
    /// The certificate chain and key to serve.
    pub identity: Identity,
    /// The ECH keys, if the server offers ECH.
    pub ech: Option<ECHKeys>,
    /// The TLS details the context is built with.
    pub tls: TLSConfig,
}

impl tokio_quiche::quic::ConnectionHook for QUICServerTLS {
    /// Builds the context, ignoring the certificate paths in the settings.
    ///
    /// A failure returns `None`, which `tokio-quiche` turns into a failed
    /// connection.
    fn create_custom_ssl_context_builder(&self, _settings: tokio_quiche::settings::TlsCertificatePaths<'_>) -> Option<SslContextBuilder> {
        self.tls.quic_server(&self.identity, self.ech.as_ref()).ok()
    }
}

/// Gives a QUIC client its TLS context.
pub struct QUICClientTLS {
    /// The trusted roots, each DER or PEM; empty uses the platform trust store.
    pub roots: Vec<Vec<u8>>,
    /// The TLS details the context is built with.
    pub tls: TLSConfig,
}

impl tokio_quiche::quic::ConnectionHook for QUICClientTLS {
    /// Builds the context, ignoring the certificate paths in the settings.
    ///
    /// A failure returns `None`, which `tokio-quiche` turns into a failed
    /// connection.
    fn create_custom_ssl_context_builder(&self, _settings: tokio_quiche::settings::TlsCertificatePaths<'_>) -> Option<SslContextBuilder> {
        self.tls.quic_client(&self.roots).ok()
    }
}
