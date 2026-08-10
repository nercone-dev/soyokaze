//! Turning an accepted transport connection into an HTTP connection.
//!
//! An [`Incoming`] is what a listener's socket hands over: a stream transport
//! from a TCP or Unix socket port, or a QUIC connection from a QUIC port.
//! [`Negotiation`] settles which version it will speak — by ALPN over TLS, by
//! sniffing the HTTP/2 preface on a plaintext port, and by ALPN again for
//! QUIC, verified in [`QUICApplication`] once the handshake completes — and
//! builds the [`AnyConnection`] a handler is given. Each transport is bridged
//! the same way, so the server above never has to care which one a connection
//! arrived over.

use std::sync::Arc;

use bytes::Bytes;

use crate::models::{ALPN, ConnectionID, Limits, Role, Version};
use crate::tls::Security;
use crate::protocol::base::{AnyConnection, Transport};
use crate::protocol::common::{Buffer, Error};
use crate::protocol::h1::H1Connection;
use crate::protocol::h2::{self, H2Connection};
use crate::protocol::h3::{H3Connection, H3Session};
use crate::protocol::quic::{Handshake, QUICApplication as QUICApplicationTrait, QUICConnection, QUICError, QUICHandshake, QUICIncoming, QUICOutcome};
use crate::helpers::sync;

/// The application driven on one QUIC connection, behind an ALPN check.
///
/// The QUIC driver fixes the application before the handshake runs, so the
/// worker is built ahead of knowing what ALPN will settle on. What can and
/// must still happen is verification: once the handshake completes, the
/// negotiated version is read back and checked against both the versions the
/// port offered and the version the worker speaks, exactly as the TLS path
/// reads back its ALPN. A mismatch fails the connection rather than letting
/// an unnegotiated protocol run.
///
/// The worker is a type parameter rather than an enum over the versions that
/// run over QUIC: every one of them implements [`QUICApplicationTrait`]
/// already, so an enum here would be a hand-written vtable over that trait,
/// with an arm to add per version for each of the six methods the driver
/// calls. A version that runs over QUIC is added by handing its worker and its
/// [`Version`] to [`QUICApplication::new`], so nothing here changes; where it
/// is added is [`Negotiation::assemble_quic`], and its client-side mirror
/// [`Client::connect_quic`], which are the two places a version is turned into
/// a worker at all.
///
/// [`Client::connect_quic`]: crate::api::client::Client::connect_quic
pub struct QUICApplication<W> {
    /// The versions on offer, already narrowed to what the port can carry.
    pub versions: Vec<Version>,
    /// The version the worker speaks, checked against what ALPN settles on.
    pub version: Version,
    /// The worker to drive once the handshake checks out.
    pub worker: W,
}

impl<W: QUICApplicationTrait> QUICApplication<W> {
    /// An application driving `worker`, which speaks `version`.
    pub fn new(versions: Vec<Version>, version: Version, worker: W) -> Self {
        Self { versions, version, worker }
    }
}

impl<W: QUICApplicationTrait> QUICApplicationTrait for QUICApplication<W> {
    fn on_conn_established(&mut self, qconn: &mut QUICConnection, handshake: &QUICHandshake) -> QUICOutcome<()> {
        let negotiated = Handshake::of(qconn).negotiated(&self.versions).map_err(|error| Box::new(error) as QUICError)?;

        if negotiated != self.version {
            let error = Error::Version(format!("the peer selected {negotiated}, which this connection does not speak"));
            return Err(Box::new(error));
        }

        self.worker.on_conn_established(qconn, handshake)
    }

    fn should_act(&self) -> bool {
        self.worker.should_act()
    }

    fn buffer(&mut self) -> &mut [u8] {
        self.worker.buffer()
    }

    async fn wait_for_data(&mut self, qconn: &mut QUICConnection) -> QUICOutcome<()> {
        self.worker.wait_for_data(qconn).await
    }

    fn process_reads(&mut self, qconn: &mut QUICConnection) -> QUICOutcome<()> {
        self.worker.process_reads(qconn)
    }

    fn process_writes(&mut self, qconn: &mut QUICConnection) -> QUICOutcome<()> {
        self.worker.process_writes(qconn)
    }
}

/// A connection that has arrived but not yet been negotiated.
#[allow(clippy::large_enum_variant)]
pub enum Incoming {
    /// A stream transport, over TCP or a Unix socket.
    Stream {
        /// The transport.
        transport: Box<dyn Transport>,
        /// The peer's address, or `unix` for a Unix socket.
        id: ConnectionID,
        /// The address the peer connected from, when it has one.
        client: Option<std::net::SocketAddr>,
    },
    /// A QUIC connection.
    QUIC(QUICIncoming),
}

impl Incoming {
    /// The address the peer connected from, when it has one.
    ///
    /// A Unix socket has none: the address of an accepted Unix socket names
    /// nothing. This is what [`Message::client`] is stamped from.
    ///
    /// [`Message::client`]: crate::models::Message::client
    pub fn client(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Stream { client, .. } => *client,
            Self::QUIC(incoming) => Some(incoming.peer_addr()),
        }
    }
}

/// Everything needed to turn an [`Incoming`] into a connection.
///
/// Kept apart from the [`Listener`] so it can be shared by reference with the
/// tasks that negotiate concurrently.
///
/// [`Listener`]: crate::api::server::Listener
#[derive(Clone)]
pub struct Negotiation {
    /// The versions on offer, already narrowed to what the port can carry.
    pub versions: Vec<Version>,
    /// The limits each connection will hold itself to.
    pub limits: Limits,
    /// The TLS acceptor, when the port is secure.
    pub acceptor: Option<Arc<boring::ssl::SslAcceptor>>,
    /// The finalisation each connection applies to the responses it sends.
    pub response_finalizer: crate::finalizer::ResponseFinalizer,
}

impl Negotiation {
    /// Negotiates a version and builds the connection.
    ///
    /// A stream transport is held to [`Limits::read_timeout`], so a peer that
    /// connects and then says nothing does not hold a slot indefinitely.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] when the handshake stalls, [`Error::TLS`]
    /// when it fails, and [`Error::Version`] when nothing usable is agreed.
    pub async fn accept(&self, incoming: Incoming) -> Result<AnyConnection, Error> {
        match incoming {
            Incoming::Stream { transport, id, client } => {
                let assembling = std::pin::pin!(self.assemble(transport, id, client));
                sync::Timeout::within(self.limits.read_timeout, assembling).await?
            }

            Incoming::QUIC(incoming) => self.assemble_quic(incoming),
        }
    }

    /// Builds the connection for a QUIC port.
    ///
    /// The QUIC driver fixes the application before the handshake runs, so the
    /// version cannot be read back first the way [`Negotiation::assemble`]
    /// reads back ALPN. It is taken from what the port offers instead — and a
    /// QUIC port offers exactly one version, per [`Port::offers`], so what is
    /// taken here is what ALPN was given to settle on. The match is over every
    /// version rather than assuming the one that runs over QUIC today: a
    /// version added to [`Version`] has to be given an arm here before this
    /// compiles, and one that cannot run over QUIC is refused rather than
    /// quietly served as something else.
    ///
    /// [`Port::offers`]: crate::models::Port::offers
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] when the port offers nothing, or offers a
    /// version that does not run over QUIC.
    pub fn assemble_quic(&self, incoming: QUICIncoming) -> Result<AnyConnection, Error> {
        let client = incoming.peer_addr();
        let id = ConnectionID(Bytes::from(client.to_string()));

        let Some(version) = self.versions.first().copied() else {
            return Err(Error::Version("this port offers no version".into()));
        };

        match version {
            Version::V3_0 => {
                let session = H3Session::new(Role::Origin, id, self.limits).with_client(Some(client));
                let (connection, worker) = H3Connection::pair(session);
                let connection = connection.with_response_finalizer(self.response_finalizer);

                let application = QUICApplication::new(self.versions.clone(), version, worker);
                let quic = incoming.start(application);

                Ok(AnyConnection::H3(connection.with_guard(Arc::new(quic))))
            }

            Version::V1_0 | Version::V1_1 | Version::V2_0 => Err(Error::Version(format!("{version} needs a stream transport"))),
        }
    }

    /// Runs the TLS handshake and builds the negotiated connection.
    ///
    /// Falls through to [`Negotiation::assemble_plain`] when the port has no
    /// acceptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TLS`] when the handshake fails and [`Error::Version`]
    /// when nothing usable is negotiated, or when what was negotiated cannot
    /// run over a stream transport.
    pub async fn assemble(&self, transport: Box<dyn Transport>, id: ConnectionID, client: Option<std::net::SocketAddr>) -> Result<AnyConnection, Error> {
        let Some(acceptor) = &self.acceptor else {
            return self.assemble_plain(transport, id, client).await;
        };

        let stream = tokio_boring::accept(acceptor, transport).await.map_err(|err| Error::TLS(err.to_string()))?;
        let version = ALPN::negotiated(stream.ssl().selected_alpn_protocol(), &self.versions)?;
        let security = Security::of(stream.ssl());

        let transport = Box::new(stream) as Box<dyn Transport>;
        match version {
            Version::V1_0 | Version::V1_1 => {
                let connection = H1Connection::new(transport, Role::Origin, id, self.limits).with_version(version).with_response_finalizer(self.response_finalizer).with_security(security).with_client(client);
                Ok(AnyConnection::H1(connection))
            }
            Version::V2_0 => {
                let connection = H2Connection::new(transport, Role::Origin, id, self.limits).with_response_finalizer(self.response_finalizer).with_security(security).with_client(client);
                Ok(AnyConnection::H2(connection))
            }
            Version::V3_0 => Err(Error::Version("HTTP/3 needs a QUIC port".into())),
        }
    }

    /// Picks a version on a plaintext port by sniffing the first few octets.
    ///
    /// There is no ALPN without TLS, so the HTTP/2 preface is looked for
    /// instead. Whatever was read is handed to the connection rather than
    /// discarded, so an HTTP/1.1 request that happens to start with the same
    /// octets is not damaged by the check.
    ///
    /// Sniffing decides between the versions the port offers; it never settles
    /// on one that was not offered. A port that offers only HTTP/2 turns away a
    /// peer that does not send the preface, exactly as the TLS path turns away
    /// a peer that selects nothing on offer.
    ///
    /// # Errors
    ///
    /// As [`Buffer::fill`], and [`Error::Version`] when the port offers no
    /// version the sniffed octets match.
    pub async fn assemble_plain(&self, mut transport: Box<dyn Transport>, id: ConnectionID, client: Option<std::net::SocketAddr>) -> Result<AnyConnection, Error> {
        let mut buffer = Buffer::with_chunk_size(self.limits.read_chunk_size as usize);

        let probe = h2::PREFACE.len().min(4);
        while buffer.len() < probe && buffer.fill(&mut transport, self.limits.read_timeout).await? {}

        let sniffed = buffer.len().min(probe);
        let h2 = self.versions.contains(&Version::V2_0)
            && sniffed > 0
            && buffer.as_slice()[..sniffed] == h2::PREFACE[..sniffed];

        if h2 {
            return Ok(AnyConnection::H2(H2Connection::resume(transport, Role::Origin, id, self.limits, buffer).with_client(client)));
        }

        let Some(version) = self.versions.iter().copied().find(|version| version.major() == 1) else {
            return Err(Error::Version("the peer sent no HTTP/2 preface and this port offers no HTTP/1.x".into()));
        };

        Ok(AnyConnection::H1(H1Connection::resume(transport, Role::Origin, id, self.limits, buffer).with_version(version).with_client(client)))
    }
}
