//! Turning an accepted transport connection into an HTTP connection.
//!
//! An [`Incoming`] is what a listener's socket hands over: a stream transport
//! from a TCP or Unix socket port, or a QUIC connection from a QUIC port.
//! [`Negotiation`] settles which version it will speak — by ALPN over TLS, by
//! sniffing the HTTP/2 preface on a plaintext port, and by the port itself for
//! QUIC — and builds the [`AnyConnection`] a handler is given. Each transport
//! is bridged the same way, so the server above never has to care which one a
//! connection arrived over.

use std::sync::Arc;

use bytes::Bytes;

use crate::api::common::Limits;
use crate::models::{ConnectionID, Role, Version};
use crate::protocol::base::{AnyConnection, Transport};
use crate::protocol::common::{self, Buffer, Error};
use crate::protocol::h1::H1Connection;
use crate::protocol::h2::{self, H2Connection};
use crate::protocol::h3::{H3Connection, H3Session};
use crate::tls;

/// A QUIC connection that has arrived but not yet been given an application.
pub type QuicIncoming = tokio_quiche::InitialQuicConnection<tokio::net::UdpSocket, tokio_quiche::metrics::DefaultMetrics>;

/// A connection that has arrived but not yet been negotiated.
#[allow(clippy::large_enum_variant)]
pub enum Incoming {
    /// A stream transport, over TCP or a Unix socket.
    Stream {
        /// The transport.
        transport: Box<dyn Transport>,
        /// The peer's address, or `unix` for a Unix socket.
        id: ConnectionID,
    },
    /// A QUIC connection.
    QUIC(QuicIncoming),
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
    /// The HSTS policy to attach to responses, if any.
    pub hsts: Option<crate::helpers::hsts::HstsPolicy>,
}

impl Negotiation {
    /// Negotiates a version and builds the connection.
    ///
    /// A stream transport is held to [`Limits::read_timeout`], so a peer that
    /// connects and then says nothing does not hold a slot indefinitely.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] when the handshake stalls, [`Error::Tls`]
    /// when it fails, and [`Error::Version`] when nothing usable is agreed.
    pub async fn accept(&self, incoming: Incoming) -> Result<AnyConnection, Error> {
        match incoming {
            Incoming::Stream { transport, id } => {
                let assembling = std::pin::pin!(self.assemble(transport, id));
                common::within(self.limits.read_timeout, assembling).await?
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

    /// Runs the TLS handshake and builds the negotiated connection.
    ///
    /// Falls through to [`Negotiation::assemble_plain`] when the port has no
    /// acceptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the handshake fails and [`Error::Version`]
    /// when nothing usable is negotiated.
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

    /// Picks a version on a plaintext port by sniffing the first few octets.
    ///
    /// There is no ALPN without TLS, so the HTTP/2 preface is looked for
    /// instead. Whatever was read is handed to the connection rather than
    /// discarded, so an HTTP/1.1 request that happens to start with the same
    /// octets is not damaged by the check.
    ///
    /// # Errors
    ///
    /// As [`Buffer::fill`].
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
