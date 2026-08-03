//! What a connection is, before any version makes it concrete.
//!
//! [`Connection`] is the trait the whole crate is written against: send a
//! [`Message`], receive one, close. [`H1Connection`], [`H2Connection`] and
//! [`H3Connection`] all implement it, and [`AnyConnection`] is the one of them
//! that was actually negotiated, so a caller that never names a version works
//! unchanged over all three. [`Stream`] is the same idea for one stream within
//! a multiplexed connection, and [`Transport`] is anything a connection can be
//! carried over.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::errors::Error;
use crate::models::{ConnectionID, Message, Role, Security, StreamID, Version};
use crate::protocol::{h1::H1Connection, h2::H2Connection, h3::H3Connection};

/// What every HTTP connection can do, whichever version it speaks.
///
/// Write against this rather than a version-specific connection wherever
/// there is a choice: the three implementations are meant to be drop-in
/// replacements for one another, and code that names one of them directly
/// gives that up.
///
/// On a server, a response must carry the [`Message::stream_id`] of the
/// request it answers, or HTTP/2 and HTTP/3 will not be able to match the two.
#[allow(async_fn_in_trait)]
pub trait Connection {
    /// The version being spoken.
    fn version(&self) -> Version;
    /// Which end of the connection this is.
    fn role(&self) -> Role;
    /// The connection's identifier.
    fn id(&self) -> ConnectionID;

    /// Whether another message may be exchanged over this connection.
    ///
    /// Only HTTP/1.x can answer no, when the peer asked to close or the
    /// connection is being wound down.
    fn reusable(&self) -> bool {
        true
    }

    /// What the transport underneath this connection turned out to be.
    ///
    /// Every message the connection receives is stamped with these, which is
    /// where [`Message::tls`] and the fields beside it come from. A connection
    /// over a plaintext transport reports [`Security::default`].
    ///
    /// [`Message::tls`]: crate::models::Message::tls
    fn security(&self) -> Security {
        Security::default()
    }

    /// Sends a message.
    ///
    /// # Errors
    ///
    /// Any [`Error`]; [`Error::Timeout`] once [`Limits::send_timeout`] passes.
    ///
    /// [`Limits::send_timeout`]: crate::api::common::Limits::send_timeout
    async fn send(&mut self, message: Message) -> Result<(), Error>;
    /// Receives the next message.
    ///
    /// # Errors
    ///
    /// Any [`Error`]; [`Error::Closed`] when the peer is done, and
    /// [`Error::Timeout`] once [`Limits::receive_timeout`] passes.
    ///
    /// [`Limits::receive_timeout`]: crate::api::common::Limits::receive_timeout
    async fn receive(&mut self) -> Result<Message, Error>;

    /// Shuts the connection down, telling the peer where that is possible.
    ///
    /// Failures are swallowed: there is nothing left to report them to.
    async fn close(&mut self);
}

/// What every stream within a multiplexed connection can do.
#[allow(async_fn_in_trait)]
pub trait Stream {
    /// The stream's identifier.
    fn id(&self) -> StreamID;

    /// Abandons the stream with a protocol error code.
    async fn reset(&mut self, code: u64);
}

/// Anything a connection can be carried over.
///
/// Blanket-implemented, so a TCP stream, a Unix socket, a TLS stream and an
/// in-memory duplex all qualify without saying so.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

/// A connection of whichever version was negotiated.
///
/// This is what [`Client::connect`] and a server's accept loop hand back, and
/// it implements [`Connection`] by forwarding, so a caller need never open it
/// up. Match on it only where the version genuinely changes what to do — as
/// [`AnyConnection::accept_websocket`] does, since the WebSocket handshake
/// really is three different exchanges.
///
/// [`Client::connect`]: crate::api::client::Client::connect
/// [`AnyConnection::accept_websocket`]: crate::websocket
#[allow(clippy::large_enum_variant)]
pub enum AnyConnection {
    /// An HTTP/1.0 or HTTP/1.1 connection.
    H1(H1Connection<Box<dyn Transport>>),
    /// An HTTP/2 connection.
    H2(H2Connection<Box<dyn Transport>>),
    /// An HTTP/3 connection.
    H3(H3Connection),
}

impl AnyConnection {
    /// Attaches what the TLS handshake settled, for a caller holding a
    /// connection that has already been negotiated.
    ///
    /// An HTTP/3 connection is left alone: QUIC carries its own TLS, so the
    /// session already knows what it is running over and there is nothing for
    /// an outside handshake to tell it.
    pub fn with_security(self, security: Security) -> Self {
        match self {
            Self::H1(connection) => Self::H1(connection.with_security(security)),
            Self::H2(connection) => Self::H2(connection.with_security(security)),
            Self::H3(connection) => Self::H3(connection),
        }
    }
}

impl Connection for AnyConnection {
    fn version(&self) -> Version {
        match self {
            Self::H1(connection) => connection.version(),
            Self::H2(connection) => connection.version(),
            Self::H3(connection) => connection.version(),
        }
    }

    fn role(&self) -> Role {
        match self {
            Self::H1(connection) => connection.role(),
            Self::H2(connection) => connection.role(),
            Self::H3(connection) => connection.role(),
        }
    }

    fn id(&self) -> ConnectionID {
        match self {
            Self::H1(connection) => connection.id(),
            Self::H2(connection) => connection.id(),
            Self::H3(connection) => connection.id(),
        }
    }

    fn reusable(&self) -> bool {
        match self {
            Self::H1(connection) => connection.reusable(),
            Self::H2(connection) => connection.reusable(),
            Self::H3(connection) => connection.reusable(),
        }
    }

    fn security(&self) -> Security {
        match self {
            Self::H1(connection) => connection.security(),
            Self::H2(connection) => connection.security(),
            Self::H3(connection) => connection.security(),
        }
    }

    async fn send(&mut self, message: Message) -> Result<(), Error> {
        match self {
            Self::H1(connection) => connection.send(message).await,
            Self::H2(connection) => connection.send(message).await,
            Self::H3(connection) => connection.send(message).await,
        }
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        match self {
            Self::H1(connection) => connection.receive().await,
            Self::H2(connection) => connection.receive().await,
            Self::H3(connection) => connection.receive().await,
        }
    }

    async fn close(&mut self) {
        match self {
            Self::H1(connection) => connection.close().await,
            Self::H2(connection) => connection.close().await,
            Self::H3(connection) => connection.close().await,
        }
    }
}
