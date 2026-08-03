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
use crate::models::{ConnectionID, Message, Role, StreamID, Version};
use crate::tls::Security;
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
    /// where [`Message::security`] comes from. A connection over a plaintext
    /// transport reports [`Security::default`].
    ///
    /// [`Message::security`]: crate::models::Message::security
    fn security(&self) -> Security {
        Security::default()
    }

    /// Sends a message.
    ///
    /// # Errors
    ///
    /// Any [`Error`]; [`Error::Timeout`] once [`Limits::send_timeout`] passes.
    ///
    /// [`Limits::send_timeout`]: crate::models::Limits::send_timeout
    async fn send(&mut self, message: Message) -> Result<(), Error>;
    /// Receives the next message.
    ///
    /// # Errors
    ///
    /// Any [`Error`]; [`Error::Closed`] when the peer is done, and
    /// [`Error::Timeout`] once [`Limits::receive_timeout`] passes.
    ///
    /// [`Limits::receive_timeout`]: crate::models::Limits::receive_timeout
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
    /// Gives up the connection and hands back the byte stream underneath one
    /// exchange, for a protocol that takes the connection over.
    ///
    /// This is the one operation whose shape genuinely differs by version, so
    /// it is settled here rather than at every call site: HTTP/1.x gives up its
    /// whole transport along with whatever it had already buffered, while
    /// HTTP/2 and HTTP/3 give up one stream and have nothing buffered. A caller
    /// gets a [`Transport`] and, where there is one, the octets that must be
    /// replayed before reading from it.
    ///
    /// `stream_id` names the exchange, and is required by every version that
    /// multiplexes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when a multiplexed version is given no
    /// stream, and otherwise as the version's own tunnel.
    pub fn into_transport(self, stream_id: Option<StreamID>) -> Result<(Box<dyn Transport>, Option<crate::protocol::common::Buffer>), Error> {
        let named = || stream_id.ok_or_else(|| Error::Protocol("a multiplexed version needs the stream to tunnel".into()));

        match self {
            Self::H1(connection) => {
                let (transport, buffer) = connection.upgrade();
                Ok((transport, Some(buffer)))
            }
            Self::H2(connection) => Ok((Box::new(connection.tunnel(named()?)), None)),
            Self::H3(mut connection) => Ok((Box::new(connection.tunnel(named()?)?), None)),
        }
    }

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

/// Forwards methods through whichever connection [`AnyConnection`] is holding.
///
/// The three versions are drop-in replacements for one another, so the enum
/// does nothing but pick one and pass the call along. Written out by hand that
/// is one arm per version per method — a table to edit in nine places to add a
/// version, and where a single missed arm is a silent difference in behaviour
/// between versions. Generated, a new version is the enum variant and the two
/// arms below, and every method follows.
///
/// Dispatch stays static: this expands to the same match a hand-written
/// forward would, so nothing is boxed and no future is allocated on the way
/// through. That is why [`Connection`] is not made object-safe instead —
/// `send` and `receive` are the hottest paths in the crate, and a
/// `Pin<Box<dyn Future>>` per message is a cost the enum does not pay.
macro_rules! forward {
    (
        $(fn $name:ident(&self) -> $ret:ty;)*
        $(async fn $sent:ident(&mut self $(, $arg:ident: $ty:ty)*) $(-> $sent_ret:ty)?;)*
    ) => {
        $(
            fn $name(&self) -> $ret {
                match self {
                    Self::H1(connection) => connection.$name(),
                    Self::H2(connection) => connection.$name(),
                    Self::H3(connection) => connection.$name(),
                }
            }
        )*
        $(
            async fn $sent(&mut self $(, $arg: $ty)*) $(-> $sent_ret)? {
                match self {
                    Self::H1(connection) => connection.$sent($($arg),*).await,
                    Self::H2(connection) => connection.$sent($($arg),*).await,
                    Self::H3(connection) => connection.$sent($($arg),*).await,
                }
            }
        )*
    };
}

impl Connection for AnyConnection {
    forward! {
        fn version(&self) -> Version;
        fn role(&self) -> Role;
        fn id(&self) -> ConnectionID;
        fn reusable(&self) -> bool;
        fn security(&self) -> Security;

        async fn send(&mut self, message: Message) -> Result<(), Error>;
        async fn receive(&mut self) -> Result<Message, Error>;
        async fn close(&mut self);
    }
}
