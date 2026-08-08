//! An HTTP/1, HTTP/2 and HTTP/3 library.
//!
//! Soyokaze speaks all three versions of HTTP through one set of types. A
//! [`Message`] carries a request or a response regardless of the version that
//! framed it, and every connection implements [`protocol::base::Connection`],
//! so code written against the trait works unchanged over HTTP/1.1, HTTP/2 and
//! HTTP/3.
//!
//! # Layers
//!
//! The crate is arranged in layers, each usable on its own, and each module
//! standing alone as a library for exactly its own concern:
//!
//! - [`helpers`] holds the codecs the versions share — [`helpers::huffman`],
//!   [`helpers::hpack`] for HTTP/2 and [`helpers::qpack`] for HTTP/3, over
//!   the shared vocabulary in [`helpers::fields`] — plus the small pieces
//!   ([`helpers::base64`], [`helpers::sha1`], [`helpers::text`],
//!   [`helpers::scan`], [`helpers::sync`]) everything else leans on. Nothing
//!   here knows about connections or transports.
//! - [`models`] is the vocabulary: [`Message`], [`Headers`], [`Version`],
//!   [`Port`], [`Limits`]. [`tls`] holds the TLS side of it — [`Security`]
//!   and the BoringSSL contexts — and [`cookies`], [`hsts`], [`responses`]
//!   and [`finalizer`] each hold one message-level concern.
//! - [`protocol`] holds one connection type per version — [`protocol::h1`],
//!   [`protocol::h2`] and [`protocol::h3`] — implementing the traits in
//!   [`protocol::base`] over the shared vocabulary in [`protocol::common`].
//!   Each binary version keeps its wire format in a module of its own
//!   ([`protocol::h2::frames`], [`protocol::h3::frames`]), which encodes and
//!   decodes frames and knows nothing of connections, exactly as
//!   [`helpers::hpack`] and [`helpers::qpack`] do for field compression.
//!   [`protocol::quic`] is the seam QUIC is consumed through, the transport
//!   counterpart of [`protocol::base::Transport`], and [`protocol::handler`]
//!   bridges each transport into a connection the same way. A higher layer
//!   drives a lower one exactly the way an outside caller would.
//! - [`api`] holds the entry points: [`Client`] dials an origin, [`Server`]
//!   binds ports and accepts connections, [`api::gate`] admits them, and
//!   [`api::cluster`] runs the server across worker threads.
//!
//! # Symmetry
//!
//! Corresponding pieces are kept interchangeable on purpose. Client and server,
//! request and response, encoder and decoder, HTTP/1 and HTTP/2 and HTTP/3 —
//! each pair shares the shape of its counterpart, and version-specific
//! connections are drop-in replacements for one another wherever the protocol
//! itself does not force a difference. Prefer naming the base type
//! ([`protocol::base::Connection`], [`AnyConnection`]) over a concrete
//! version wherever a choice exists. Nothing keys on a version where the
//! transport is the real question: a port carries whichever versions run over
//! its transport, per [`Port::carries`], so a new version slots in without
//! touching the routing.
//!
//! # Getting started
//!
//! Fetch a resource:
//!
//! ```no_run
//! # async fn example() -> Result<(), soyokaze::Error> {
//! let client = soyokaze::Client::default();
//! let response = client.get("https://example.com/").await?;
//!
//! println!("{:?}", response.status_code);
//! # Ok(())
//! # }
//! ```
//!
//! Serve one:
//!
//! ```no_run
//! # async fn example() -> Result<(), soyokaze::Error> {
//! use soyokaze::{Port, Server};
//!
//! struct Echo;
//! impl soyokaze::Handler for Echo {}
//!
//! let server = Server::default();
//! let handle = server.serve(Echo, &[Port::TCP(8080)]).await?;
//!
//! handle.close(None).await;
//! # Ok(())
//! # }
//! ```
//!
//! [`AnyConnection`]: protocol::base::AnyConnection

pub mod ffi;
pub mod models;
pub mod errors;
pub mod cookies;
pub mod hsts;
pub mod responses;
pub mod finalizer;
pub mod websocket;
pub mod tls;

pub mod api {
    //! The entry points a user of the crate reaches for first.
    //!
    //! [`client`] dials an origin, [`server`] binds ports and accepts
    //! connections, and [`common`] holds what the two configure in common.
    //! [`gate`] is the server's admission control, and [`cluster`] runs it
    //! across worker threads.

    pub mod common;
    pub mod client;
    pub mod server;
    pub mod gate;
    pub mod cluster;
}

pub mod protocol {
    //! One connection type per HTTP version, over a shared vocabulary.
    //!
    //! [`common`] holds what every version shares, [`base`] holds what a
    //! connection is before any version makes it concrete, [`quic`] is the
    //! seam QUIC is consumed through, [`handler`] bridges each transport into
    //! a connection, and [`h1`], [`h2`] and [`h3`] each implement one version.

    pub mod common;
    pub mod base;
    pub mod quic;
    pub mod handler;
    pub mod h1;
    pub mod h2;
    pub mod h3;

    pub use base::{AnyConnection, Connection, Stream, Transport};
    pub use handler::{Incoming, Negotiation};
    pub use quic::{QuicDialer, QuicListener, QuicTransport};
    pub use h1::{H1Connection, H1Limits};
    pub use h2::{H2Connection, H2Limits};
    pub use h3::{H3Connection, H3Limits};
}

pub mod helpers {
    //! The codecs and utilities the protocol implementations share.
    //!
    //! [`huffman`], [`hpack`] and [`qpack`] are the field compression formats,
    //! over the shared vocabulary in [`fields`]; [`base64`] and [`sha1`] are
    //! what the WebSocket handshake needs; and [`text`], [`scan`] and [`sync`]
    //! are small pieces the parsers lean on.

    pub mod base64;
    pub mod scan;
    pub mod text;
    pub mod sha1;
    pub mod sync;
    pub mod huffman;
    pub mod fields;
    pub mod hpack;
    pub mod qpack;
}

pub use errors::Error;
pub use models::{Alpn, Body, ConnectionID, HeaderCase, Headers, Limits, Message, Method, Port, Role, StreamID, TransportKind, Url, Version};
pub use cookies::{Cookie, CookieJar, CookieLimits, SameSite, SetCookie};
pub use finalizer::{DateCache, RequestFinalizer, ResponseFinalizer};
pub use api::common::VERSIONS;
pub use api::client::{Client, ClientConfig, ClientLimits};
pub use api::server::{Handler, RawSocket, Server, ServerConfig, ServerLimits};
pub use api::gate::{Gate, Permit};
pub use api::cluster::{cores, Cluster};
pub use tls::{EchConfig, EchConfigList, EchKeys, EchStatus, Format, Identity, Security, TLSCipher, TLSGroup, TLSVersion};
pub use hsts::{HstsLimits, HstsPolicy, HstsStore};
pub use helpers::text::Text;
pub use websocket::{WebSocketConnection, WebSocketLimits};
