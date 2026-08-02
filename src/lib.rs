//! An HTTP/1, HTTP/2 and HTTP/3 library.
//!
//! Soyokaze speaks all three versions of HTTP through one set of types. A
//! [`Message`] carries a request or a response regardless of the version that
//! framed it, and every connection implements [`protocol::common::Connection`],
//! so code written against the trait works unchanged over HTTP/1.1, HTTP/2 and
//! HTTP/3.
//!
//! # Layers
//!
//! The crate is arranged in three layers, each usable on its own:
//!
//! - [`api`] holds the entry points: [`Client`] dials an origin, [`Server`]
//!   binds ports and accepts connections, and [`api::tls`] builds the BoringSSL
//!   contexts both of them negotiate with.
//! - [`protocol`] holds one connection type per version — [`protocol::h1`],
//!   [`protocol::h2`] and [`protocol::h3`] — over the shared vocabulary in
//!   [`protocol::common`]. A higher layer drives a lower one exactly the way an
//!   outside caller would; HTTP/1.1 over TCP is built from a `TCPServer` and an
//!   `H1Connection` with no private back channel between them.
//! - [`helpers`] holds the codecs the versions share: [`helpers::huffman`],
//!   [`helpers::hpack`] for HTTP/2 and [`helpers::qpack`] for HTTP/3, plus the
//!   small pieces ([`helpers::base64`], [`helpers::sha1`]) the WebSocket
//!   handshake needs.
//!
//! # Symmetry
//!
//! Corresponding pieces are kept interchangeable on purpose. Client and server,
//! request and response, encoder and decoder, HTTP/1 and HTTP/2 and HTTP/3 —
//! each pair shares the shape of its counterpart, and version-specific
//! connections are drop-in replacements for one another wherever the protocol
//! itself does not force a difference. Prefer naming the base type
//! ([`protocol::common::Connection`], [`AnyConnection`]) over a concrete
//! version wherever a choice exists.
//!
//! # Getting started
//!
//! Fetch a resource:
//!
//! ```no_run
//! # async fn example() -> Result<(), soyokaze::Error> {
//! let client = soyokaze::Client::builder().build();
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
//! let server = Server::builder().build();
//! let handle = server.serve(Echo, &[Port::TCP(8080)]).await?;
//!
//! handle.close(None).await;
//! # Ok(())
//! # }
//! ```
//!
//! [`AnyConnection`]: protocol::common::AnyConnection

pub mod models;
pub mod errors;
pub mod headers;
pub mod responses;
pub mod finalizer;
pub mod websocket;

pub mod api {
    //! The entry points a user of the crate reaches for first.
    //!
    //! [`client`] dials an origin, [`server`] binds ports and accepts
    //! connections, and [`tls`] builds the contexts both of them negotiate
    //! with.

    pub mod client;
    pub mod server;
    pub mod tls;
}

pub mod protocol {
    //! One connection type per HTTP version, over a shared vocabulary.
    //!
    //! [`common`] holds what every version shares, and [`h1`], [`h2`] and
    //! [`h3`] each implement one version over it.

    pub mod common;
    pub mod h1;
    pub mod h2;
    pub mod h3;
}

pub mod helpers {
    //! The codecs and utilities the protocol implementations share.
    //!
    //! [`huffman`], [`hpack`] and [`qpack`] are the field compression formats;
    //! [`base64`] and [`sha1`] are what the WebSocket handshake needs;
    //! [`text`], [`scan`] and [`sync`] are small pieces the parsers lean on;
    //! and [`hsts`] holds the Strict-Transport-Security policy types.

    pub mod base64;
    pub mod scan;
    pub mod text;
    pub mod sha1;
    pub mod sync;
    pub mod huffman;
    pub mod hpack;
    pub mod qpack;
    pub mod hsts;
}

pub use errors::Error;
pub use models::{Body, ConnectionID, HeaderCase, Headers, Limits, Message, Method, Port, Role, StreamID, Url, Version};
pub use headers::{Cookie, CookieJar, SameSite, SetCookie};
pub use finalizer::{http_date, DateCache};
pub use api::client::{Client, ClientLimits};
pub use api::server::{cores, Cluster, Gate, Handler, Permit, RawSocket, Server, ServerLimits};
pub use api::tls::{EchConfig, EchConfigList, EchKeys, EchStatus, Identity};
pub use helpers::hsts::{HstsPolicy, HstsStore};
pub use helpers::text::Text;
pub use websocket::WebSocketConnection;
