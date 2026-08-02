//! What the client and the server configure in common.
//!
//! [`Limits`] bounds what one connection is allowed to spend on the peer's
//! behalf, whichever side of it this end is, and [`VERSIONS`] is the version
//! list both configurations offer by default. [`ClientLimits`] and
//! [`ServerLimits`] extend this with what only one side needs.
//!
//! [`ClientLimits`]: crate::api::client::ClientLimits
//! [`ServerLimits`]: crate::api::server::ServerLimits

use crate::models::Version;

/// The versions a configuration offers by default, in the order they are
/// preferred.
///
/// A server offers all of them and lets negotiation choose; a client prefers
/// them in this order.
pub const VERSIONS: &[Version] = &[Version::V3_0, Version::V2_0, Version::V1_1];

/// What one connection is allowed to spend on the peer's behalf.
///
/// Every field is a ceiling: exceeding one produces [`Error::Limit`] and, for
/// the counters that exist to blunt floods, tears the connection down. The
/// defaults are meant to be usable as they stand for a public-facing server.
///
/// Timeouts are in seconds, and zero means wait forever.
///
/// [`Error::Limit`]: crate::errors::Error::Limit
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    /// In bytes, the total size of the HTTP message allowed for reception.
    pub max_message_size:      u64,
    /// In bytes, the size of the HTTP message body allowed for reception.
    pub max_message_body_size: u64,

    /// In bytes, the request/status line ceiling.
    pub max_startline_size:    u32,
    /// In bytes, the whole header (or trailer) block.
    pub max_headers_size:      u64,
    /// The number of header fields allowed in one block.
    pub max_header_count:      u16,
    /// In bytes, the chunk-size line ceiling for chunked transfer encoding.
    pub max_chunk_header_size: u32,

    /// The number of connections a listener may negotiate at once (mitigates slow handshake floods).
    pub max_pending_handshakes: u32,

    /// In seconds, how long one read may wait for the peer to deliver more octets (0 waits forever).
    pub read_timeout: f64,
    /// In seconds, how long one write may wait for the peer to accept more octets (0 waits forever).
    pub write_timeout: f64,
    /// In seconds, how long one whole message may take to arrive once it has begun (0 waits forever).
    pub receive_timeout: f64,
    /// In seconds, how long one whole message may take to send (0 waits forever).
    pub send_timeout: f64,

    // HTTP/2 and HTTP/3
    /// The number of streams a peer may have open at once, per connection.
    pub max_concurrent_streams:     u32,
    /// In bytes, the unread message data one connection may hold across all of its streams.
    pub max_connection_buffer_size: u64,
    /// The number of streams a peer may reset before a response was sent, per connection (mitigates rapid reset floods).
    pub max_premature_resets:       u32,

    // HTTP/2
    /// The number of frames a peer may send without advancing a stream, per connection (mitigates PING and SETTINGS floods).
    pub max_idle_frames:            u32,

    // HTTP/3
    /// In seconds, how long to wait for a blocking QPACK reference to resolve before failing the connection.
    pub qpack_block_timeout:        f64,
    /// The number of unidirectional streams a peer may open at once, per connection.
    pub max_peer_uni_streams:       u32,
    /// The number of unacknowledged QPACK field sections the encoder may track before it stops referencing the dynamic table.
    pub max_outstanding_sections:   u32,

    // WebSocket
    /// In seconds, how long a close waits for the peer to echo it back before the transport is shut down.
    pub ws_linger_timeout: f64,
    /// The number of continuation frames allowed in one message.
    pub ws_max_fragments:  u16,

    // Client state
    /// The number of cookies one jar may hold across all origins.
    pub max_cookies:            u32,
    /// The number of cookies one jar may hold for a single domain.
    pub max_cookies_per_domain: u16,
    /// The number of hosts one HSTS store may remember.
    pub max_hsts_entries:       u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024 * 1024,
            max_message_body_size: 64 * 1024 * 1024,

            max_startline_size: 8 * 1024,
            max_headers_size: 64 * 1024,
            max_header_count: 100,
            max_chunk_header_size: 128,

            max_pending_handshakes: 256,

            read_timeout: 30.0,
            write_timeout: 30.0,
            receive_timeout: 300.0,
            send_timeout: 1800.0,

            max_concurrent_streams: 100,
            max_connection_buffer_size: 64 * 1024 * 1024,
            max_premature_resets: 1000,
            max_idle_frames: 1000,

            qpack_block_timeout: 5.0,
            max_peer_uni_streams: 32,
            max_outstanding_sections: 512,

            ws_linger_timeout: 10.0,
            ws_max_fragments: 4096,

            max_cookies: 3000,
            max_cookies_per_domain: 50,
            max_hsts_entries: 4096,
        }
    }
}
