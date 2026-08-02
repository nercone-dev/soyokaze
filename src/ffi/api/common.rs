//! What the client and the server configure in common, from C.
//!
//! [`Limits`] is the C half of [`crate::api::common::Limits`], field for
//! field.

/// What one connection is allowed to spend on the peer's behalf.
///
/// The C half of [`Limits`], field for field. Passing null wherever one of
/// these is asked for takes every default; a caller that wants to change one
/// ceiling starts from [`soyokaze_limits_default`] and adjusts it.
///
/// [`Limits`]: crate::api::common::Limits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Limits {
    /// In bytes, the total size of the HTTP message allowed for reception.
    pub max_message_size: u64,
    /// In bytes, the size of the HTTP message body allowed for reception.
    pub max_message_body_size: u64,

    /// In bytes, the request/status line ceiling.
    pub max_startline_size: u32,
    /// In bytes, the whole header (or trailer) block.
    pub max_headers_size: u64,
    /// The number of header fields allowed in one block.
    pub max_header_count: u16,
    /// In bytes, the chunk-size line ceiling for chunked transfer encoding.
    pub max_chunk_header_size: u32,

    /// The number of connections a listener may negotiate at once.
    pub max_pending_handshakes: u32,

    /// In seconds, how long one read may wait. Zero waits forever.
    pub read_timeout: f64,
    /// In seconds, how long one write may wait. Zero waits forever.
    pub write_timeout: f64,
    /// In seconds, how long one whole message may take to arrive. Zero waits forever.
    pub receive_timeout: f64,
    /// In seconds, how long one whole message may take to send. Zero waits forever.
    pub send_timeout: f64,

    /// The number of streams a peer may have open at once, per connection.
    pub max_concurrent_streams: u32,
    /// In bytes, the unread message data one connection may hold.
    pub max_connection_buffer_size: u64,
    /// The number of streams a peer may reset before a response was sent.
    pub max_premature_resets: u32,

    /// The number of frames a peer may send without advancing a stream.
    pub max_idle_frames: u32,

    /// In seconds, how long to wait for a blocking QPACK reference.
    pub qpack_block_timeout: f64,
    /// The number of unidirectional streams a peer may open at once.
    pub max_peer_uni_streams: u32,
    /// The number of unacknowledged QPACK field sections the encoder may track.
    pub max_outstanding_sections: u32,

    /// In seconds, how long a WebSocket close waits for the peer's echo.
    pub ws_linger_timeout: f64,
    /// The number of continuation frames allowed in one WebSocket message.
    pub ws_max_fragments: u16,

    /// The number of cookies one jar may hold across all origins.
    pub max_cookies: u32,
    /// The number of cookies one jar may hold for a single domain.
    pub max_cookies_per_domain: u16,
    /// The number of hosts one HSTS store may remember.
    pub max_hsts_entries: u32,
}

impl Limits {
    /// The [`Limits`] this stands for.
    ///
    /// [`Limits`]: crate::api::common::Limits
    pub fn parse(&self) -> crate::api::common::Limits {
        crate::api::common::Limits {
            max_message_size: self.max_message_size,
            max_message_body_size: self.max_message_body_size,
            max_startline_size: self.max_startline_size,
            max_headers_size: self.max_headers_size,
            max_header_count: self.max_header_count,
            max_chunk_header_size: self.max_chunk_header_size,
            max_pending_handshakes: self.max_pending_handshakes,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            receive_timeout: self.receive_timeout,
            send_timeout: self.send_timeout,
            max_concurrent_streams: self.max_concurrent_streams,
            max_connection_buffer_size: self.max_connection_buffer_size,
            max_premature_resets: self.max_premature_resets,
            max_idle_frames: self.max_idle_frames,
            qpack_block_timeout: self.qpack_block_timeout,
            max_peer_uni_streams: self.max_peer_uni_streams,
            max_outstanding_sections: self.max_outstanding_sections,
            ws_linger_timeout: self.ws_linger_timeout,
            ws_max_fragments: self.ws_max_fragments,
            max_cookies: self.max_cookies,
            max_cookies_per_domain: self.max_cookies_per_domain,
            max_hsts_entries: self.max_hsts_entries,
        }
    }

    /// The C half of `limits`.
    pub fn build(limits: &crate::api::common::Limits) -> Self {
        Self {
            max_message_size: limits.max_message_size,
            max_message_body_size: limits.max_message_body_size,
            max_startline_size: limits.max_startline_size,
            max_headers_size: limits.max_headers_size,
            max_header_count: limits.max_header_count,
            max_chunk_header_size: limits.max_chunk_header_size,
            max_pending_handshakes: limits.max_pending_handshakes,
            read_timeout: limits.read_timeout,
            write_timeout: limits.write_timeout,
            receive_timeout: limits.receive_timeout,
            send_timeout: limits.send_timeout,
            max_concurrent_streams: limits.max_concurrent_streams,
            max_connection_buffer_size: limits.max_connection_buffer_size,
            max_premature_resets: limits.max_premature_resets,
            max_idle_frames: limits.max_idle_frames,
            qpack_block_timeout: limits.qpack_block_timeout,
            max_peer_uni_streams: limits.max_peer_uni_streams,
            max_outstanding_sections: limits.max_outstanding_sections,
            ws_linger_timeout: limits.ws_linger_timeout,
            ws_max_fragments: limits.ws_max_fragments,
            max_cookies: limits.max_cookies,
            max_cookies_per_domain: limits.max_cookies_per_domain,
            max_hsts_entries: limits.max_hsts_entries,
        }
    }

    /// The [`Limits`] a pointer stands for: what it points at, or the defaults
    /// when it is null.
    ///
    /// [`Limits`]: crate::api::common::Limits
    ///
    /// # Safety
    ///
    /// `limits` must either be null or point to a readable [`Limits`].
    pub unsafe fn or_default(limits: *const Limits) -> crate::api::common::Limits {
        match unsafe { limits.as_ref() } {
            Some(limits) => limits.parse(),
            None => crate::api::common::Limits::default(),
        }
    }
}

/// The default [`Limits`], to be adjusted and passed back.
///
/// [`Limits`]: crate::api::common::Limits
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_limits_default() -> Limits {
    Limits::build(&crate::api::common::Limits::default())
}
