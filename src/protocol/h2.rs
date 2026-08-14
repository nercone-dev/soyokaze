//! HTTP/2.
//!
//! Many concurrent streams over one connection, framed as fixed nine-octet
//! headers followed by payloads. Field sections are compressed with
//! [`hpack`], which is what makes a field block that will not decode fatal to
//! the whole connection rather than to one stream.
//!
//! Flow control is credit-based and applies at two levels at once, the
//! connection and each stream, so a send is bounded by whichever of the two
//! windows is smaller. Both are tracked as `i64` rather than `u32` because a
//! `SETTINGS_INITIAL_WINDOW_SIZE` that shrinks mid-connection can leave a
//! window legitimately negative.
//!
//! Several counters here exist only to blunt floods that cost the server far
//! more than the peer: [`Limits::max_premature_resets`] against rapid reset,
//! and [`Limits::max_idle_frames`] against frames that never advance a stream.
//!
//! [`hpack`]: crate::helpers::hpack

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The ceilings an [`H2Connection`] holds itself to.
///
/// RFC 9113 framing, flow control and HPACK, and nothing else. No QPACK
/// setting and no HTTP/1.x line ceiling appears here.
///
/// [`Limits`] converts into one, so a caller configuring everything at once
/// still passes the one struct and each connection takes its own share.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct H2Limits {
    /// In bytes, the total size of a message allowed for reception.
    pub max_message_size: u64,
    /// In bytes, the message body size allowed for reception.
    pub max_message_body_size: u64,
    /// In bytes, the size a received body may reach once its content coding is undone.
    pub max_decompressed_body_size: u64,
    /// In bytes, the whole header (or trailer) block.
    pub max_headers_size: u64,
    /// The number of header fields allowed in one block.
    pub max_header_count: u16,
    /// The number of streams a peer may have open at once.
    pub max_concurrent_streams: u32,
    /// In bytes, the unread data one connection may hold across its streams.
    pub max_connection_buffer_size: u64,
    /// The number of streams a peer may reset before a response was sent.
    pub max_premature_resets: u32,
    /// The number of frames a peer may send without advancing a stream.
    pub max_idle_frames: u32,
    /// In bytes, the buffered output size at which a body write flushes.
    pub output_high_water: u64,
    /// In bytes, the largest HPACK encoder table this end will keep.
    pub max_encoder_table_size: u64,
    /// In bytes, how much room each read from the transport is given.
    pub read_chunk_size: u64,
    /// In bytes, the buffer size above which an idle connection gives memory back.
    pub idle_capacity: u64,
    /// In seconds, how long one read may wait (0 waits forever).
    pub read_timeout: f64,
    /// In seconds, how long one write may wait (0 waits forever).
    pub write_timeout: f64,
    /// In seconds, how long one whole message may take to arrive (0 waits forever).
    pub receive_timeout: f64,
    /// In seconds, how long one whole message may take to send (0 waits forever).
    pub send_timeout: f64,
}

impl Default for H2Limits {
    fn default() -> Self {
        Limits::default().into()
    }
}

impl From<Limits> for H2Limits {
    fn from(limits: Limits) -> Self {
        Self {
            max_message_size: limits.max_message_size,
            max_message_body_size: limits.max_message_body_size,
            max_decompressed_body_size: limits.max_decompressed_body_size,
            max_headers_size: limits.max_headers_size,
            max_header_count: limits.max_header_count,
            max_concurrent_streams: limits.max_concurrent_streams,
            max_connection_buffer_size: limits.max_connection_buffer_size,
            max_premature_resets: limits.max_premature_resets,
            max_idle_frames: limits.max_idle_frames,
            output_high_water: limits.output_high_water,
            max_encoder_table_size: limits.max_encoder_table_size,
            read_chunk_size: limits.read_chunk_size,
            idle_capacity: limits.idle_capacity,
            read_timeout: limits.read_timeout,
            write_timeout: limits.write_timeout,
            receive_timeout: limits.receive_timeout,
            send_timeout: limits.send_timeout,
        }
    }
}

pub mod frames;

pub use frames::{Code, Flag, Frame, FrameHeader, FrameType, Settings, PREFACE};

use crate::helpers::compression::Compression;
use crate::helpers::fields::HeaderField;
use crate::helpers::hpack::{Decoder as HPACKDecoder, Encoder as HPACKEncoder};
use crate::models::{Body, ConnectionID, Limits, Message, Method, Role, StreamID, Version};
use crate::tls::Security;
use crate::protocol::base::{Connection, Stream};
use crate::protocol::common::{self, Buffer, Error};
use crate::helpers::sync;

/// Where a stream is in its lifetime.
///
/// A stream is half-closed once one side has finished, and closed once both
/// have. The two reserved states belong to server push, which is disabled
/// here, so they are never entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Nothing has been sent on it yet.
    Idle,
    /// Reserved by a push this end promised.
    ReservedLocal,
    /// Reserved by a push the peer promised.
    ReservedRemote,
    /// Both ends may still send.
    Open,
    /// This end has finished sending.
    HalfClosedLocal,
    /// The peer has finished sending.
    HalfClosedRemote,
    /// Both ends have finished.
    Closed,
}

impl StreamState {
    /// Whether the peer may still send on this stream.
    pub fn receivable(&self) -> bool {
        matches!(self, Self::Idle | Self::Open | Self::HalfClosedLocal)
    }

    /// Whether this end may still send on this stream.
    pub fn sendable(&self) -> bool {
        matches!(self, Self::Idle | Self::Open | Self::HalfClosedRemote)
    }

    /// The state after this end finishes sending.
    pub fn close_local(&self) -> Self {
        match self {
            Self::Open | Self::Idle => Self::HalfClosedLocal,
            _ => Self::Closed,
        }
    }

    /// The state after the peer finishes sending.
    pub fn close_remote(&self) -> Self {
        match self {
            Self::Open | Self::Idle => Self::HalfClosedRemote,
            _ => Self::Closed,
        }
    }
}

/// One stream within an HTTP/2 connection.
///
/// Holds the message being assembled and the two flow control windows, which
/// are signed because a shrinking `SETTINGS_INITIAL_WINDOW_SIZE` can push the
/// send window legitimately below zero.
pub struct H2Stream {
    id: StreamID,
    state: StreamState,

    window_local: i64,
    window_remote: i64,

    block: Vec<u8>,
    head: u64,
    body: BytesMut,
    headers: Option<Message>,
    method: Option<Method>,
    accepted: Option<Compression>,

    pending_reset: Option<u64>,
    resets: Arc<AtomicBool>,
}

impl H2Stream {
    /// An idle stream with the given starting windows.
    ///
    /// `resets` is the connection's flag saying some stream has asked to be
    /// reset; see [`H2Connection::flush_resets`].
    pub fn new(id: StreamID, window_local: i64, window_remote: i64, resets: Arc<AtomicBool>) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            window_local,
            window_remote,
            block: Vec::new(),
            head: 0,
            body: BytesMut::new(),
            headers: None,
            method: None,
            accepted: None,
            pending_reset: None,
            resets,
        }
    }

    /// Where the stream is in its lifetime.
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// The best coding the request on this stream said it would take.
    ///
    /// Set when the request arrives, and read when the response goes out, so
    /// that [`Compression::Auto`] settles on something the peer can read.
    pub fn accepted(&self) -> Option<Compression> {
        self.accepted
    }

    /// How many octets of message have arrived, compressed head and body alike.
    ///
    /// This is what [`Limits::max_message_size`] is checked against.
    pub fn received(&self) -> u64 {
        self.head + self.body.len() as u64
    }

    /// The credit the peer has left to send on this stream.
    pub fn window_local(&self) -> i64 {
        self.window_local
    }

    /// The credit this end has left to send on this stream.
    pub fn window_remote(&self) -> i64 {
        self.window_remote
    }
}

impl Stream for H2Stream {
    fn id(&self) -> StreamID {
        self.id
    }

    async fn reset(&mut self, code: u64) {
        self.state = StreamState::Closed;
        self.pending_reset = Some(code);
        self.resets.store(true, Ordering::Relaxed);
    }
}

/// An HTTP/2 connection.
///
/// Many streams multiplexed over one transport. Frames are queued into an
/// output buffer and flushed together, so a message that spans several frames
/// costs one write rather than one per frame.
///
/// [`Connection::receive`] drives the whole connection, not just the stream a
/// caller is waiting on: it answers PING and SETTINGS, tracks flow control,
/// and hands back messages as they complete, whichever stream they arrived on.
pub struct H2Connection<T> {
    transport: T,
    role: Role,
    id: ConnectionID,
    client: Option<std::net::SocketAddr>,
    limits: H2Limits,
    buffer: Buffer,

    streams: common::StreamMap<StreamID, H2Stream>,

    hpack_encoder: HPACKEncoder,
    hpack_decoder: HPACKDecoder,

    settings_local: Settings,
    settings_remote: Settings,

    window_local: i64,
    window_remote: i64,

    next_stream_id: u64,
    highest_peer_stream_id: u64,
    started: bool,
    goaway: Option<u32>,
    ready: VecDeque<Message>,
    out: BytesMut,
    block: Vec<u8>,
    fields: Vec<HeaderField>,
    buffered_bound: u64,

    resets: Arc<AtomicBool>,
    premature_resets: u32,
    idle_frames: u32,
    request_finalizer: crate::finalizer::RequestFinalizer,
    response_finalizer: crate::finalizer::ResponseFinalizer,
    security: Security,
}

impl<T> H2Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// A connection over a transport nothing has been read from yet.
    ///
    /// The preface and the opening SETTINGS are not sent until the first
    /// [`H2Connection::start`], which every send and receive does for itself.
    pub fn new(transport: T, role: Role, id: ConnectionID, limits: impl Into<H2Limits>) -> Self {
        let limits = limits.into();
        Self::resume(transport, role, id, limits, Buffer::new())
    }

    /// A connection over a transport that has already been read from.
    ///
    /// This is what preface sniffing on a plaintext port needs: the octets
    /// read to recognise HTTP/2 are handed over rather than lost.
    pub fn resume(transport: T, role: Role, id: ConnectionID, limits: impl Into<H2Limits>, buffer: Buffer) -> Self {
        let limits = limits.into();
        let settings_local = Settings { max_concurrent_streams: Some(limits.max_concurrent_streams), ..Settings::default() };

        let mut hpack_encoder = HPACKEncoder::new();
        hpack_encoder.set_capacity_limit(limits.max_encoder_table_size as usize);

        let mut buffer = buffer;
        buffer.set_chunk_size(limits.read_chunk_size as usize);

        Self {
            transport,
            role,
            id,
            client: None,
            limits,
            buffer,
            streams: common::StreamMap::default(),
            hpack_encoder,
            hpack_decoder: HPACKDecoder::new(),
            settings_local,
            settings_remote: Settings::peer(),
            window_local: Settings::DEFAULT_INITIAL_WINDOW_SIZE as i64,
            window_remote: Settings::DEFAULT_INITIAL_WINDOW_SIZE as i64,
            next_stream_id: if role.is_client() { 1 } else { 2 },
            highest_peer_stream_id: 0,
            started: false,
            goaway: None,
            ready: VecDeque::new(),
            out: BytesMut::new(),
            block: Vec::new(),
            fields: Vec::new(),
            buffered_bound: 0,
            resets: Arc::new(AtomicBool::new(false)),

            premature_resets: 0,
            idle_frames: 0,
            request_finalizer: crate::finalizer::RequestFinalizer::default(),
            response_finalizer: crate::finalizer::ResponseFinalizer::new(None),
            security: Security::default(),
        }
    }

    /// The ceilings this connection holds itself to.
    pub fn limits(&self) -> H2Limits {
        self.limits
    }

    /// Attaches the finalisation applied to requests on the way out.
    ///
    /// What finalising a request means is the finalizer's business, not this
    /// connection's: a connection frames messages and knows nothing of what an
    /// endpoint owes them.
    pub fn with_request_finalizer(mut self, finalizer: crate::finalizer::RequestFinalizer) -> Self {
        self.request_finalizer = finalizer;
        self
    }

    /// Attaches the finalisation applied to responses on the way out.
    ///
    /// The counterpart of [`H2Connection::with_request_finalizer`], and for the
    /// same reason.
    pub fn with_response_finalizer(mut self, finalizer: crate::finalizer::ResponseFinalizer) -> Self {
        self.response_finalizer = finalizer;
        self
    }

    /// Attaches what the handshake settled, to be stamped on every message
    /// this connection receives.
    pub fn with_security(mut self, security: Security) -> Self {
        self.security = security;
        self
    }

    /// Attaches the address the peer connected from, to be stamped on every
    /// request this connection receives.
    ///
    /// A client connection is told none, and neither is one over a Unix
    /// socket, so [`Message::client`] stays absent on both.
    pub fn with_client(mut self, client: Option<std::net::SocketAddr>) -> Self {
        self.client = client;
        self
    }

    /// The settings this end advertised.
    pub fn settings_local(&self) -> &Settings {
        &self.settings_local
    }

    /// The settings the peer advertised.
    pub fn settings_remote(&self) -> &Settings {
        &self.settings_remote
    }

    /// The HPACK encoder for this direction.
    pub fn hpack_encoder(&self) -> &HPACKEncoder {
        &self.hpack_encoder
    }

    /// The HPACK decoder for the other direction.
    pub fn hpack_decoder(&self) -> &HPACKDecoder {
        &self.hpack_decoder
    }

    /// How many streams this end may open at once.
    ///
    /// The peer's advertised ceiling where it gave one, and
    /// [`Limits::max_concurrent_streams`] otherwise. Never zero, so that a
    /// peer advertising none cannot deadlock the connection.
    pub fn local_stream_ceiling(&self) -> usize {
        let advertised = self.settings_remote.max_concurrent_streams.unwrap_or(self.limits.max_concurrent_streams);
        (advertised as usize).max(1)
    }

    /// One open stream, if it is still open.
    pub fn stream(&self, stream_id: StreamID) -> Option<&H2Stream> {
        self.streams.get(&stream_id)
    }

    /// One open stream, mutably.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the stream is no longer open.
    pub fn open_stream(&mut self, stream_id: StreamID) -> Result<&mut H2Stream, Error> {
        self.streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::Protocol(format!("stream {} is no longer open", stream_id.0)))
    }

    /// Exchanges the preface and sends the opening SETTINGS, once.
    ///
    /// Every send and receive calls this for itself, so it rarely needs
    /// calling directly. Repeat calls do nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when a server's peer does not begin with
    /// [`PREFACE`], and otherwise as [`Buffer::require`] and
    /// [`H2Connection::flush_out`].
    pub async fn start(&mut self) -> Result<(), Error> {
        if self.started {
            return Ok(());
        }
        self.started = true;

        if self.role.is_client() {
            self.out.extend_from_slice(PREFACE);
        } else {
            let preface = self.buffer.require(&mut self.transport, PREFACE.len(), self.limits.read_timeout).await?;
            if preface != PREFACE {
                return Err(Error::Protocol("connection preface is not the HTTP/2 preface".into()));
            }
            self.buffer.consume(PREFACE.len());
        }

        self.hpack_decoder.set_max_capacity(self.settings_local.header_table_size as usize);
        self.hpack_decoder.set_max_decoded_size(self.limits.max_headers_size as usize);

        let settings = Frame::Settings { ack: false, params: self.settings_local.parameters() };
        self.queue(&settings);
        self.flush_out().await
    }

    /// Adds a frame to the output buffer, without writing anything yet.
    pub fn queue(&mut self, frame: &Frame) {
        frame.encode_into(&mut self.out);
    }

    /// Writes and flushes everything queued.
    ///
    /// The buffer is kept and reused, and given back with [`Buffer::reclaim_bytes`]
    /// once it has grown past what an idle connection should hold.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] past [`Limits::write_timeout`], and
    /// [`Error::IO`] when the transport fails.
    pub async fn flush_out(&mut self) -> Result<(), Error> {
        if self.out.is_empty() {
            return Ok(());
        }

        let out = std::mem::take(&mut self.out);
        let transport = &mut self.transport;

        let result = sync::Timeout::within(self.limits.write_timeout, async move {
            transport.write_all(&out).await?;
            transport.flush().await.map(|()| out)
        })
        .await;

        match result? {
            Ok(out) => {
                self.out = out;
                self.out.clear();
                common::Buffer::reclaim_bytes(&mut self.out, self.limits.idle_capacity as usize);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Queues one frame and flushes.
    ///
    /// # Errors
    ///
    /// As [`H2Connection::flush_out`].
    pub async fn write(&mut self, frame: &Frame) -> Result<(), Error> {
        self.queue(frame);
        self.flush_out().await
    }

    /// Drives the connection until a message completes.
    ///
    /// Messages that completed while an earlier send was blocked on flow
    /// control are handed back first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] once the peer has sent GOAWAY and no stream
    /// is left, and otherwise as [`H2Connection::pump`].
    pub async fn receive_message(&mut self) -> Result<Message, Error> {
        loop {
            let arrived = match self.ready.pop_front() {
                Some(message) => Some(message),
                None => self.pump().await?,
            };

            if let Some(mut message) = arrived {
                message.decompress(self.limits.max_decompressed_body_size)?;
                return Ok(message);
            }

            if self.goaway.is_some() && self.streams.is_empty() {
                return Err(Error::Closed);
            }
        }
    }

    /// Sends one whole message on a stream.
    ///
    /// A message with no [`Message::stream_id`] opens a new stream; one with a
    /// stream identifier uses that stream, which is how a server answers the
    /// request it was asked. The stream is left open for a tunnel or an
    /// informational response, since more is to follow on it.
    ///
    /// Body writes block on flow control, and pump the connection while they
    /// wait, so messages that complete meanwhile are held for the next
    /// [`H2Connection::receive_message`] rather than dropped.
    ///
    /// The message is flushed at once unless input from the peer is still
    /// buffered, in which case it batches with the answers that input is owed
    /// and goes out in one write — as [`Limits::output_high_water`] is
    /// crossed, or as the connection next waits on the transport in
    /// [`H2Connection::read_frame`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when opening a stream would go past
    /// [`H2Connection::local_stream_ceiling`], and otherwise as
    /// [`H2Connection::start`], [`common::Fields::of`], [`Body::into_bytes`],
    /// [`H2Connection::write_data`] and [`H2Connection::flush_out`].
    pub async fn send_message(&mut self, message: Message) -> Result<(), Error> {
        let mut message = message;
        self.request_finalizer.finalize(self.role, &mut message);
        self.response_finalizer.finalize(self.role, self.security.secure, &mut message);

        self.start().await?;
        self.flush_resets().await?;

        let window_local = self.settings_local.initial_window_size as i64;
        let window_remote = self.settings_remote.initial_window_size as i64;

        let stream_id = match message.stream_id {
            // A stream the caller names is one that already exists: the
            // request it answers opened it. Making one here instead would
            // resurrect a stream the peer had reset, and since a resurrected
            // stream never reaches `Closed` it would never be retired either,
            // so the map would grow for the life of the connection and the
            // concurrency ceiling would close over it.
            Some(stream_id) => {
                if !self.streams.contains_key(&stream_id) {
                    let reason = format!("stream {} is no longer open", stream_id.0);
                    return Err(Error::stream(stream_id, Code::STREAM_CLOSED as u64, reason));
                }

                stream_id
            }

            None => {
                let ceiling = self.local_stream_ceiling();
                if self.streams.len() >= ceiling {
                    return Err(Error::Limit(format!("more than {ceiling} streams are open at once")));
                }

                let stream_id = StreamID(self.next_stream_id);
                self.next_stream_id += 2;

                self.streams.insert(stream_id, H2Stream::new(stream_id, window_local, window_remote, self.resets.clone()));
                stream_id
            }
        };

        message.materialize().await?;
        message.compress(message.is_response().then(|| self.streams.get(&stream_id)?.accepted).flatten())?;

        self.fields.clear();
        common::Fields::write(&message, &mut self.fields)?;

        let mut block = std::mem::take(&mut self.block);
        block.clear();
        self.hpack_encoder.encode_into(&mut block, &self.fields);

        // A message that ends at its field section carries neither DATA nor a
        // trailer section, whatever the caller attached — RFC 9112 §6.3 for
        // the `HEAD` case, and the status itself for the rest.
        let framed = !message.bodyless(self.streams.get(&stream_id).and_then(|stream| stream.method));

        let body = message.body.take().and_then(|body| body.inline());

        let body = body.filter(|body| framed && !body.is_empty());
        let trailers = message.trailers.as_ref().filter(|trailers| framed && !trailers.is_empty());

        let tunneling = message.method == Some(Method::CONNECT)
            || (matches!(message.status_code, Some(200..=299))
                && self.streams.get(&stream_id).is_some_and(|stream| stream.method == Some(Method::CONNECT)));

        let open = tunneling || message.is_informational();

        let end_stream = !open && body.is_none() && trailers.is_none();
        let written = self.write_block(stream_id, &block, end_stream).await;
        self.block = block;
        common::Buffer::reclaim_octets(&mut self.block, self.limits.idle_capacity as usize);
        written?;

        if let Some(body) = body {
            self.write_data(stream_id, &body, trailers.is_none()).await?;
        }

        if let Some(trailers) = trailers {
            self.fields.clear();
            self.fields.extend_from_slice(trailers.fields());

            let mut block = std::mem::take(&mut self.block);
            block.clear();
            self.hpack_encoder.encode_into(&mut block, &self.fields);

            let written = self.write_block(stream_id, &block, true).await;
            self.block = block;
            common::Buffer::reclaim_octets(&mut self.block, self.limits.idle_capacity as usize);
            written?;
        }

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            if !open {
                stream.state = stream.state.close_local();
            }
            if message.is_request() {
                stream.method = message.method;
            }
        }

        self.retire(stream_id);

        if self.buffer.is_empty() {
            self.flush_out().await?;
        }

        Ok(())
    }

    /// Abandons one stream and tells the peer why.
    ///
    /// # Errors
    ///
    /// As [`H2Connection::flush_out`]. The stream is forgotten either way.
    pub async fn reset(&mut self, stream_id: StreamID, error_code: u32) -> Result<(), Error> {
        self.streams.remove(&stream_id);
        self.write(&Frame::RstStream { stream_id, error_code }).await
    }

    /// Sends GOAWAY with `ENHANCE_YOUR_CALM` and builds the matching error.
    ///
    /// Used where the peer is costing far more than it is spending. Failing to
    /// send the GOAWAY is ignored: the connection is going down regardless.
    pub async fn overloaded(&mut self, reason: impl Into<String>) -> Error {
        let goaway = Frame::GoAway {
            last_stream_id: StreamID(self.highest_peer_stream_id),
            error_code: Code::ENHANCE_YOUR_CALM,
            debug_data: Vec::new(),
        };

        let _ = self.write(&goaway).await;
        Error::Limit(reason.into())
    }

    /// Counts one frame that did not advance any stream.
    ///
    /// PING and SETTINGS floods cost a server work while costing the peer
    /// almost nothing, so a run of frames that move nothing forward is capped.
    /// The counter is reset by anything that does make progress.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] past [`Limits::max_idle_frames`], having first
    /// told the peer with GOAWAY.
    pub async fn idle(&mut self) -> Result<(), Error> {
        self.idle_frames = self.idle_frames.saturating_add(1);

        if self.idle_frames > self.limits.max_idle_frames {
            let reason = format!("more than {} frames arrived without advancing a stream", self.limits.max_idle_frames);
            return Err(self.overloaded(reason).await);
        }

        Ok(())
    }

    /// How much unread body the connection is holding across all its streams.
    ///
    /// Checked against [`Limits::max_connection_buffer_size`], so that many
    /// streams each within their own limit cannot add up without bound.
    pub fn buffered(&self) -> u64 {
        self.streams.values().map(|stream| stream.body.len() as u64).sum()
    }

    /// Whether the connection is holding more than
    /// [`Limits::max_connection_buffer_size`] across all of its streams.
    ///
    /// [`H2Connection::buffered`] walks every stream, and this is asked on
    /// every DATA frame, which would make one pass over the connection's
    /// streams cost a walk per stream. So `buffered_bound` is kept instead: it
    /// grows with every octet taken in and is never reduced as octets are read
    /// away, so it can read high but never low. The exact sum is taken only
    /// once the bound reaches the ceiling, which is at most once per ceiling's
    /// worth of octets rather than once per frame.
    pub fn overbuffered(&mut self) -> bool {
        let limit = self.limits.max_connection_buffer_size;

        if self.buffered_bound <= limit {
            return false;
        }

        self.buffered_bound = self.buffered();
        self.buffered_bound > limit
    }

    /// Drops a stream if it has finished, so its state is not held forever.
    pub fn retire(&mut self, stream_id: StreamID) {
        if self.streams.get(&stream_id).is_some_and(|stream| stream.state == StreamState::Closed) {
            self.streams.remove(&stream_id);
        }
    }

    /// Reads until one whole frame has arrived.
    ///
    /// Frames of unknown type are read past and discarded inside
    /// [`Frame::parse`] rather than failing the connection, so what comes back
    /// is always a frame this end understands.
    ///
    /// Everything queued is flushed before waiting on the transport, so output
    /// batches up while whole frames are still buffered and goes out in one
    /// write the moment the peer's next move is what matters. This is what
    /// keeps a multiplexed burst of responses from costing a write per frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the transport ends mid-frame, and
    /// otherwise as [`Frame::parse`], [`H2Connection::flush_out`] and
    /// [`Buffer::fill`].
    pub async fn read_frame(&mut self) -> Result<Frame, Error> {
        loop {
            if let Ok(frame) = self.read_frame_kept().await? {
                return Ok(frame);
            }
        }
    }

    /// [`H2Connection::read_frame`], reporting a frame of unknown type rather
    /// than reading past it.
    ///
    /// What [`H2Connection::continue_headers`] reads through, since nothing at
    /// all may come between a HEADERS frame and its CONTINUATION frames.
    ///
    /// # Errors
    ///
    /// As [`H2Connection::read_frame`].
    pub async fn read_frame_kept(&mut self) -> Result<Result<Frame, u8>, Error> {
        let max_frame_size = self.settings_local.max_frame_size;

        loop {
            if let Some(frame) = Frame::take(self.buffer.as_bytes_mut(), max_frame_size)? {
                return Ok(frame);
            }

            self.flush_out().await?;

            if !self.buffer.fill(&mut self.transport, self.limits.read_timeout).await? {
                return Err(Error::Closed);
            }
        }
    }

    /// Reads and handles one frame, returning a message if that completed one.
    ///
    /// # Errors
    ///
    /// As [`H2Connection::start`], [`H2Connection::read_frame`],
    /// [`H2Connection::handle`] and [`H2Connection::flush_out`].
    pub async fn pump(&mut self) -> Result<Option<Message>, Error> {
        self.start().await?;
        self.flush_resets().await?;

        let frame = self.read_frame().await?;
        let message = self.handle(frame).await?;

        if self.buffer.is_empty() {
            self.flush_out().await?;
            self.buffer.reclaim(self.limits.idle_capacity as usize);
        }

        Ok(message)
    }

    /// Acts on one frame, returning a message if that completed one.
    ///
    /// This is where the connection is actually run: settings applied, PINGs
    /// answered, flow control credit tracked and replenished, and field blocks
    /// and body octets gathered into messages.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for a frame that breaks the protocol — a
    /// PUSH_PROMISE with push disabled, a CONTINUATION outside a field block,
    /// DATA on a stream that is not open, a window overflowed — and
    /// [`Error::Limit`] when one of the [`Limits`] ceilings is passed. A
    /// stream-level flow control failure resets that stream instead.
    pub async fn handle(&mut self, frame: Frame) -> Result<Option<Message>, Error> {
        match frame {
            Frame::Settings { ack: false, params } => {
                self.idle().await?;

                let window_before = self.settings_remote.initial_window_size;

                for (id, value) in params {
                    self.settings_remote.apply(id, value)?;
                }

                let change = self.settings_remote.initial_window_size as i64 - window_before as i64;
                if change != 0 {
                    for stream in self.streams.values_mut() {
                        stream.window_remote += change;
                    }
                }

                self.hpack_encoder.set_max_capacity(self.settings_remote.header_table_size as usize);
                self.queue(&Frame::Settings { ack: true, params: Vec::new() });
                Ok(None)
            }

            Frame::Settings { ack: true, .. } => {
                self.idle().await?;
                Ok(None)
            }

            Frame::Ping { ack: false, payload } => {
                self.idle().await?;
                self.queue(&Frame::Ping { ack: true, payload });
                Ok(None)
            }

            Frame::Ping { ack: true, .. } => {
                self.idle().await?;
                Ok(None)
            }

            Frame::WindowUpdate { stream_id, increment } => {
                let mut unblocked = false;

                if stream_id == StreamID(0) {
                    let stalled = self.window_remote <= 0;
                    self.window_remote += increment as i64;
                    if self.window_remote > Settings::MAXIMUM_WINDOW_SIZE as i64 {
                        return Err(Error::Protocol("connection send window overflowed".into()));
                    }
                    unblocked = stalled && self.window_remote > 0;
                } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                    let stalled = stream.window_remote <= 0;
                    stream.window_remote += increment as i64;
                    if stream.window_remote > Settings::MAXIMUM_WINDOW_SIZE as i64 {
                        let stream_id = stream.id;
                        self.reset(stream_id, Code::FLOW_CONTROL_ERROR).await?;
                        return Ok(None);
                    }
                    unblocked = stalled && stream.window_remote > 0;
                }

                if unblocked {
                    self.idle_frames = 0;
                } else {
                    self.idle().await?;
                }

                Ok(None)
            }

            Frame::GoAway { error_code, .. } => {
                self.idle().await?;
                self.goaway = Some(error_code);
                Ok(None)
            }

            Frame::RstStream { stream_id, .. } => {
                self.idle().await?;

                let premature = self.streams.remove(&stream_id).is_some_and(|stream| stream.state.sendable());

                if premature {
                    self.premature_resets = self.premature_resets.saturating_add(1);

                    if self.premature_resets > self.limits.max_premature_resets {
                        let reason = format!(
                            "more than {} streams were reset before a response was sent",
                            self.limits.max_premature_resets
                        );
                        return Err(self.overloaded(reason).await);
                    }
                }

                Ok(None)
            }

            Frame::Priority { .. } => {
                self.idle().await?;
                Ok(None)
            }

            Frame::PushPromise { .. } => Err(Error::Protocol("PUSH_PROMISE arrived with push disabled".into())),

            Frame::Headers { stream_id, end_stream, end_headers, block } => {
                self.begin_stream(stream_id)?;

                if end_headers {
                    return self.finish_headers(stream_id, &block, end_stream);
                }

                let gathered = &mut self.open_stream(stream_id)?.block;
                gathered.clear();
                gathered.extend_from_slice(&block);

                self.continue_headers(stream_id, end_stream).await
            }

            Frame::Continuation { .. } => {
                Err(Error::Protocol("CONTINUATION arrived outside a header block".into()))
            }

            Frame::Data { stream_id, end_stream, data } => {
                match self.streams.get(&stream_id) {
                    None => return Err(Error::Protocol(format!("DATA on unopened stream {}", stream_id.0))),
                    Some(stream) if !stream.state.receivable() => {
                        return Err(Error::Protocol(format!("DATA on closed stream {}", stream_id.0)));
                    }
                    Some(_) => {}
                }

                if data.is_empty() && !end_stream {
                    self.idle().await?;
                } else {
                    self.idle_frames = 0;
                }

                // The connection window is spent by every DATA frame that
                // arrives, whatever becomes of the stream carrying it. It is
                // accounted for and given back here rather than after the
                // stream checks below, since a frame that costs one stream its
                // life still cost the peer connection credit, and never
                // returning that credit would shrink the connection window for
                // good and stall every other stream on it.
                self.window_local -= data.len() as i64;
                if self.window_local < 0 {
                    return Err(Error::Protocol("connection receive window overflowed".into()));
                }

                if !data.is_empty() {
                    let increment = data.len() as u32;
                    self.queue(&Frame::WindowUpdate { stream_id: StreamID(0), increment });
                    self.window_local += increment as i64;
                }

                let stream = self.open_stream(stream_id)?;
                stream.window_local -= data.len() as i64;
                if stream.window_local < 0 {
                    self.reset(stream_id, Code::FLOW_CONTROL_ERROR).await?;
                    return Ok(None);
                }

                stream.body.extend_from_slice(&data);

                let body = stream.body.len() as u64;
                let received = stream.received();

                self.buffered_bound = self.buffered_bound.saturating_add(data.len() as u64);

                let limit = self.limits.max_message_body_size;
                if body > limit {
                    return Err(Error::Limit(format!("body exceeds {limit} octets")));
                }

                let limit = self.limits.max_message_size;
                if received > limit {
                    return Err(Error::Limit(format!("message exceeds {limit} octets")));
                }

                if self.overbuffered() {
                    let limit = self.limits.max_connection_buffer_size;
                    return Err(Error::Limit(format!("buffered messages exceed {limit} octets")));
                }

                if !data.is_empty() && self.streams.get(&stream_id).is_some_and(|stream| stream.state.receivable()) {
                    let increment = data.len() as u32;
                    self.queue(&Frame::WindowUpdate { stream_id, increment });

                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.window_local += increment as i64;
                    }
                }

                if end_stream {
                    return Ok(self.complete(stream_id, true));
                }

                Ok(None)
            }
        }
    }

    /// Reads CONTINUATION frames until the field section is complete.
    ///
    /// Nothing else may arrive in between, so this reads the connection
    /// directly rather than going back through the frame loop.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when the block goes past
    /// [`Limits::max_headers_size`] or spans more than
    /// [`Limits::max_header_count`] frames — a CONTINUATION flood otherwise
    /// costs unbounded memory — [`Error::Protocol`] when any other frame
    /// interrupts the block, and otherwise as [`H2Connection::read_frame`] and
    /// [`H2Connection::finish_headers`].
    pub async fn continue_headers(&mut self, stream_id: StreamID, end_stream: bool) -> Result<Option<Message>, Error> {
        let mut frames = 0u64;

        loop {
            let size = self.streams.get(&stream_id).map(|stream| stream.block.len()).unwrap_or_default() as u64;
            if size > self.limits.max_headers_size {
                return Err(Error::Limit(format!("field block exceeds {} octets", self.limits.max_headers_size)));
            }

            frames += 1;
            if frames > self.limits.max_header_count as u64 {
                return Err(Error::Limit(format!("field block spans more than {} CONTINUATION frames", self.limits.max_header_count)));
            }

            match self.read_frame_kept().await?.map_err(|kind| Error::Protocol(format!("a frame of type {kind:#x} interrupted a field block")))? {
                Frame::Continuation { stream_id: other, end_headers, block } if other == stream_id => {
                    self.open_stream(stream_id)?.block.extend_from_slice(&block);

                    if end_headers {
                        let gathered = std::mem::take(&mut self.open_stream(stream_id)?.block);
                        let finished = self.finish_headers(stream_id, &gathered, end_stream);

                        if let Ok(stream) = self.open_stream(stream_id) {
                            stream.block = gathered;
                            stream.block.clear();
                        }

                        return finished;
                    }
                }

                _ => return Err(Error::Protocol("a field block was interrupted".into())),
            }
        }
    }

    /// Opens the stream a HEADERS frame names, if the peer may open it.
    ///
    /// Clients use odd identifiers and servers even ones, and each must be
    /// higher than the last that end opened; a peer that reuses or goes
    /// backwards is trying to reopen a stream that has been closed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the stream is not the peer's to open,
    /// does not exceed the last it opened, or would go past
    /// [`Settings::max_concurrent_streams`].
    pub fn begin_stream(&mut self, stream_id: StreamID) -> Result<(), Error> {
        let peer_odd = !self.role.is_client();
        if stream_id.0 == 0 || (stream_id.0 % 2 == 1) != peer_odd {
            if !self.streams.contains_key(&stream_id) {
                return Err(Error::Protocol(format!("stream {} is not the peer's to open", stream_id.0)));
            }
            return Ok(());
        }

        if !self.streams.contains_key(&stream_id) {
            if stream_id.0 <= self.highest_peer_stream_id {
                return Err(Error::Protocol(format!("stream {} does not exceed the last stream the peer opened", stream_id.0)));
            }
            self.highest_peer_stream_id = stream_id.0;

            if let Some(max) = self.settings_local.max_concurrent_streams
                && self.streams.len() as u32 >= max
            {
                return Err(Error::Protocol(format!("stream {} exceeds the concurrent stream limit", stream_id.0)));
            }

            let window_local = self.settings_local.initial_window_size as i64;
            let window_remote = self.settings_remote.initial_window_size as i64;
            self.streams.insert(stream_id, H2Stream::new(stream_id, window_local, window_remote, self.resets.clone()));
        }

        Ok(())
    }

    /// Decodes a complete field section and folds it into the stream's message.
    ///
    /// `block` is the whole compressed section, which is passed in rather than
    /// read off the stream so that a section arriving in one HEADERS frame can
    /// be decoded where it already sits in the read buffer; only one gathered
    /// across CONTINUATION frames comes from [`H2Stream`]'s own buffer.
    ///
    /// The first section on a stream becomes the message; a second becomes its
    /// trailers. Informational responses are handed back as they are, since
    /// the real response follows on the same stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] past [`Limits::max_message_size`] or
    /// [`Limits::max_header_count`], [`Error::Protocol`] when a trailer
    /// section carries a pseudo-header, and otherwise as the HPACK decoder and
    /// [`common::Fields::into_message`].
    pub fn finish_headers(&mut self, stream_id: StreamID, block: &[u8], end_stream: bool) -> Result<Option<Message>, Error> {
        self.idle_frames = 0;

        let received = {
            let stream = self.open_stream(stream_id)?;
            stream.head += block.len() as u64;
            stream.received()
        };

        let limit = self.limits.max_message_size;
        if received > limit {
            return Err(Error::Limit(format!("message exceeds {limit} octets")));
        }

        let decoded = self.hpack_decoder.decode(block)?;

        if decoded.len() > self.limits.max_header_count as usize {
            return Err(Error::Limit(format!("more than {} header fields", self.limits.max_header_count)));
        }

        let connection_id = self.id.clone();
        let client = self.client;
        let security = self.security;

        // A second field section on a stream is its trailer section, and is
        // held to different rules, so which it is has to be settled before the
        // fields are read at all.
        if self.open_stream(stream_id)?.headers.is_some() {
            let trailers = common::Fields::into_trailers(decoded)?;

            if let Some(message) = &mut self.open_stream(stream_id)?.headers {
                message.trailers = Some(trailers);
            }
        } else {
            let mut message = common::Fields::into_message(decoded, Version::V2_0)?;
            let stream = self.open_stream(stream_id)?;
            message.stream_id = Some(stream_id);
            message.connection_id = Some(connection_id);
            message.client = client;
            security.apply(&mut message);

            if message.is_request() {
                stream.method = message.method;
                stream.accepted = message.accepted();
            }

            if message.is_informational() {
                stream.state = if stream.state == StreamState::Idle { StreamState::Open } else { stream.state };
                return Ok(Some(message));
            }

            stream.headers = Some(message);
        }

        let stream = self.open_stream(stream_id)?;
        stream.state = if stream.state == StreamState::Idle { StreamState::Open } else { stream.state };

        let tunneling = stream.headers.as_ref().is_some_and(|message| message.tunneling(stream.method));

        if end_stream || tunneling {
            return Ok(self.complete(stream_id, end_stream));
        }

        Ok(None)
    }

    /// Takes the finished message off a stream, attaching whatever body arrived.
    ///
    /// `None` when the stream is gone or has no message waiting.
    pub fn complete(&mut self, stream_id: StreamID, end_stream: bool) -> Option<Message> {
        let stream = self.streams.get_mut(&stream_id)?;
        if end_stream {
            stream.state = stream.state.close_remote();
        }

        let mut message = stream.headers.take()?;
        if !stream.body.is_empty() {
            message.body = Some(Body::Data(std::mem::take(&mut stream.body).freeze()));
        }

        self.retire(stream_id);
        Some(message)
    }

    /// Takes whatever body octets have arrived on a stream, without waiting for
    /// the message to finish.
    ///
    /// This is what a tunnel reads through, where the octets are a byte stream
    /// rather than a message.
    pub fn drain(&mut self, stream_id: StreamID) -> Option<Bytes> {
        let stream = self.streams.get_mut(&stream_id)?;
        (!stream.body.is_empty()).then(|| std::mem::take(&mut stream.body).freeze())
    }

    /// Queues a RST_STREAM for every stream that [`Stream::reset`] marked.
    ///
    /// [`Stream::reset`] cannot write, so it records the intent and
    /// this sends it the next time the connection is driven.
    ///
    /// # Errors
    ///
    /// Currently infallible; the signature leaves room for a reset that has to
    /// flush.
    pub async fn flush_resets(&mut self) -> Result<(), Error> {
        // Asked once per frame, where walking every stream of a connection
        // carrying many would cost a pass over all of them per frame. The flag
        // is set by the only thing that can record the intent, so a connection
        // no caller has reset never walks anything.
        if !self.resets.swap(false, Ordering::Relaxed) {
            return Ok(());
        }

        let pending: Vec<(StreamID, u64)> = self
            .streams
            .iter_mut()
            .filter_map(|(id, stream)| stream.pending_reset.take().map(|code| (*id, code)))
            .collect();

        for (stream_id, code) in pending {
            self.queue(&Frame::RstStream { stream_id, error_code: code as u32 });
            self.streams.remove(&stream_id);
        }

        Ok(())
    }

    /// Queues a field section, split across CONTINUATION frames if it is large.
    ///
    /// Field sections are not flow controlled, so this never blocks.
    ///
    /// # Errors
    ///
    /// Currently infallible; the signature matches
    /// [`H2Connection::write_data`], which is not.
    pub async fn write_block(&mut self, stream_id: StreamID, block: &[u8], end_stream: bool) -> Result<(), Error> {
        let size = self.settings_remote.max_frame_size as usize;
        let mut chunks = block.chunks(size.max(1));

        let first = chunks.next().unwrap_or_default();
        let mut rest = chunks.peekable();

        let end_headers = if rest.peek().is_none() { Flag::END_HEADERS } else { 0 };
        let flags = end_headers | if end_stream { Flag::END_STREAM } else { 0 };
        FrameHeader::write(&mut self.out, FrameType::Headers, flags, stream_id, first);

        while let Some(chunk) = rest.next() {
            let flags = if rest.peek().is_none() { Flag::END_HEADERS } else { 0 };
            FrameHeader::write(&mut self.out, FrameType::Continuation, flags, stream_id, chunk);
        }

        Ok(())
    }

    /// Sends body octets, respecting flow control.
    ///
    /// Bounded by whichever of the connection and stream windows is smaller,
    /// and by the peer's maximum frame size. When credit runs out this pumps
    /// the connection rather than parking, since it is the peer's
    /// WINDOW_UPDATE that will unblock it; any message that completes while
    /// waiting is held for the next [`H2Connection::receive_message`].
    ///
    /// # Errors
    ///
    /// As [`H2Connection::pump`] and [`H2Connection::flush_out`].
    pub async fn write_data(&mut self, stream_id: StreamID, data: &[u8], end_stream: bool) -> Result<(), Error> {
        let mut rest = data;

        loop {
            // A stream that has gone will never be given credit again, so
            // waiting on it would hold the task until the send deadline for
            // nothing. The peer reset it; say so and let the caller move on.
            let Some(stream_window) = self.streams.get(&stream_id).map(|stream| stream.window_remote) else {
                let reason = format!("stream {} is no longer open", stream_id.0);
                return Err(Error::stream(stream_id, Code::STREAM_CLOSED as u64, reason));
            };

            let window = self.window_remote.min(stream_window);

            if window <= 0 && !rest.is_empty() {
                if let Some(message) = self.pump().await? {
                    self.ready.push_back(message);
                }
                continue;
            }

            let size = rest.len().min(window.max(0) as usize).min(self.settings_remote.max_frame_size as usize);
            let (chunk, remaining) = rest.split_at(size);
            rest = remaining;

            let flags = if end_stream && rest.is_empty() { Flag::END_STREAM } else { 0 };
            FrameHeader::write(&mut self.out, FrameType::Data, flags, stream_id, chunk);

            if self.out.len() >= self.limits.output_high_water as usize {
                self.flush_out().await?;
            }

            self.window_remote -= size as i64;
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.window_remote -= size as i64;
            }

            if rest.is_empty() {
                return Ok(());
            }
        }
    }
}

impl<T> H2Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Turns the connection into a byte stream over one of its streams.
    ///
    /// The connection is given over to a task that does nothing but relay
    /// octets, which is what a `CONNECT` tunnel — and so WebSocket over
    /// HTTP/2 — needs. Every other stream on the connection is given up.
    pub fn tunnel(self, stream_id: StreamID) -> H2Tunnel {
        let (application, internal) = tokio::io::duplex(self.limits.read_chunk_size as usize);
        let driver = tokio::spawn(async move { self.drive(stream_id, internal).await });

        H2Tunnel { stream: application, driver }
    }

    /// Relays octets between one stream and an in-memory duplex, until either
    /// end finishes.
    ///
    /// # Errors
    ///
    /// Any [`Error`] the connection raises while relaying.
    pub async fn drive(mut self, stream_id: StreamID, internal: tokio::io::DuplexStream) -> Result<(), Error> {
        let (mut reader, mut writer) = tokio::io::split(internal);
        let mut scratch = vec![0u8; self.limits.read_chunk_size as usize];

        self.start().await?;

        loop {
            self.flush_out().await?;

            tokio::select! {
                biased;

                frame = self.read_frame() => {
                    let frame = frame?;
                    self.handle(frame).await?;

                    if let Some(data) = self.drain(stream_id) {
                        writer.write_all(&data).await?;
                    }

                    if self.streams.get(&stream_id).is_none_or(|stream| !stream.state.receivable()) {
                        writer.shutdown().await?;
                        return Ok(());
                    }
                }

                read = reader.read(&mut scratch) => {
                    match read? {
                        0 => {
                            self.write_data(stream_id, &[], true).await?;
                            return Ok(());
                        }
                        read => self.write_data(stream_id, &scratch[..read], false).await?,
                    }
                }
            }
        }
    }
}

/// One HTTP/2 stream as a plain byte stream.
///
/// Reads and writes as any transport does, so a protocol that expects one —
/// WebSocket, say — can run over it unchanged. A background task relays octets
/// between this and the connection.
pub struct H2Tunnel {
    stream: tokio::io::DuplexStream,
    driver: tokio::task::JoinHandle<Result<(), Error>>,
}

impl H2Tunnel {
    /// Stops the relay task without waiting for either end to finish.
    pub fn abort(&self) {
        self.driver.abort();
    }

    /// Whether the relay task has stopped, for any reason.
    pub fn finished(&self) -> bool {
        self.driver.is_finished()
    }
}

impl AsyncRead for H2Tunnel {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for H2Tunnel {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(context, data)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl<T> Connection for H2Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn version(&self) -> Version {
        Version::V2_0
    }

    fn role(&self) -> Role {
        self.role
    }

    fn id(&self) -> ConnectionID {
        self.id.clone()
    }

    fn security(&self) -> Security {
        self.security
    }

    fn client(&self) -> Option<std::net::SocketAddr> {
        self.client
    }

    async fn send(&mut self, message: Message) -> Result<(), Error> {
        let timeout = self.limits.send_timeout;
        let sending = std::pin::pin!(self.send_message(message));
        sync::Timeout::within(timeout, sending).await?
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        let timeout = self.limits.receive_timeout;
        let receiving = std::pin::pin!(self.receive_message());
        sync::Timeout::within(timeout, receiving).await?
    }

    async fn close(&mut self) {
        let last_stream_id = StreamID(self.next_stream_id.saturating_sub(2));
        let goaway = Frame::GoAway { last_stream_id, error_code: Code::NO_ERROR, debug_data: Vec::new() };

        let _ = self.write(&goaway).await;
        let _ = self.transport.shutdown().await;
    }
}
