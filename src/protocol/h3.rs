//! HTTP/3 over QUIC.
//!
//! QUIC provides the streams, so HTTP/3 keeps no framing layer of its own for
//! multiplexing or flow control. What remains is a frame format inside each
//! stream, a control stream carrying settings, and [`qpack`] for field
//! compression — split across its own pair of unidirectional streams, since
//! QUIC may deliver streams out of order.
//!
//! That reordering is what shapes this module. A field block can arrive before
//! the QPACK insertions it depends on, so a stream can sit *blocked* until the
//! encoder stream catches up, bounded by [`Limits::qpack_block_timeout`].
//!
//! The design differs from HTTP/1 and HTTP/2 in one respect: the QUIC driver
//! drives the connection through [`QUICApplication`] callbacks rather than
//! letting this crate own the read loop. So the work is split in two —
//! [`H3Worker`] runs inside those callbacks, and [`H3Connection`] is the
//! handle a caller holds, talking to the worker over channels. Everything that
//! does not need the QUIC connection lives in [`H3Session`], which both share
//! and which is where the protocol itself is implemented.
//!
//! [`qpack`]: crate::helpers::qpack

use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};

/// The ceilings an [`H3Connection`] holds itself to.
///
/// RFC 9114 framing and RFC 9204 QPACK, and nothing else. No HPACK table size
/// and no HTTP/1.x line ceiling appears here.
///
/// [`Limits`] converts into one, so a caller configuring everything at once
/// still passes the one struct and each connection takes its own share.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct H3Limits {
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
    /// The number of requests one connection may serve over its lifetime (0 serves forever).
    pub max_requests_per_connection: u64,
    /// In bytes, the largest QPACK encoder table this end will keep.
    pub max_encoder_table_size: u64,
    /// In seconds, how long to wait for a blocking QPACK reference to resolve.
    pub qpack_block_timeout: f64,
    /// The number of unidirectional streams a peer may open at once.
    pub max_peer_uni_streams: u32,
    /// The unacknowledged QPACK field sections the encoder may track.
    pub max_outstanding_sections: u32,
    /// The number of streams that may wait QPACK-blocked at once.
    pub max_blocked_streams: u32,
    /// The reads or writes a tunnel holds before it applies back pressure.
    pub tunnel_backlog: u32,
    /// The commands or events queued between a handle and its worker.
    pub command_backlog: u32,
    /// In bytes, the buffer size above which an idle connection gives memory back.
    pub idle_capacity: u64,
    /// In seconds, how long one whole message may take to arrive (0 waits forever).
    pub receive_timeout: f64,
    /// In seconds, how long one whole message may take to send (0 waits forever).
    pub send_timeout: f64,
}

impl Default for H3Limits {
    fn default() -> Self {
        Limits::default().into()
    }
}

impl From<Limits> for H3Limits {
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
            max_requests_per_connection: limits.max_requests_per_connection,
            max_encoder_table_size: limits.max_encoder_table_size,
            qpack_block_timeout: limits.qpack_block_timeout,
            max_peer_uni_streams: limits.max_peer_uni_streams,
            max_outstanding_sections: limits.max_outstanding_sections,
            max_blocked_streams: limits.max_blocked_streams,
            tunnel_backlog: limits.tunnel_backlog,
            command_backlog: limits.command_backlog,
            idle_capacity: limits.idle_capacity,
            receive_timeout: limits.receive_timeout,
            send_timeout: limits.send_timeout,
        }
    }
}

pub mod frames;

pub use frames::{Code, Frame, FrameType, Settings, StreamKind};

use crate::helpers::compression::Compression;
use crate::helpers::fields::HeaderField;
use crate::helpers::qpack::{self, Decoder, Encoder, EncoderInstruction};
use crate::models::{Body, ConnectionID, Limits, Message, Method, Role, StreamID, Version};
use crate::tls::Security;
use crate::protocol::base::{Connection, Stream};
use crate::protocol::common::{self, Error};
use crate::protocol::quic::{Handshake, QUICApplication, QUICConnection, QUICError, QUICGuard, QUICHandshake, QUICOutcome, QUICTransport, QUICStreamID, StreamRead, StreamWrite, Varint};
use crate::helpers::sync::{Lock, Timeout};

/// What is known about one request stream.
#[derive(Default)]
pub struct StreamState {
    /// Octets received but not yet parsed into frames.
    pub buffer: BytesMut,
    /// Body octets gathered so far.
    pub body: BytesMut,
    /// The message being assembled, once its field section has decoded.
    pub message: Option<Message>,
    /// The request method, kept so a tunnel can be recognised.
    pub method: Option<Method>,
    /// The best coding the request said it would take, kept so the response
    /// can be coded in something the peer reads.
    pub accepted: Option<Compression>,
    /// A field block waiting on QPACK insertions that have not arrived.
    pub pending: Option<Bytes>,
    /// Whether the peer has finished sending on this stream.
    pub eof: bool,
    /// Whether the message has been handed to the caller.
    pub delivered: bool,
    /// Whether this end has finished sending on this stream.
    pub finished: bool,
    /// Whether the stream has become a tunnel, and so carries octets rather
    /// than frames.
    pub raw: bool,
    /// Whether a response has been sent, which distinguishes a reset that
    /// wasted work from one that did not.
    pub responded: bool,
}

impl StreamState {
    /// Whether the stream is finished with and its state can be dropped.
    ///
    /// A tunnel is never spent while it is still relaying.
    pub fn spent(&self) -> bool {
        self.finished && self.eof && self.delivered && !self.raw
    }
}

/// The HTTP/3 protocol state, apart from the QUIC connection.
///
/// This is where the protocol itself lives: framing, QPACK, settings, and the
/// per-stream state. It holds no QUIC handle, so it can be driven from inside
/// the [`QUICApplication`] callbacks where the connection is only borrowed.
/// Octets go in through the `on_*_bytes` methods and come back out through the
/// `take_*` ones, leaving the caller to do the actual sending.
pub struct H3Session {
    /// Which end of the connection this is.
    pub role: Role,
    /// The connection's identifier.
    pub id: ConnectionID,
    /// The address the peer connected from, stamped on every request received.
    pub client: Option<std::net::SocketAddr>,
    /// The limits this connection holds itself to.
    pub limits: H3Limits,

    /// The settings this end advertised.
    pub settings_local: Settings,
    /// The settings the peer advertised, once its SETTINGS has arrived.
    pub settings_remote: Option<Settings>,

    /// The QPACK encoder for outgoing field sections.
    pub encoder: Encoder,
    /// The QPACK decoder for incoming ones.
    pub decoder: Decoder,

    /// State for each request stream.
    pub streams: common::StreamMap<StreamID, StreamState>,
    /// When each blocked stream became blocked, for the timeout.
    ///
    /// Which streams are blocked, and on what, is the decoder's own
    /// bookkeeping; the wall clock is a connection concern, so it is kept
    /// here.
    pub blocked_since: common::StreamMap<StreamID, std::time::Instant>,
    /// Messages that have completed and are waiting to be handed over.
    pub ready: VecDeque<Message>,

    /// An upper bound on [`H3Session::buffered`]; see [`H3Session::overbuffered`].
    pub buffered_bound: u64,

    /// Partial octets received on the peer's control stream.
    pub control_recv: BytesMut,

    /// The next bidirectional stream this end will open.
    pub next_stream_id: u64,
    /// The highest request stream the peer has opened so far.
    pub highest_peer_stream_id: u64,
    /// How many request streams the peer has opened over the connection's
    /// lifetime, checked against [`Limits::max_requests_per_connection`].
    pub total_streams: u64,

    /// The identifier from the GOAWAY the peer sent, once one has arrived.
    ///
    /// The peer will take no request above it, so once the streams drain the
    /// connection is done; the worker closes it and the handle reports
    /// [`Error::Closed`], exactly as HTTP/2 does when its GOAWAY drains.
    pub goaway: Option<u64>,
    /// The identifier from the GOAWAY this end sent, once one has.
    ///
    /// Requests at or above it are refused with `REQUEST_REJECTED`, which
    /// tells the peer they were not processed and may be retried elsewhere.
    pub goaway_sent: Option<u64>,

    /// The field list an outgoing message is framed from, kept between
    /// messages so that framing one costs no list of its own.
    pub fields: Vec<HeaderField>,
    /// The field block an outgoing section is encoded into, kept for the same
    /// reason and given back through [`common::Buffer::reclaim_octets`].
    pub block: Vec<u8>,

    /// What the transport underneath turned out to be, stamped on every
    /// message this session hands over.
    ///
    /// Shared with the [`H3Connection`] this session was paired with: QUIC only
    /// reports what it settled once the handshake completes, which happens in
    /// the worker, long after the handle has been handed to the caller. One
    /// cell means [`Connection::security`] and [`Message::security`] cannot
    /// disagree.
    pub security: std::sync::Arc<std::sync::Mutex<Security>>,
}

impl H3Session {
    /// A session with nothing exchanged yet.
    pub fn new(role: Role, id: ConnectionID, limits: impl Into<H3Limits>) -> Self {
        let limits: H3Limits = limits.into();
        let settings_local = Settings { qpack_blocked_streams: limits.max_blocked_streams as u64, ..Settings::default() };

        let mut decoder = Decoder::new();
        decoder.set_max_capacity(settings_local.qpack_max_table_capacity as usize);
        decoder.set_max_decoded_size(limits.max_headers_size as usize);
        decoder.set_max_instruction_size(limits.max_headers_size as usize);
        decoder.set_max_blocked_streams(limits.max_blocked_streams as usize);
        decoder.set_idle_capacity(limits.idle_capacity as usize);

        let mut encoder = Encoder::new();
        encoder.set_max_outstanding_sections(limits.max_outstanding_sections as usize);
        encoder.set_max_instruction_size(limits.max_headers_size as usize);
        encoder.set_idle_capacity(limits.idle_capacity as usize);

        if let Some(instruction) = encoder.set_capacity_limit(limits.max_encoder_table_size as usize) {
            encoder.queue(&[instruction]);
        }

        let next_stream_id = QUICStreamID::first_bidi(role);

        Self {
            role,
            id,
            client: None,
            limits,
            settings_local,
            settings_remote: None,
            encoder,
            decoder,
            streams: common::StreamMap::default(),
            blocked_since: common::StreamMap::default(),
            ready: VecDeque::new(),
            buffered_bound: 0,
            control_recv: BytesMut::new(),
            next_stream_id,
            highest_peer_stream_id: 0,
            total_streams: 0,
            goaway: None,
            goaway_sent: None,
            fields: Vec::new(),
            block: Vec::new(),
            security: std::sync::Arc::new(std::sync::Mutex::new(Security::quic(None))),
        }
    }

    /// Attaches the address the peer connected from.
    ///
    /// QUIC knows it before the handshake runs, unlike [`H3Session::security`],
    /// so it needs no shared cell: the paired [`H3Connection`] takes a copy.
    pub fn with_client(mut self, client: Option<std::net::SocketAddr>) -> Self {
        self.client = client;
        self
    }

    /// The SETTINGS frame that must lead this end's control stream.
    pub fn control_frame(&self) -> Bytes {
        let mut out = BytesMut::new();
        Frame::Settings(self.settings_local.parameters()).encode_into(&mut out);
        out.freeze()
    }

    /// Allocates the next bidirectional stream this end may open.
    ///
    /// Clients get 0, 4, 8, ... and servers 1, 5, 9, ..., which is how QUIC
    /// keeps the two ends from colliding.
    pub fn open(&mut self) -> StreamID {
        let stream_id = StreamID(self.next_stream_id);
        self.next_stream_id += QUICStreamID::STEP;
        self.streams.entry(stream_id).or_default();
        stream_id
    }

    /// How many request streams may be held at once.
    ///
    /// Twice [`Limits::max_concurrent_streams`], because a stream lingers
    /// after it completes until both directions have finished, so the two
    /// generations overlap.
    pub fn stream_ceiling(&self) -> usize {
        (self.limits.max_concurrent_streams as usize).saturating_mul(2).max(2)
    }

    /// Drops all state for a stream, and stops waiting on its QPACK
    /// acknowledgement.
    pub fn forget(&mut self, stream_id: StreamID) -> Option<StreamState> {
        self.blocked_since.remove(&stream_id);
        self.encoder.cancel(stream_id.0);
        self.decoder.cancel(stream_id.0);
        self.streams.remove(&stream_id)
    }

    /// Drops a stream's state if it is spent; see [`StreamState::spent`].
    pub fn retire(&mut self, stream_id: StreamID) {
        if self.streams.get(&stream_id).is_some_and(StreamState::spent) {
            self.forget(stream_id);
        }
    }

    /// Frames a message, returning the octets and whether the stream ends with them.
    ///
    /// # Errors
    ///
    /// As [`H3Session::frame_message`].
    pub fn encode_message(&mut self, stream_id: StreamID, message: &mut Message) -> Result<(Bytes, bool), Error> {
        let mut out = BytesMut::new();
        let fin = self.encode_message_into(stream_id, message, &mut out)?;
        Ok((out.freeze(), fin))
    }

    /// [`H3Session::encode_message`], appending to a buffer the caller owns.
    ///
    /// The buffer is rolled back to where it started if framing fails, so a
    /// failed message never leaves half a frame on the stream.
    ///
    /// # Errors
    ///
    /// As [`H3Session::frame_message`].
    pub fn encode_message_into(&mut self, stream_id: StreamID, message: &mut Message, out: &mut BytesMut) -> Result<bool, Error> {
        let start = out.len();

        match self.frame_message(stream_id, message, out) {
            Ok(fin) => Ok(fin),
            Err(error) => {
                out.truncate(start);
                Err(error)
            }
        }
    }

    /// Encodes a field section and appends it as a frame of `kind`.
    ///
    /// The list and the block are the session's own and are refilled rather
    /// than made afresh, so `gather` says what goes in them and nothing else
    /// has to know they are reused. The block shrinks again once an outsized
    /// section has gone out.
    ///
    /// # Errors
    ///
    /// Whatever `gather` returns.
    pub fn write_block(
        &mut self,
        stream_id: StreamID,
        kind: FrameType,
        out: &mut BytesMut,
        gather: impl FnOnce(&mut Vec<HeaderField>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.fields.clear();
        gather(&mut self.fields)?;

        self.block.clear();
        self.encoder.encode_into(&mut self.block, stream_id.0, &self.fields);
        Frame::write(kind, &self.block, out);

        let idle = self.limits.idle_capacity as usize;
        common::Buffer::reclaim_octets(&mut self.block, idle);

        Ok(())
    }

    /// Frames a message into HEADERS, DATA and trailing HEADERS.
    ///
    /// Any QPACK instructions the field sections need are queued for the
    /// encoder stream. Returns whether the stream ends here, which it does
    /// unless the message opens a tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the body is a [`Body::File`], which
    /// must be read before it reaches here, and otherwise as
    /// [`Message::compress`] and [`common::Fields::of`].
    pub fn frame_message(&mut self, stream_id: StreamID, message: &mut Message, out: &mut BytesMut) -> Result<bool, Error> {
        let accepted = message.is_response().then(|| self.streams.get(&stream_id)?.accepted).flatten();
        message.compress(accepted)?;

        // A message that ends at its field section carries neither DATA nor a
        // trailer section, whatever the caller attached: RFC 9112 §6.3 for the
        // `HEAD` case, and the status itself for the rest.
        let framed = !message.bodyless(self.streams.get(&stream_id).and_then(|state| state.method));

        let message = &*message;
        self.write_block(stream_id, FrameType::Headers, out, |fields| common::Fields::write(message, fields))?;

        if let Some(body) = message.body.as_ref().filter(|_| framed) {
            let body = body
                .inline()
                .ok_or_else(|| Error::Protocol("a file body must be materialised before HTTP/3 encoding".into()))?;
            if !body.is_empty() {
                Frame::Data(body).encode_into(out);
            }
        }

        if let Some(trailers) = message.trailers.as_ref().filter(|trailers| framed && !trailers.is_empty()) {
            self.write_block(stream_id, FrameType::Headers, out, |fields| {
                fields.extend_from_slice(trailers.fields());
                Ok(())
            })?;
        }

        let state = self.streams.entry(stream_id).or_default();
        if message.is_request() {
            state.method = message.method;
        }

        let tunneling = message.tunneling(state.method);
        state.finished |= !tunneling;

        Ok(!tunneling)
    }

    /// Takes in octets from the peer's QPACK encoder stream.
    ///
    /// The decoder buffers and applies the instructions itself; what is done
    /// here is the connection's part — advancing any stream that was blocked
    /// on the insertions that just arrived.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when a single instruction grows past
    /// [`Limits::max_headers_size`], and otherwise as
    /// [`qpack::Decoder::on_encoder_stream`] and [`H3Session::advance`].
    pub fn on_encoder_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.decoder.on_encoder_stream(bytes).map_err(|err| match err {
            qpack::Error::InstructionTooLarge => {
                Error::Limit(format!("an encoder instruction exceeds {} octets", self.limits.max_headers_size))
            }
            err => err.into(),
        })?;

        if self.blocked_since.is_empty() {
            return Ok(());
        }

        for stream_id in self.decoder.unblocked() {
            self.advance(StreamID(stream_id))?;
        }

        Ok(())
    }

    /// Takes in octets from the peer's QPACK decoder stream.
    ///
    /// Acknowledgements here are what free the encoder to reference more of
    /// its table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when a single instruction grows past
    /// [`Limits::max_headers_size`], and [`Error::Protocol`] when one will not
    /// decode.
    pub fn on_decoder_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.encoder.on_decoder_stream(bytes).map_err(|err| match err {
            qpack::Error::InstructionTooLarge => {
                Error::Limit(format!("a decoder instruction exceeds {} octets", self.limits.max_headers_size))
            }
            err => err.into(),
        })
    }

    /// Takes in octets from the peer's control stream.
    ///
    /// GOAWAY is recorded on [`H3Session::goaway`], so the worker can close
    /// the connection once the remaining streams drain. MAX_PUSH_ID and
    /// CANCEL_PUSH are accepted and ignored, since push is disabled.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when a frame grows past
    /// [`Limits::max_headers_size`], and [`Error::Protocol`] when a second
    /// SETTINGS arrives or a frame appears that does not belong on the control
    /// stream. Otherwise as [`Frame::parse`] and [`Settings::apply`].
    pub fn on_control_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.control_recv.extend_from_slice(bytes);

        let limit = self.limits.max_headers_size;
        if self.control_recv.len() as u64 > limit {
            return Err(Error::Limit(format!("a control frame exceeds {limit} octets")));
        }

        while let Some(frame) = Frame::parse(&mut self.control_recv)? {
            match frame {
                Frame::Settings(parameters) => {
                    if self.settings_remote.is_some() {
                        return Err(Error::Protocol("a second SETTINGS frame arrived on the control stream".into()));
                    }
                    let mut settings = Settings::peer();
                    for (id, value) in parameters {
                        settings.apply(id, value)?;
                    }
                    self.apply_peer_settings(settings);
                }
                Frame::GoAway { id } => {
                    self.goaway = Some(self.goaway.map_or(id, |earlier| earlier.min(id)));
                }
                Frame::MaxPushID { .. } | Frame::CancelPush { .. } => {}
                _ => return Err(Error::Protocol("an unexpected frame arrived on the control stream".into())),
            }
        }

        Ok(())
    }

    /// Adopts the peer's settings, and sizes the QPACK encoder table to match.
    ///
    /// Until this happens the encoder has no dynamic table at all, so every
    /// field goes out as a literal or a static reference. What the peer permits
    /// is a ceiling and not an instruction: the table settles at the smaller of
    /// it and [`Limits::max_encoder_table_size`], which is this end's own.
    pub fn apply_peer_settings(&mut self, settings: Settings) {
        let permitted = usize::try_from(settings.qpack_max_table_capacity).unwrap_or(usize::MAX);
        if let Some(instruction) = self.encoder.set_max_capacity(permitted) {
            self.encoder.queue(&[instruction]);
        }

        self.settings_remote = Some(settings);
    }

    /// Takes in octets from a request stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Stream`] when the connection is holding more than
    /// [`H3Session::stream_ceiling`] streams or one stream's unparsed data
    /// goes past [`Limits::max_message_size`] — either resets that stream and
    /// leaves the connection running — and [`Error::Limit`] when the
    /// connection as a whole goes past
    /// [`Limits::max_connection_buffer_size`]. Otherwise as
    /// [`H3Session::advance`].
    pub fn on_stream_bytes(&mut self, stream_id: StreamID, bytes: &[u8], fin: bool) -> Result<(), Error> {
        let created = !self.streams.contains_key(&stream_id);

        if created && self.streams.len() >= self.stream_ceiling() {
            let reason = format!("more than {} streams are held open at once", self.stream_ceiling());
            return Err(Error::stream(stream_id, Code::EXCESSIVE_LOAD, reason));
        }

        if created {
            self.total_streams += 1;
            self.highest_peer_stream_id = self.highest_peer_stream_id.max(stream_id.0);
        }

        let state = self.streams.entry(stream_id).or_default();
        state.buffer.extend_from_slice(bytes);
        if fin {
            state.eof = true;
        }
        let unparsed = state.buffer.len() as u64;

        self.buffered_bound = self.buffered_bound.saturating_add(bytes.len() as u64);

        let limit = self.limits.max_message_size;
        if unparsed > limit {
            let reason = format!("unparsed stream data exceeds {limit} octets");
            return Err(Error::stream(stream_id, Code::EXCESSIVE_LOAD, reason));
        }

        if self.overbuffered() {
            let limit = self.limits.max_connection_buffer_size;
            return Err(Error::Limit(format!("buffered messages exceed {limit} octets")));
        }

        self.advance(stream_id)
    }

    /// How much unparsed and unread data the connection is holding across all
    /// its streams.
    pub fn buffered(&self) -> u64 {
        self.streams.values().map(|state| (state.buffer.len() + state.body.len()) as u64).sum()
    }

    /// Whether the connection is holding more than
    /// [`Limits::max_connection_buffer_size`] across all of its streams.
    ///
    /// [`H3Session::buffered`] walks every stream, and this is asked on every
    /// read, which would make one pass over the connection's streams cost a
    /// walk per stream. So [`H3Session::buffered_bound`] is kept instead: it
    /// grows with every octet taken in and is never reduced as octets are
    /// parsed away, so it can read high but never low. The exact sum is taken
    /// only once the bound reaches the ceiling, which is at most once per
    /// ceiling's worth of octets rather than once per read.
    pub fn overbuffered(&mut self) -> bool {
        let limit = self.limits.max_connection_buffer_size;

        if self.buffered_bound <= limit {
            return false;
        }

        self.buffered_bound = self.buffered();
        self.buffered_bound > limit
    }

    /// Parses as far as it can on one stream, and delivers the message if it
    /// completes.
    ///
    /// Stops without error when the stream is QPACK-blocked, leaving the block
    /// held in [`StreamState::pending`] to be retried once the encoder stream
    /// catches up. Also stops when the stream turns out to be a tunnel, whose
    /// octets are not frames.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when DATA arrives before HEADERS, a
    /// control frame appears on a request stream, or PUSH_PROMISE arrives with
    /// push disabled, [`Error::Stream`] when the field section or body goes
    /// past its limit or the stream ends with no field section at all, and
    /// otherwise as the QPACK decoder, [`H3Session::absorb_headers`] and
    /// [`Frame::parse`].
    pub fn advance(&mut self, stream_id: StreamID) -> Result<(), Error> {
        loop {
            if self.streams.get(&stream_id).is_some_and(|state| state.raw) {
                return Ok(());
            }

            if let Some(block) = self.streams.get(&stream_id).and_then(|state| state.pending.clone()) {
                match self.decoder.decode(stream_id.0, &block) {
                    Ok((fields, acknowledgment)) => {
                        if let Some(acknowledgment) = acknowledgment {
                            self.decoder.queue(&[acknowledgment]);
                        }
                        let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;
                        state.pending = None;
                        self.blocked_since.remove(&stream_id);
                        self.absorb_headers(stream_id, fields)?;
                        continue;
                    }
                    Err(qpack::Error::Blocked) => return Ok(()),
                    Err(err) => return Err(err.into()),
                }
            }

            let Some(state) = self.streams.get_mut(&stream_id) else {
                return Ok(());
            };

            let Some(frame) = Frame::parse(&mut state.buffer)? else {
                if state.eof {
                    break;
                }
                return Ok(());
            };

            match frame {
                Frame::Headers(block) => {
                    if block.len() as u64 > self.limits.max_headers_size {
                        let reason = format!("field section exceeds {} octets", self.limits.max_headers_size);
                        return Err(Error::stream(stream_id, Code::EXCESSIVE_LOAD, reason));
                    }
                    match self.decoder.decode(stream_id.0, &block) {
                        Ok((fields, acknowledgment)) => {
                            if let Some(acknowledgment) = acknowledgment {
                                self.decoder.queue(&[acknowledgment]);
                            }
                            self.absorb_headers(stream_id, fields)?;
                        }
                        Err(qpack::Error::Blocked) => {
                            let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;
                            state.pending = Some(block);
                            self.blocked_since.entry(stream_id).or_insert_with(std::time::Instant::now);
                            return Ok(());
                        }
                        Err(err) => return Err(err.into()),
                    }
                }

                Frame::Data(data) => {
                    let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;
                    if state.message.is_none() {
                        return Err(Error::Protocol("DATA arrived before HEADERS".into()));
                    }
                    state.body.extend_from_slice(&data);

                    let limit = self.limits.max_message_body_size;
                    if state.body.len() as u64 > limit {
                        return Err(Error::stream(stream_id, Code::EXCESSIVE_LOAD, format!("body exceeds {limit} octets")));
                    }
                }

                Frame::Settings(_) | Frame::GoAway { .. } | Frame::MaxPushID { .. } | Frame::CancelPush { .. } => {
                    return Err(Error::Protocol("a control frame arrived on a request stream".into()));
                }

                Frame::PushPromise { .. } => {
                    return Err(Error::Protocol("PUSH_PROMISE arrived with push disabled".into()));
                }
            }
        }

        let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;
        if state.delivered {
            self.retire(stream_id);
            return Ok(());
        }

        let Some(mut message) = state.message.take() else {
            return Err(Error::stream(stream_id, Code::REQUEST_INCOMPLETE, "request stream carried no field section"));
        };

        if !state.body.is_empty() {
            message.body = Some(Body::Data(std::mem::take(&mut state.body).freeze()));
        }

        state.delivered = true;
        self.ready.push_back(message);

        self.retire(stream_id);
        Ok(())
    }

    /// Folds a decoded field section into the stream's message.
    ///
    /// The first section becomes the message; a second becomes its trailers. A
    /// section that opens a tunnel is delivered at once, and the stream turns
    /// to relaying octets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Stream`] when the section carries more than
    /// [`Limits::max_header_count`] fields, when a trailer section carries a
    /// pseudo-header, and when [`common::Fields::into_message`] rejects the message.
    pub fn absorb_headers(&mut self, stream_id: StreamID, fields: Vec<HeaderField>) -> Result<(), Error> {
        if fields.len() > self.limits.max_header_count as usize {
            let reason = format!("more than {} header fields", self.limits.max_header_count);
            return Err(Error::stream(stream_id, Code::EXCESSIVE_LOAD, reason));
        }

        let id = self.id.clone();
        let client = self.client;
        let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;

        if state.message.is_some() {
            let trailers = common::Fields::into_trailers(fields).map_err(|err| err.on_stream(stream_id, Code::MESSAGE_ERROR))?;
            let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;

            if let Some(message) = state.message.as_mut() {
                message.trailers = Some(trailers);
            }

            return Ok(());
        }

        let mut message = common::Fields::into_message(fields, Version::V3_0).map_err(|err| err.on_stream(stream_id, Code::MESSAGE_ERROR))?;
        message.stream_id = Some(stream_id);
        message.connection_id = Some(id);
        message.client = client;
        Lock::on(&self.security).apply(&mut message);

        if message.is_request() {
            state.method = message.method;
            state.accepted = message.accepted();
        }

        if message.tunneling(state.method) {
            state.delivered = true;
            state.raw = true;
            self.ready.push_back(message);
            return Ok(());
        }

        state.message = Some(message);
        Ok(())
    }

    /// Takes the next completed message, if there is one.
    pub fn take_ready(&mut self) -> Option<Message> {
        self.ready.pop_front()
    }

    /// Takes the QPACK encoder instructions queued for the encoder stream.
    pub fn take_encoder_out(&mut self) -> Bytes {
        Bytes::from(self.encoder.take_encoder_stream())
    }

    /// Takes the QPACK decoder instructions queued for the decoder stream.
    pub fn take_decoder_out(&mut self) -> Bytes {
        Bytes::from(self.decoder.take_decoder_stream())
    }
}

/// What an [`H3Connection`] asks its [`H3Worker`] to do.
///
/// The worker owns the QUIC connection, so everything that needs it goes
/// through here.
///
/// A [`Message`] is much the largest of these. Boxing it would shrink the
/// channel's slots at the cost of an allocation on every message sent, which
/// is the wrong trade on the hottest path the connection has.
#[allow(clippy::large_enum_variant)]
pub enum H3Command {
    /// Frame and send a message.
    Send(Message),
    /// Allocate a bidirectional stream, replying with its identifier.
    Open(tokio::sync::oneshot::Sender<StreamID>),
    /// Open a unidirectional stream of a given kind, replying with its identifier.
    OpenUni(StreamKind, tokio::sync::oneshot::Sender<StreamID>),
    /// Turn a stream into a tunnel, delivering its octets to this sink.
    Tunnel(StreamID, tokio::sync::mpsc::Sender<(Bytes, bool)>),
    /// Write raw octets to the QPACK encoder stream.
    WriteEncoder(Bytes),
    /// Abandon a stream, resetting it towards the peer with an error code.
    Reset(StreamID, u64),
    /// Close the QUIC connection.
    Close,
}

impl H3Command {
    /// Whether carrying this command out adds to what is waiting to be sent.
    ///
    /// A worker runs inside QUIC callbacks and cannot await the credit to send
    /// with, the way [`H2Connection::write_data`] does, so what it frames has
    /// to wait in [`H3Worker::outbound`] until the peer grants some. That is
    /// what [`H3Worker::accepting_writes`] bounds — and it can only bound it by
    /// holding these back, since running them is what makes the buffer grow.
    ///
    /// Everything else is run whatever the buffer holds: a reset and a close
    /// are how a connection whose peer has stopped reading is wound down, and
    /// holding those back would leave it with no way out.
    ///
    /// [`H2Connection::write_data`]: crate::protocol::h2::H2Connection::write_data
    pub fn buffers(&self) -> bool {
        matches!(self, Self::Send(_) | Self::WriteEncoder(_))
    }
}

/// What an [`H3Worker`] reports back to its [`H3Connection`].
///
/// A [`Message`] dwarfs an [`Error`] here, and is left unboxed for the reason
/// [`H3Command`] gives: boxing would cost an allocation per message received.
#[allow(clippy::large_enum_variant)]
pub enum H3Event {
    /// A message has completed.
    Message(Message),
    /// Something failed, on one stream or on the connection.
    Failed(Error),
}

/// An HTTP/3 connection, as the caller holds it.
///
/// The protocol itself runs in an [`H3Worker`] inside the QUIC driver's
/// callbacks, because that is where the QUIC connection is reachable. This is
/// the handle on the other side of the channels, and it implements
/// [`Connection`] like the other two versions, so the split does not show from
/// outside.
pub struct H3Connection {
    /// Commands to the worker.
    pub commands: tokio::sync::mpsc::Sender<H3Command>,
    /// Events from the worker.
    pub events: tokio::sync::mpsc::Receiver<H3Event>,
    /// Raw stream writes, which bypass framing; used by tunnels.
    pub raw: tokio::sync::mpsc::Sender<(StreamID, Bytes, bool)>,
    /// The connection's identifier.
    pub id: ConnectionID,
    /// Which end of the connection this is.
    pub role: Role,
    /// The address the peer connected from, as the paired [`H3Session`] holds it.
    ///
    /// A copy rather than a shared cell, for the reason
    /// [`H3Connection::settings_local`] gives: QUIC settles it before the
    /// worker starts.
    pub client: Option<std::net::SocketAddr>,
    /// The limits this connection holds itself to.
    pub limits: H3Limits,
    /// Keeps the QUIC connection alive for as long as this handle exists.
    pub guard: Option<std::sync::Arc<QUICGuard>>,
    /// The settings this end advertised, as the paired [`H3Session`] holds them.
    ///
    /// A copy rather than a borrow: the session itself lives in the worker,
    /// where the QUIC connection is reachable, so the handle keeps the part of
    /// it that is settled before the worker starts. What the peer advertised
    /// is not settled then, and stays on [`H3Session::settings_remote`].
    pub settings_local: Settings,
    /// The finalisation applied to requests on the way out.
    pub request_finalizer: crate::finalizer::RequestFinalizer,
    /// The finalisation applied to responses on the way out.
    pub response_finalizer: crate::finalizer::ResponseFinalizer,
    /// What the transport underneath turned out to be, as the session sees it.
    ///
    /// The same cell the paired [`H3Session`] holds, so what the handshake
    /// settled shows here as soon as the worker has read it.
    pub security: std::sync::Arc<std::sync::Mutex<Security>>,
}

impl H3Connection {
    /// Builds a connection handle and the worker that backs it.
    ///
    /// The worker has to be handed to the QUIC driver to be driven; until it
    /// is, nothing the handle asks for happens.
    pub fn pair(session: H3Session) -> (Self, H3Worker) {
        let backlog = (session.limits.command_backlog as usize).max(1);
        let (commands, commands_receiver) = tokio::sync::mpsc::channel(backlog);
        let (events_sender, events) = tokio::sync::mpsc::channel(backlog);
        let (raw, raw_receiver) = tokio::sync::mpsc::channel(session.limits.tunnel_backlog as usize);

        let connection = Self {
            commands,
            events,
            raw,
            id: session.id.clone(),
            role: session.role,
            client: session.client,
            limits: session.limits,
            guard: None,
            settings_local: session.settings_local,
            request_finalizer: crate::finalizer::RequestFinalizer::default(),
            response_finalizer: crate::finalizer::ResponseFinalizer::new(None),
            security: std::sync::Arc::clone(&session.security),
        };

        (connection, H3Worker::new(session, commands_receiver, events_sender, raw_receiver))
    }

    /// The ceilings this connection holds itself to.
    pub fn limits(&self) -> H3Limits {
        self.limits
    }

    /// The settings this end advertised.
    pub fn settings_local(&self) -> &Settings {
        &self.settings_local
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
    /// The counterpart of [`H3Connection::with_request_finalizer`], and for the
    /// same reason.
    pub fn with_response_finalizer(mut self, finalizer: crate::finalizer::ResponseFinalizer) -> Self {
        self.response_finalizer = finalizer;
        self
    }

    /// Attaches what the handshake settled.
    ///
    /// QUIC carries its own TLS and reports what it settled through the worker,
    /// so this is only for a caller building a session by hand; a connection
    /// paired with a worker fills it in for itself.
    pub fn with_security(self, security: Security) -> Self {
        *Lock::on(&self.security) = security;
        self
    }

    /// Attaches the handle that keeps the QUIC connection alive.
    pub fn with_guard(mut self, guard: std::sync::Arc<QUICGuard>) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Sends one whole message on a stream.
    ///
    /// A [`Body::File`] is read here, before the message is handed to the
    /// worker, since the worker runs inside callbacks that cannot await.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when a [`Body::File`] cannot be read, and
    /// [`Error::Closed`] when the worker is gone. Failures in framing itself
    /// surface later, through [`H3Connection::receive_message`].
    pub async fn send_message(&mut self, message: Message) -> Result<(), Error> {
        let mut message = message;
        self.request_finalizer.finalize(self.role, &mut message);
        self.response_finalizer.finalize(self.role, Lock::on(&self.security).secure, &mut message);

        message.materialize().await?;

        self.commands.send(H3Command::Send(message)).await.map_err(|_| Error::Closed)
    }

    /// Waits for the next message, or the next failure.
    ///
    /// A returned [`Error::Stream`] concerns one stream only and leaves the
    /// connection usable, so it is worth calling again after one.
    ///
    /// # Errors
    ///
    /// Returns whatever the worker reported, and [`Error::Closed`] once the
    /// worker is gone.
    pub async fn receive_message(&mut self) -> Result<Message, Error> {
        match self.events.recv().await {
            Some(H3Event::Message(mut message)) => {
                message.decompress(self.limits.max_decompressed_body_size)?;
                Ok(message)
            }
            Some(H3Event::Failed(error)) => Err(error),
            None => Err(Error::Closed),
        }
    }

    /// Does nothing.
    ///
    /// HTTP/3 has no preface to exchange — the QUIC handshake has already
    /// happened and the control streams are opened by the worker. Kept so the
    /// three versions can be started the same way.
    ///
    /// # Errors
    ///
    /// Never.
    pub async fn start(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Allocates a bidirectional stream to send a request on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the worker is gone.
    pub async fn open(&mut self) -> Result<StreamID, Error> {
        let (reply, opened) = tokio::sync::oneshot::channel();
        self.commands.send(H3Command::Open(reply)).await.map_err(|_| Error::Closed)?;
        opened.await.map_err(|_| Error::Closed)
    }

    /// Opens a unidirectional stream of the given kind.
    ///
    /// The returned stream is write-only; its read half is wired to a channel
    /// that never delivers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for [`StreamKind::Request`], which is
    /// bidirectional, and [`Error::Closed`] when the worker is gone.
    pub async fn open_uni(&mut self, kind: StreamKind) -> Result<H3Stream, Error> {
        if kind.code().is_none() {
            return Err(Error::Protocol(format!("{kind:?} is not a unidirectional stream type")));
        }

        let (reply, opened) = tokio::sync::oneshot::channel();
        self.commands.send(H3Command::OpenUni(kind, reply)).await.map_err(|_| Error::Closed)?;
        let stream_id = opened.await.map_err(|_| Error::Closed)?;

        let (_, silent) = tokio::sync::mpsc::channel(1);
        Ok(H3Stream::new(stream_id, self.raw.clone(), silent, self.guard.clone()))
    }

    /// Turns one stream into a plain byte stream.
    ///
    /// Octets already buffered on the stream are handed over rather than lost.
    /// Unlike HTTP/2's tunnel this costs only the one stream — the connection
    /// keeps running, and other streams are unaffected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the worker is gone or its command queue
    /// is full.
    pub fn tunnel(&mut self, stream_id: StreamID) -> Result<H3Stream, Error> {
        let (sink, reads) = tokio::sync::mpsc::channel(self.limits.tunnel_backlog as usize);
        self.commands.try_send(H3Command::Tunnel(stream_id, sink)).map_err(|_| Error::Closed)?;
        Ok(H3Stream::new(stream_id, self.raw.clone(), reads, self.guard.clone()).with_commands(self.commands.clone()))
    }

    /// Writes QPACK encoder instructions straight onto the encoder stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the worker is gone.
    pub async fn write_encoder(&mut self, instructions: &[EncoderInstruction]) -> Result<(), Error> {
        let mut bytes = BytesMut::new();
        for instruction in instructions {
            bytes.extend_from_slice(&instruction.encode());
        }

        self.commands.send(H3Command::WriteEncoder(bytes.freeze())).await.map_err(|_| Error::Closed)
    }
}

/// A raw write to one stream: where, what, and whether it ends the stream.
pub type RawWrite = (StreamID, Bytes, bool);

/// A reserved slot in the raw write queue.
pub type RawPermit = tokio::sync::mpsc::OwnedPermit<RawWrite>;
/// A reservation still in progress, held across polls of a write.
pub type Reserving = std::pin::Pin<Box<dyn std::future::Future<Output = Result<RawPermit, tokio::sync::mpsc::error::SendError<()>>> + Send>>;

/// One HTTP/3 stream as a plain byte stream.
///
/// Reads and writes as any transport does, so a protocol that expects one —
/// WebSocket, say — can run over it unchanged. Writes go through a bounded
/// queue, so a peer that will not read eventually applies back pressure rather
/// than growing a buffer without bound.
pub struct H3Stream {
    /// The stream this carries.
    pub id: StreamID,
    /// Where writes are queued for the worker.
    pub writes: tokio::sync::mpsc::Sender<RawWrite>,
    /// Where reads arrive from the worker.
    pub reads: tokio::sync::mpsc::Receiver<(Bytes, bool)>,
    /// A queue reservation in progress, kept so a pending write can resume.
    pub reserving: Option<Reserving>,
    /// Octets received but not yet handed to the reader.
    pub buffer: BytesMut,
    /// Whether the peer has finished sending.
    pub eof: bool,
    /// Keeps the QUIC connection alive for as long as this stream exists.
    pub guard: Option<std::sync::Arc<QUICGuard>>,
    /// Where a reset is sent, when the worker is still reachable.
    pub commands: Option<tokio::sync::mpsc::Sender<H3Command>>,
}

impl H3Stream {
    /// A stream over the given write and read channels.
    pub fn new(id: StreamID, writes: tokio::sync::mpsc::Sender<RawWrite>, reads: tokio::sync::mpsc::Receiver<(Bytes, bool)>, guard: Option<std::sync::Arc<QUICGuard>>) -> Self {
        Self { id, writes, reads, reserving: None, buffer: BytesMut::new(), eof: false, guard, commands: None }
    }

    /// Attaches the channel a reset travels down.
    pub fn with_commands(mut self, commands: tokio::sync::mpsc::Sender<H3Command>) -> Self {
        self.commands = Some(commands);
        self
    }

    /// Reserves a slot in the write queue.
    ///
    /// `Ready(None)` means the worker is gone and the stream is dead. A
    /// reservation that has to wait is stored, so the next poll resumes it
    /// rather than starting over.
    pub fn reserve(&mut self, context: &mut std::task::Context<'_>) -> std::task::Poll<Option<RawPermit>> {
        use std::task::Poll;

        loop {
            if let Some(reserving) = &mut self.reserving {
                let reserved = std::future::Future::poll(reserving.as_mut(), context);

                return match reserved {
                    Poll::Ready(permit) => {
                        self.reserving = None;
                        Poll::Ready(permit.ok())
                    }
                    Poll::Pending => Poll::Pending,
                };
            }

            match self.writes.clone().try_reserve_owned() {
                Ok(permit) => return Poll::Ready(Some(permit)),
                Err(tokio::sync::mpsc::error::TrySendError::Full(sender)) => {
                    self.reserving = Some(Box::pin(sender.reserve_owned()));
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return Poll::Ready(None),
            }
        }
    }

    /// The handle keeping the QUIC connection alive, if there is one.
    pub fn guard(&self) -> Option<&std::sync::Arc<QUICGuard>> {
        self.guard.as_ref()
    }
}

impl Stream for H3Stream {
    fn id(&self) -> StreamID {
        self.id
    }

    async fn reset(&mut self, code: u64) {
        self.eof = true;

        if let Some(commands) = &self.commands {
            let _ = commands.send(H3Command::Reset(self.id, code)).await;
        }
    }
}

impl tokio::io::AsyncRead for H3Stream {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>, out: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if !self.buffer.is_empty() {
                let count = self.buffer.len().min(out.remaining());
                out.put_slice(&self.buffer.split_to(count));
                return std::task::Poll::Ready(Ok(()));
            }

            if self.eof {
                return std::task::Poll::Ready(Ok(()));
            }

            match self.reads.poll_recv(context) {
                std::task::Poll::Ready(Some((bytes, fin))) => {
                    self.buffer.extend_from_slice(&bytes);
                    self.eof |= fin;
                }
                std::task::Poll::Ready(None) => {
                    self.eof = true;
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl tokio::io::AsyncWrite for H3Stream {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let id = self.id;

        match std::task::ready!(self.reserve(context)) {
            Some(permit) => {
                permit.send((id, Bytes::copy_from_slice(data), false));
                std::task::Poll::Ready(Ok(data.len()))
            }
            None => std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))),
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _context: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let id = self.id;

        if let Some(permit) = std::task::ready!(self.reserve(context)) {
            permit.send((id, Bytes::new(), true));
        }

        std::task::Poll::Ready(Ok(()))
    }
}

impl Connection for H3Connection {
    fn version(&self) -> Version {
        Version::V3_0
    }

    fn role(&self) -> Role {
        self.role
    }

    fn id(&self) -> ConnectionID {
        self.id.clone()
    }

    fn security(&self) -> Security {
        *Lock::on(&self.security)
    }

    fn client(&self) -> Option<std::net::SocketAddr> {
        self.client
    }

    async fn send(&mut self, message: Message) -> Result<(), Error> {
        let timeout = self.limits.send_timeout;
        let sending = std::pin::pin!(self.send_message(message));
        Timeout::within(timeout, sending).await?
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        let timeout = self.limits.receive_timeout;
        let receiving = std::pin::pin!(self.receive_message());
        Timeout::within(timeout, receiving).await?
    }

    async fn close(&mut self) {
        let _ = self.commands.send(H3Command::Close).await;
    }
}

/// A unidirectional stream the peer opened, before and after its kind is known.
///
/// The kind arrives as a variable-length integer at the front, which may span
/// several reads, so the prefix is gathered until it can be decoded.
#[derive(Default)]
pub struct PeerUni {
    /// The stream's kind, once the prefix has been read.
    pub kind: Option<StreamKind>,
    /// Octets gathered while the kind is still unknown.
    pub prefix: Vec<u8>,
    /// Whether the stream announced a kind this end does not speak, and so
    /// is read no further.
    pub abandoned: bool,
}

/// Which QPACK side channel a drain concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The encoder stream, carrying table insertions.
    Encoder,
    /// The decoder stream, carrying acknowledgements.
    Decoder,
}

/// The half of an HTTP/3 connection that runs inside the QUIC driver.
///
/// Implements [`QUICApplication`], so the QUIC driver calls into it as the
/// QUIC connection makes progress. It owns the [`H3Session`] and does the
/// actual reading and writing; the caller's [`H3Connection`] talks to it over
/// channels.
///
/// Writes are buffered per stream rather than sent straight out, since QUIC
/// may only take part of a write. [`H3Worker::outbound_bytes`] tracks what is
/// held across all of them, and raw writes stop being accepted once it passes
/// [`Limits::max_connection_buffer_size`].
pub struct H3Worker {
    /// The protocol state.
    pub session: H3Session,
    /// Commands from the connection handle.
    pub commands: tokio::sync::mpsc::Receiver<H3Command>,
    /// Events back to the connection handle.
    pub events: tokio::sync::mpsc::Sender<H3Event>,
    /// Raw stream writes from tunnels.
    pub raw_writes: tokio::sync::mpsc::Receiver<(StreamID, Bytes, bool)>,
    /// A command taken while waiting, to be run on the next write pass.
    pub pending: Option<H3Command>,
    /// A raw write taken while waiting, to be run on the next write pass.
    pub pending_raw: Option<(StreamID, Bytes, bool)>,
    /// Whether the connection handle has been dropped.
    pub orphaned: bool,

    /// Whether the QUIC handshake has completed.
    pub established: bool,
    /// The next unidirectional stream this end will open.
    pub next_uni: u64,
    /// This end's control stream.
    pub local_control: u64,
    /// This end's QPACK encoder stream.
    pub local_encoder: u64,
    /// This end's QPACK decoder stream.
    pub local_decoder: u64,

    /// The peer's unidirectional streams, by identifier.
    pub peer_uni: common::StreamMap<u64, PeerUni>,
    /// Where to deliver octets for each stream that has become a tunnel.
    pub tunnels: common::StreamMap<u64, tokio::sync::mpsc::Sender<(Bytes, bool)>>,
    /// Octets waiting to be sent on each stream, and whether the stream ends
    /// with them.
    pub outbound: common::StreamMap<u64, (BytesMut, bool)>,
    /// How much is waiting to be sent across every stream.
    pub outbound_bytes: u64,

    /// How many streams the peer reset before a response was sent.
    pub premature_resets: u32,
    /// How many streams arrived at or above the GOAWAY this end sent.
    ///
    /// Each is refused with `REQUEST_REJECTED`; a peer that keeps opening
    /// them regardless is cut off once a whole generation's worth has been
    /// turned away.
    pub rejected: u32,
    /// The first stream a rejection has not been counted for yet.
    ///
    /// A refused stream can surface several reads before the peer acts on
    /// `STOP_SENDING`, and each would otherwise count again; this keeps
    /// [`H3Worker::rejected`] a count of streams rather than of reads.
    pub rejected_floor: u64,
    /// Whether the connection has been closed after its GOAWAY drained.
    pub drained: bool,

    /// The buffer the QUIC driver reads datagrams into.
    pub scratch: Vec<u8>,
    /// The buffer stream octets are read into.
    pub read: Vec<u8>,

    /// Reusable storage for the readable stream list.
    pub readable: Vec<u64>,
    /// Reusable storage for the flushing stream list.
    pub flushing: Vec<u64>,
}

impl H3Worker {
    /// Boxes an [`Error`] as the error type the QUIC driver expects.
    pub fn boxed(error: Error) -> QUICError {
        Box::new(error)
    }

    /// A worker over `session`, wired to a connection handle's channels.
    pub fn new(session: H3Session, commands: tokio::sync::mpsc::Receiver<H3Command>, events: tokio::sync::mpsc::Sender<H3Event>, raw_writes: tokio::sync::mpsc::Receiver<(StreamID, Bytes, bool)>) -> Self {
        let next_uni = QUICStreamID::first_uni(session.role);

        Self {
            session,
            commands,
            events,
            raw_writes,
            pending: None,
            pending_raw: None,
            orphaned: false,
            established: false,
            next_uni,
            local_control: 0,
            local_encoder: 0,
            local_decoder: 0,
            peer_uni: common::StreamMap::default(),
            tunnels: common::StreamMap::default(),
            outbound: common::StreamMap::default(),
            outbound_bytes: 0,
            premature_resets: 0,
            rejected: 0,
            rejected_floor: 0,
            drained: false,
            scratch: vec![0u8; 64 * 1024],
            read: vec![0u8; 64 * 1024],
            readable: Vec::new(),
            flushing: Vec::new(),
        }
    }

    /// Drops every trace of a stream: session state, tunnel, pending writes.
    pub fn forget_stream(&mut self, stream_id: u64) {
        self.session.forget(StreamID(stream_id));
        self.peer_uni.remove(&stream_id);
        self.tunnels.remove(&stream_id);

        if let Some((buffer, _)) = self.outbound.remove(&stream_id) {
            self.outbound_bytes = self.outbound_bytes.saturating_sub(buffer.len() as u64);
        }
    }

    /// How much may wait to be sent before writes are refused.
    pub fn outbound_limit(&self) -> u64 {
        self.session.limits.max_connection_buffer_size
    }

    /// Whether more raw writes may be taken on.
    ///
    /// This is the back pressure a tunnel feels when the peer stops reading.
    pub fn accepting_writes(&self) -> bool {
        self.outbound_bytes < self.outbound_limit()
    }

    /// Reports a failure to the connection handle and converts it for the QUIC driver.
    ///
    /// The error is described before it is sent, so the description survives
    /// even if the handle is gone and the event is dropped.
    pub fn fail(&mut self, error: Error) -> QUICError {
        let description = error.to_string();
        let _ = self.events.try_send(H3Event::Failed(error));
        Box::new(std::io::Error::other(description))
    }

    /// When the longest-blocked stream runs out of patience.
    ///
    /// `None` when nothing is blocked, or when
    /// [`Limits::qpack_block_timeout`] disables the timeout.
    pub fn block_deadline(&self) -> Option<std::time::Instant> {
        if self.session.blocked_since.is_empty() {
            return None;
        }

        let wait = Timeout::duration(self.session.limits.qpack_block_timeout)?;
        let earliest = self.session.blocked_since.values().min()?;
        Some(*earliest + wait)
    }

    /// The error for a QPACK block that has waited too long, if one has.
    ///
    /// A peer that references insertions it never sends would otherwise hold
    /// the stream open indefinitely.
    pub fn expired_block(&self) -> Option<Error> {
        let deadline = self.block_deadline()?;
        (std::time::Instant::now() >= deadline).then(|| {
            Error::Timeout(format!(
                "a QPACK block stayed blocked beyond {}s",
                self.session.limits.qpack_block_timeout
            ))
        })
    }

    /// Allocates the next unidirectional stream this end may open.
    ///
    /// Clients get 2, 6, 10, ... and servers 3, 7, 11, ....
    pub fn alloc_uni(&mut self) -> u64 {
        let id = self.next_uni;
        self.next_uni += QUICStreamID::STEP;
        id
    }

    /// Opens a unidirectional stream by writing the code that announces its kind.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for [`StreamKind::Request`], which is
    /// bidirectional, and otherwise as [`H3Worker::write`].
    pub fn open_uni(&mut self, transport: &mut impl QUICTransport, stream_id: u64, kind: StreamKind) -> Result<(), Error> {
        let code = kind
            .code()
            .ok_or_else(|| Error::Protocol(format!("{kind:?} is not a unidirectional stream type")))?;

        let mut prefix = BytesMut::new();
        Varint::encode(&mut prefix, code);
        self.write(transport, stream_id, &prefix, false)
    }

    /// Buffers octets for a stream and tries to send at once.
    ///
    /// # Errors
    ///
    /// As [`H3Worker::flush_stream`].
    pub fn write(&mut self, transport: &mut impl QUICTransport, stream_id: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        let entry = self.outbound.entry(stream_id).or_default();
        entry.0.extend_from_slice(data);
        entry.1 |= fin;
        self.outbound_bytes = self.outbound_bytes.saturating_add(data.len() as u64);
        self.flush_stream(transport, stream_id)
    }

    /// Sends as much of a stream's buffered output as QUIC will take.
    ///
    /// A partial send leaves the rest buffered for the next pass. A stream the
    /// peer has stopped is dropped and reported, without failing the
    /// connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IO`] when QUIC fails for any reason other than the
    /// stream being blocked or stopped.
    pub fn flush_stream(&mut self, transport: &mut impl QUICTransport, stream_id: u64) -> Result<(), Error> {
        let Some((buffer, fin)) = self.outbound.get_mut(&stream_id) else {
            return Ok(());
        };

        if buffer.is_empty() && !*fin {
            return Ok(());
        }

        match transport.send(stream_id, buffer, *fin)? {
            StreamWrite::Sent(sent) => {
                let _ = buffer.split_to(sent);
                self.outbound_bytes = self.outbound_bytes.saturating_sub(sent as u64);

                if buffer.is_empty() {
                    self.outbound.remove(&stream_id);
                }
                Ok(())
            }
            StreamWrite::Blocked => Ok(()),
            StreamWrite::Stopped(code) => {
                if let Some((buffer, _)) = self.outbound.remove(&stream_id) {
                    self.outbound_bytes = self.outbound_bytes.saturating_sub(buffer.len() as u64);
                }

                let error = Error::stream(StreamID(stream_id), code, "the peer stopped the stream");
                let _ = self.events.try_send(H3Event::Failed(error));
                Ok(())
            }
        }
    }

    /// Carries out one command from the connection handle.
    ///
    /// # Errors
    ///
    /// As [`H3Session::encode_message_into`] and [`H3Worker::write`].
    pub fn execute(&mut self, transport: &mut impl QUICTransport, command: H3Command) -> Result<(), Error> {
        match command {
            H3Command::Send(message) => {
                let mut message = message;
                let stream_id = message.stream_id.unwrap_or_else(|| self.session.open());
                self.session.streams.entry(stream_id).or_default().responded = true;

                let entry = self.outbound.entry(stream_id.0).or_default();
                let before = entry.0.len();
                let fin = self.session.encode_message_into(stream_id, &mut message, &mut entry.0)?;
                entry.1 |= fin;

                let framed = entry.0.len().saturating_sub(before) as u64;
                self.outbound_bytes = self.outbound_bytes.saturating_add(framed);

                self.flush_stream(transport, stream_id.0)?;
                self.session.retire(stream_id);
                Ok(())
            }
            H3Command::Open(reply) => {
                let _ = reply.send(self.session.open());
                Ok(())
            }
            H3Command::OpenUni(kind, reply) => {
                let stream_id = self.alloc_uni();
                self.open_uni(transport, stream_id, kind)?;
                let _ = reply.send(StreamID(stream_id));
                Ok(())
            }
            H3Command::Tunnel(stream_id, sink) => {
                if let Some(state) = self.session.streams.get_mut(&stream_id) {
                    let buffered = std::mem::take(&mut state.buffer);
                    if !buffered.is_empty() || state.eof {
                        let _ = sink.try_send((buffered.freeze(), state.eof));
                    }
                }
                self.tunnels.insert(stream_id.0, sink);
                Ok(())
            }
            H3Command::WriteEncoder(bytes) => self.write(transport, self.local_encoder, &bytes, false),
            H3Command::Reset(stream_id, code) => {
                self.outbound.remove(&stream_id.0);
                self.tunnels.remove(&stream_id.0);
                self.session.retire(stream_id);

                let _ = transport.shutdown_write(stream_id.0, code);
                let _ = transport.shutdown_read(stream_id.0, code);
                Ok(())
            }
            H3Command::Close => {
                let _ = transport.close(Code::NO_ERROR, b"");
                Ok(())
            }
        }
    }

    /// Routes incoming octets to wherever the stream belongs.
    ///
    /// Tunnels first, then bidirectional streams to the session, then
    /// unidirectional ones to [`H3Worker::feed_uni`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Stream`] when a tunnel cannot take the octets, and
    /// otherwise as [`H3Worker::reject`], [`H3Session::on_stream_bytes`],
    /// [`H3Worker::goaway`] and [`H3Worker::feed_uni`].
    pub fn dispatch(&mut self, transport: &mut impl QUICTransport, stream_id: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        if let Some(sink) = self.tunnels.get(&stream_id) {
            if sink.try_send((Bytes::copy_from_slice(data), fin)).is_err() {
                return Err(Error::stream(StreamID(stream_id), Code::EXCESSIVE_LOAD, "the tunnel could not take the octets"));
            }

            if fin {
                self.tunnels.remove(&stream_id);
                self.session.forget(StreamID(stream_id));
            }

            return Ok(());
        }

        if QUICStreamID::is_bidi(stream_id) {
            if self.session.goaway_sent.is_some_and(|id| stream_id >= id) && !self.session.streams.contains_key(&StreamID(stream_id)) {
                return self.reject(transport, stream_id);
            }

            self.session.on_stream_bytes(StreamID(stream_id), data, fin)?;
            return self.goaway(transport);
        }

        self.feed_uni(transport, stream_id, data, fin)
    }

    /// Sends GOAWAY once [`Limits::max_requests_per_connection`] is reached.
    ///
    /// Only an origin winds a connection down this way: a client's GOAWAY
    /// speaks of pushes, which are disabled. The identifier is the first
    /// stream after everything accepted so far, so nothing already taken in
    /// is abandoned, and everything after it is refused by
    /// [`H3Worker::reject`]. The connection closes when the peer, told that
    /// nothing more will be served, closes it or drains and goes idle.
    ///
    /// # Errors
    ///
    /// As [`H3Worker::write`].
    pub fn goaway(&mut self, transport: &mut impl QUICTransport) -> Result<(), Error> {
        let limit = self.session.limits.max_requests_per_connection;

        if self.session.role.is_client() || self.session.goaway_sent.is_some() || limit == 0 || self.session.total_streams < limit {
            return Ok(());
        }

        let id = self.session.highest_peer_stream_id + QUICStreamID::STEP;
        let mut frame = BytesMut::new();
        Frame::GoAway { id }.encode_into(&mut frame);

        self.write(transport, self.local_control, &frame, false)?;
        self.session.goaway_sent = Some(id);
        Ok(())
    }

    /// Refuses a stream the peer opened past the GOAWAY this end sent.
    ///
    /// `REQUEST_REJECTED` tells the peer the request was not processed and is
    /// safe to retry on another connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when the peer keeps opening streams past the
    /// GOAWAY instead of winding down, having first closed the connection.
    pub fn reject(&mut self, transport: &mut impl QUICTransport, stream_id: u64) -> Result<(), Error> {
        if stream_id >= self.rejected_floor {
            self.rejected_floor = stream_id + QUICStreamID::STEP;
            self.rejected = self.rejected.saturating_add(1);
        }

        if self.rejected as usize > self.session.stream_ceiling() {
            let reason = format!("more than {} streams arrived after GOAWAY", self.session.stream_ceiling());
            return Err(self.overloaded(transport, reason));
        }

        let _ = transport.shutdown_write(stream_id, Code::REQUEST_REJECTED);
        let _ = transport.shutdown_read(stream_id, Code::REQUEST_REJECTED);
        Ok(())
    }

    /// Closes the connection once the peer's GOAWAY has drained.
    ///
    /// The peer will take nothing more, so once every stream has finished and
    /// everything owed has been handed to QUIC the connection is done: it is
    /// closed cleanly and the handle is told [`Error::Closed`], exactly as an
    /// HTTP/2 connection reports itself once its GOAWAY drains.
    pub fn wind_down(&mut self, transport: &mut impl QUICTransport) {
        if self.drained || self.session.goaway.is_none() {
            return;
        }

        if !self.session.streams.is_empty() || !self.session.ready.is_empty() || !self.outbound.is_empty() || !self.tunnels.is_empty() {
            return;
        }

        self.drained = true;
        let _ = transport.close(Code::NO_ERROR, b"");
        let _ = self.events.try_send(H3Event::Failed(Error::Closed));
    }

    /// Feeds octets to a peer's unidirectional stream, forgetting it at end of
    /// stream.
    ///
    /// # Errors
    ///
    /// As [`H3Worker::feed_uni_bytes`].
    pub fn feed_uni(&mut self, transport: &mut impl QUICTransport, stream_id: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        let outcome = self.feed_uni_bytes(transport, stream_id, data);

        if fin {
            self.peer_uni.remove(&stream_id);
        }

        outcome
    }

    /// Reads a unidirectional stream's kind prefix, then feeds it onward.
    ///
    /// The prefix may span several reads, so it is gathered until it decodes.
    /// A stream announcing a kind this end does not speak is abandoned, as
    /// RFC 9114 §6.2 allows: reading stops and the peer is told to as well.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] past [`Limits::max_peer_uni_streams`],
    /// [`Error::Protocol`] when the prefix grows past [`Varint::MAX_SIZE`]
    /// without decoding, and otherwise as [`H3Worker::feed_uni_kind`].
    pub fn feed_uni_bytes(&mut self, transport: &mut impl QUICTransport, stream_id: u64, data: &[u8]) -> Result<(), Error> {
        if self.peer_uni.get(&stream_id).is_some_and(|uni| uni.abandoned) {
            return Ok(());
        }

        if let Some(kind) = self.peer_uni.get(&stream_id).and_then(|uni| uni.kind) {
            return self.feed_uni_kind(kind, data);
        }

        let ceiling = self.session.limits.max_peer_uni_streams as usize;

        if !self.peer_uni.contains_key(&stream_id) && self.peer_uni.len() >= ceiling {
            let reason = format!("more than {ceiling} unidirectional streams are open at once");
            return Err(Error::Limit(reason));
        }

        let uni = self.peer_uni.entry(stream_id).or_default();
        uni.prefix.extend_from_slice(data);

        let (consumed, code) = Varint::decode(&uni.prefix);
        if consumed == 0 {
            if uni.prefix.len() > Varint::MAX_SIZE {
                return Err(Error::Protocol("a unidirectional stream carries no readable type".into()));
            }
            return Ok(());
        }

        let Some(kind) = StreamKind::from_code(code) else {
            uni.prefix = Vec::new();
            uni.abandoned = true;
            let _ = transport.shutdown_read(stream_id, Code::STREAM_CREATION_ERROR);
            return Ok(());
        };

        uni.kind = Some(kind);

        let payload = uni.prefix.split_off(consumed);
        uni.prefix = Vec::new();

        self.feed_uni_kind(kind, &payload)
    }

    /// Hands a unidirectional stream's octets to whichever handler its kind
    /// calls for.
    ///
    /// Push and request kinds are ignored, since push is disabled and a
    /// request cannot arrive unidirectionally.
    ///
    /// # Errors
    ///
    /// As [`H3Session::on_control_bytes`], [`H3Session::on_encoder_bytes`] and
    /// [`H3Session::on_decoder_bytes`].
    pub fn feed_uni_kind(&mut self, kind: StreamKind, payload: &[u8]) -> Result<(), Error> {
        match kind {
            StreamKind::Control => self.session.on_control_bytes(payload),
            StreamKind::QPACKEncoder => self.session.on_encoder_bytes(payload),
            StreamKind::QPACKDecoder => self.session.on_decoder_bytes(payload),
            _ => Ok(()),
        }
    }

    /// Closes the connection with `Code::EXCESSIVE_LOAD` and builds the matching error.
    pub fn overloaded(&mut self, transport: &mut impl QUICTransport, reason: impl Into<String>) -> Error {
        let _ = transport.close(Code::EXCESSIVE_LOAD, b"");
        Error::Limit(reason.into())
    }

    /// Abandons one stream in both directions, leaving the connection running.
    ///
    /// The code comes from the error where it carries one, and falls back to
    /// `Code::MESSAGE_ERROR`.
    pub fn reset_stream(&mut self, transport: &mut impl QUICTransport, stream_id: u64, error: &Error) {
        self.forget_stream(stream_id);

        let code = match error {
            Error::Stream { code, .. } => *code,
            _ => Code::MESSAGE_ERROR,
        };

        let _ = transport.shutdown_write(stream_id, code);
        let _ = transport.shutdown_read(stream_id, code);
    }

    /// Sends whatever QPACK has queued on both side channels.
    ///
    /// # Errors
    ///
    /// As [`H3Worker::drain_side_channel`].
    pub fn drain_side_channels(&mut self, transport: &mut impl QUICTransport) -> Result<(), Error> {
        self.drain_side_channel(transport, Side::Encoder)?;
        self.drain_side_channel(transport, Side::Decoder)
    }

    /// Sends whatever QPACK has queued on one side channel.
    ///
    /// The buffer is kept and reused, and given back through
    /// [`qpack::Encoder::reclaim_encoder_stream`] and
    /// [`qpack::Decoder::reclaim_decoder_stream`], which shrink it once it has
    /// grown past what an idle codec should hold.
    ///
    /// # Errors
    ///
    /// As [`H3Worker::write`].
    pub fn drain_side_channel(&mut self, transport: &mut impl QUICTransport, side: Side) -> Result<(), Error> {
        let (pending, stream_id) = match side {
            Side::Encoder => (!self.session.encoder.encoder_stream().is_empty(), self.local_encoder),
            Side::Decoder => (!self.session.decoder.decoder_stream().is_empty(), self.local_decoder),
        };

        if !pending {
            return Ok(());
        }

        let queued = match side {
            Side::Encoder => self.session.encoder.take_encoder_stream(),
            Side::Decoder => self.session.decoder.take_decoder_stream(),
        };

        let outcome = self.write(transport, stream_id, &queued, false);

        match side {
            Side::Encoder => self.session.encoder.reclaim_encoder_stream(queued),
            Side::Decoder => self.session.decoder.reclaim_decoder_stream(queued),
        }

        outcome
    }
}

impl QUICApplication for H3Worker {
    /// Opens the three streams HTTP/3 needs and sends the opening SETTINGS.
    ///
    /// Called once the QUIC handshake completes, which is the first moment a
    /// stream can be opened — and the first moment the transport facts exist
    /// to be read, which is when [`H3Session::security`] is stamped.
    fn on_conn_established(&mut self, qconn: &mut QUICConnection, _handshake: &QUICHandshake) -> QUICOutcome<()> {
        self.established = true;
        *Lock::on(&self.session.security) = Handshake::of(qconn).security();

        self.local_control = self.alloc_uni();
        self.local_encoder = self.alloc_uni();
        self.local_decoder = self.alloc_uni();

        let opened = (|| {
            self.open_uni(qconn, self.local_control, StreamKind::Control)?;
            let settings = self.session.control_frame();
            self.write(qconn, self.local_control, &settings, false)?;

            self.open_uni(qconn, self.local_encoder, StreamKind::QPACKEncoder)?;
            self.open_uni(qconn, self.local_decoder, StreamKind::QPACKDecoder)
        })();

        opened.map_err(|error| self.fail(error))
    }

    /// Always true: the worker has streams to run from the moment it exists.
    fn should_act(&self) -> bool {
        true
    }

    /// The buffer the QUIC driver reads datagrams into.
    fn buffer(&mut self) -> &mut [u8] {
        &mut self.scratch
    }

    /// Waits until there is something to do.
    ///
    /// Wakes for a command, a raw write, or the QPACK block deadline. Raw
    /// writes are only taken while [`H3Worker::accepting_writes`], which is
    /// how back pressure reaches a tunnel. Once the connection handle is gone
    /// the command arm is dropped, so a closed channel does not spin.
    async fn wait_for_data(&mut self, _qconn: &mut QUICConnection) -> QUICOutcome<()> {
        let deadline = self.block_deadline();

        tokio::select! {
            command = self.commands.recv(), if !self.orphaned && self.pending.is_none() => match command {
                Some(command) => {
                    self.pending = Some(command);
                    Ok(())
                }
                None => {
                    self.orphaned = true;
                    Ok(())
                }
            },

            raw = self.raw_writes.recv(), if self.pending_raw.is_none() && self.accepting_writes() => match raw {
                Some(raw) => {
                    self.pending_raw = Some(raw);
                    Ok(())
                }
                None => Err(Self::boxed(Error::Closed)),
            },

            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.unwrap_or_else(std::time::Instant::now))), if deadline.is_some() => Ok(()),

            else => {
                std::future::pending::<()>().await;
                Ok(())
            }
        }
    }

    /// Reads every readable stream and delivers whatever messages complete.
    fn process_reads(&mut self, qconn: &mut QUICConnection) -> QUICOutcome<()> {
        let mut read = std::mem::take(&mut self.read);
        let mut readable = std::mem::take(&mut self.readable);

        readable.clear();
        readable.extend(QUICTransport::readable(qconn));

        let outcome = self.drain_reads(qconn, &readable, &mut read);

        self.read = read;
        self.readable = readable;

        outcome?;

        self.deliver_ready();
        self.wind_down(qconn);
        Ok(())
    }

    /// Runs pending commands and flushes everything waiting to be sent.
    ///
    /// Checks the QPACK block deadline first: a stream that has waited too
    /// long takes the connection down with `Code::QPACK_DECOMPRESSION_FAILED`, since
    /// the peer has left the decoder unable to make progress.
    fn process_writes(&mut self, qconn: &mut QUICConnection) -> QUICOutcome<()> {
        if let Some(error) = self.expired_block() {
            let _ = QUICTransport::close(qconn, Code::QPACK_DECOMPRESSION_FAILED, b"");
            return Err(self.fail(error));
        }

        // A command that frames octets is held until there is room for them,
        // so that a peer granting no flow control credit cannot have every
        // response it asked for buffered here. One that frees room is run
        // whatever is waiting; see [`H3Command::buffers`].
        if let Some(command) = self.pending.take() {
            match command.buffers() && !self.accepting_writes() {
                true => self.pending = Some(command),
                false => {
                    if let Err(error) = self.execute(qconn, command) {
                        return Err(self.fail(error));
                    }
                }
            }
        }

        while self.pending.is_none() {
            let Ok(command) = self.commands.try_recv() else {
                break;
            };

            if command.buffers() && !self.accepting_writes() {
                self.pending = Some(command);
                break;
            }

            if let Err(error) = self.execute(qconn, command) {
                return Err(self.fail(error));
            }
        }

        while self.accepting_writes() {
            let Some((stream_id, bytes, fin)) = self.pending_raw.take().or_else(|| self.raw_writes.try_recv().ok()) else {
                break;
            };

            if let Err(error) = self.write(qconn, stream_id.0, &bytes, fin) {
                return Err(self.fail(error));
            }
        }

        if let Err(error) = self.drain_side_channels(qconn) {
            return Err(self.fail(error));
        }

        let mut flushing = std::mem::take(&mut self.flushing);
        flushing.clear();
        flushing.extend(self.outbound.keys().copied());

        let mut outcome = Ok(());
        for stream_id in &flushing {
            if let Err(error) = self.flush_stream(qconn, *stream_id) {
                outcome = Err(error);
                break;
            }
        }

        self.flushing = flushing;

        if let Err(error) = outcome {
            return Err(self.fail(error));
        }

        self.deliver_ready();
        self.wind_down(qconn);
        Ok(())
    }
}

impl H3Worker {
    /// Hands completed messages to the connection handle.
    ///
    /// Stops when the event channel is full, putting the message back at the
    /// front so ordering holds. This is the back pressure a caller that stops
    /// receiving applies to the connection.
    pub fn deliver_ready(&mut self) {
        while let Some(message) = self.session.take_ready() {
            let Err(tokio::sync::mpsc::error::TrySendError::Full(event)) = self.events.try_send(H3Event::Message(message)) else {
                continue;
            };

            if let H3Event::Message(message) = event {
                self.session.ready.push_front(message);
            }

            return;
        }
    }

    /// Reads every readable stream until it is drained or blocked.
    ///
    /// An [`Error::Stream`] resets that stream and moves on, so one bad
    /// request does not take the connection with it; anything else fails the
    /// connection. A stream whose tunnel has no room is left for the next
    /// pass rather than read into a growing buffer.
    ///
    /// # Errors
    ///
    /// Any connection-fatal failure, already reported to the connection
    /// handle by [`H3Worker::fail`].
    pub fn drain_reads(&mut self, transport: &mut impl QUICTransport, readable: &[u64], read: &mut [u8]) -> Result<(), QUICError> {
        for stream_id in readable.iter().copied() {
            loop {
                if self.tunnels.get(&stream_id).is_some_and(|sink| sink.capacity() == 0) {
                    break;
                }

                let outcome = match transport.receive(stream_id, read) {
                    Ok(outcome) => outcome,
                    Err(error) => return Err(self.fail(error)),
                };

                match outcome {
                    StreamRead::Data { len, fin } => {
                        match self.dispatch(transport, stream_id, &read[..len], fin) {
                            Ok(()) => {}
                            Err(error) if matches!(error, Error::Stream { .. }) => {
                                self.reset_stream(transport, stream_id, &error);
                                let _ = self.events.try_send(H3Event::Failed(error));
                                break;
                            }
                            Err(error) => return Err(self.fail(error)),
                        }
                        if fin || len == 0 {
                            break;
                        }
                    }
                    StreamRead::Done => break,
                    StreamRead::Reset(code) => {
                        let premature = self.session.forget(StreamID(stream_id)).is_some_and(|state| !state.responded);
                        self.forget_stream(stream_id);

                        if premature {
                            self.premature_resets = self.premature_resets.saturating_add(1);

                            if self.premature_resets > self.session.limits.max_premature_resets {
                                let reason = format!(
                                    "more than {} streams were reset before a response was sent",
                                    self.session.limits.max_premature_resets
                                );
                                let error = self.overloaded(transport, reason);
                                return Err(self.fail(error));
                            }
                        }

                        let error = Error::stream(StreamID(stream_id), code, "the peer reset the stream");
                        let _ = self.events.try_send(H3Event::Failed(error));
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}
