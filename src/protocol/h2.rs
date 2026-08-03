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

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::api::common::Limits;
use crate::helpers::hpack::{Decoder as HPACKDecoder, Encoder as HPACKEncoder, HeaderField};
use crate::models::{Body, ConnectionID, Headers, Message, Method, Role, StreamID, Version};
use crate::protocol::base::{Connection, Stream};
use crate::protocol::common::{self, Buffer, Error};

/// The octets a client sends before anything else, to prove it means HTTP/2.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The fixed size of a frame header.
pub const FRAME_HEADER_SIZE: usize = 9;

/// The buffered output size at which a body write flushes rather than growing.
pub const OUTPUT_HIGH_WATER: usize = 64 * 1024;

/// `SETTINGS_HEADER_TABLE_SIZE`: the peer's HPACK dynamic table ceiling.
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
/// `SETTINGS_ENABLE_PUSH`: whether server push is allowed.
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
/// `SETTINGS_MAX_CONCURRENT_STREAMS`: how many streams may be open at once.
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
/// `SETTINGS_INITIAL_WINDOW_SIZE`: the flow control window a new stream starts at.
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
/// `SETTINGS_MAX_FRAME_SIZE`: the largest frame payload the peer will accept.
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
/// `SETTINGS_MAX_HEADER_LIST_SIZE`: the largest decoded field section.
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL`: whether extended CONNECT is allowed.
///
/// This is what WebSocket over HTTP/2 is carried by.
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u16 = 0x8;

/// The flow control window both ends assume before any setting says otherwise.
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;
/// The frame size both ends assume, and the smallest that may be negotiated.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
/// The largest frame size that may be negotiated.
pub const MAXIMUM_FRAME_SIZE: u32 = 16_777_215;
/// The largest a flow control window may reach, and the stream identifier mask.
pub const MAXIMUM_WINDOW_SIZE: u32 = 0x7fff_ffff;
/// The largest HPACK encoder table this end will keep, whatever the peer allows.
pub const MAXIMUM_ENCODER_TABLE_SIZE: usize = 64 * 1024;

/// `NO_ERROR`: the connection or stream ended cleanly.
pub const NO_ERROR: u32 = 0x0;
/// `PROTOCOL_ERROR`: the peer broke the protocol.
pub const PROTOCOL_ERROR: u32 = 0x1;
/// `INTERNAL_ERROR`: something failed on this end.
pub const INTERNAL_ERROR: u32 = 0x2;
/// `FLOW_CONTROL_ERROR`: the peer sent past its window, or overflowed one.
pub const FLOW_CONTROL_ERROR: u32 = 0x3;
/// `SETTINGS_TIMEOUT`: settings went unacknowledged too long.
pub const SETTINGS_TIMEOUT: u32 = 0x4;
/// `STREAM_CLOSED`: a frame arrived for a stream that had finished.
pub const STREAM_CLOSED: u32 = 0x5;
/// `FRAME_SIZE_ERROR`: a frame's length is wrong for its type.
pub const FRAME_SIZE_ERROR: u32 = 0x6;
/// `REFUSED_STREAM`: the stream was declined before any processing.
pub const REFUSED_STREAM: u32 = 0x7;
/// `CANCEL`: the stream is no longer wanted.
pub const CANCEL: u32 = 0x8;
/// `COMPRESSION_ERROR`: the HPACK state cannot be maintained.
pub const COMPRESSION_ERROR: u32 = 0x9;
/// `CONNECT_ERROR`: a tunnel failed.
pub const CONNECT_ERROR: u32 = 0xa;
/// `ENHANCE_YOUR_CALM`: the peer is generating excessive load.
pub const ENHANCE_YOUR_CALM: u32 = 0xb;
/// `INADEQUATE_SECURITY`: the transport does not meet the requirements.
pub const INADEQUATE_SECURITY: u32 = 0xc;
/// `HTTP_1_1_REQUIRED`: the peer should retry over HTTP/1.1.
pub const HTTP_1_1_REQUIRED: u32 = 0xd;

/// Frame flag: this is the last frame this end will send on the stream.
pub const END_STREAM: u8 = 0x1;
/// Frame flag: this SETTINGS or PING acknowledges the peer's.
///
/// The same bit as [`END_STREAM`], on frame types where that has no meaning.
pub const ACK: u8 = 0x1;
/// Frame flag: the field section ends here, with no CONTINUATION to follow.
pub const END_HEADERS: u8 = 0x4;
/// Frame flag: the payload begins with a padding length and ends with padding.
pub const PADDED: u8 = 0x8;
/// Frame flag: a HEADERS frame carries priority information before its block.
pub const PRIORITY: u8 = 0x20;

/// The kind of an HTTP/2 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// `DATA`: message body octets.
    Data,
    /// `HEADERS`: a compressed field section.
    Headers,
    /// `PRIORITY`: a priority hint, which this implementation reads and ignores.
    Priority,
    /// `RST_STREAM`: abandon one stream.
    RstStream,
    /// `SETTINGS`: connection parameters, or their acknowledgement.
    Settings,
    /// `PUSH_PROMISE`: a promised stream; refused here, since push is disabled.
    PushPromise,
    /// `PING`: a liveness probe, or its acknowledgement.
    Ping,
    /// `GOAWAY`: no further streams will be accepted.
    GoAway,
    /// `WINDOW_UPDATE`: more flow control credit.
    WindowUpdate,
    /// `CONTINUATION`: more of the field section a HEADERS frame began.
    Continuation,
}

impl FrameType {
    /// The type code that goes on the wire.
    pub fn code(&self) -> u8 {
        match self {
            Self::Data => 0x0,
            Self::Headers => 0x1,
            Self::Priority => 0x2,
            Self::RstStream => 0x3,
            Self::Settings => 0x4,
            Self::PushPromise => 0x5,
            Self::Ping => 0x6,
            Self::GoAway => 0x7,
            Self::WindowUpdate => 0x8,
            Self::Continuation => 0x9,
        }
    }

    /// The frame type a code names, or `None` for an unknown type.
    ///
    /// Unknown types are skipped rather than rejected, so that extensions do
    /// not break the connection.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x0 => Some(Self::Data),
            0x1 => Some(Self::Headers),
            0x2 => Some(Self::Priority),
            0x3 => Some(Self::RstStream),
            0x4 => Some(Self::Settings),
            0x5 => Some(Self::PushPromise),
            0x6 => Some(Self::Ping),
            0x7 => Some(Self::GoAway),
            0x8 => Some(Self::WindowUpdate),
            0x9 => Some(Self::Continuation),
            _ => None,
        }
    }

    /// Whether this type belongs on a stream or on the connection.
    ///
    /// `Some(true)` must be on a stream, `Some(false)` must be on stream zero,
    /// and `None` is `WINDOW_UPDATE`, which is valid either way.
    pub fn streamed(&self) -> Option<bool> {
        match self {
            Self::Data | Self::Headers | Self::Priority | Self::RstStream | Self::PushPromise
            | Self::Continuation => Some(true),
            Self::Settings | Self::Ping | Self::GoAway => Some(false),
            Self::WindowUpdate => None,
        }
    }
}

/// The fixed nine-octet header every frame begins with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// The payload length; only its low 24 bits go on the wire.
    pub length: u32,
    /// The frame type.
    pub kind: FrameType,
    /// The type-specific flags.
    pub flags: u8,
    /// The stream, or zero for the connection.
    pub stream_id: StreamID,
}

impl FrameHeader {
    /// Encodes the header.
    pub fn encode(&self) -> [u8; FRAME_HEADER_SIZE] {
        let length = self.length.to_be_bytes();
        let stream_id = (self.stream_id.0 as u32 & MAXIMUM_WINDOW_SIZE).to_be_bytes();

        [
            length[1],
            length[2],
            length[3],
            self.kind.code(),
            self.flags,
            stream_id[0],
            stream_id[1],
            stream_id[2],
            stream_id[3],
        ]
    }

    /// Decodes a header.
    ///
    /// Returns the payload length, and the header itself unless the type is
    /// unknown. The length comes back either way, since an unknown frame still
    /// has to be read past rather than fail the connection.
    pub fn decode(octets: &[u8; FRAME_HEADER_SIZE]) -> (u32, Option<Self>) {
        let length = u32::from_be_bytes([0, octets[0], octets[1], octets[2]]);
        let stream_id = u32::from_be_bytes([octets[5], octets[6], octets[7], octets[8]]) & MAXIMUM_WINDOW_SIZE;

        let header = FrameType::from_code(octets[3]).map(|kind| Self {
            length,
            kind,
            flags: octets[4],
            stream_id: StreamID(stream_id as u64),
        });

        (length, header)
    }
}

/// One decoded HTTP/2 frame.
///
/// Padding has already been stripped by the time a frame reaches this form,
/// since it carries no meaning above the framing layer.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// Message body octets.
    Data {
        /// The stream carrying the body.
        stream_id: StreamID,
        /// Whether the body ends here.
        end_stream: bool,
        /// The octets.
        data: Bytes,
    },
    /// A compressed field section, possibly continued by [`Frame::Continuation`].
    Headers {
        /// The stream.
        stream_id: StreamID,
        /// Whether the message ends here.
        end_stream: bool,
        /// Whether the field section is complete.
        end_headers: bool,
        /// The compressed field block, priority information already stripped.
        block: Bytes,
    },
    /// A priority hint, which this implementation reads and ignores.
    Priority {
        /// The stream being prioritised.
        stream_id: StreamID,
        /// The stream it is said to depend on.
        dependency: StreamID,
        /// Whether the dependency is exclusive.
        exclusive: bool,
        /// The relative weight.
        weight: u8,
    },
    /// Abandon one stream.
    RstStream {
        /// The stream to abandon.
        stream_id: StreamID,
        /// Why.
        error_code: u32,
    },
    /// Connection parameters, or their acknowledgement.
    Settings {
        /// Whether this acknowledges the peer's settings rather than setting any.
        ack: bool,
        /// The identifier and value of each parameter.
        params: Vec<(u16, u32)>,
    },
    /// A promised stream. Refused here, since push is disabled.
    PushPromise {
        /// The stream the promise arrived on.
        stream_id: StreamID,
        /// The stream being promised.
        promised_stream_id: StreamID,
        /// The compressed field block of the promised request.
        block: Bytes,
    },
    /// A liveness probe, or its acknowledgement.
    Ping {
        /// Whether this answers the peer's probe rather than being one.
        ack: bool,
        /// The eight octets to be echoed back unchanged.
        payload: [u8; 8],
    },
    /// No further streams will be accepted.
    GoAway {
        /// The last stream that may still be processed.
        last_stream_id: StreamID,
        /// Why the connection is ending.
        error_code: u32,
        /// Free-form diagnostic octets.
        debug_data: Vec<u8>,
    },
    /// More flow control credit.
    WindowUpdate {
        /// The stream, or zero for the connection as a whole.
        stream_id: StreamID,
        /// How much credit is being added; never zero.
        increment: u32,
    },
    /// More of the field section a [`Frame::Headers`] began.
    Continuation {
        /// The stream.
        stream_id: StreamID,
        /// Whether the field section is complete.
        end_headers: bool,
        /// The next part of the compressed field block.
        block: Bytes,
    },
}

impl Frame {
    /// The frame's type.
    pub fn kind(&self) -> FrameType {
        match self {
            Self::Data { .. } => FrameType::Data,
            Self::Headers { .. } => FrameType::Headers,
            Self::Priority { .. } => FrameType::Priority,
            Self::RstStream { .. } => FrameType::RstStream,
            Self::Settings { .. } => FrameType::Settings,
            Self::PushPromise { .. } => FrameType::PushPromise,
            Self::Ping { .. } => FrameType::Ping,
            Self::GoAway { .. } => FrameType::GoAway,
            Self::WindowUpdate { .. } => FrameType::WindowUpdate,
            Self::Continuation { .. } => FrameType::Continuation,
        }
    }

    /// The stream the frame belongs to, or zero for a connection-wide one.
    pub fn stream_id(&self) -> StreamID {
        match self {
            Self::Data { stream_id, .. }
            | Self::Headers { stream_id, .. }
            | Self::Priority { stream_id, .. }
            | Self::RstStream { stream_id, .. }
            | Self::PushPromise { stream_id, .. }
            | Self::WindowUpdate { stream_id, .. }
            | Self::Continuation { stream_id, .. } => *stream_id,
            Self::Settings { .. } | Self::Ping { .. } | Self::GoAway { .. } => StreamID(0),
        }
    }

    /// The flags this frame goes out with.
    ///
    /// Frames written here are never padded, so [`PADDED`] is never set.
    pub fn flags(&self) -> u8 {
        match self {
            Self::Data { end_stream, .. } => u8::from(*end_stream) * END_STREAM,
            Self::Headers { end_stream, end_headers, .. } => {
                (u8::from(*end_stream) * END_STREAM) | (u8::from(*end_headers) * END_HEADERS)
            }
            Self::Settings { ack, .. } | Self::Ping { ack, .. } => u8::from(*ack) * ACK,
            Self::PushPromise { .. } => END_HEADERS,
            Self::Continuation { end_headers, .. } => u8::from(*end_headers) * END_HEADERS,
            Self::Priority { .. } | Self::RstStream { .. } | Self::GoAway { .. } | Self::WindowUpdate { .. } => 0,
        }
    }

    /// Appends the payload, without the frame header.
    pub fn write_payload(&self, out: &mut BytesMut) {
        match self {
            Self::Data { data, .. } => out.extend_from_slice(data),

            Self::Headers { block, .. } | Self::Continuation { block, .. } => out.extend_from_slice(block),

            Self::Priority { dependency, exclusive, weight, .. } => {
                out.extend_from_slice(&(dependency.0 as u32 | u32::from(*exclusive) << 31).to_be_bytes());
                out.extend_from_slice(&[*weight]);
            }

            Self::RstStream { error_code, .. } => out.extend_from_slice(&error_code.to_be_bytes()),

            Self::Settings { params, .. } => {
                for (id, value) in params {
                    out.extend_from_slice(&id.to_be_bytes());
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }

            Self::PushPromise { promised_stream_id, block, .. } => {
                out.extend_from_slice(&(promised_stream_id.0 as u32).to_be_bytes());
                out.extend_from_slice(block);
            }

            Self::Ping { payload, .. } => out.extend_from_slice(payload),

            Self::GoAway { last_stream_id, error_code, debug_data } => {
                out.extend_from_slice(&(last_stream_id.0 as u32).to_be_bytes());
                out.extend_from_slice(&error_code.to_be_bytes());
                out.extend_from_slice(debug_data);
            }

            Self::WindowUpdate { increment, .. } => out.extend_from_slice(&increment.to_be_bytes()),
        }
    }

    /// The payload on its own.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        self.write_payload(&mut out);
        out.to_vec()
    }

    /// Appends the whole frame, header included.
    ///
    /// The header is reserved first and filled in once the payload length is
    /// known, so the payload need not be sized in advance.
    pub fn encode_into(&self, out: &mut BytesMut) {
        let start = out.len();
        out.extend_from_slice(&[0u8; FRAME_HEADER_SIZE]);
        self.write_payload(out);

        let length = (out.len() - start - FRAME_HEADER_SIZE) as u32;
        let header = FrameHeader { length, kind: self.kind(), flags: self.flags(), stream_id: self.stream_id() };
        out[start..start + FRAME_HEADER_SIZE].copy_from_slice(&header.encode());
    }

    /// The whole frame as its own buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        self.encode_into(&mut out);
        out.to_vec()
    }

    /// Decodes a frame, copying its payload.
    ///
    /// # Errors
    ///
    /// As [`Frame::assemble`].
    pub fn decode(header: FrameHeader, payload: &[u8]) -> Result<Self, Error> {
        Self::assemble(header, payload, None)
    }

    /// [`Frame::decode`] over a shared buffer, so a body is referenced rather
    /// than copied.
    ///
    /// # Errors
    ///
    /// As [`Frame::assemble`].
    pub fn decode_shared(header: FrameHeader, payload: &Bytes) -> Result<Self, Error> {
        Self::assemble(header, payload.as_ref(), Some(payload))
    }

    /// Decodes a frame, referencing `shared` where one is given.
    ///
    /// Padding is stripped here, and a frame on the wrong kind of stream is
    /// rejected before its payload is looked at.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the payload does not match its
    /// declared length, when the frame is on a stream its type does not
    /// belong on, when padding runs past the payload, when a fixed-size
    /// frame is the wrong size, when a SETTINGS acknowledgement carries a
    /// payload or its length is not a multiple of six, or when a
    /// `WINDOW_UPDATE` increment is zero.
    pub fn assemble(header: FrameHeader, payload: &[u8], shared: Option<&Bytes>) -> Result<Self, Error> {
        if payload.len() != header.length as usize {
            return Err(Error::Protocol("frame payload does not match its declared length".into()));
        }

        let streamed = header.stream_id != StreamID(0);
        if header.kind.streamed().is_some_and(|expected| expected != streamed) {
            return Err(Error::Protocol(format!("{:?} frame on stream {}", header.kind, header.stream_id.0)));
        }

        let borrow = |slice: &[u8]| match shared {
            Some(whole) => whole.slice_ref(slice),
            None => Bytes::copy_from_slice(slice),
        };

        let stream_id = header.stream_id;
        let payload = if header.flags & PADDED != 0 && matches!(header.kind, FrameType::Data | FrameType::Headers | FrameType::PushPromise)
        {
            let padding = *payload.first().ok_or_else(|| Error::Protocol("padded frame is empty".into()))? as usize;
            payload
                .get(1..payload.len().checked_sub(padding).ok_or_else(|| {
                    Error::Protocol("padding is longer than the frame payload".into())
                })?)
                .ok_or_else(|| Error::Protocol("padding is longer than the frame payload".into()))?
        } else {
            payload
        };

        match header.kind {
            FrameType::Data => Ok(Self::Data {
                stream_id,
                end_stream: header.flags & END_STREAM != 0,
                data: borrow(payload),
            }),

            FrameType::Headers => {
                let block = if header.flags & PRIORITY != 0 {
                    payload.get(5..).ok_or_else(|| Error::Protocol("HEADERS is too short for its priority".into()))?
                } else {
                    payload
                };

                Ok(Self::Headers {
                    stream_id,
                    end_stream: header.flags & END_STREAM != 0,
                    end_headers: header.flags & END_HEADERS != 0,
                    block: borrow(block),
                })
            }

            FrameType::Priority => {
                let [a, b, c, d, weight] = exact::<5>(payload, "PRIORITY")?;
                let dependency = u32::from_be_bytes([a, b, c, d]);

                Ok(Self::Priority {
                    stream_id,
                    dependency: StreamID((dependency & MAXIMUM_WINDOW_SIZE) as u64),
                    exclusive: dependency & 0x8000_0000 != 0,
                    weight,
                })
            }

            FrameType::RstStream => {
                let error_code = u32::from_be_bytes(exact::<4>(payload, "RST_STREAM")?);
                Ok(Self::RstStream { stream_id, error_code })
            }

            FrameType::Settings => {
                let ack = header.flags & ACK != 0;

                if ack && !payload.is_empty() {
                    return Err(Error::Protocol("SETTINGS acknowledgement carries a payload".into()));
                }

                if !payload.len().is_multiple_of(6) {
                    return Err(Error::Protocol("SETTINGS length is not a multiple of six".into()));
                }

                let params = payload
                    .chunks_exact(6)
                    .map(|entry| {
                        (
                            u16::from_be_bytes([entry[0], entry[1]]),
                            u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
                        )
                    })
                    .collect();

                Ok(Self::Settings { ack, params })
            }

            FrameType::PushPromise => {
                if payload.len() < 4 {
                    return Err(Error::Protocol("PUSH_PROMISE is too short".into()));
                }

                let promised = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Self::PushPromise {
                    stream_id,
                    promised_stream_id: StreamID((promised & MAXIMUM_WINDOW_SIZE) as u64),
                    block: borrow(&payload[4..]),
                })
            }

            FrameType::Ping => Ok(Self::Ping {
                ack: header.flags & ACK != 0,
                payload: exact::<8>(payload, "PING")?,
            }),

            FrameType::GoAway => {
                if payload.len() < 8 {
                    return Err(Error::Protocol("GOAWAY is too short".into()));
                }

                let last = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Self::GoAway {
                    last_stream_id: StreamID((last & MAXIMUM_WINDOW_SIZE) as u64),
                    error_code: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
                    debug_data: payload[8..].to_vec(),
                })
            }

            FrameType::WindowUpdate => {
                let increment = u32::from_be_bytes(exact::<4>(payload, "WINDOW_UPDATE")?) & MAXIMUM_WINDOW_SIZE;

                if increment == 0 {
                    return Err(Error::Protocol("WINDOW_UPDATE increment is zero".into()));
                }

                Ok(Self::WindowUpdate { stream_id, increment })
            }

            FrameType::Continuation => Ok(Self::Continuation {
                stream_id,
                end_headers: header.flags & END_HEADERS != 0,
                block: borrow(payload),
            }),
        }
    }
}

/// Appends a frame straight from its parts, without building a [`Frame`].
///
/// This is the path body and field block writes take, where the payload is
/// already sitting in a buffer and a [`Frame`] would only copy it.
pub fn write_frame_into(out: &mut BytesMut, kind: FrameType, flags: u8, stream_id: StreamID, payload: &[u8]) {
    let header = FrameHeader { length: payload.len() as u32, kind, flags, stream_id };

    out.reserve(FRAME_HEADER_SIZE + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
}

/// Reads a payload that must be exactly `N` octets.
///
/// # Errors
///
/// Returns [`Error::Protocol`] when the payload is any other length.
pub fn exact<const N: usize>(payload: &[u8], name: &str) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(payload)
        .map_err(|_| Error::Protocol(format!("{name} length is {} rather than {N}", payload.len())))
}

/// The parameters one end of a connection has announced.
///
/// Each connection keeps two: what this end advertised, and what the peer did.
/// The defaults are what both ends must assume before any SETTINGS arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The HPACK dynamic table ceiling.
    pub header_table_size: u32,
    /// Whether server push is allowed. Always advertised off here.
    pub enable_push: bool,
    /// How many streams may be open at once; `None` leaves it unbounded.
    pub max_concurrent_streams: Option<u32>,
    /// The flow control window a new stream starts at.
    pub initial_window_size: u32,
    /// The largest frame payload that will be accepted.
    pub max_frame_size: u32,
    /// The largest decoded field section; `None` leaves it unbounded.
    pub max_header_list_size: Option<u32>,
    /// Whether extended CONNECT, and so WebSocket, is allowed.
    pub enable_connect_protocol: bool,
}

impl Settings {
    /// The parameters as they go on the wire.
    ///
    /// The two optional ones are omitted when unset rather than sent as a
    /// sentinel, since absent and unbounded are the same thing.
    pub fn parameters(&self) -> Vec<(u16, u32)> {
        let mut params = vec![
            (SETTINGS_HEADER_TABLE_SIZE, self.header_table_size),
            (SETTINGS_ENABLE_PUSH, u32::from(self.enable_push)),
            (SETTINGS_INITIAL_WINDOW_SIZE, self.initial_window_size),
            (SETTINGS_MAX_FRAME_SIZE, self.max_frame_size),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, u32::from(self.enable_connect_protocol)),
        ];

        if let Some(streams) = self.max_concurrent_streams {
            params.push((SETTINGS_MAX_CONCURRENT_STREAMS, streams));
        }

        if let Some(size) = self.max_header_list_size {
            params.push((SETTINGS_MAX_HEADER_LIST_SIZE, size));
        }

        params
    }

    /// Applies one parameter.
    ///
    /// Returns how much [`SETTINGS_INITIAL_WINDOW_SIZE`] moved, which every
    /// open stream's send window must be adjusted by; zero for every other
    /// parameter. Unknown identifiers are ignored, so extensions do not break
    /// the connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when a flag is neither zero nor one, when
    /// the window size is above [`MAXIMUM_WINDOW_SIZE`], or when the frame
    /// size is outside [`DEFAULT_MAX_FRAME_SIZE`]..=[`MAXIMUM_FRAME_SIZE`].
    pub fn apply(&mut self, id: u16, value: u32) -> Result<i64, Error> {
        match id {
            SETTINGS_HEADER_TABLE_SIZE => self.header_table_size = value,

            SETTINGS_ENABLE_PUSH => {
                if value > 1 {
                    return Err(Error::Protocol("SETTINGS_ENABLE_PUSH is not a flag".into()));
                }
                self.enable_push = value == 1;
            }

            SETTINGS_MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = Some(value),

            SETTINGS_INITIAL_WINDOW_SIZE => {
                if value > MAXIMUM_WINDOW_SIZE {
                    return Err(Error::Protocol("SETTINGS_INITIAL_WINDOW_SIZE is above the maximum".into()));
                }

                let change = value as i64 - self.initial_window_size as i64;
                self.initial_window_size = value;
                return Ok(change);
            }

            SETTINGS_MAX_FRAME_SIZE => {
                if !(DEFAULT_MAX_FRAME_SIZE..=MAXIMUM_FRAME_SIZE).contains(&value) {
                    return Err(Error::Protocol("SETTINGS_MAX_FRAME_SIZE is outside the permitted range".into()));
                }
                self.max_frame_size = value;
            }

            SETTINGS_MAX_HEADER_LIST_SIZE => self.max_header_list_size = Some(value),

            SETTINGS_ENABLE_CONNECT_PROTOCOL => {
                if value > 1 {
                    return Err(Error::Protocol("SETTINGS_ENABLE_CONNECT_PROTOCOL is not a flag".into()));
                }
                self.enable_connect_protocol = value == 1;
            }

            _ => {}
        }

        Ok(0)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: false,
            max_concurrent_streams: None,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
            enable_connect_protocol: true,
        }
    }
}

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

    pending_reset: Option<u64>,
}

impl H2Stream {
    /// An idle stream with the given starting windows.
    pub fn new(id: StreamID, window_local: i64, window_remote: i64) -> Self {
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
            pending_reset: None,
        }
    }

    /// Where the stream is in its lifetime.
    pub fn state(&self) -> StreamState {
        self.state
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
    limits: Limits,
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
    buffered_bound: u64,

    premature_resets: u32,
    idle_frames: u32,
    hsts: Option<crate::helpers::hsts::HstsPolicy>,
}

impl<T> H2Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// A connection over a transport nothing has been read from yet.
    ///
    /// The preface and the opening SETTINGS are not sent until the first
    /// [`H2Connection::start`], which every send and receive does for itself.
    pub fn new(transport: T, role: Role, id: ConnectionID, limits: Limits) -> Self {
        Self::resume(transport, role, id, limits, Buffer::new())
    }

    /// A connection over a transport that has already been read from.
    ///
    /// This is what preface sniffing on a plaintext port needs: the octets
    /// read to recognise HTTP/2 are handed over rather than lost.
    pub fn resume(transport: T, role: Role, id: ConnectionID, limits: Limits, buffer: Buffer) -> Self {
        let settings_local = Settings { max_concurrent_streams: Some(limits.max_concurrent_streams), ..Settings::default() };

        Self {
            transport,
            role,
            id,
            limits,
            buffer,
            streams: common::StreamMap::default(),
            hpack_encoder: HPACKEncoder::new(),
            hpack_decoder: HPACKDecoder::new(),
            settings_local,
            settings_remote: Settings::default(),
            window_local: DEFAULT_INITIAL_WINDOW_SIZE as i64,
            window_remote: DEFAULT_INITIAL_WINDOW_SIZE as i64,
            next_stream_id: if role.is_client() { 1 } else { 2 },
            highest_peer_stream_id: 0,
            started: false,
            goaway: None,
            ready: VecDeque::new(),
            out: BytesMut::new(),
            block: Vec::new(),
            buffered_bound: 0,

            premature_resets: 0,
            idle_frames: 0,
            hsts: None,
        }
    }

    /// Attaches an HSTS policy to be added to the responses this connection sends.
    pub fn with_hsts(mut self, hsts: Option<crate::helpers::hsts::HstsPolicy>) -> Self {
        self.hsts = hsts;
        self
    }

    /// The limits this connection holds itself to.
    pub fn limits(&self) -> &Limits {
        &self.limits
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
    /// [`PREFACE`], and otherwise as [`Buffer::require`].
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

        self.hpack_decoder.set_dynamic_table_size(self.settings_local.header_table_size as usize);
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
    /// The buffer is kept and reused, and given back with [`common::reclaim`]
    /// once it has grown past what an idle connection should hold.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] past [`Limits::write_timeout`], and
    /// [`Error::Io`] when the transport fails.
    pub async fn flush_out(&mut self) -> Result<(), Error> {
        if self.out.is_empty() {
            return Ok(());
        }

        let out = std::mem::take(&mut self.out);
        let transport = &mut self.transport;

        let result = common::within(self.limits.write_timeout, async move {
            transport.write_all(&out).await?;
            transport.flush().await.map(|()| out)
        })
        .await;

        match result? {
            Ok(out) => {
                self.out = out;
                self.out.clear();
                common::reclaim(&mut self.out);
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
            if let Some(message) = self.ready.pop_front() {
                return Ok(message);
            }

            if let Some(message) = self.pump().await? {
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
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when opening a stream would go past
    /// [`H2Connection::local_stream_ceiling`], and otherwise as
    /// [`common::fields`] and [`H2Connection::flush_out`].
    pub async fn send_message(&mut self, message: Message) -> Result<(), Error> {
        let mut message = message;
        if self.role.is_server() && message.is_response() {
            if self.hsts.is_some() {
                message.secure = true;
            }
            crate::finalizer::finalize_response(&mut message, crate::finalizer::date_cache(), self.hsts.as_ref());
        }

        self.start().await?;
        self.flush_resets().await?;

        let stream_id = match message.stream_id {
            Some(stream_id) => stream_id,
            None => {
                let ceiling = self.local_stream_ceiling();
                if self.streams.len() >= ceiling {
                    return Err(Error::Limit(format!("more than {ceiling} streams are open at once")));
                }

                let stream_id = StreamID(self.next_stream_id);
                self.next_stream_id += 2;
                stream_id
            }
        };

        self.streams.entry(stream_id).or_insert_with(|| {
            H2Stream::new(
                stream_id,
                self.settings_local.initial_window_size as i64,
                self.settings_remote.initial_window_size as i64,
            )
        });

        let fields = common::fields(&message)?;

        let mut block = std::mem::take(&mut self.block);
        block.clear();
        self.hpack_encoder.encode_into(&mut block, &fields);

        let body = match message.body.take() {
            Some(body) => Some(body.into_bytes().await?),
            None => None,
        };

        let body = body.filter(|body| !body.is_empty());
        let trailers = message.trailers.as_ref().filter(|trailers| !trailers.is_empty());

        let tunneling = message.method == Some(Method::CONNECT)
            || (matches!(message.status_code, Some(200..=299))
                && self.streams.get(&stream_id).is_some_and(|stream| stream.method == Some(Method::CONNECT)));

        let open = tunneling || message.is_informational();

        let end_stream = !open && body.is_none() && trailers.is_none();
        let written = self.write_block(stream_id, &block, end_stream).await;
        self.block = block;
        common::reclaim_octets(&mut self.block);
        written?;

        if let Some(body) = body {
            self.write_data(stream_id, &body, trailers.is_none()).await?;
        }

        if let Some(trailers) = trailers {
            let fields = trailers.iter().map(|(name, value)| HeaderField::new(name, value)).collect::<Vec<_>>();

            let mut block = std::mem::take(&mut self.block);
            block.clear();
            self.hpack_encoder.encode_into(&mut block, &fields);

            let written = self.write_block(stream_id, &block, true).await;
            self.block = block;
            common::reclaim_octets(&mut self.block);
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
        self.flush_out().await?;
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
            error_code: ENHANCE_YOUR_CALM,
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

    /// Reads one frame.
    ///
    /// `None` for a frame of unknown type, which has been read past and
    /// discarded rather than failing the connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when the frame is larger than this end
    /// advertised, and otherwise as [`Buffer::require`] and [`Frame::assemble`].
    pub async fn read_frame(&mut self) -> Result<Option<Frame>, Error> {
        let head = self.buffer.require(&mut self.transport, FRAME_HEADER_SIZE, self.limits.read_timeout).await?;
        let octets = <[u8; FRAME_HEADER_SIZE]>::try_from(head).map_err(|_| Error::Closed)?;
        let (length, header) = FrameHeader::decode(&octets);

        if length > self.settings_local.max_frame_size {
            return Err(Error::Limit(format!("frame of {length} octets exceeds the advertised maximum")));
        }

        self.buffer.require(&mut self.transport, FRAME_HEADER_SIZE + length as usize, self.limits.read_timeout).await?;
        self.buffer.consume(FRAME_HEADER_SIZE);
        let payload = self.buffer.take(length as usize).freeze();

        match header {
            Some(header) => Frame::decode_shared(header, &payload).map(Some),
            None => Ok(None),
        }
    }

    /// Reads and handles one frame, returning a message if that completed one.
    ///
    /// # Errors
    ///
    /// As [`H2Connection::read_frame`] and [`H2Connection::handle`].
    pub async fn pump(&mut self) -> Result<Option<Message>, Error> {
        self.start().await?;
        self.flush_resets().await?;

        self.flush_out().await?;

        let message = match self.read_frame().await? {
            Some(frame) => self.handle(frame).await?,
            None => None,
        };

        if self.buffer.is_empty() {
            self.flush_out().await?;
            self.buffer.reclaim();
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

                let table_size = (self.settings_remote.header_table_size as usize).min(MAXIMUM_ENCODER_TABLE_SIZE);
                self.hpack_encoder.set_dynamic_table_size(table_size);
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
                    if self.window_remote > MAXIMUM_WINDOW_SIZE as i64 {
                        return Err(Error::Protocol("connection send window overflowed".into()));
                    }
                    unblocked = stalled && self.window_remote > 0;
                } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                    let stalled = stream.window_remote <= 0;
                    stream.window_remote += increment as i64;
                    if stream.window_remote > MAXIMUM_WINDOW_SIZE as i64 {
                        let stream_id = stream.id;
                        self.reset(stream_id, FLOW_CONTROL_ERROR).await?;
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

                let stream = self.open_stream(stream_id)?;
                stream.window_local -= data.len() as i64;
                if stream.window_local < 0 {
                    self.reset(stream_id, FLOW_CONTROL_ERROR).await?;
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

                self.window_local -= data.len() as i64;
                if self.window_local < 0 {
                    return Err(Error::Protocol("connection receive window overflowed".into()));
                }

                if !data.is_empty() {
                    let increment = data.len() as u32;
                    self.queue(&Frame::WindowUpdate { stream_id: StreamID(0), increment });
                    self.window_local += increment as i64;

                    if self.streams.get(&stream_id).is_some_and(|stream| stream.state.receivable()) {
                        self.queue(&Frame::WindowUpdate { stream_id, increment });
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            stream.window_local += increment as i64;
                        }
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
    /// costs unbounded memory — and [`Error::Protocol`] when any other frame
    /// interrupts the block.
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

            match self.read_frame().await? {
                Some(Frame::Continuation { stream_id: other, end_headers, block }) if other == stream_id => {
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
            self.streams.insert(stream_id, H2Stream::new(stream_id, window_local, window_remote));
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
    /// [`common::message_from`].
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
        let stream = self.open_stream(stream_id)?;

        if let Some(message) = &mut stream.headers {
            let mut trailers = Headers::with_capacity(decoded.len());

            for field in decoded {
                if field.name.starts_with(':') {
                    return Err(Error::Protocol("trailer section carries a pseudo-header".into()));
                }

                trailers.append(field.name, field.value);
            }

            message.trailers = Some(trailers);
        } else {
            let mut message = common::message_from(decoded, Version::V2_0)?;
            message.stream_id = Some(stream_id);
            message.connection_id = Some(connection_id);

            if message.is_request() {
                stream.method = message.method;
            }

            if message.is_informational() {
                stream.state = if stream.state == StreamState::Idle { StreamState::Open } else { stream.state };
                return Ok(Some(message));
            }

            stream.headers = Some(message);
        }

        stream.state = if stream.state == StreamState::Idle { StreamState::Open } else { stream.state };

        let tunneling = stream.method == Some(Method::CONNECT)
            && stream.headers.as_ref().is_some_and(|message| {
                message.is_request() || matches!(message.status_code, Some(200..=299))
            });

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

        let end_headers = if rest.peek().is_none() { END_HEADERS } else { 0 };
        let flags = end_headers | if end_stream { END_STREAM } else { 0 };
        write_frame_into(&mut self.out, FrameType::Headers, flags, stream_id, first);

        while let Some(chunk) = rest.next() {
            let flags = if rest.peek().is_none() { END_HEADERS } else { 0 };
            write_frame_into(&mut self.out, FrameType::Continuation, flags, stream_id, chunk);
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
            let window = self.window_remote.min(self.streams.get(&stream_id).map(|stream| stream.window_remote).unwrap_or_default());

            if window <= 0 && !rest.is_empty() {
                if let Some(message) = self.pump().await? {
                    self.ready.push_back(message);
                }
                continue;
            }

            let size = rest.len().min(window.max(0) as usize).min(self.settings_remote.max_frame_size as usize);
            let (chunk, remaining) = rest.split_at(size);
            rest = remaining;

            let flags = if end_stream && rest.is_empty() { END_STREAM } else { 0 };
            write_frame_into(&mut self.out, FrameType::Data, flags, stream_id, chunk);

            if self.out.len() >= OUTPUT_HIGH_WATER {
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
        let (application, internal) = tokio::io::duplex(Buffer::CHUNK_SIZE);
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
        let mut scratch = vec![0u8; Buffer::CHUNK_SIZE];

        self.start().await?;

        loop {
            self.flush_out().await?;

            tokio::select! {
                biased;

                frame = self.read_frame() => {
                    if let Some(frame) = frame? {
                        self.handle(frame).await?;
                    }

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

    async fn send(&mut self, message: Message) -> Result<(), Error> {
        let timeout = self.limits.send_timeout;
        let sending = std::pin::pin!(self.send_message(message));
        common::within(timeout, sending).await?
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        let timeout = self.limits.receive_timeout;
        let receiving = std::pin::pin!(self.receive_message());
        common::within(timeout, receiving).await?
    }

    async fn close(&mut self) {
        let last_stream_id = StreamID(self.next_stream_id.saturating_sub(2));
        let goaway = Frame::GoAway { last_stream_id, error_code: NO_ERROR, debug_data: Vec::new() };

        let _ = self.write(&goaway).await;
        let _ = self.transport.shutdown().await;
    }
}
