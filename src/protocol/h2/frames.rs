//! The HTTP/2 frame layer: RFC 9113 §4 and §6.
//!
//! Frames on and off the wire, and nothing else. There is no connection here,
//! no transport and no state machine — [`Frame::parse`] takes octets out of a
//! buffer and [`Frame::encode_into`] puts them back, so this module can be read,
//! tested and used on its own the way [`hpack`] and [`qpack`] can.
//!
//! [`Settings`] is the parameter set the two ends exchange, kept here because a
//! SETTINGS frame is what carries it.
//!
//! [`hpack`]: crate::helpers::hpack
//! [`qpack`]: crate::helpers::qpack

use bytes::{Bytes, BytesMut};

use crate::helpers::hpack;
use crate::models::StreamID;
use crate::protocol::common::Error;

/// The octets a client sends before anything else, to prove it means HTTP/2.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The error codes a RST_STREAM or GOAWAY frame carries.
pub struct Code;

impl Code {
    /// The connection or stream ended cleanly.
    pub const NO_ERROR: u32 = 0x0;
    /// The peer broke the protocol.
    pub const PROTOCOL_ERROR: u32 = 0x1;
    /// Something failed on this end.
    pub const INTERNAL_ERROR: u32 = 0x2;
    /// The peer sent past its window, or overflowed one.
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    /// Settings went unacknowledged too long.
    pub const SETTINGS_TIMEOUT: u32 = 0x4;
    /// A frame arrived for a stream that had finished.
    pub const STREAM_CLOSED: u32 = 0x5;
    /// A frame's length is wrong for its type.
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    /// The stream was declined before any processing.
    pub const REFUSED_STREAM: u32 = 0x7;
    /// The stream is no longer wanted.
    pub const CANCEL: u32 = 0x8;
    /// The HPACK state cannot be maintained.
    pub const COMPRESSION_ERROR: u32 = 0x9;
    /// A tunnel failed.
    pub const CONNECT_ERROR: u32 = 0xa;
    /// The peer is generating excessive load.
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;
    /// The transport does not meet the requirements.
    pub const INADEQUATE_SECURITY: u32 = 0xc;
    /// The peer should retry over HTTP/1.1.
    pub const HTTP_1_1_REQUIRED: u32 = 0xd;
}

/// The flags a frame header carries.
pub struct Flag;

impl Flag {
    /// This is the last frame this end will send on the stream.
    pub const END_STREAM: u8 = 0x1;
    /// This SETTINGS or PING acknowledges the peer's.
    ///
    /// The same bit as [`Flag::END_STREAM`], on frame types where that has no
    /// meaning.
    pub const ACK: u8 = 0x1;
    /// The field section ends here, with no CONTINUATION to follow.
    pub const END_HEADERS: u8 = 0x4;
    /// The payload begins with a padding length and ends with padding.
    pub const PADDED: u8 = 0x8;
    /// A HEADERS frame carries priority information before its block.
    pub const PRIORITY: u8 = 0x20;
}

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
    /// Appends a frame straight from its parts, without building a [`Frame`].
    ///
    /// This is the path body and field block writes take, where the payload is
    /// already sitting in a buffer and a [`Frame`] would only copy it.
    pub fn write(out: &mut BytesMut, kind: FrameType, flags: u8, stream_id: StreamID, payload: &[u8]) {
        let header = FrameHeader { length: payload.len() as u32, kind, flags, stream_id };

        out.reserve(FrameHeader::SIZE + payload.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(payload);
    }

    /// The fixed size of a frame header on the wire.
    pub const SIZE: usize = 9;

    /// Encodes the header.
    pub fn encode(&self) -> [u8; FrameHeader::SIZE] {
        let length = self.length.to_be_bytes();
        let stream_id = (self.stream_id.0 as u32 & Settings::MAXIMUM_WINDOW_SIZE).to_be_bytes();

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
    pub fn decode(octets: &[u8; FrameHeader::SIZE]) -> (u32, Option<Self>) {
        let length = u32::from_be_bytes([0, octets[0], octets[1], octets[2]]);
        let stream_id = u32::from_be_bytes([octets[5], octets[6], octets[7], octets[8]]) & Settings::MAXIMUM_WINDOW_SIZE;

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
    /// Reads a payload that must be exactly `N` octets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the payload is any other length.
    pub fn exact<const N: usize>(payload: &[u8], name: &str) -> Result<[u8; N], Error> {
        <[u8; N]>::try_from(payload)
            .map_err(|_| Error::Protocol(format!("{name} length is {} rather than {N}", payload.len())))
    }

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
    /// Frames written here are never padded, so [`Flag::PADDED`] is never set.
    pub fn flags(&self) -> u8 {
        match self {
            Self::Data { end_stream, .. } => u8::from(*end_stream) * Flag::END_STREAM,
            Self::Headers { end_stream, end_headers, .. } => {
                (u8::from(*end_stream) * Flag::END_STREAM) | (u8::from(*end_headers) * Flag::END_HEADERS)
            }
            Self::Settings { ack, .. } | Self::Ping { ack, .. } => u8::from(*ack) * Flag::ACK,
            Self::PushPromise { .. } => Flag::END_HEADERS,
            Self::Continuation { end_headers, .. } => u8::from(*end_headers) * Flag::END_HEADERS,
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
        out.extend_from_slice(&[0u8; FrameHeader::SIZE]);
        self.write_payload(out);

        let length = (out.len() - start - FrameHeader::SIZE) as u32;
        let header = FrameHeader { length, kind: self.kind(), flags: self.flags(), stream_id: self.stream_id() };
        out[start..start + FrameHeader::SIZE].copy_from_slice(&header.encode());
    }

    /// The whole frame as its own buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        self.encode_into(&mut out);
        out.to_vec()
    }

    /// Takes one whole frame off the front of a buffer.
    ///
    /// `None` when the frame has not fully arrived; the buffer is left
    /// untouched so the call can be repeated as more octets come in. Frames of
    /// unknown type are consumed and skipped over rather than returned, as RFC
    /// 9113 §4.1 requires.
    ///
    /// `max_frame_size` is what this end advertised in
    /// [`Settings::MAX_FRAME_SIZE`], which is the largest payload a peer may
    /// send; it is a parameter rather than a constant because the two ends
    /// advertise their own.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] for a frame larger than `max_frame_size`, and
    /// otherwise as [`Frame::assemble`].
    pub fn parse(buffer: &mut BytesMut, max_frame_size: u32) -> Result<Option<Frame>, Error> {
        loop {
            match Self::take(buffer, max_frame_size)? {
                Some(Ok(frame)) => return Ok(Some(frame)),
                Some(Err(_)) => continue,
                None => return Ok(None),
            }
        }
    }

    /// [`Frame::parse`], reporting a frame of unknown type rather than reading
    /// past it.
    ///
    /// The octets are consumed either way — an unknown frame still has to be
    /// stepped over — but its type code comes back, so a caller that may not
    /// have one arrive can say so. That is what gathering a field block needs:
    /// RFC 9113 §6.10 admits nothing between a HEADERS frame and the
    /// CONTINUATION frames that finish it, and one skipped quietly is one that
    /// got between them unnoticed.
    ///
    /// # Errors
    ///
    /// As [`Frame::parse`].
    pub fn take(buffer: &mut BytesMut, max_frame_size: u32) -> Result<Option<Result<Frame, u8>>, Error> {
        let Some(octets) = buffer.get(..FrameHeader::SIZE) else {
            return Ok(None);
        };

        let octets = <[u8; FrameHeader::SIZE]>::try_from(octets).unwrap_or([0; FrameHeader::SIZE]);
        let (length, header) = FrameHeader::decode(&octets);

        if length > max_frame_size {
            return Err(Error::Limit(format!("frame of {length} octets exceeds the advertised maximum")));
        }

        let whole = FrameHeader::SIZE + length as usize;
        if buffer.len() < whole {
            return Ok(None);
        }

        let mut frame = buffer.split_to(whole).freeze();
        let payload = frame.split_off(FrameHeader::SIZE);

        match header {
            Some(header) => Frame::decode_shared(header, &payload).map(|frame| Some(Ok(frame))),
            None => Ok(Some(Err(octets[3]))),
        }
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
    /// belong on, when padding runs past the payload, when a HEADERS,
    /// PUSH_PROMISE or GOAWAY payload is too short for its fixed fields, when
    /// a fixed-size frame is the wrong size, when a SETTINGS acknowledgement
    /// carries a payload or its length is not a multiple of six, or when a
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
        let payload = if header.flags & Flag::PADDED != 0 && matches!(header.kind, FrameType::Data | FrameType::Headers | FrameType::PushPromise)
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
                end_stream: header.flags & Flag::END_STREAM != 0,
                data: borrow(payload),
            }),

            FrameType::Headers => {
                let block = if header.flags & Flag::PRIORITY != 0 {
                    payload.get(5..).ok_or_else(|| Error::Protocol("HEADERS is too short for its priority".into()))?
                } else {
                    payload
                };

                Ok(Self::Headers {
                    stream_id,
                    end_stream: header.flags & Flag::END_STREAM != 0,
                    end_headers: header.flags & Flag::END_HEADERS != 0,
                    block: borrow(block),
                })
            }

            FrameType::Priority => {
                let [a, b, c, d, weight] = Self::exact::<5>(payload, "PRIORITY")?;
                let dependency = u32::from_be_bytes([a, b, c, d]);

                Ok(Self::Priority {
                    stream_id,
                    dependency: StreamID((dependency & Settings::MAXIMUM_WINDOW_SIZE) as u64),
                    exclusive: dependency & 0x8000_0000 != 0,
                    weight,
                })
            }

            FrameType::RstStream => {
                let error_code = u32::from_be_bytes(Self::exact::<4>(payload, "RST_STREAM")?);
                Ok(Self::RstStream { stream_id, error_code })
            }

            FrameType::Settings => {
                let ack = header.flags & Flag::ACK != 0;

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
                    promised_stream_id: StreamID((promised & Settings::MAXIMUM_WINDOW_SIZE) as u64),
                    block: borrow(&payload[4..]),
                })
            }

            FrameType::Ping => Ok(Self::Ping {
                ack: header.flags & Flag::ACK != 0,
                payload: Self::exact::<8>(payload, "PING")?,
            }),

            FrameType::GoAway => {
                if payload.len() < 8 {
                    return Err(Error::Protocol("GOAWAY is too short".into()));
                }

                let last = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Self::GoAway {
                    last_stream_id: StreamID((last & Settings::MAXIMUM_WINDOW_SIZE) as u64),
                    error_code: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
                    debug_data: payload[8..].to_vec(),
                })
            }

            FrameType::WindowUpdate => {
                let increment = u32::from_be_bytes(Self::exact::<4>(payload, "WINDOW_UPDATE")?) & Settings::MAXIMUM_WINDOW_SIZE;

                if increment == 0 {
                    return Err(Error::Protocol("WINDOW_UPDATE increment is zero".into()));
                }

                Ok(Self::WindowUpdate { stream_id, increment })
            }

            FrameType::Continuation => Ok(Self::Continuation {
                stream_id,
                end_headers: header.flags & Flag::END_HEADERS != 0,
                block: borrow(payload),
            }),
        }
    }
}

/// The parameters one end of a connection has announced.
///
/// Each connection keeps two: what this end advertised, which starts at
/// [`Settings::default`], and what the peer did, which starts at
/// [`Settings::peer`] until its SETTINGS arrives.
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
    /// `SETTINGS_HEADER_TABLE_SIZE`: the peer's HPACK dynamic table ceiling.
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    /// `SETTINGS_ENABLE_PUSH`: whether server push is allowed.
    pub const ENABLE_PUSH: u16 = 0x2;
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`: how many streams may be open at once.
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    /// `SETTINGS_INITIAL_WINDOW_SIZE`: the flow control window a new stream starts at.
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    /// `SETTINGS_MAX_FRAME_SIZE`: the largest frame payload the peer will accept.
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`: the largest decoded field section.
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`: whether extended CONNECT is allowed.
    ///
    /// This is what WebSocket over HTTP/2 is carried by.
    pub const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;

    /// The flow control window both ends assume before any setting says otherwise.
    pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;
    /// The frame size both ends assume, and the smallest that may be negotiated.
    pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
    /// The largest frame size that may be negotiated.
    pub const MAXIMUM_FRAME_SIZE: u32 = 16_777_215;
    /// The largest a flow control window may reach, and the stream identifier mask.
    pub const MAXIMUM_WINDOW_SIZE: u32 = 0x7fff_ffff;

    /// What a peer must be assumed to have advertised before its SETTINGS
    /// arrives.
    ///
    /// The initial values of RFC 9113 §6.5.2 and RFC 8441 §3, which are not
    /// the same thing as what this end advertises: server push is permitted
    /// until a peer says otherwise, and extended CONNECT is not. This is the
    /// base a peer's parameters are applied onto, not [`Settings::default`].
    pub fn peer() -> Self {
        Self {
            header_table_size: hpack::DynamicTable::DEFAULT_CAPACITY as u32,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: Settings::DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: Settings::DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
            enable_connect_protocol: false,
        }
    }

    /// The parameters as they go on the wire.
    ///
    /// The two optional ones are omitted when unset rather than sent as a
    /// sentinel, since absent and unbounded are the same thing.
    pub fn parameters(&self) -> Vec<(u16, u32)> {
        let mut params = vec![
            (Settings::HEADER_TABLE_SIZE, self.header_table_size),
            (Settings::ENABLE_PUSH, u32::from(self.enable_push)),
            (Settings::INITIAL_WINDOW_SIZE, self.initial_window_size),
            (Settings::MAX_FRAME_SIZE, self.max_frame_size),
            (Settings::ENABLE_CONNECT_PROTOCOL, u32::from(self.enable_connect_protocol)),
        ];

        if let Some(streams) = self.max_concurrent_streams {
            params.push((Settings::MAX_CONCURRENT_STREAMS, streams));
        }

        if let Some(size) = self.max_header_list_size {
            params.push((Settings::MAX_HEADER_LIST_SIZE, size));
        }

        params
    }

    /// Applies one parameter.
    ///
    /// Returns how much [`Settings::INITIAL_WINDOW_SIZE`] moved, which every
    /// open stream's send window must be adjusted by; zero for every other
    /// parameter. Unknown identifiers are ignored, so extensions do not break
    /// the connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when a flag is neither zero nor one, when
    /// the window size is above [`Settings::MAXIMUM_WINDOW_SIZE`], or when the frame
    /// size is outside [`Settings::DEFAULT_MAX_FRAME_SIZE`]..=[`Settings::MAXIMUM_FRAME_SIZE`].
    pub fn apply(&mut self, id: u16, value: u32) -> Result<i64, Error> {
        match id {
            Settings::HEADER_TABLE_SIZE => self.header_table_size = value,

            Settings::ENABLE_PUSH => {
                if value > 1 {
                    return Err(Error::Protocol("SETTINGS_ENABLE_PUSH is not a flag".into()));
                }
                self.enable_push = value == 1;
            }

            Settings::MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = Some(value),

            Settings::INITIAL_WINDOW_SIZE => {
                if value > Settings::MAXIMUM_WINDOW_SIZE {
                    return Err(Error::Protocol("SETTINGS_INITIAL_WINDOW_SIZE is above the maximum".into()));
                }

                let change = value as i64 - self.initial_window_size as i64;
                self.initial_window_size = value;
                return Ok(change);
            }

            Settings::MAX_FRAME_SIZE => {
                if !(Settings::DEFAULT_MAX_FRAME_SIZE..=Settings::MAXIMUM_FRAME_SIZE).contains(&value) {
                    return Err(Error::Protocol("SETTINGS_MAX_FRAME_SIZE is outside the permitted range".into()));
                }
                self.max_frame_size = value;
            }

            Settings::MAX_HEADER_LIST_SIZE => self.max_header_list_size = Some(value),

            Settings::ENABLE_CONNECT_PROTOCOL => {
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
            header_table_size: hpack::DynamicTable::DEFAULT_CAPACITY as u32,
            enable_push: false,
            max_concurrent_streams: None,
            initial_window_size: Settings::DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: Settings::DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
            enable_connect_protocol: true,
        }
    }
}

