//! The HTTP/3 frame layer and stream typing: RFC 9114 §7 and §6.2.
//!
//! Frames on and off the wire, and nothing else. There is no connection here,
//! no QUIC and no state machine — [`Frame::parse`] takes octets out of a buffer
//! and [`Frame::encode_into`] puts them back, so this module can be read,
//! tested and used on its own the way [`hpack`] and [`qpack`] can. It is the
//! HTTP/3 counterpart of [`h2::frames`], and is arranged the same way.
//!
//! [`StreamKind`] is the unidirectional stream typing of §6.2, and [`Settings`]
//! the parameter set the two ends exchange, kept here because a SETTINGS frame
//! is what carries it.
//!
//! [`hpack`]: crate::helpers::hpack
//! [`qpack`]: crate::helpers::qpack
//! [`h2::frames`]: crate::protocol::h2::frames

use bytes::{Bytes, BytesMut};

use crate::helpers::qpack;
use crate::protocol::common::Error;
use crate::protocol::quic::Varint;

/// The error codes a stream reset or connection close carries.
pub struct Code;

impl Code {
    /// The connection or stream ended cleanly.
    pub const NO_ERROR: u64 = 0x0100;
    /// A protocol violation with no better code.
    pub const GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
    /// Something failed on this end.
    pub const INTERNAL_ERROR: u64 = 0x0102;
    /// A stream was opened that should not have been.
    pub const STREAM_CREATION_ERROR: u64 = 0x0103;
    /// A stream the connection depends on was closed.
    pub const CLOSED_CRITICAL_STREAM: u64 = 0x0104;
    /// A frame arrived where it does not belong.
    pub const FRAME_UNEXPECTED: u64 = 0x0105;
    /// A frame is malformed.
    pub const FRAME_ERROR: u64 = 0x0106;
    /// The peer is generating excessive load.
    pub const EXCESSIVE_LOAD: u64 = 0x0107;
    /// An identifier was used outside its permitted range.
    pub const ID_ERROR: u64 = 0x0108;
    /// The settings are invalid.
    pub const SETTINGS_ERROR: u64 = 0x0109;
    /// The control stream carried no SETTINGS first.
    pub const MISSING_SETTINGS: u64 = 0x010a;
    /// The request was declined before any processing.
    pub const REQUEST_REJECTED: u64 = 0x010b;
    /// The request is no longer wanted.
    pub const REQUEST_CANCELLED: u64 = 0x010c;
    /// The stream ended before the message did.
    pub const REQUEST_INCOMPLETE: u64 = 0x010d;
    /// The message is malformed.
    pub const MESSAGE_ERROR: u64 = 0x010e;
    /// A tunnel failed.
    pub const CONNECT_ERROR: u64 = 0x010f;
    /// The peer should retry over an earlier version.
    pub const VERSION_FALLBACK: u64 = 0x0110;

    /// A field section could not be decoded.
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
    /// The encoder stream is unusable.
    pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x0201;
    /// The decoder stream is unusable.
    pub const QPACK_DECODER_STREAM_ERROR: u64 = 0x0202;
}

/// The kind of an HTTP/3 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// `DATA`: message body octets.
    Data,
    /// `HEADERS`: a QPACK-compressed field section.
    Headers,
    /// `CANCEL_PUSH`: a promised push is no longer wanted.
    CancelPush,
    /// `SETTINGS`: connection parameters, on the control stream.
    Settings,
    /// `PUSH_PROMISE`: a promised stream; refused here, since push is disabled.
    PushPromise,
    /// `GOAWAY`: no further requests will be accepted.
    GoAway,
    /// `MAX_PUSH_ID`: how far push identifiers may go.
    MaxPushID,
}

impl FrameType {
    /// Frame types reserved so that an HTTP/2 frame cannot be mistaken for
    /// one.
    ///
    /// A peer sending these is speaking the wrong protocol, and must be
    /// rejected rather than ignored.
    pub const RESERVED: &[u64] = &[0x02, 0x06, 0x08, 0x09];

    /// The type code that goes on the wire.
    pub fn code(&self) -> u64 {
        match self {
            Self::Data => 0x00,
            Self::Headers => 0x01,
            Self::CancelPush => 0x03,
            Self::Settings => 0x04,
            Self::PushPromise => 0x05,
            Self::GoAway => 0x07,
            Self::MaxPushID => 0x0d,
        }
    }

    /// The frame type a code names, or `None` for an unknown type.
    ///
    /// Unknown types are skipped rather than rejected, so extensions and
    /// greasing do not break the connection. [`FrameType::RESERVED`] are
    /// caught before this and rejected.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Headers),
            0x03 => Some(Self::CancelPush),
            0x04 => Some(Self::Settings),
            0x05 => Some(Self::PushPromise),
            0x07 => Some(Self::GoAway),
            0x0d => Some(Self::MaxPushID),
            _ => None,
        }
    }
}

/// One decoded HTTP/3 frame.
///
/// There is no stream identifier here: the stream is whichever one the frame
/// arrived on, since QUIC keeps them apart.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// Message body octets.
    Data(Bytes),
    /// A QPACK-compressed field section.
    Headers(Bytes),
    /// A promised push is no longer wanted.
    CancelPush {
        /// The push being cancelled.
        push_id: u64,
    },
    /// Connection parameters, as identifier and value pairs.
    Settings(Vec<(u64, u64)>),
    /// A promised stream. Refused here, since push is disabled.
    PushPromise {
        /// The push being promised.
        push_id: u64,
        /// The compressed field block of the promised request.
        block: Bytes,
    },
    /// No further requests will be accepted.
    GoAway {
        /// The last request or push that may still be processed.
        id: u64,
    },
    /// How far push identifiers may go.
    MaxPushID {
        /// The new ceiling.
        push_id: u64,
    },
}

impl Frame {
    /// Takes one whole frame off the front of a buffer.
    ///
    /// `None` when the frame has not fully arrived; the buffer is left untouched
    /// so the call can be repeated as more octets come in. Frames of unknown type
    /// are consumed and skipped over rather than returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for a [`FrameType::RESERVED`] frame, which
    /// means the peer is speaking HTTP/2, and otherwise as [`Frame::assemble`].
    pub fn parse(buffer: &mut BytesMut) -> Result<Option<Frame>, Error> {
        loop {
            let (consumed, code, length) = {
                let data = &buffer[..];
                let (taken, code) = Varint::decode(data);
                let (took, length) = Varint::decode(&data[taken.min(data.len())..]);

                if taken == 0 || took == 0 || data.len() < taken + took + length as usize {
                    (0, 0, 0)
                } else {
                    (taken + took, code, length)
                }
            };

            if consumed == 0 {
                return Ok(None);
            }

            if FrameType::RESERVED.contains(&code) {
                return Err(Error::Protocol(format!("frame type {code:#x} is reserved")));
            }

            let mut frame = buffer.split_to(consumed + length as usize).freeze();
            let payload = frame.split_off(consumed);

            match FrameType::from_code(code) {
                Some(kind) => return Frame::decode_shared(kind, &payload).map(Some),
                None => continue,
            }
        }
    }

    /// The frame's type.
    pub fn kind(&self) -> FrameType {
        match self {
            Self::Data(_) => FrameType::Data,
            Self::Headers(_) => FrameType::Headers,
            Self::CancelPush { .. } => FrameType::CancelPush,
            Self::Settings(_) => FrameType::Settings,
            Self::PushPromise { .. } => FrameType::PushPromise,
            Self::GoAway { .. } => FrameType::GoAway,
            Self::MaxPushID { .. } => FrameType::MaxPushID,
        }
    }

    /// Appends the payload, without the type and length that precede it.
    pub fn write_payload(&self, out: &mut BytesMut) {
        match self {
            Self::Data(data) | Self::Headers(data) => out.extend_from_slice(data),

            Self::CancelPush { push_id } | Self::MaxPushID { push_id } => Varint::encode(out, *push_id),

            Self::GoAway { id } => Varint::encode(out, *id),

            Self::Settings(params) => {
                for (id, value) in params {
                    Varint::encode(out, *id);
                    Varint::encode(out, *value);
                }
            }

            Self::PushPromise { push_id, block } => {
                Varint::encode(out, *push_id);
                out.extend_from_slice(block);
            }
        }
    }

    /// How long the payload will be, worked out without writing it.
    ///
    /// The length precedes the payload on the wire, so it has to be known
    /// first.
    pub fn payload_len(&self) -> usize {
        match self {
            Self::Data(data) | Self::Headers(data) => data.len(),

            Self::CancelPush { push_id } | Self::MaxPushID { push_id } => Varint::len(*push_id),

            Self::GoAway { id } => Varint::len(*id),

            Self::Settings(params) => {
                params.iter().map(|(id, value)| Varint::len(*id) + Varint::len(*value)).sum()
            }

            Self::PushPromise { push_id, block } => Varint::len(*push_id) + block.len(),
        }
    }

    /// The payload on its own.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.payload_len());
        self.write_payload(&mut out);
        out.into()
    }

    /// Appends the whole frame: type, length, payload.
    ///
    /// # Panics
    ///
    /// Debug builds assert that [`Frame::payload_len`] agreed with what
    /// [`Frame::write_payload`] actually wrote; if they disagreed the length
    /// on the wire would be wrong and the stream unreadable.
    pub fn encode_into(&self, out: &mut BytesMut) {
        let length = self.payload_len();

        out.reserve(length + 2 * Varint::len(Varint::MAXIMUM));
        Varint::encode(out, self.kind().code());
        Varint::encode(out, length as u64);

        let start = out.len();
        self.write_payload(out);
        debug_assert_eq!(out.len() - start, length, "payload_len disagreed with write_payload");
    }

    /// The whole frame as its own buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.payload_len() + 2 * Varint::len(Varint::MAXIMUM));
        self.encode_into(&mut out);
        out.into()
    }

    /// Decodes a frame payload, copying it.
    ///
    /// # Errors
    ///
    /// As [`Frame::assemble`].
    pub fn decode(kind: FrameType, payload: &[u8]) -> Result<Self, Error> {
        Self::assemble(kind, payload, None)
    }

    /// [`Frame::decode`] over a shared buffer, so a body is referenced rather
    /// than copied.
    ///
    /// # Errors
    ///
    /// As [`Frame::assemble`].
    pub fn decode_shared(kind: FrameType, payload: &Bytes) -> Result<Self, Error> {
        Self::assemble(kind, payload.as_ref(), Some(payload))
    }

    /// Decodes a frame payload, referencing `shared` where one is given.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when a payload that must be a single
    /// variable-length integer is not, when SETTINGS ends inside a parameter
    /// or repeats one, or when PUSH_PROMISE carries no push identifier.
    pub fn assemble(kind: FrameType, payload: &[u8], shared: Option<&Bytes>) -> Result<Self, Error> {
        let borrow = |slice: &[u8]| match shared {
            Some(whole) => whole.slice_ref(slice),
            None => Bytes::copy_from_slice(slice),
        };

        match kind {
            FrameType::Data => Ok(Self::Data(borrow(payload))),
            FrameType::Headers => Ok(Self::Headers(borrow(payload))),

            FrameType::CancelPush => Ok(Self::CancelPush { push_id: Varint::only(payload, "CANCEL_PUSH")? }),
            FrameType::MaxPushID => Ok(Self::MaxPushID { push_id: Varint::only(payload, "MAX_PUSH_ID")? }),
            FrameType::GoAway => Ok(Self::GoAway { id: Varint::only(payload, "GOAWAY")? }),

            FrameType::Settings => {
                let mut rest = payload;
                let mut params = Vec::new();

                while !rest.is_empty() {
                    let (consumed, id) = Varint::decode(rest);
                    let (taken, value) = Varint::decode(&rest[consumed..]);

                    if consumed == 0 || taken == 0 {
                        return Err(Error::Protocol("SETTINGS ends inside a parameter".into()));
                    }

                    if params.iter().any(|(other, _)| *other == id) {
                        return Err(Error::Protocol(format!("setting {id:#x} is repeated")));
                    }

                    params.push((id, value));
                    rest = &rest[consumed + taken..];
                }

                Ok(Self::Settings(params))
            }

            FrameType::PushPromise => {
                let (consumed, push_id) = Varint::decode(payload);
                if consumed == 0 {
                    return Err(Error::Protocol("PUSH_PROMISE has no push identifier".into()));
                }

                Ok(Self::PushPromise { push_id, block: borrow(&payload[consumed..]) })
            }
        }
    }
}

/// What a stream is for.
///
/// A unidirectional stream announces its kind with a code at the front; a
/// bidirectional one carries a request and has no such prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// The control stream, carrying SETTINGS and connection-wide frames.
    Control,
    /// A push stream. Not opened here, since push is disabled.
    Push,
    /// The QPACK encoder stream, carrying table insertions.
    QPACKEncoder,
    /// The QPACK decoder stream, carrying acknowledgements.
    QPACKDecoder,
    /// A bidirectional request stream.
    Request,
}

impl StreamKind {
    /// The code a unidirectional stream announces itself with, or `None` for
    /// [`StreamKind::Request`], which is bidirectional and announces nothing.
    pub fn code(&self) -> Option<u64> {
        match self {
            Self::Control => Some(0x00),
            Self::Push => Some(0x01),
            Self::QPACKEncoder => Some(0x02),
            Self::QPACKDecoder => Some(0x03),
            Self::Request => None,
        }
    }

    /// The stream kind a code names, or `None` for an unknown one.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x00 => Some(Self::Control),
            0x01 => Some(Self::Push),
            0x02 => Some(Self::QPACKEncoder),
            0x03 => Some(Self::QPACKDecoder),
            _ => None,
        }
    }
}

/// The parameters one end of a connection has announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The QPACK dynamic table capacity this end is willing to hold.
    pub qpack_max_table_capacity: u64,
    /// How many streams may be QPACK-blocked at once.
    pub qpack_blocked_streams: u64,
    /// The largest decoded field section; `None` leaves it unbounded.
    pub max_field_section_size: Option<u64>,
    /// Whether extended CONNECT, and so WebSocket, is allowed.
    pub enable_connect_protocol: bool,
}

impl Settings {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`: the QPACK dynamic table ceiling.
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`: the largest decoded field section.
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    /// `SETTINGS_QPACK_BLOCKED_STREAMS`: how many streams may be blocked at once.
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`: whether extended CONNECT is allowed.
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

    /// Settings reserved so that an HTTP/2 setting cannot be mistaken for
    /// one, from HTTP/2's identifiers.
    pub const RESERVED: &[u64] = &[0x00, 0x02, 0x03, 0x04, 0x05];

    /// The parameters as they go on the wire.
    pub fn parameters(&self) -> Vec<(u64, u64)> {
        let mut params = vec![
            (Settings::QPACK_MAX_TABLE_CAPACITY, self.qpack_max_table_capacity),
            (Settings::QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams),
            (Settings::ENABLE_CONNECT_PROTOCOL, u64::from(self.enable_connect_protocol)),
        ];

        if let Some(size) = self.max_field_section_size {
            params.push((Settings::MAX_FIELD_SECTION_SIZE, size));
        }

        params
    }

    /// What a peer must be assumed to have advertised before its SETTINGS
    /// arrives.
    ///
    /// Conservative throughout: no dynamic table, no blocked streams, no
    /// extended CONNECT — nothing that could be got wrong by assuming it.
    /// This is the base a peer's parameters are applied onto, not
    /// [`Settings::default`], which is what this end advertises.
    pub fn peer() -> Self {
        Self {
            qpack_max_table_capacity: qpack::DynamicTable::DEFAULT_CAPACITY as u64,
            qpack_blocked_streams: 0,
            max_field_section_size: None,
            enable_connect_protocol: false,
        }
    }

    /// Applies one parameter.
    ///
    /// Unknown identifiers are ignored, so extensions and greasing do not
    /// break the connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for a [`Settings::RESERVED`] identifier,
    /// which means the peer is speaking HTTP/2, and for a flag that is
    /// neither zero nor one.
    pub fn apply(&mut self, id: u64, value: u64) -> Result<(), Error> {
        if Settings::RESERVED.contains(&id) {
            return Err(Error::Protocol(format!("setting {id:#x} is reserved")));
        }

        match id {
            Settings::QPACK_MAX_TABLE_CAPACITY => self.qpack_max_table_capacity = value,
            Settings::QPACK_BLOCKED_STREAMS => self.qpack_blocked_streams = value,
            Settings::MAX_FIELD_SECTION_SIZE => self.max_field_section_size = Some(value),

            Settings::ENABLE_CONNECT_PROTOCOL => {
                if value > 1 {
                    return Err(Error::Protocol("SETTINGS_ENABLE_CONNECT_PROTOCOL is not a flag".into()));
                }
                self.enable_connect_protocol = value == 1;
            }

            _ => {}
        }

        Ok(())
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            qpack_max_table_capacity: qpack::Decoder::DEFAULT_MAX_CAPACITY as u64,
            qpack_blocked_streams: qpack::Decoder::DEFAULT_MAX_BLOCKED_STREAMS as u64,
            max_field_section_size: None,
            enable_connect_protocol: true,
        }
    }
}

