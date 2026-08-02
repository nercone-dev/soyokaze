use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};
use tokio_quiche::quic::{HandshakeInfo, QuicheConnection};
use tokio_quiche::{ApplicationOverQuic, BoxError, QuicResult};

use crate::helpers::hpack::HeaderField;
use crate::helpers::qpack::{self, Decoder, DecoderInstruction, Encoder, EncoderInstruction};
use crate::models::{Body, ConnectionID, Headers, Limits, Message, Method, Role, StreamID, Version};
use crate::protocol::common::{self, Connection, Error};

pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

pub const RESERVED_FRAME_TYPES: &[u64] = &[0x02, 0x06, 0x08, 0x09];
pub const RESERVED_SETTINGS: &[u64] = &[0x00, 0x02, 0x03, 0x04, 0x05];

pub const H3_NO_ERROR: u64 = 0x0100;
pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
pub const H3_INTERNAL_ERROR: u64 = 0x0102;
pub const H3_STREAM_CREATION_ERROR: u64 = 0x0103;
pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;
pub const H3_FRAME_UNEXPECTED: u64 = 0x0105;
pub const H3_FRAME_ERROR: u64 = 0x0106;
pub const H3_EXCESSIVE_LOAD: u64 = 0x0107;
pub const H3_ID_ERROR: u64 = 0x0108;
pub const H3_SETTINGS_ERROR: u64 = 0x0109;
pub const H3_MISSING_SETTINGS: u64 = 0x010a;
pub const H3_REQUEST_REJECTED: u64 = 0x010b;
pub const H3_REQUEST_CANCELLED: u64 = 0x010c;
pub const H3_REQUEST_INCOMPLETE: u64 = 0x010d;
pub const H3_MESSAGE_ERROR: u64 = 0x010e;
pub const H3_CONNECT_ERROR: u64 = 0x010f;
pub const H3_VERSION_FALLBACK: u64 = 0x0110;

pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x0201;
pub const QPACK_DECODER_STREAM_ERROR: u64 = 0x0202;

pub const MAXIMUM_VARINT: u64 = (1 << 62) - 1;
pub const MAX_VARINT_SIZE: usize = 8;

pub const TUNNEL_BACKLOG: usize = 32;

pub fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

pub fn encode_varint(out: &mut impl bytes::BufMut, value: u64) {
    match varint_len(value) {
        1 => out.put_u8(value as u8),
        2 => out.put_slice(&(value as u16 | 0x4000).to_be_bytes()),
        4 => out.put_slice(&(value as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.put_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

pub fn decode_varint(input: &[u8]) -> (usize, u64) {
    let Some(first) = input.first() else {
        return (0, 0);
    };

    let length = 1 << (first >> 6);
    if input.len() < length {
        return (0, 0);
    }

    let mut value = (first & 0x3f) as u64;
    for octet in &input[1..length] {
        value = value << 8 | *octet as u64;
    }

    (length, value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    GoAway,
    MaxPushID,
}

impl FrameType {
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

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Data(Bytes),
    Headers(Bytes),
    CancelPush { push_id: u64 },
    Settings(Vec<(u64, u64)>),
    PushPromise { push_id: u64, block: Bytes },
    GoAway { id: u64 },
    MaxPushID { push_id: u64 },
}

impl Frame {
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

    pub fn write_payload(&self, out: &mut BytesMut) {
        match self {
            Self::Data(data) | Self::Headers(data) => out.extend_from_slice(data),

            Self::CancelPush { push_id } | Self::MaxPushID { push_id } => encode_varint(out, *push_id),

            Self::GoAway { id } => encode_varint(out, *id),

            Self::Settings(params) => {
                for (id, value) in params {
                    encode_varint(out, *id);
                    encode_varint(out, *value);
                }
            }

            Self::PushPromise { push_id, block } => {
                encode_varint(out, *push_id);
                out.extend_from_slice(block);
            }
        }
    }

    pub fn payload_len(&self) -> usize {
        match self {
            Self::Data(data) | Self::Headers(data) => data.len(),

            Self::CancelPush { push_id } | Self::MaxPushID { push_id } => varint_len(*push_id),

            Self::GoAway { id } => varint_len(*id),

            Self::Settings(params) => {
                params.iter().map(|(id, value)| varint_len(*id) + varint_len(*value)).sum()
            }

            Self::PushPromise { push_id, block } => varint_len(*push_id) + block.len(),
        }
    }

    pub fn payload(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.payload_len());
        self.write_payload(&mut out);
        out.into()
    }

    pub fn encode_into(&self, out: &mut BytesMut) {
        let length = self.payload_len();

        out.reserve(length + 2 * varint_len(MAXIMUM_VARINT));
        encode_varint(out, self.kind().code());
        encode_varint(out, length as u64);

        let start = out.len();
        self.write_payload(out);
        debug_assert_eq!(out.len() - start, length, "payload_len disagreed with write_payload");
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.payload_len() + 2 * varint_len(MAXIMUM_VARINT));
        self.encode_into(&mut out);
        out.into()
    }

    pub fn decode(kind: FrameType, payload: &[u8]) -> Result<Self, Error> {
        Self::assemble(kind, payload, None)
    }

    pub fn decode_shared(kind: FrameType, payload: &Bytes) -> Result<Self, Error> {
        Self::assemble(kind, payload.as_ref(), Some(payload))
    }

    pub fn assemble(kind: FrameType, payload: &[u8], shared: Option<&Bytes>) -> Result<Self, Error> {
        let borrow = |slice: &[u8]| match shared {
            Some(whole) => whole.slice_ref(slice),
            None => Bytes::copy_from_slice(slice),
        };

        match kind {
            FrameType::Data => Ok(Self::Data(borrow(payload))),
            FrameType::Headers => Ok(Self::Headers(borrow(payload))),

            FrameType::CancelPush => Ok(Self::CancelPush { push_id: only_varint(payload, "CANCEL_PUSH")? }),
            FrameType::MaxPushID => Ok(Self::MaxPushID { push_id: only_varint(payload, "MAX_PUSH_ID")? }),
            FrameType::GoAway => Ok(Self::GoAway { id: only_varint(payload, "GOAWAY")? }),

            FrameType::Settings => {
                let mut rest = payload;
                let mut params = Vec::new();

                while !rest.is_empty() {
                    let (consumed, id) = decode_varint(rest);
                    let (taken, value) = decode_varint(&rest[consumed..]);

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
                let (consumed, push_id) = decode_varint(payload);
                if consumed == 0 {
                    return Err(Error::Protocol("PUSH_PROMISE has no push identifier".into()));
                }

                Ok(Self::PushPromise { push_id, block: borrow(&payload[consumed..]) })
            }
        }
    }
}

pub fn only_varint(payload: &[u8], name: &str) -> Result<u64, Error> {
    let (consumed, value) = decode_varint(payload);

    if consumed == 0 || consumed != payload.len() {
        return Err(Error::Protocol(format!("{name} payload is not a single variable-length integer")));
    }

    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Control,
    Push,
    QPACKEncoder,
    QPACKDecoder,
    Request,
}

impl StreamKind {
    pub fn code(&self) -> Option<u64> {
        match self {
            Self::Control => Some(0x00),
            Self::Push => Some(0x01),
            Self::QPACKEncoder => Some(0x02),
            Self::QPACKDecoder => Some(0x03),
            Self::Request => None,
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
    pub max_field_section_size: Option<u64>,
    pub enable_connect_protocol: bool,
}

impl Settings {
    pub fn parameters(&self) -> Vec<(u64, u64)> {
        let mut params = vec![
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, self.qpack_max_table_capacity),
            (SETTINGS_QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, u64::from(self.enable_connect_protocol)),
        ];

        if let Some(size) = self.max_field_section_size {
            params.push((SETTINGS_MAX_FIELD_SECTION_SIZE, size));
        }

        params
    }

    pub fn peer() -> Self {
        Self {
            qpack_max_table_capacity: qpack::DEFAULT_MAX_TABLE_CAPACITY as u64,
            qpack_blocked_streams: 0,
            max_field_section_size: None,
            enable_connect_protocol: false,
        }
    }

    pub fn apply(&mut self, id: u64, value: u64) -> Result<(), Error> {
        if RESERVED_SETTINGS.contains(&id) {
            return Err(Error::Protocol(format!("setting {id:#x} is reserved")));
        }

        match id {
            SETTINGS_QPACK_MAX_TABLE_CAPACITY => self.qpack_max_table_capacity = value,
            SETTINGS_QPACK_BLOCKED_STREAMS => self.qpack_blocked_streams = value,
            SETTINGS_MAX_FIELD_SECTION_SIZE => self.max_field_section_size = Some(value),

            SETTINGS_ENABLE_CONNECT_PROTOCOL => {
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
            qpack_max_table_capacity: qpack::ADVERTISED_TABLE_CAPACITY as u64,
            qpack_blocked_streams: 0,
            max_field_section_size: None,
            enable_connect_protocol: true,
        }
    }
}

pub fn quic_error(err: impl std::fmt::Display) -> Error {
    Error::Io(std::io::Error::other(err.to_string()))
}

#[derive(Default)]
pub struct StreamState {
    pub buffer: BytesMut,
    pub body: BytesMut,
    pub message: Option<Message>,
    pub method: Option<Method>,
    pub pending: Option<Bytes>,
    pub eof: bool,
    pub delivered: bool,
    pub finished: bool,
    pub raw: bool,
    pub responded: bool,
}

impl StreamState {
    pub fn spent(&self) -> bool {
        self.finished && self.eof && self.delivered && !self.raw
    }
}

pub struct H3Session {
    pub role: Role,
    pub id: ConnectionID,
    pub limits: Limits,

    pub settings_local: Settings,
    pub settings_remote: Option<Settings>,

    pub encoder: Encoder,
    pub decoder: Decoder,

    pub streams: common::StreamMap<StreamID, StreamState>,
    pub blocked: common::StreamMap<StreamID, std::time::Instant>,
    pub ready: VecDeque<Message>,

    pub encoder_out: Vec<u8>,
    pub decoder_out: Vec<u8>,

    pub encoder_recv: BytesMut,
    pub decoder_recv: BytesMut,
    pub control_recv: BytesMut,

    pub next_stream_id: u64,
}

impl H3Session {
    pub fn new(role: Role, id: ConnectionID, limits: Limits) -> Self {
        let settings_local = Settings::default();

        let mut decoder = Decoder::new();
        decoder.set_max_capacity(settings_local.qpack_max_table_capacity as usize);
        decoder.set_max_decoded_size(limits.max_headers_size as usize);

        let mut encoder = Encoder::new();
        encoder.set_max_outstanding_sections(limits.max_outstanding_sections as usize);

        let next_stream_id = if role.is_client() { 0 } else { 1 };

        Self {
            role,
            id,
            limits,
            settings_local,
            settings_remote: None,
            encoder,
            decoder,
            streams: common::StreamMap::default(),
            blocked: common::StreamMap::default(),
            ready: VecDeque::new(),
            encoder_out: Vec::new(),
            decoder_out: Vec::new(),
            encoder_recv: BytesMut::new(),
            decoder_recv: BytesMut::new(),
            control_recv: BytesMut::new(),
            next_stream_id,
        }
    }

    pub fn control_frame(&self) -> Bytes {
        let mut out = BytesMut::new();
        Frame::Settings(self.settings_local.parameters()).encode_into(&mut out);
        out.freeze()
    }

    pub fn open(&mut self) -> StreamID {
        let stream_id = StreamID(self.next_stream_id);
        self.next_stream_id += 4;
        self.streams.entry(stream_id).or_default();
        stream_id
    }

    pub fn stream_ceiling(&self) -> usize {
        (self.limits.max_concurrent_streams as usize).saturating_mul(2).max(2)
    }

    pub fn forget(&mut self, stream_id: StreamID) -> Option<StreamState> {
        self.blocked.remove(&stream_id);
        self.encoder.cancel(stream_id.0);
        self.streams.remove(&stream_id)
    }

    pub fn retire(&mut self, stream_id: StreamID) {
        if self.streams.get(&stream_id).is_some_and(StreamState::spent) {
            self.forget(stream_id);
        }
    }

    pub fn encode_message(&mut self, stream_id: StreamID, message: &Message) -> Result<(Bytes, bool), Error> {
        let mut out = BytesMut::new();
        let fin = self.encode_message_into(stream_id, message, &mut out)?;
        Ok((out.freeze(), fin))
    }

    pub fn encode_message_into(&mut self, stream_id: StreamID, message: &Message, out: &mut BytesMut) -> Result<bool, Error> {
        let start = out.len();

        match self.frame_message(stream_id, message, out) {
            Ok(fin) => Ok(fin),
            Err(error) => {
                out.truncate(start);
                Err(error)
            }
        }
    }

    pub fn frame_message(&mut self, stream_id: StreamID, message: &Message, out: &mut BytesMut) -> Result<bool, Error> {
        let fields = common::fields(message)?;
        let (block, instructions) = self.encoder.encode(stream_id.0, &fields);
        self.queue_encoder(&instructions);

        Frame::Headers(block.into()).encode_into(out);

        if let Some(body) = &message.body {
            let body = body
                .inline()
                .ok_or_else(|| Error::Protocol("a file body must be materialised before HTTP/3 encoding".into()))?;
            if !body.is_empty() {
                Frame::Data(body).encode_into(out);
            }
        }

        if let Some(trailers) = message.trailers.as_ref().filter(|trailers| !trailers.is_empty()) {
            let fields: Vec<HeaderField> = trailers.iter().map(|(name, value)| HeaderField::new(name, value)).collect();
            let (block, instructions) = self.encoder.encode(stream_id.0, &fields);
            self.queue_encoder(&instructions);
            Frame::Headers(block.into()).encode_into(out);
        }

        let state = self.streams.entry(stream_id).or_default();
        if message.is_request() {
            state.method = message.method;
        }

        let tunneling = tunneling(state.method, message);
        state.finished |= !tunneling;

        Ok(!tunneling)
    }

    pub fn queue_encoder(&mut self, instructions: &[EncoderInstruction]) {
        for instruction in instructions {
            instruction.encode_into(&mut self.encoder_out);
        }
    }

    pub fn on_encoder_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.encoder_recv.extend_from_slice(bytes);

        let limit = self.limits.max_headers_size;
        if self.encoder_recv.len() as u64 > limit {
            return Err(Error::Limit(format!("an encoder instruction exceeds {limit} octets")));
        }

        loop {
            match EncoderInstruction::decode(&self.encoder_recv) {
                Ok((consumed, instruction)) => {
                    let _ = self.encoder_recv.split_to(consumed);
                    if let Some(acknowledgment) = self.decoder.on_encoder_instruction(instruction)? {
                        acknowledgment.encode_into(&mut self.decoder_out);
                    }
                }
                Err(qpack::Error::Incomplete) => break,
                Err(err) => return Err(err.into()),
            }
        }

        let blocked: Vec<StreamID> = self.streams.iter().filter(|(_, state)| state.pending.is_some()).map(|(id, _)| *id).collect();
        for stream_id in blocked {
            self.advance(stream_id)?;
        }

        Ok(())
    }

    pub fn on_decoder_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.decoder_recv.extend_from_slice(bytes);

        let limit = self.limits.max_headers_size;
        if self.decoder_recv.len() as u64 > limit {
            return Err(Error::Limit(format!("a decoder instruction exceeds {limit} octets")));
        }

        loop {
            match DecoderInstruction::decode(&self.decoder_recv) {
                Ok((consumed, instruction)) => {
                    let _ = self.decoder_recv.split_to(consumed);
                    self.encoder.on_decoder_instruction(instruction);
                }
                Err(qpack::Error::Incomplete) => break,
                Err(err) => return Err(err.into()),
            }
        }

        Ok(())
    }

    pub fn on_control_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.control_recv.extend_from_slice(bytes);

        let limit = self.limits.max_headers_size;
        if self.control_recv.len() as u64 > limit {
            return Err(Error::Limit(format!("a control frame exceeds {limit} octets")));
        }

        while let Some(frame) = parse_frame(&mut self.control_recv)? {
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
                Frame::GoAway { .. } | Frame::MaxPushID { .. } | Frame::CancelPush { .. } => {}
                _ => return Err(Error::Protocol("an unexpected frame arrived on the control stream".into())),
            }
        }

        Ok(())
    }

    pub fn apply_peer_settings(&mut self, settings: Settings) {
        let permitted = usize::try_from(settings.qpack_max_table_capacity).unwrap_or(usize::MAX);
        self.encoder.set_max_capacity(permitted);

        if let Some(instruction) = self.encoder.set_capacity(permitted.min(qpack::ADVERTISED_TABLE_CAPACITY)) {
            self.queue_encoder(&[instruction]);
        }

        self.settings_remote = Some(settings);
    }

    pub fn on_stream_bytes(&mut self, stream_id: StreamID, bytes: &[u8], fin: bool) -> Result<(), Error> {
        if !self.streams.contains_key(&stream_id) && self.streams.len() >= self.stream_ceiling() {
            let reason = format!("more than {} streams are held open at once", self.stream_ceiling());
            return Err(Error::stream(stream_id, H3_EXCESSIVE_LOAD, reason));
        }

        let state = self.streams.entry(stream_id).or_default();
        state.buffer.extend_from_slice(bytes);
        if fin {
            state.eof = true;
        }

        let limit = self.limits.max_message_size;
        if state.buffer.len() as u64 > limit {
            let reason = format!("unparsed stream data exceeds {limit} octets");
            return Err(Error::stream(stream_id, H3_EXCESSIVE_LOAD, reason));
        }

        let limit = self.limits.max_connection_buffer_size;
        if self.buffered() > limit {
            return Err(Error::Limit(format!("buffered messages exceed {limit} octets")));
        }

        self.advance(stream_id)
    }

    pub fn buffered(&self) -> u64 {
        self.streams.values().map(|state| (state.buffer.len() + state.body.len()) as u64).sum()
    }

    pub fn advance(&mut self, stream_id: StreamID) -> Result<(), Error> {
        loop {
            if self.streams.get(&stream_id).is_some_and(|state| state.raw) {
                return Ok(());
            }

            if let Some(block) = self.streams.get(&stream_id).and_then(|state| state.pending.clone()) {
                match self.decoder.decode(stream_id.0, &block) {
                    Ok((fields, acknowledgment)) => {
                        if let Some(acknowledgment) = acknowledgment {
                            acknowledgment.encode_into(&mut self.decoder_out);
                        }
                        let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;
                        state.pending = None;
                        self.blocked.remove(&stream_id);
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

            let Some(frame) = parse_frame(&mut state.buffer)? else {
                if state.eof {
                    break;
                }
                return Ok(());
            };

            match frame {
                Frame::Headers(block) => {
                    if block.len() as u64 > self.limits.max_headers_size {
                        let reason = format!("field section exceeds {} octets", self.limits.max_headers_size);
                        return Err(Error::stream(stream_id, H3_EXCESSIVE_LOAD, reason));
                    }
                    match self.decoder.decode(stream_id.0, &block) {
                        Ok((fields, acknowledgment)) => {
                            if let Some(acknowledgment) = acknowledgment {
                                acknowledgment.encode_into(&mut self.decoder_out);
                            }
                            self.absorb_headers(stream_id, fields)?;
                        }
                        Err(qpack::Error::Blocked) => {
                            let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;
                            state.pending = Some(block);
                            self.blocked.entry(stream_id).or_insert_with(std::time::Instant::now);
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
                        return Err(Error::stream(stream_id, H3_EXCESSIVE_LOAD, format!("body exceeds {limit} octets")));
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
            return Err(Error::stream(stream_id, H3_REQUEST_INCOMPLETE, "request stream carried no field section"));
        };

        if !state.body.is_empty() {
            message.body = Some(Body::Data(std::mem::take(&mut state.body).freeze()));
        }

        state.delivered = true;
        self.ready.push_back(message);

        self.retire(stream_id);
        Ok(())
    }

    pub fn absorb_headers(&mut self, stream_id: StreamID, fields: Vec<HeaderField>) -> Result<(), Error> {
        if fields.len() > self.limits.max_header_count as usize {
            let reason = format!("more than {} header fields", self.limits.max_header_count);
            return Err(Error::stream(stream_id, H3_EXCESSIVE_LOAD, reason));
        }

        let id = self.id.clone();
        let state = self.streams.get_mut(&stream_id).ok_or(Error::Closed)?;

        if let Some(message) = state.message.as_mut() {
            let mut trailers = Headers::with_capacity(fields.len());
            for field in fields {
                if field.name.starts_with(':') {
                    return Err(Error::stream(stream_id, H3_MESSAGE_ERROR, "trailer section carries a pseudo-header"));
                }
                trailers.append(field.name, field.value);
            }
            message.trailers = Some(trailers);
            return Ok(());
        }

        let mut message = common::message_from(fields, Version::V3_0).map_err(|err| err.on_stream(stream_id, H3_MESSAGE_ERROR))?;
        message.stream_id = Some(stream_id);
        message.connection_id = Some(id);
        message.quic = true;
        message.secure = true;

        if message.is_request() {
            state.method = message.method;
        }

        if tunneling(state.method, &message) {
            state.delivered = true;
            state.raw = true;
            self.ready.push_back(message);
            return Ok(());
        }

        state.message = Some(message);
        Ok(())
    }

    pub fn take_ready(&mut self) -> Option<Message> {
        self.ready.pop_front()
    }

    pub fn take_encoder_out(&mut self) -> Bytes {
        Bytes::from(std::mem::take(&mut self.encoder_out))
    }

    pub fn take_decoder_out(&mut self) -> Bytes {
        Bytes::from(std::mem::take(&mut self.decoder_out))
    }
}

pub fn tunneling(method: Option<Method>, message: &Message) -> bool {
    method == Some(Method::CONNECT) && (message.is_request() || matches!(message.status_code, Some(200..=299)))
}

pub fn parse_frame(buffer: &mut BytesMut) -> Result<Option<Frame>, Error> {
    loop {
        let (consumed, code, length) = {
            let data = &buffer[..];
            let (taken, code) = decode_varint(data);
            let (took, length) = decode_varint(&data[taken.min(data.len())..]);

            if taken == 0 || took == 0 || data.len() < taken + took + length as usize {
                (0, 0, 0)
            } else {
                (taken + took, code, length)
            }
        };

        if consumed == 0 {
            return Ok(None);
        }

        if RESERVED_FRAME_TYPES.contains(&code) {
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

pub enum H3Command {
    Send(Message),
    Open(tokio::sync::oneshot::Sender<StreamID>),
    OpenUni(StreamKind, tokio::sync::oneshot::Sender<StreamID>),
    Tunnel(StreamID, tokio::sync::mpsc::Sender<(Bytes, bool)>),
    WriteEncoder(Bytes),
    Close,
}

pub enum H3Event {
    Message(Message),
    Failed(Error),
}

pub struct H3Connection {
    pub commands: tokio::sync::mpsc::Sender<H3Command>,
    pub events: tokio::sync::mpsc::Receiver<H3Event>,
    pub raw: tokio::sync::mpsc::Sender<(StreamID, Bytes, bool)>,
    pub id: ConnectionID,
    pub role: Role,
    pub limits: Limits,
    pub guard: Option<std::sync::Arc<tokio_quiche::QuicConnection>>,
    pub hsts: Option<crate::helpers::hsts::HstsPolicy>,
}

impl H3Connection {
    pub fn pair(session: H3Session, hsts: Option<crate::helpers::hsts::HstsPolicy>) -> (Self, H3Worker) {
        let (commands, commands_receiver) = tokio::sync::mpsc::channel(256);
        let (events_sender, events) = tokio::sync::mpsc::channel(256);
        let (raw, raw_receiver) = tokio::sync::mpsc::channel(TUNNEL_BACKLOG);

        let connection = Self {
            commands,
            events,
            raw,
            id: session.id.clone(),
            role: session.role,
            limits: session.limits,
            guard: None,
            hsts,
        };

        (connection, H3Worker::new(session, commands_receiver, events_sender, raw_receiver))
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub async fn send_message(&mut self, message: Message) -> Result<(), Error> {
        let mut message = message;
        if self.role.is_server() && message.is_response() {
            if self.hsts.is_some() {
                message.secure = true;
            }
            crate::finalizer::finalize_response(&mut message, crate::finalizer::date_cache(), self.hsts.as_ref());
        }

        if let Some(body) = message.body.take() {
            message.body = Some(Body::Data(body.into_bytes().await?));
        }

        self.commands.send(H3Command::Send(message)).await.map_err(|_| Error::Closed)
    }

    pub async fn receive_message(&mut self) -> Result<Message, Error> {
        match self.events.recv().await {
            Some(H3Event::Message(message)) => Ok(message),
            Some(H3Event::Failed(error)) => Err(error),
            None => Err(Error::Closed),
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        Ok(())
    }

    pub async fn open(&mut self) -> Result<StreamID, Error> {
        let (reply, opened) = tokio::sync::oneshot::channel();
        self.commands.send(H3Command::Open(reply)).await.map_err(|_| Error::Closed)?;
        opened.await.map_err(|_| Error::Closed)
    }

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

    pub fn tunnel(&mut self, stream_id: StreamID) -> Result<H3Stream, Error> {
        let (sink, reads) = tokio::sync::mpsc::channel(TUNNEL_BACKLOG);
        self.commands.try_send(H3Command::Tunnel(stream_id, sink)).map_err(|_| Error::Closed)?;
        Ok(H3Stream::new(stream_id, self.raw.clone(), reads, self.guard.clone()))
    }

    pub async fn write_encoder(&mut self, instructions: &[EncoderInstruction]) -> Result<(), Error> {
        let mut bytes = BytesMut::new();
        for instruction in instructions {
            bytes.extend_from_slice(&instruction.encode());
        }

        self.commands.send(H3Command::WriteEncoder(bytes.freeze())).await.map_err(|_| Error::Closed)
    }
}

pub type RawWrite = (StreamID, Bytes, bool);

pub type RawPermit = tokio::sync::mpsc::OwnedPermit<RawWrite>;
pub type Reserving = std::pin::Pin<Box<dyn std::future::Future<Output = Result<RawPermit, tokio::sync::mpsc::error::SendError<()>>> + Send>>;

pub struct H3Stream {
    pub id: StreamID,
    pub writes: tokio::sync::mpsc::Sender<RawWrite>,
    pub reads: tokio::sync::mpsc::Receiver<(Bytes, bool)>,
    pub reserving: Option<Reserving>,
    pub buffer: BytesMut,
    pub eof: bool,
    pub guard: Option<std::sync::Arc<tokio_quiche::QuicConnection>>,
}

impl H3Stream {
    pub fn new(id: StreamID, writes: tokio::sync::mpsc::Sender<RawWrite>, reads: tokio::sync::mpsc::Receiver<(Bytes, bool)>, guard: Option<std::sync::Arc<tokio_quiche::QuicConnection>>) -> Self {
        Self { id, writes, reads, reserving: None, buffer: BytesMut::new(), eof: false, guard }
    }

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

    pub fn id(&self) -> StreamID {
        self.id
    }

    pub fn guard(&self) -> Option<&std::sync::Arc<tokio_quiche::QuicConnection>> {
        self.guard.as_ref()
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

    async fn send(&mut self, message: Message) -> Result<(), Error> {
        common::within(self.limits.send_timeout, self.send_message(message)).await?
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        common::within(self.limits.receive_timeout, self.receive_message()).await?
    }

    async fn close(&mut self) {
        let _ = self.commands.send(H3Command::Close).await;
    }
}

pub fn boxed(error: Error) -> BoxError {
    Box::new(error)
}

#[derive(Default)]
pub struct PeerUni {
    pub kind: Option<StreamKind>,
    pub prefix: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Encoder,
    Decoder,
}

pub struct H3Worker {
    pub session: H3Session,
    pub commands: tokio::sync::mpsc::Receiver<H3Command>,
    pub events: tokio::sync::mpsc::Sender<H3Event>,
    pub raw_writes: tokio::sync::mpsc::Receiver<(StreamID, Bytes, bool)>,
    pub pending: Option<H3Command>,
    pub pending_raw: Option<(StreamID, Bytes, bool)>,
    pub orphaned: bool,

    pub established: bool,
    pub next_uni: u64,
    pub local_control: u64,
    pub local_encoder: u64,
    pub local_decoder: u64,

    pub peer_uni: common::StreamMap<u64, PeerUni>,
    pub tunnels: common::StreamMap<u64, tokio::sync::mpsc::Sender<(Bytes, bool)>>,
    pub outbound: common::StreamMap<u64, (BytesMut, bool)>,
    pub outbound_bytes: u64,

    pub premature_resets: u32,

    pub scratch: Vec<u8>,
    pub read: Vec<u8>,

    pub readable: Vec<u64>,
    pub flushing: Vec<u64>,
}

impl H3Worker {
    pub fn new(session: H3Session, commands: tokio::sync::mpsc::Receiver<H3Command>, events: tokio::sync::mpsc::Sender<H3Event>, raw_writes: tokio::sync::mpsc::Receiver<(StreamID, Bytes, bool)>) -> Self {
        let next_uni = if session.role.is_server() { 3 } else { 2 };

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
            scratch: vec![0u8; 64 * 1024],
            read: vec![0u8; 64 * 1024],
            readable: Vec::new(),
            flushing: Vec::new(),
        }
    }

    pub fn forget_stream(&mut self, stream_id: u64) {
        self.session.forget(StreamID(stream_id));
        self.peer_uni.remove(&stream_id);
        self.tunnels.remove(&stream_id);

        if let Some((buffer, _)) = self.outbound.remove(&stream_id) {
            self.outbound_bytes = self.outbound_bytes.saturating_sub(buffer.len() as u64);
        }
    }

    pub fn outbound_limit(&self) -> u64 {
        self.session.limits.max_connection_buffer_size
    }

    pub fn accepting_writes(&self) -> bool {
        self.outbound_bytes < self.outbound_limit()
    }

    pub fn fail(&mut self, error: Error) -> BoxError {
        let description = error.to_string();
        let _ = self.events.try_send(H3Event::Failed(error));
        Box::new(std::io::Error::other(description))
    }

    pub fn block_deadline(&self) -> Option<std::time::Instant> {
        if self.session.blocked.is_empty() {
            return None;
        }

        let wait = common::duration(self.session.limits.qpack_block_timeout)?;
        let earliest = self.session.blocked.values().min()?;
        Some(*earliest + wait)
    }

    pub fn expired_block(&self) -> Option<Error> {
        let deadline = self.block_deadline()?;
        (std::time::Instant::now() >= deadline).then(|| {
            Error::Timeout(format!(
                "a QPACK block stayed blocked beyond {}s",
                self.session.limits.qpack_block_timeout
            ))
        })
    }

    pub fn alloc_uni(&mut self) -> u64 {
        let id = self.next_uni;
        self.next_uni += 4;
        id
    }

    pub fn open_uni(&mut self, qconn: &mut QuicheConnection, stream_id: u64, kind: StreamKind) -> Result<(), Error> {
        let code = kind
            .code()
            .ok_or_else(|| Error::Protocol(format!("{kind:?} is not a unidirectional stream type")))?;

        let mut prefix = BytesMut::new();
        encode_varint(&mut prefix, code);
        self.write(qconn, stream_id, &prefix, false)
    }

    pub fn write(&mut self, qconn: &mut QuicheConnection, stream_id: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        let entry = self.outbound.entry(stream_id).or_default();
        entry.0.extend_from_slice(data);
        entry.1 |= fin;
        self.outbound_bytes = self.outbound_bytes.saturating_add(data.len() as u64);
        self.flush_stream(qconn, stream_id)
    }

    pub fn flush_stream(&mut self, qconn: &mut QuicheConnection, stream_id: u64) -> Result<(), Error> {
        let Some((buffer, fin)) = self.outbound.get_mut(&stream_id) else {
            return Ok(());
        };

        if buffer.is_empty() && !*fin {
            return Ok(());
        }

        match qconn.stream_send(stream_id, buffer, *fin) {
            Ok(sent) => {
                let _ = buffer.split_to(sent);
                self.outbound_bytes = self.outbound_bytes.saturating_sub(sent as u64);

                if buffer.is_empty() {
                    self.outbound.remove(&stream_id);
                }
                Ok(())
            }
            Err(quiche::Error::Done) => Ok(()),
            Err(quiche::Error::StreamStopped(code)) => {
                if let Some((buffer, _)) = self.outbound.remove(&stream_id) {
                    self.outbound_bytes = self.outbound_bytes.saturating_sub(buffer.len() as u64);
                }

                let error = Error::stream(StreamID(stream_id), code, "the peer stopped the stream");
                let _ = self.events.try_send(H3Event::Failed(error));
                Ok(())
            }
            Err(err) => Err(quic_error(err)),
        }
    }

    pub fn execute(&mut self, qconn: &mut QuicheConnection, command: H3Command) -> Result<(), Error> {
        match command {
            H3Command::Send(message) => {
                let stream_id = message.stream_id.unwrap_or_else(|| self.session.open());
                self.session.streams.entry(stream_id).or_default().responded = true;

                let entry = self.outbound.entry(stream_id.0).or_default();
                let before = entry.0.len();
                let fin = self.session.encode_message_into(stream_id, &message, &mut entry.0)?;
                entry.1 |= fin;

                let framed = entry.0.len().saturating_sub(before) as u64;
                self.outbound_bytes = self.outbound_bytes.saturating_add(framed);

                self.flush_stream(qconn, stream_id.0)?;
                self.session.retire(stream_id);
                Ok(())
            }
            H3Command::Open(reply) => {
                let _ = reply.send(self.session.open());
                Ok(())
            }
            H3Command::OpenUni(kind, reply) => {
                let stream_id = self.alloc_uni();
                self.open_uni(qconn, stream_id, kind)?;
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
            H3Command::WriteEncoder(bytes) => self.write(qconn, self.local_encoder, &bytes, false),
            H3Command::Close => {
                let _ = qconn.close(true, H3_NO_ERROR, b"");
                Ok(())
            }
        }
    }

    pub fn dispatch(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        if let Some(sink) = self.tunnels.get(&stream_id) {
            if sink.try_send((Bytes::copy_from_slice(data), fin)).is_err() {
                return Err(Error::stream(StreamID(stream_id), H3_EXCESSIVE_LOAD, "the tunnel could not take the octets"));
            }

            if fin {
                self.tunnels.remove(&stream_id);
                self.session.forget(StreamID(stream_id));
            }

            return Ok(());
        }

        if stream_id & 0x2 == 0 {
            return self.session.on_stream_bytes(StreamID(stream_id), data, fin);
        }

        self.feed_uni(stream_id, data, fin)
    }

    pub fn feed_uni(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        let outcome = self.feed_uni_bytes(stream_id, data);

        if fin {
            self.peer_uni.remove(&stream_id);
        }

        outcome
    }

    pub fn feed_uni_bytes(&mut self, stream_id: u64, data: &[u8]) -> Result<(), Error> {
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

        let (consumed, code) = decode_varint(&uni.prefix);
        if consumed == 0 {
            if uni.prefix.len() > MAX_VARINT_SIZE {
                return Err(Error::Protocol("a unidirectional stream carries no readable type".into()));
            }
            return Ok(());
        }

        let kind = StreamKind::from_code(code).unwrap_or(StreamKind::Push);
        uni.kind = Some(kind);

        let payload = uni.prefix.split_off(consumed);
        uni.prefix = Vec::new();

        self.feed_uni_kind(kind, &payload)
    }

    pub fn feed_uni_kind(&mut self, kind: StreamKind, payload: &[u8]) -> Result<(), Error> {
        match kind {
            StreamKind::Control => self.session.on_control_bytes(payload),
            StreamKind::QPACKEncoder => self.session.on_encoder_bytes(payload),
            StreamKind::QPACKDecoder => self.session.on_decoder_bytes(payload),
            _ => Ok(()),
        }
    }

    pub fn overloaded(&mut self, qconn: &mut QuicheConnection, reason: impl Into<String>) -> Error {
        let _ = qconn.close(true, H3_EXCESSIVE_LOAD, b"");
        Error::Limit(reason.into())
    }

    pub fn reset_stream(&mut self, qconn: &mut QuicheConnection, stream_id: u64, error: &Error) {
        self.forget_stream(stream_id);

        let code = match error {
            Error::Stream { code, .. } => *code,
            _ => H3_MESSAGE_ERROR,
        };

        let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, code);
        let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Read, code);
    }

    pub fn drain_side_channels(&mut self, qconn: &mut QuicheConnection) -> Result<(), Error> {
        self.drain_side_channel(qconn, Side::Encoder)?;
        self.drain_side_channel(qconn, Side::Decoder)
    }

    pub fn drain_side_channel(&mut self, qconn: &mut QuicheConnection, side: Side) -> Result<(), Error> {
        let (source, stream_id) = match side {
            Side::Encoder => (&mut self.session.encoder_out, self.local_encoder),
            Side::Decoder => (&mut self.session.decoder_out, self.local_decoder),
        };

        if source.is_empty() {
            return Ok(());
        }

        let mut queued = std::mem::take(source);
        let outcome = self.write(qconn, stream_id, &queued, false);

        queued.clear();
        common::reclaim_octets(&mut queued);

        match side {
            Side::Encoder => self.session.encoder_out = queued,
            Side::Decoder => self.session.decoder_out = queued,
        }

        outcome
    }
}

impl ApplicationOverQuic for H3Worker {
    fn on_conn_established(&mut self, qconn: &mut QuicheConnection, _handshake: &HandshakeInfo) -> QuicResult<()> {
        self.established = true;

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

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.scratch
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        let deadline = self.block_deadline();

        tokio::select! {
            command = self.commands.recv(), if !self.orphaned => match command {
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
                None => Err(boxed(Error::Closed)),
            },

            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.unwrap_or_else(std::time::Instant::now))), if deadline.is_some() => Ok(()),

            else => {
                std::future::pending::<()>().await;
                Ok(())
            }
        }
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut read = std::mem::take(&mut self.read);
        let mut readable = std::mem::take(&mut self.readable);

        readable.clear();
        readable.extend(qconn.readable());

        let outcome = self.drain_reads(qconn, &readable, &mut read);

        self.read = read;
        self.readable = readable;

        outcome?;

        self.deliver_ready();
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if let Some(error) = self.expired_block() {
            let _ = qconn.close(true, QPACK_DECOMPRESSION_FAILED, b"");
            return Err(self.fail(error));
        }

        if let Some(command) = self.pending.take()
            && let Err(error) = self.execute(qconn, command)
        {
            return Err(self.fail(error));
        }

        while let Ok(command) = self.commands.try_recv() {
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
        Ok(())
    }
}

impl H3Worker {
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

    pub fn drain_reads(&mut self, qconn: &mut QuicheConnection, readable: &[u64], read: &mut [u8]) -> Result<(), BoxError> {
        for stream_id in readable.iter().copied() {
            loop {
                if self.tunnels.get(&stream_id).is_some_and(|sink| sink.capacity() == 0) {
                    break;
                }

                match qconn.stream_recv(stream_id, read) {
                    Ok((count, fin)) => {
                        match self.dispatch(stream_id, &read[..count], fin) {
                            Ok(()) => {}
                            Err(error) if matches!(error, Error::Stream { .. }) => {
                                self.reset_stream(qconn, stream_id, &error);
                                let _ = self.events.try_send(H3Event::Failed(error));
                                break;
                            }
                            Err(error) => return Err(self.fail(error)),
                        }
                        if fin || count == 0 {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(quiche::Error::StreamReset(code)) => {
                        let premature = self.session.forget(StreamID(stream_id)).is_some_and(|state| !state.responded);
                        self.forget_stream(stream_id);

                        if premature {
                            self.premature_resets = self.premature_resets.saturating_add(1);

                            if self.premature_resets > self.session.limits.max_premature_resets {
                                let reason = format!(
                                    "more than {} streams were reset before a response was sent",
                                    self.session.limits.max_premature_resets
                                );
                                let error = self.overloaded(qconn, reason);
                                return Err(self.fail(error));
                            }
                        }

                        let error = Error::stream(StreamID(stream_id), code, "the peer reset the stream");
                        let _ = self.events.try_send(H3Event::Failed(error));
                        break;
                    }
                    Err(err) => {
                        let error = quic_error(err);
                        return Err(self.fail(error));
                    }
                }
            }
        }

        Ok(())
    }
}
