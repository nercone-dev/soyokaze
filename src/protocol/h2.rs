use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::helpers::hpack::{Decoder as HPACKDecoder, Encoder as HPACKEncoder, HeaderField};
use crate::models::{Body, ConnectionID, Headers, Limits, Message, Method, Role, StreamID, Version};
use crate::protocol::common::{self, Buffer, Connection, Error};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FRAME_HEADER_SIZE: usize = 9;

pub const OUTPUT_HIGH_WATER: usize = 64 * 1024;

pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u16 = 0x8;

pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
pub const MAXIMUM_FRAME_SIZE: u32 = 16_777_215;
pub const MAXIMUM_WINDOW_SIZE: u32 = 0x7fff_ffff;
pub const MAXIMUM_ENCODER_TABLE_SIZE: usize = 64 * 1024;

pub const NO_ERROR: u32 = 0x0;
pub const PROTOCOL_ERROR: u32 = 0x1;
pub const INTERNAL_ERROR: u32 = 0x2;
pub const FLOW_CONTROL_ERROR: u32 = 0x3;
pub const SETTINGS_TIMEOUT: u32 = 0x4;
pub const STREAM_CLOSED: u32 = 0x5;
pub const FRAME_SIZE_ERROR: u32 = 0x6;
pub const REFUSED_STREAM: u32 = 0x7;
pub const CANCEL: u32 = 0x8;
pub const COMPRESSION_ERROR: u32 = 0x9;
pub const CONNECT_ERROR: u32 = 0xa;
pub const ENHANCE_YOUR_CALM: u32 = 0xb;
pub const INADEQUATE_SECURITY: u32 = 0xc;
pub const HTTP_1_1_REQUIRED: u32 = 0xd;

pub const END_STREAM: u8 = 0x1;
pub const ACK: u8 = 0x1;
pub const END_HEADERS: u8 = 0x4;
pub const PADDED: u8 = 0x8;
pub const PRIORITY: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
}

impl FrameType {
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

    pub fn streamed(&self) -> Option<bool> {
        match self {
            Self::Data | Self::Headers | Self::Priority | Self::RstStream | Self::PushPromise
            | Self::Continuation => Some(true),
            Self::Settings | Self::Ping | Self::GoAway => Some(false),
            Self::WindowUpdate => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32,
    pub kind: FrameType,
    pub flags: u8,
    pub stream_id: StreamID,
}

impl FrameHeader {
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

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Data { stream_id: StreamID, end_stream: bool, data: Bytes },
    Headers { stream_id: StreamID, end_stream: bool, end_headers: bool, block: Vec<u8> },
    Priority { stream_id: StreamID, dependency: StreamID, exclusive: bool, weight: u8 },
    RstStream { stream_id: StreamID, error_code: u32 },
    Settings { ack: bool, params: Vec<(u16, u32)> },
    PushPromise { stream_id: StreamID, promised_stream_id: StreamID, block: Vec<u8> },
    Ping { ack: bool, payload: [u8; 8] },
    GoAway { last_stream_id: StreamID, error_code: u32, debug_data: Vec<u8> },
    WindowUpdate { stream_id: StreamID, increment: u32 },
    Continuation { stream_id: StreamID, end_headers: bool, block: Vec<u8> },
}

impl Frame {
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

    pub fn payload(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        self.write_payload(&mut out);
        out.to_vec()
    }

    pub fn encode_into(&self, out: &mut BytesMut) {
        let start = out.len();
        out.extend_from_slice(&[0u8; FRAME_HEADER_SIZE]);
        self.write_payload(out);

        let length = (out.len() - start - FRAME_HEADER_SIZE) as u32;
        let header = FrameHeader { length, kind: self.kind(), flags: self.flags(), stream_id: self.stream_id() };
        out[start..start + FRAME_HEADER_SIZE].copy_from_slice(&header.encode());
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        self.encode_into(&mut out);
        out.to_vec()
    }

    pub fn decode(header: FrameHeader, payload: &[u8]) -> Result<Self, Error> {
        Self::assemble(header, payload, None)
    }

    pub fn decode_shared(header: FrameHeader, payload: &Bytes) -> Result<Self, Error> {
        Self::assemble(header, payload.as_ref(), Some(payload))
    }

    pub fn assemble(header: FrameHeader, payload: &[u8], shared: Option<&Bytes>) -> Result<Self, Error> {
        if payload.len() != header.length as usize {
            return Err(Error::Protocol("frame payload does not match its declared length".into()));
        }

        let streamed = header.stream_id != StreamID(0);
        if header.kind.streamed().is_some_and(|expected| expected != streamed) {
            return Err(Error::Protocol(format!("{:?} frame on stream {}", header.kind, header.stream_id.0)));
        }

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
                data: match shared {
                    Some(whole) => whole.slice_ref(payload),
                    None => Bytes::copy_from_slice(payload),
                },
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
                    block: block.to_vec(),
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
                    block: payload[4..].to_vec(),
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
                block: payload.to_vec(),
            }),
        }
    }
}

pub fn write_frame_into(out: &mut BytesMut, kind: FrameType, flags: u8, stream_id: StreamID, payload: &[u8]) {
    let header = FrameHeader { length: payload.len() as u32, kind, flags, stream_id };

    out.reserve(FRAME_HEADER_SIZE + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
}

pub fn exact<const N: usize>(payload: &[u8], name: &str) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(payload)
        .map_err(|_| Error::Protocol(format!("{name} length is {} rather than {N}", payload.len())))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: bool,
}

impl Settings {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

impl StreamState {
    pub fn receivable(&self) -> bool {
        matches!(self, Self::Idle | Self::Open | Self::HalfClosedLocal)
    }

    pub fn sendable(&self) -> bool {
        matches!(self, Self::Idle | Self::Open | Self::HalfClosedRemote)
    }

    pub fn close_local(&self) -> Self {
        match self {
            Self::Open | Self::Idle => Self::HalfClosedLocal,
            _ => Self::Closed,
        }
    }

    pub fn close_remote(&self) -> Self {
        match self {
            Self::Open | Self::Idle => Self::HalfClosedRemote,
            _ => Self::Closed,
        }
    }
}

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

    pub fn state(&self) -> StreamState {
        self.state
    }

    pub fn received(&self) -> u64 {
        self.head + self.body.len() as u64
    }

    pub fn window_local(&self) -> i64 {
        self.window_local
    }

    pub fn window_remote(&self) -> i64 {
        self.window_remote
    }
}

impl common::Stream for H2Stream {
    fn id(&self) -> StreamID {
        self.id
    }

    async fn reset(&mut self, code: u64) {
        self.state = StreamState::Closed;
        self.pending_reset = Some(code);
    }
}

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

    premature_resets: u32,
    idle_frames: u32,
    hsts: Option<crate::helpers::hsts::HstsPolicy>,
}

impl<T> H2Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(transport: T, role: Role, id: ConnectionID, limits: Limits) -> Self {
        Self::resume(transport, role, id, limits, Buffer::new())
    }

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

            premature_resets: 0,
            idle_frames: 0,
            hsts: None,
        }
    }

    pub fn with_hsts(mut self, hsts: Option<crate::helpers::hsts::HstsPolicy>) -> Self {
        self.hsts = hsts;
        self
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn settings_local(&self) -> &Settings {
        &self.settings_local
    }

    pub fn settings_remote(&self) -> &Settings {
        &self.settings_remote
    }

    pub fn hpack_encoder(&self) -> &HPACKEncoder {
        &self.hpack_encoder
    }

    pub fn local_stream_ceiling(&self) -> usize {
        let advertised = self.settings_remote.max_concurrent_streams.unwrap_or(self.limits.max_concurrent_streams);
        (advertised as usize).max(1)
    }

    pub fn stream(&self, stream_id: StreamID) -> Option<&H2Stream> {
        self.streams.get(&stream_id)
    }

    pub fn open_stream(&mut self, stream_id: StreamID) -> Result<&mut H2Stream, Error> {
        self.streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::Protocol(format!("stream {} is no longer open", stream_id.0)))
    }

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

    pub fn queue(&mut self, frame: &Frame) {
        frame.encode_into(&mut self.out);
    }

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

    pub async fn write(&mut self, frame: &Frame) -> Result<(), Error> {
        self.queue(frame);
        self.flush_out().await
    }

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

    pub async fn reset(&mut self, stream_id: StreamID, error_code: u32) -> Result<(), Error> {
        self.streams.remove(&stream_id);
        self.write(&Frame::RstStream { stream_id, error_code }).await
    }

    pub async fn overloaded(&mut self, reason: impl Into<String>) -> Error {
        let goaway = Frame::GoAway {
            last_stream_id: StreamID(self.highest_peer_stream_id),
            error_code: ENHANCE_YOUR_CALM,
            debug_data: Vec::new(),
        };

        let _ = self.write(&goaway).await;
        Error::Limit(reason.into())
    }

    pub async fn idle(&mut self) -> Result<(), Error> {
        self.idle_frames = self.idle_frames.saturating_add(1);

        if self.idle_frames > self.limits.max_idle_frames {
            let reason = format!("more than {} frames arrived without advancing a stream", self.limits.max_idle_frames);
            return Err(self.overloaded(reason).await);
        }

        Ok(())
    }

    pub fn buffered(&self) -> u64 {
        self.streams.values().map(|stream| stream.body.len() as u64).sum()
    }

    pub fn retire(&mut self, stream_id: StreamID) {
        if self.streams.get(&stream_id).is_some_and(|stream| stream.state == StreamState::Closed) {
            self.streams.remove(&stream_id);
        }
    }

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
                self.open_stream(stream_id)?.block = block;

                if !end_headers {
                    return self.continue_headers(stream_id, end_stream).await;
                }

                self.finish_headers(stream_id, end_stream)
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

                let limit = self.limits.max_message_body_size;
                if body > limit {
                    return Err(Error::Limit(format!("body exceeds {limit} octets")));
                }

                let limit = self.limits.max_message_size;
                if received > limit {
                    return Err(Error::Limit(format!("message exceeds {limit} octets")));
                }

                let limit = self.limits.max_connection_buffer_size;
                if self.buffered() > limit {
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
                        return self.finish_headers(stream_id, end_stream);
                    }
                }

                _ => return Err(Error::Protocol("a field block was interrupted".into())),
            }
        }
    }

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

    pub fn finish_headers(&mut self, stream_id: StreamID, end_stream: bool) -> Result<Option<Message>, Error> {
        self.idle_frames = 0;

        let (block, received) = {
            let stream = self.open_stream(stream_id)?;
            stream.head += stream.block.len() as u64;
            (std::mem::take(&mut stream.block), stream.received())
        };

        let limit = self.limits.max_message_size;
        if received > limit {
            return Err(Error::Limit(format!("message exceeds {limit} octets")));
        }

        let decoded = self.hpack_decoder.decode(&block)?;

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

    pub fn drain(&mut self, stream_id: StreamID) -> Option<Bytes> {
        let stream = self.streams.get_mut(&stream_id)?;
        (!stream.body.is_empty()).then(|| std::mem::take(&mut stream.body).freeze())
    }

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
    pub fn tunnel(self, stream_id: StreamID) -> H2Tunnel {
        let (application, internal) = tokio::io::duplex(Buffer::CHUNK_SIZE);
        let driver = tokio::spawn(async move { self.drive(stream_id, internal).await });

        H2Tunnel { stream: application, driver }
    }

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

pub struct H2Tunnel {
    stream: tokio::io::DuplexStream,
    driver: tokio::task::JoinHandle<Result<(), Error>>,
}

impl H2Tunnel {
    pub fn abort(&self) {
        self.driver.abort();
    }

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
        common::within(self.limits.send_timeout, self.send_message(message)).await?
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        common::within(self.limits.receive_timeout, self.receive_message()).await?
    }

    async fn close(&mut self) {
        let last_stream_id = StreamID(self.next_stream_id.saturating_sub(2));
        let goaway = Frame::GoAway { last_stream_id, error_code: NO_ERROR, debug_data: Vec::new() };

        let _ = self.write(&goaway).await;
        let _ = self.transport.shutdown().await;
    }
}
