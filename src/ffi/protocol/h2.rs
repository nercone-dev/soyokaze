//! HTTP/2, from C.
//!
//! The wire format on its own: the connection preface, the frame header, every
//! frame, and the settings both ends exchange. A frame crosses as a handle,
//! since each kind carries different fields, and is built by the constructor
//! that names it and read back through the accessors — the same shape the
//! QPACK instructions take.

use bytes::Bytes;

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Slice};
use crate::models::StreamID;
use crate::protocol::h2::frames::{Code, Flag, Frame, FrameHeader, FrameType, Settings};

/// What one HTTP/2 connection may spend on the peer's behalf.
///
/// The C half of [`H2Limits`], field for field.
///
/// [`H2Limits`]: crate::protocol::h2::H2Limits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct H2Limits {
    /// How large one whole message may grow.
    pub max_message_size: u64,
    /// How large one message body may grow.
    pub max_message_body_size: u64,
    /// How large the field section may grow.
    pub max_headers_size: u64,
    /// How many fields one section may hold.
    pub max_header_count: u16,
    /// How many streams may be open at once.
    pub max_concurrent_streams: u32,
    /// How many octets may sit buffered across every stream.
    pub max_connection_buffer_size: u64,
    /// How many streams the peer may open and abandon before it is cut off.
    pub max_premature_resets: u32,
    /// How many frames that do nothing may arrive before the peer is cut off.
    pub max_idle_frames: u32,
    /// How much output may queue before a write is forced.
    pub output_high_water: u64,
    /// How large the peer may size this end's HPACK table.
    pub max_encoder_table_size: u64,
    /// How many octets one read asks the transport for.
    pub read_chunk_size: u64,
    /// How much of a drained buffer is kept for reuse.
    pub idle_capacity: u64,
    /// How long one read may take.
    pub read_timeout: f64,
    /// How long one write may take.
    pub write_timeout: f64,
    /// How long receiving one whole message may take.
    pub receive_timeout: f64,
    /// How long sending one whole message may take.
    pub send_timeout: f64,
}

impl H2Limits {
    /// The C half of `limits`.
    pub fn build(limits: &crate::protocol::h2::H2Limits) -> Self {
        Self {
            max_message_size: limits.max_message_size,
            max_message_body_size: limits.max_message_body_size,
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

/// The limits an HTTP/2 connection takes when nothing narrows them.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_limits_default() -> H2Limits {
    H2Limits::build(&crate::protocol::h2::H2Limits::default())
}

/// The limits a [`Limits`] narrows an HTTP/2 connection to.
///
/// # Safety
///
/// `limits` must either be null or point to a readable [`Limits`].
///
/// [`Limits`]: crate::ffi::models::Limits
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_limits_of(limits: *const crate::ffi::models::Limits) -> H2Limits {
    H2Limits::build(&crate::protocol::h2::H2Limits::from(unsafe { crate::ffi::models::Limits::or_default(limits) }))
}

/// The octets an HTTP/2 connection opens with, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_preface() -> Slice {
    Slice::new(crate::protocol::h2::PREFACE)
}

/// The HTTP/2 error codes, as they travel in `RST_STREAM` and `GOAWAY`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrorCode {
    /// The stream or connection ended with nothing wrong.
    NoError = 0x0,
    /// The peer broke the protocol.
    ProtocolError = 0x1,
    /// This end could not carry on.
    InternalError = 0x2,
    /// A flow control window was overrun.
    FlowControlError = 0x3,
    /// Settings went unacknowledged for too long.
    SettingsTimeout = 0x4,
    /// A frame arrived on a stream that is closed.
    StreamClosed = 0x5,
    /// A frame's length is wrong for its kind.
    FrameSizeError = 0x6,
    /// The stream was refused before anything was done with it.
    RefusedStream = 0x7,
    /// The stream is no longer wanted.
    Cancel = 0x8,
    /// The HPACK tables have diverged.
    CompressionError = 0x9,
    /// A tunnelled connection failed.
    ConnectError = 0xa,
    /// The peer is asking for too much, too fast.
    EnhanceYourCalm = 0xb,
    /// The transport underneath is not secure enough.
    InadequateSecurity = 0xc,
    /// The request must be retried over HTTP/1.1.
    HTTP11Required = 0xd,
}

/// The `END_STREAM` flag, which says the message ends with this frame.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_flag_end_stream() -> u8 {
    Flag::END_STREAM
}

/// The `ACK` flag, which turns a `SETTINGS` or `PING` into its answer.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_flag_ack() -> u8 {
    Flag::ACK
}

/// The `END_HEADERS` flag, which says the field section is complete.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_flag_end_headers() -> u8 {
    Flag::END_HEADERS
}

/// The `PADDED` flag, which says a padding length leads the payload.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_flag_padded() -> u8 {
    Flag::PADDED
}

/// The `PRIORITY` flag, which says priority information leads the block.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_flag_priority() -> u8 {
    Flag::PRIORITY
}

/// Which frame this is.
///
/// The C half of [`FrameType`], numbered as the wire numbers them.
///
/// [`FrameType`]: crate::protocol::h2::frames::FrameType
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// `DATA`: message body octets.
    Data = 0x0,
    /// `HEADERS`: a compressed field section.
    Headers = 0x1,
    /// `PRIORITY`: a priority hint, which this implementation reads and ignores.
    Priority = 0x2,
    /// `RST_STREAM`: abandon one stream.
    RstStream = 0x3,
    /// `SETTINGS`: connection parameters, or their acknowledgement.
    Settings = 0x4,
    /// `PUSH_PROMISE`: a promised stream; refused here, since push is disabled.
    PushPromise = 0x5,
    /// `PING`: a liveness probe, or its acknowledgement.
    Ping = 0x6,
    /// `GOAWAY`: no further streams will be accepted.
    GoAway = 0x7,
    /// `WINDOW_UPDATE`: more flow control credit.
    WindowUpdate = 0x8,
    /// `CONTINUATION`: more of the field section a `HEADERS` frame began.
    Continuation = 0x9,
}

impl Kind {
    /// The C half of `kind`.
    pub fn build(kind: FrameType) -> Self {
        match kind {
            FrameType::Data => Self::Data,
            FrameType::Headers => Self::Headers,
            FrameType::Priority => Self::Priority,
            FrameType::RstStream => Self::RstStream,
            FrameType::Settings => Self::Settings,
            FrameType::PushPromise => Self::PushPromise,
            FrameType::Ping => Self::Ping,
            FrameType::GoAway => Self::GoAway,
            FrameType::WindowUpdate => Self::WindowUpdate,
            FrameType::Continuation => Self::Continuation,
        }
    }
}

/// Whether a wire number names a frame this library knows.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_frame_type_known(code: u8) -> bool {
    FrameType::from_code(code).is_some()
}

/// Whether a frame kind belongs on a stream.
///
/// `1` for a frame that must name one, `0` for one that must not, and `-1` for
/// the two that may go either way.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_frame_type_streamed(kind: Kind) -> i32 {
    let kind = match FrameType::from_code(kind as u8) {
        Some(kind) => kind,
        None => return -1,
    };

    match kind.streamed() {
        Some(true) => 1,
        Some(false) => 0,
        None => -1,
    }
}

/// The head of a frame, as it sits on the wire.
///
/// The C half of [`FrameHeader`], field for field.
///
/// [`FrameHeader`]: crate::protocol::h2::frames::FrameHeader
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Header {
    /// How long the payload is.
    pub length: u32,
    /// Which frame this is.
    pub kind: Kind,
    /// The flags that go with it.
    pub flags: u8,
    /// The stream it names, or zero for the connection as a whole.
    pub stream_id: u64,
}

/// How many octets a frame header is.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_header_size() -> usize {
    FrameHeader::SIZE
}

/// Encodes a frame header, owned by the caller. Always nine octets.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_header_encode(header: Header) -> Buffer {
    let header = FrameHeader {
        length: header.length,
        kind: FrameType::from_code(header.kind as u8).unwrap_or(FrameType::Data),
        flags: header.flags,
        stream_id: StreamID(header.stream_id),
    };

    Buffer::new(header.encode().to_vec())
}

/// Decodes a frame header, writing it through `out` and its length through
/// `length`.
///
/// The length is always written, even for a frame kind this library does not
/// know, so a caller can skip past one it cannot read. Returns whether the
/// kind was one it knows.
///
/// # Safety
///
/// `data` must point to at least [`soyokaze_h2_header_size`] readable octets,
/// and `out` and `length` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_header_decode(data: *const u8, data_len: usize, out: *mut Header, length: *mut u32) -> bool {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return false;
    };

    let Some(octets) = data.first_chunk::<{ FrameHeader::SIZE }>() else {
        return false;
    };

    let (payload_length, header) = FrameHeader::decode(octets);

    if !length.is_null() {
        unsafe { *length = payload_length };
    }

    let Some(header) = header else {
        return false;
    };

    if !out.is_null() {
        unsafe {
            *out = Header {
                length: header.length,
                kind: Kind::build(header.kind),
                flags: header.flags,
                stream_id: header.stream_id.0,
            }
        };
    }

    true
}

/// Builds a `DATA` frame.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_data(stream_id: u64, end_stream: bool, data: *const u8, data_len: usize) -> *mut Frame {
    let data = Bytes::copy_from_slice(unsafe { Slice::borrow(data, data_len) }.unwrap_or_default());
    Box::into_raw(Box::new(Frame::Data { stream_id: StreamID(stream_id), end_stream, data }))
}

/// Builds a `HEADERS` frame.
///
/// # Safety
///
/// `block` must either be null or point to `block_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_headers(stream_id: u64, end_stream: bool, end_headers: bool, block: *const u8, block_len: usize) -> *mut Frame {
    let block = Bytes::copy_from_slice(unsafe { Slice::borrow(block, block_len) }.unwrap_or_default());
    Box::into_raw(Box::new(Frame::Headers { stream_id: StreamID(stream_id), end_stream, end_headers, block }))
}

/// Builds a `PRIORITY` frame.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_frame_priority(stream_id: u64, dependency: u64, exclusive: bool, weight: u8) -> *mut Frame {
    Box::into_raw(Box::new(Frame::Priority { stream_id: StreamID(stream_id), dependency: StreamID(dependency), exclusive, weight }))
}

/// Builds a `RST_STREAM` frame.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_frame_rst_stream(stream_id: u64, error_code: u32) -> *mut Frame {
    Box::into_raw(Box::new(Frame::RstStream { stream_id: StreamID(stream_id), error_code }))
}

/// Builds a `SETTINGS` frame.
///
/// `params` is one identifier and value pair per two words, in the order they
/// are to be sent. An `ack` frame carries none.
///
/// # Safety
///
/// `params` must either be null or point to `count` readable pairs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_settings(ack: bool, params: *const Parameter, count: usize) -> *mut Frame {
    let mut settings = Vec::with_capacity(count);

    if !params.is_null() {
        for index in 0..count {
            let parameter = unsafe { *params.add(index) };
            settings.push((parameter.id, parameter.value));
        }
    }

    Box::into_raw(Box::new(Frame::Settings { ack, params: settings }))
}

/// One settings parameter: an identifier and the value it is being set to.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Parameter {
    /// Which parameter.
    pub id: u16,
    /// What it is being set to.
    pub value: u32,
}

/// Builds a `PUSH_PROMISE` frame.
///
/// # Safety
///
/// `block` must either be null or point to `block_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_push_promise(stream_id: u64, promised_stream_id: u64, block: *const u8, block_len: usize) -> *mut Frame {
    let block = Bytes::copy_from_slice(unsafe { Slice::borrow(block, block_len) }.unwrap_or_default());
    Box::into_raw(Box::new(Frame::PushPromise { stream_id: StreamID(stream_id), promised_stream_id: StreamID(promised_stream_id), block }))
}

/// Builds a `PING` frame.
///
/// `payload` is exactly eight octets, echoed back unchanged.
///
/// # Safety
///
/// `payload` must either be null or point to eight readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_ping(ack: bool, payload: *const u8) -> *mut Frame {
    let payload = match unsafe { Slice::borrow(payload, 8) } {
        Some(payload) => match <[u8; 8]>::try_from(payload) {
            Ok(payload) => payload,
            Err(_) => return std::ptr::null_mut(),
        },
        None => [0; 8],
    };

    Box::into_raw(Box::new(Frame::Ping { ack, payload }))
}

/// Builds a `GOAWAY` frame.
///
/// # Safety
///
/// `debug_data` must either be null or point to `debug_data_len` readable
/// octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_goaway(last_stream_id: u64, error_code: u32, debug_data: *const u8, debug_data_len: usize) -> *mut Frame {
    let debug_data = unsafe { Slice::borrow(debug_data, debug_data_len) }.unwrap_or_default().to_vec();
    Box::into_raw(Box::new(Frame::GoAway { last_stream_id: StreamID(last_stream_id), error_code, debug_data }))
}

/// Builds a `WINDOW_UPDATE` frame.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_frame_window_update(stream_id: u64, increment: u32) -> *mut Frame {
    Box::into_raw(Box::new(Frame::WindowUpdate { stream_id: StreamID(stream_id), increment }))
}

/// Builds a `CONTINUATION` frame.
///
/// # Safety
///
/// `block` must either be null or point to `block_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_continuation(stream_id: u64, end_headers: bool, block: *const u8, block_len: usize) -> *mut Frame {
    let block = Bytes::copy_from_slice(unsafe { Slice::borrow(block, block_len) }.unwrap_or_default());
    Box::into_raw(Box::new(Frame::Continuation { stream_id: StreamID(stream_id), end_headers, block }))
}

/// Releases a frame.
///
/// # Safety
///
/// `frame` must come from one of the constructors here or from
/// [`soyokaze_h2_frame_decode`], and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_free(frame: *mut Frame) {
    if !frame.is_null() {
        drop(unsafe { Box::from_raw(frame) });
    }
}

/// Which frame this is.
///
/// A null handle reads as `DATA`.
///
/// # Safety
///
/// `frame` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_kind(frame: *const Frame) -> Kind {
    match unsafe { frame.as_ref() } {
        Some(frame) => Kind::build(frame.kind()),
        None => Kind::Data,
    }
}

/// The stream the frame names, or zero for the connection as a whole.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_stream_id(frame: *const Frame) -> u64 {
    unsafe { frame.as_ref() }.map_or(0, |frame| frame.stream_id().0)
}

/// The flags the frame carries.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_flags(frame: *const Frame) -> u8 {
    unsafe { frame.as_ref() }.map_or(0, |frame| frame.flags())
}

/// The octets a `DATA`, `HEADERS`, `PUSH_PROMISE`, `CONTINUATION`, `PING` or
/// `GOAWAY` frame carries, borrowed from the handle.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_bytes(frame: *const Frame) -> Slice {
    match unsafe { frame.as_ref() } {
        Some(Frame::Data { data, .. }) => Slice::new(data),
        Some(Frame::Headers { block, .. }) => Slice::new(block),
        Some(Frame::PushPromise { block, .. }) => Slice::new(block),
        Some(Frame::Continuation { block, .. }) => Slice::new(block),
        Some(Frame::Ping { payload, .. }) => Slice::new(payload),
        Some(Frame::GoAway { debug_data, .. }) => Slice::new(debug_data),
        _ => Slice::ABSENT,
    }
}

/// The error code a `RST_STREAM` or `GOAWAY` carries, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_error_code(frame: *const Frame) -> i64 {
    match unsafe { frame.as_ref() } {
        Some(Frame::RstStream { error_code, .. }) => *error_code as i64,
        Some(Frame::GoAway { error_code, .. }) => *error_code as i64,
        _ => -1,
    }
}

/// The second stream a `GOAWAY`, `PUSH_PROMISE` or `PRIORITY` names, or `-1`.
///
/// That is the last stream still to be processed, the stream being promised,
/// or the stream depended on, whichever the frame is.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_other_stream_id(frame: *const Frame) -> i64 {
    match unsafe { frame.as_ref() } {
        Some(Frame::GoAway { last_stream_id, .. }) => last_stream_id.0 as i64,
        Some(Frame::PushPromise { promised_stream_id, .. }) => promised_stream_id.0 as i64,
        Some(Frame::Priority { dependency, .. }) => dependency.0 as i64,
        _ => -1,
    }
}

/// The credit a `WINDOW_UPDATE` adds, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_increment(frame: *const Frame) -> i64 {
    match unsafe { frame.as_ref() } {
        Some(Frame::WindowUpdate { increment, .. }) => *increment as i64,
        _ => -1,
    }
}

/// The weight a `PRIORITY` carries, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_weight(frame: *const Frame) -> i32 {
    match unsafe { frame.as_ref() } {
        Some(Frame::Priority { weight, .. }) => *weight as i32,
        _ => -1,
    }
}

/// Whether a `PRIORITY` calls its dependency exclusive.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_exclusive(frame: *const Frame) -> bool {
    matches!(unsafe { frame.as_ref() }, Some(Frame::Priority { exclusive: true, .. }))
}

/// How many parameters a `SETTINGS` frame carries.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_parameter_count(frame: *const Frame) -> usize {
    match unsafe { frame.as_ref() } {
        Some(Frame::Settings { params, .. }) => params.len(),
        _ => 0,
    }
}

/// The parameter at `index` in a `SETTINGS` frame.
///
/// An index past the end reads as an identifier and value of zero.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_parameter(frame: *const Frame, index: usize) -> Parameter {
    match unsafe { frame.as_ref() } {
        Some(Frame::Settings { params, .. }) => match params.get(index) {
            Some(&(id, value)) => Parameter { id, value },
            None => Parameter { id: 0, value: 0 },
        },
        _ => Parameter { id: 0, value: 0 },
    }
}

/// Encodes the frame, header and payload, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_encode(frame: *const Frame) -> Buffer {
    match unsafe { frame.as_ref() } {
        Some(frame) => Buffer::new(frame.encode()),
        None => Buffer::EMPTY,
    }
}

/// Encodes the frame's payload alone, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_h2_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_payload(frame: *const Frame) -> Buffer {
    match unsafe { frame.as_ref() } {
        Some(frame) => Buffer::new(frame.payload()),
        None => Buffer::EMPTY,
    }
}

/// Decodes one frame off a stream of octets.
///
/// Writes the frame through `out` and how many octets it took through `read`.
/// Returns [`Status::Ok`] when a whole frame was there, [`Status::Closed`]
/// when more octets are needed, and a protocol failure when it is malformed. A
/// frame kind this library does not know is skipped, and decoding carries on
/// past it, so a caller that sees [`Status::Closed`] with a non-zero `read`
/// should drop that many octets and try again.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` and `read` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_frame_decode(data: *const u8, data_len: usize, max_frame_size: u32, out: *mut *mut Frame, read: *mut usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let mut buffer = bytes::BytesMut::from(data);
    let before = buffer.len();

    let outcome = Frame::parse(&mut buffer, max_frame_size);

    if !read.is_null() {
        unsafe { *read = before - buffer.len() };
    }

    match outcome {
        Ok(Some(frame)) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(frame)) };
            }

            Status::Ok
        }
        Ok(None) => Status::Closed,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The connection parameters both ends exchange.
///
/// The C half of [`Settings`], with the two that may be absent carried as
/// `-1`.
///
/// [`Settings`]: crate::protocol::h2::frames::Settings
#[repr(C)]
#[derive(Clone, Copy)]
pub struct H2Settings {
    /// How large the peer may size its HPACK table.
    pub header_table_size: u32,
    /// Whether server push is allowed. Always false here.
    pub enable_push: bool,
    /// How many streams may be open at once, or `-1` for no ceiling.
    pub max_concurrent_streams: i64,
    /// The flow control window each new stream opens with.
    pub initial_window_size: u32,
    /// How large one frame's payload may be.
    pub max_frame_size: u32,
    /// How large one field section may be, or `-1` for no ceiling.
    pub max_header_list_size: i64,
    /// Whether extended CONNECT is allowed, which WebSocket needs.
    pub enable_connect_protocol: bool,
}

impl H2Settings {
    /// The C half of `settings`.
    pub fn build(settings: &Settings) -> Self {
        Self {
            header_table_size: settings.header_table_size,
            enable_push: settings.enable_push,
            max_concurrent_streams: settings.max_concurrent_streams.map_or(-1, |streams| streams as i64),
            initial_window_size: settings.initial_window_size,
            max_frame_size: settings.max_frame_size,
            max_header_list_size: settings.max_header_list_size.map_or(-1, |size| size as i64),
            enable_connect_protocol: settings.enable_connect_protocol,
        }
    }

    /// The [`Settings`] this stands for.
    ///
    /// [`Settings`]: crate::protocol::h2::frames::Settings
    pub fn parse(&self) -> Settings {
        Settings {
            header_table_size: self.header_table_size,
            enable_push: self.enable_push,
            max_concurrent_streams: u32::try_from(self.max_concurrent_streams).ok(),
            initial_window_size: self.initial_window_size,
            max_frame_size: self.max_frame_size,
            max_header_list_size: u32::try_from(self.max_header_list_size).ok(),
            enable_connect_protocol: self.enable_connect_protocol,
        }
    }
}

/// The settings this end starts from.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_settings_default() -> H2Settings {
    H2Settings::build(&Settings::default())
}

/// The settings a peer is assumed to hold until it says otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_settings_peer() -> H2Settings {
    H2Settings::build(&Settings::peer())
}

/// How many parameters these settings would be sent as.
///
/// # Safety
///
/// `settings` must either be null or point to readable settings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_settings_parameter_count(settings: *const H2Settings) -> usize {
    match unsafe { settings.as_ref() } {
        Some(settings) => settings.parse().parameters().len(),
        None => 0,
    }
}

/// The parameter at `index` these settings would be sent as.
///
/// # Safety
///
/// As [`soyokaze_h2_settings_parameter_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_settings_parameter(settings: *const H2Settings, index: usize) -> Parameter {
    let Some(settings) = (unsafe { settings.as_ref() }) else {
        return Parameter { id: 0, value: 0 };
    };

    match settings.parse().parameters().get(index) {
        Some(&(id, value)) => Parameter { id, value },
        None => Parameter { id: 0, value: 0 },
    }
}

/// Applies one parameter the peer sent, writing through `window_delta` how
/// much every open stream's window moves as a result.
///
/// Only `SETTINGS_INITIAL_WINDOW_SIZE` moves a window; everything else writes
/// zero. A parameter this library does not know is accepted and ignored, which
/// is what the protocol asks for.
///
/// # Safety
///
/// `settings` must either be null or point to writable settings, and
/// `window_delta` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h2_settings_apply(settings: *mut H2Settings, id: u16, value: u32, window_delta: *mut i64, error: *mut *mut ErrorHandle) -> Status {
    let Some(settings) = (unsafe { settings.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let mut parsed = settings.parse();

    match parsed.apply(id, value) {
        Ok(delta) => {
            *settings = H2Settings::build(&parsed);

            if !window_delta.is_null() {
                unsafe { *window_delta = delta };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The identifier `SETTINGS_HEADER_TABLE_SIZE` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_setting_header_table_size() -> u16 {
    Settings::HEADER_TABLE_SIZE
}

/// The identifier `SETTINGS_ENABLE_PUSH` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_setting_enable_push() -> u16 {
    Settings::ENABLE_PUSH
}

/// The identifier `SETTINGS_MAX_CONCURRENT_STREAMS` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_setting_max_concurrent_streams() -> u16 {
    Settings::MAX_CONCURRENT_STREAMS
}

/// The identifier `SETTINGS_INITIAL_WINDOW_SIZE` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_setting_initial_window_size() -> u16 {
    Settings::INITIAL_WINDOW_SIZE
}

/// The identifier `SETTINGS_MAX_FRAME_SIZE` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_setting_max_frame_size() -> u16 {
    Settings::MAX_FRAME_SIZE
}

/// The identifier `SETTINGS_MAX_HEADER_LIST_SIZE` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_setting_max_header_list_size() -> u16 {
    Settings::MAX_HEADER_LIST_SIZE
}

/// The identifier `SETTINGS_ENABLE_CONNECT_PROTOCOL` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_setting_enable_connect_protocol() -> u16 {
    Settings::ENABLE_CONNECT_PROTOCOL
}

/// The flow control window a stream opens with before any settings arrive.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_default_initial_window_size() -> u32 {
    Settings::DEFAULT_INITIAL_WINDOW_SIZE
}

/// The frame size a connection assumes before any settings arrive.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_default_max_frame_size() -> u32 {
    Settings::DEFAULT_MAX_FRAME_SIZE
}

/// The largest frame size a peer may ask for.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_maximum_frame_size() -> u32 {
    Settings::MAXIMUM_FRAME_SIZE
}

/// The largest flow control window a peer may ask for.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_maximum_window_size() -> u32 {
    Settings::MAXIMUM_WINDOW_SIZE
}

/// A fixed name for one of the error codes, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h2_error_code_name(code: u32) -> Slice {
    Slice::text(match code {
        Code::NO_ERROR => "NO_ERROR",
        Code::PROTOCOL_ERROR => "PROTOCOL_ERROR",
        Code::INTERNAL_ERROR => "INTERNAL_ERROR",
        Code::FLOW_CONTROL_ERROR => "FLOW_CONTROL_ERROR",
        Code::SETTINGS_TIMEOUT => "SETTINGS_TIMEOUT",
        Code::STREAM_CLOSED => "STREAM_CLOSED",
        Code::FRAME_SIZE_ERROR => "FRAME_SIZE_ERROR",
        Code::REFUSED_STREAM => "REFUSED_STREAM",
        Code::CANCEL => "CANCEL",
        Code::COMPRESSION_ERROR => "COMPRESSION_ERROR",
        Code::CONNECT_ERROR => "CONNECT_ERROR",
        Code::ENHANCE_YOUR_CALM => "ENHANCE_YOUR_CALM",
        Code::INADEQUATE_SECURITY => "INADEQUATE_SECURITY",
        Code::HTTP_1_1_REQUIRED => "HTTP_1_1_REQUIRED",
        _ => "UNKNOWN",
    })
}
