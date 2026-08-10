//! HTTP/3, from C.
//!
//! The wire format on its own: every frame, the kinds a unidirectional stream
//! announces itself as, and the settings both ends exchange. A frame crosses
//! as a handle, exactly as an HTTP/2 one does — the two versions are kept
//! interchangeable here on purpose.

use bytes::Bytes;

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Slice};
use crate::protocol::h3::frames::{Code, Frame, FrameType, Settings, StreamKind};

/// What one HTTP/3 connection may spend on the peer's behalf.
///
/// The C half of [`H3Limits`], field for field.
///
/// [`H3Limits`]: crate::protocol::h3::H3Limits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct H3Limits {
    /// How large one whole message may grow.
    pub max_message_size: u64,
    /// How large one message body may grow.
    pub max_message_body_size: u64,
    /// How large one message body may grow once its content coding is undone.
    pub max_decompressed_body_size: u64,
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
    /// How many requests one connection may carry before it is retired.
    pub max_requests_per_connection: u64,
    /// How large the peer may size this end's QPACK table.
    pub max_encoder_table_size: u64,
    /// How long a stream may wait QPACK-blocked.
    pub qpack_block_timeout: f64,
    /// How many unidirectional streams the peer may open.
    pub max_peer_uni_streams: u32,
    /// How many unacknowledged field sections the encoder tracks.
    pub max_outstanding_sections: u32,
    /// How many streams may wait QPACK-blocked at once.
    pub max_blocked_streams: u32,
    /// How many tunnelled writes may queue.
    pub tunnel_backlog: u32,
    /// How many commands may queue for the connection's worker.
    pub command_backlog: u32,
    /// How much of a drained buffer is kept for reuse.
    pub idle_capacity: u64,
    /// How long receiving one whole message may take.
    pub receive_timeout: f64,
    /// How long sending one whole message may take.
    pub send_timeout: f64,
}

impl H3Limits {
    /// The C half of `limits`.
    pub fn build(limits: &crate::protocol::h3::H3Limits) -> Self {
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

/// The limits an HTTP/3 connection takes when nothing narrows them.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_limits_default() -> H3Limits {
    H3Limits::build(&crate::protocol::h3::H3Limits::default())
}

/// The limits a [`Limits`] narrows an HTTP/3 connection to.
///
/// # Safety
///
/// `limits` must either be null or point to a readable [`Limits`].
///
/// [`Limits`]: crate::ffi::models::Limits
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_limits_of(limits: *const crate::ffi::models::Limits) -> H3Limits {
    H3Limits::build(&crate::protocol::h3::H3Limits::from(unsafe { crate::ffi::models::Limits::or_default(limits) }))
}

/// What a unidirectional stream announces itself as.
///
/// The C half of [`StreamKind`], numbered as the wire numbers the
/// unidirectional kinds. A request stream is bidirectional and announces
/// nothing, so it has no wire number of its own.
///
/// [`StreamKind`]: crate::protocol::h3::frames::StreamKind
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// The control stream, carrying SETTINGS and connection-wide frames.
    Control = 0x00,
    /// A push stream. Not opened here, since push is disabled.
    Push = 0x01,
    /// The QPACK encoder stream, carrying table insertions.
    QPACKEncoder = 0x02,
    /// The QPACK decoder stream, carrying acknowledgements.
    QPACKDecoder = 0x03,
    /// A bidirectional request stream.
    Request = 0x04,
}

impl Kind {
    /// The C half of `kind`.
    pub fn build(kind: StreamKind) -> Self {
        match kind {
            StreamKind::Control => Self::Control,
            StreamKind::Push => Self::Push,
            StreamKind::QPACKEncoder => Self::QPACKEncoder,
            StreamKind::QPACKDecoder => Self::QPACKDecoder,
            StreamKind::Request => Self::Request,
        }
    }

    /// The [`StreamKind`] this stands for.
    ///
    /// [`StreamKind`]: crate::protocol::h3::frames::StreamKind
    pub fn parse(self) -> StreamKind {
        match self {
            Self::Control => StreamKind::Control,
            Self::Push => StreamKind::Push,
            Self::QPACKEncoder => StreamKind::QPACKEncoder,
            Self::QPACKDecoder => StreamKind::QPACKDecoder,
            Self::Request => StreamKind::Request,
        }
    }
}

/// The code a unidirectional stream announces itself with, or `-1` for a
/// request stream, which announces nothing.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_stream_kind_code(kind: Kind) -> i64 {
    match kind.parse().code() {
        Some(code) => code as i64,
        None => -1,
    }
}

/// The stream kind a code names, or `-1` for one this library does not know.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_stream_kind_from_code(code: u64) -> i32 {
    match StreamKind::from_code(code) {
        Some(kind) => Kind::build(kind) as i32,
        None => -1,
    }
}

/// Which frame this is.
///
/// The C half of [`FrameType`], numbered as the wire numbers them.
///
/// [`FrameType`]: crate::protocol::h3::frames::FrameType
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameKind {
    /// `DATA`: message body octets.
    Data = 0x00,
    /// `HEADERS`: a QPACK-compressed field section.
    Headers = 0x01,
    /// `CANCEL_PUSH`: a promised push is no longer wanted.
    CancelPush = 0x03,
    /// `SETTINGS`: connection parameters.
    Settings = 0x04,
    /// `PUSH_PROMISE`: a promised stream; refused here, since push is disabled.
    PushPromise = 0x05,
    /// `GOAWAY`: no further requests will be accepted.
    GoAway = 0x07,
    /// `MAX_PUSH_ID`: how far push identifiers may go.
    MaxPushID = 0x0d,
}

impl FrameKind {
    /// The C half of `kind`.
    pub fn build(kind: FrameType) -> Self {
        match kind {
            FrameType::Data => Self::Data,
            FrameType::Headers => Self::Headers,
            FrameType::CancelPush => Self::CancelPush,
            FrameType::Settings => Self::Settings,
            FrameType::PushPromise => Self::PushPromise,
            FrameType::GoAway => Self::GoAway,
            FrameType::MaxPushID => Self::MaxPushID,
        }
    }
}

/// Whether a wire number names a frame this library knows.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_frame_type_known(code: u64) -> bool {
    FrameType::from_code(code).is_some()
}

/// How many frame types are reserved to catch an HTTP/2 peer.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_reserved_frame_count() -> usize {
    FrameType::RESERVED.len()
}

/// The reserved frame type at `index`, or `-1` past the end.
///
/// A frame of one of these types means the peer is speaking HTTP/2, which ends
/// the connection rather than being ignored.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_reserved_frame(index: usize) -> i64 {
    match FrameType::RESERVED.get(index) {
        Some(&code) => code as i64,
        None => -1,
    }
}

/// Builds a `DATA` frame.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_data(data: *const u8, data_len: usize) -> *mut Frame {
    let data = Bytes::copy_from_slice(unsafe { Slice::borrow(data, data_len) }.unwrap_or_default());
    Box::into_raw(Box::new(Frame::Data(data)))
}

/// Builds a `HEADERS` frame.
///
/// # Safety
///
/// `block` must either be null or point to `block_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_headers(block: *const u8, block_len: usize) -> *mut Frame {
    let block = Bytes::copy_from_slice(unsafe { Slice::borrow(block, block_len) }.unwrap_or_default());
    Box::into_raw(Box::new(Frame::Headers(block)))
}

/// Builds a `CANCEL_PUSH` frame.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_frame_cancel_push(push_id: u64) -> *mut Frame {
    Box::into_raw(Box::new(Frame::CancelPush { push_id }))
}

/// Builds a `SETTINGS` frame.
///
/// # Safety
///
/// `params` must either be null or point to `count` readable pairs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_settings(params: *const Parameter, count: usize) -> *mut Frame {
    let mut settings = Vec::with_capacity(count);

    if !params.is_null() {
        for index in 0..count {
            let parameter = unsafe { *params.add(index) };
            settings.push((parameter.id, parameter.value));
        }
    }

    Box::into_raw(Box::new(Frame::Settings(settings)))
}

/// One settings parameter: an identifier and the value it is being set to.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Parameter {
    /// Which parameter.
    pub id: u64,
    /// What it is being set to.
    pub value: u64,
}

/// Builds a `PUSH_PROMISE` frame.
///
/// # Safety
///
/// `block` must either be null or point to `block_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_push_promise(push_id: u64, block: *const u8, block_len: usize) -> *mut Frame {
    let block = Bytes::copy_from_slice(unsafe { Slice::borrow(block, block_len) }.unwrap_or_default());
    Box::into_raw(Box::new(Frame::PushPromise { push_id, block }))
}

/// Builds a `GOAWAY` frame.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_frame_goaway(id: u64) -> *mut Frame {
    Box::into_raw(Box::new(Frame::GoAway { id }))
}

/// Builds a `MAX_PUSH_ID` frame.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_frame_max_push_id(push_id: u64) -> *mut Frame {
    Box::into_raw(Box::new(Frame::MaxPushID { push_id }))
}

/// Releases a frame.
///
/// # Safety
///
/// `frame` must come from one of the constructors here or from
/// [`soyokaze_h3_frame_decode`], and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_free(frame: *mut Frame) {
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
pub unsafe extern "C" fn soyokaze_h3_frame_kind(frame: *const Frame) -> FrameKind {
    match unsafe { frame.as_ref() } {
        Some(frame) => FrameKind::build(frame.kind()),
        None => FrameKind::Data,
    }
}

/// The octets a `DATA`, `HEADERS` or `PUSH_PROMISE` frame carries, borrowed
/// from the handle.
///
/// # Safety
///
/// As [`soyokaze_h3_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_bytes(frame: *const Frame) -> Slice {
    match unsafe { frame.as_ref() } {
        Some(Frame::Data(data)) => Slice::new(data),
        Some(Frame::Headers(block)) => Slice::new(block),
        Some(Frame::PushPromise { block, .. }) => Slice::new(block),
        _ => Slice::ABSENT,
    }
}

/// The identifier a `CANCEL_PUSH`, `PUSH_PROMISE`, `GOAWAY` or `MAX_PUSH_ID`
/// carries, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_h3_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_id(frame: *const Frame) -> i64 {
    match unsafe { frame.as_ref() } {
        Some(Frame::CancelPush { push_id }) => *push_id as i64,
        Some(Frame::PushPromise { push_id, .. }) => *push_id as i64,
        Some(Frame::GoAway { id }) => *id as i64,
        Some(Frame::MaxPushID { push_id }) => *push_id as i64,
        _ => -1,
    }
}

/// How many parameters a `SETTINGS` frame carries.
///
/// # Safety
///
/// As [`soyokaze_h3_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_parameter_count(frame: *const Frame) -> usize {
    match unsafe { frame.as_ref() } {
        Some(Frame::Settings(params)) => params.len(),
        _ => 0,
    }
}

/// The parameter at `index` in a `SETTINGS` frame.
///
/// # Safety
///
/// As [`soyokaze_h3_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_parameter(frame: *const Frame, index: usize) -> Parameter {
    match unsafe { frame.as_ref() } {
        Some(Frame::Settings(params)) => match params.get(index) {
            Some(&(id, value)) => Parameter { id, value },
            None => Parameter { id: 0, value: 0 },
        },
        _ => Parameter { id: 0, value: 0 },
    }
}

/// How long the frame's payload is.
///
/// # Safety
///
/// As [`soyokaze_h3_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_payload_len(frame: *const Frame) -> usize {
    unsafe { frame.as_ref() }.map_or(0, |frame| frame.payload_len())
}

/// Encodes the frame, type and length included, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_h3_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_encode(frame: *const Frame) -> Buffer {
    match unsafe { frame.as_ref() } {
        Some(frame) => Buffer::new(frame.encode()),
        None => Buffer::EMPTY,
    }
}

/// Encodes the frame's payload alone, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_h3_frame_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_payload(frame: *const Frame) -> Buffer {
    match unsafe { frame.as_ref() } {
        Some(frame) => Buffer::new(frame.payload()),
        None => Buffer::EMPTY,
    }
}

/// Decodes one frame off a stream of octets.
///
/// As [`soyokaze_h2_frame_decode`], for HTTP/3. A frame of a type this library
/// does not know is consumed and skipped, so a caller that sees
/// [`Status::Closed`] with a non-zero `read` should drop that many octets and
/// try again.
///
/// [`soyokaze_h2_frame_decode`]: crate::ffi::protocol::h2::soyokaze_h2_frame_decode
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` and `read` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_frame_decode(data: *const u8, data_len: usize, out: *mut *mut Frame, read: *mut usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let mut buffer = bytes::BytesMut::from(data);
    let before = buffer.len();

    let outcome = Frame::parse(&mut buffer);

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

/// The parameters one end of a connection has announced.
///
/// The C half of [`Settings`], with the one that may be absent carried as
/// `-1`.
///
/// [`Settings`]: crate::protocol::h3::frames::Settings
#[repr(C)]
#[derive(Clone, Copy)]
pub struct H3Settings {
    /// The QPACK dynamic table capacity this end is willing to hold.
    pub qpack_max_table_capacity: u64,
    /// How many streams may be QPACK-blocked at once.
    pub qpack_blocked_streams: u64,
    /// How large one field section may be, or `-1` for no ceiling.
    pub max_field_section_size: i64,
    /// Whether extended CONNECT is allowed, which WebSocket needs.
    pub enable_connect_protocol: bool,
}

impl H3Settings {
    /// The C half of `settings`.
    pub fn build(settings: &Settings) -> Self {
        Self {
            qpack_max_table_capacity: settings.qpack_max_table_capacity,
            qpack_blocked_streams: settings.qpack_blocked_streams,
            max_field_section_size: settings.max_field_section_size.map_or(-1, |size| size as i64),
            enable_connect_protocol: settings.enable_connect_protocol,
        }
    }

    /// The [`Settings`] this stands for.
    ///
    /// [`Settings`]: crate::protocol::h3::frames::Settings
    pub fn parse(&self) -> Settings {
        Settings {
            qpack_max_table_capacity: self.qpack_max_table_capacity,
            qpack_blocked_streams: self.qpack_blocked_streams,
            max_field_section_size: u64::try_from(self.max_field_section_size).ok(),
            enable_connect_protocol: self.enable_connect_protocol,
        }
    }
}

/// The settings this end starts from.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_settings_default() -> H3Settings {
    H3Settings::build(&Settings::default())
}

/// The settings a peer is assumed to hold until it says otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_settings_peer() -> H3Settings {
    H3Settings::build(&Settings::peer())
}

/// How many parameters these settings would be sent as.
///
/// # Safety
///
/// `settings` must either be null or point to readable settings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_settings_parameter_count(settings: *const H3Settings) -> usize {
    match unsafe { settings.as_ref() } {
        Some(settings) => settings.parse().parameters().len(),
        None => 0,
    }
}

/// The parameter at `index` these settings would be sent as.
///
/// # Safety
///
/// As [`soyokaze_h3_settings_parameter_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_settings_parameter(settings: *const H3Settings, index: usize) -> Parameter {
    let Some(settings) = (unsafe { settings.as_ref() }) else {
        return Parameter { id: 0, value: 0 };
    };

    match settings.parse().parameters().get(index) {
        Some(&(id, value)) => Parameter { id, value },
        None => Parameter { id: 0, value: 0 },
    }
}

/// Applies one parameter the peer sent.
///
/// A parameter this library does not know is accepted and ignored, which is
/// what the protocol asks for; a reserved one ends the connection, since it
/// means the peer is speaking HTTP/2.
///
/// # Safety
///
/// `settings` must either be null or point to writable settings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h3_settings_apply(settings: *mut H3Settings, id: u64, value: u64, error: *mut *mut ErrorHandle) -> Status {
    let Some(settings) = (unsafe { settings.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let mut parsed = settings.parse();

    match parsed.apply(id, value) {
        Ok(()) => {
            *settings = H3Settings::build(&parsed);
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The identifier `SETTINGS_QPACK_MAX_TABLE_CAPACITY` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_setting_qpack_max_table_capacity() -> u64 {
    Settings::QPACK_MAX_TABLE_CAPACITY
}

/// The identifier `SETTINGS_MAX_FIELD_SECTION_SIZE` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_setting_max_field_section_size() -> u64 {
    Settings::MAX_FIELD_SECTION_SIZE
}

/// The identifier `SETTINGS_QPACK_BLOCKED_STREAMS` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_setting_qpack_blocked_streams() -> u64 {
    Settings::QPACK_BLOCKED_STREAMS
}

/// The identifier `SETTINGS_ENABLE_CONNECT_PROTOCOL` travels under.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_setting_enable_connect_protocol() -> u64 {
    Settings::ENABLE_CONNECT_PROTOCOL
}

/// How many settings identifiers are reserved to catch an HTTP/2 peer.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_reserved_setting_count() -> usize {
    Settings::RESERVED.len()
}

/// The reserved settings identifier at `index`, or `-1` past the end.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_reserved_setting(index: usize) -> i64 {
    match Settings::RESERVED.get(index) {
        Some(&id) => id as i64,
        None => -1,
    }
}

/// A fixed name for one of the error codes, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h3_error_code_name(code: u64) -> Slice {
    Slice::text(match code {
        Code::NO_ERROR => "H3_NO_ERROR",
        Code::GENERAL_PROTOCOL_ERROR => "H3_GENERAL_PROTOCOL_ERROR",
        Code::INTERNAL_ERROR => "H3_INTERNAL_ERROR",
        Code::STREAM_CREATION_ERROR => "H3_STREAM_CREATION_ERROR",
        Code::CLOSED_CRITICAL_STREAM => "H3_CLOSED_CRITICAL_STREAM",
        Code::FRAME_UNEXPECTED => "H3_FRAME_UNEXPECTED",
        Code::FRAME_ERROR => "H3_FRAME_ERROR",
        Code::EXCESSIVE_LOAD => "H3_EXCESSIVE_LOAD",
        Code::ID_ERROR => "H3_ID_ERROR",
        Code::SETTINGS_ERROR => "H3_SETTINGS_ERROR",
        Code::MISSING_SETTINGS => "H3_MISSING_SETTINGS",
        Code::REQUEST_REJECTED => "H3_REQUEST_REJECTED",
        Code::REQUEST_CANCELLED => "H3_REQUEST_CANCELLED",
        Code::REQUEST_INCOMPLETE => "H3_REQUEST_INCOMPLETE",
        Code::MESSAGE_ERROR => "H3_MESSAGE_ERROR",
        Code::CONNECT_ERROR => "H3_CONNECT_ERROR",
        Code::VERSION_FALLBACK => "H3_VERSION_FALLBACK",
        Code::QPACK_DECOMPRESSION_FAILED => "QPACK_DECOMPRESSION_FAILED",
        Code::QPACK_ENCODER_STREAM_ERROR => "QPACK_ENCODER_STREAM_ERROR",
        Code::QPACK_DECODER_STREAM_ERROR => "QPACK_DECODER_STREAM_ERROR",
        _ => "UNKNOWN",
    })
}
