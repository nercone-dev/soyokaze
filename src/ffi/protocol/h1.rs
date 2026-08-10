//! HTTP/1.x, from C.
//!
//! The wire format on its own: the start line, one field, one chunk, and how a
//! body's length is worked out. Nothing here touches a connection, so a caller
//! can frame and parse HTTP/1.x messages without opening one — which is what
//! [`crate::protocol::h1`] separates the same way.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::models::HeaderCase;
use crate::ffi::{Buffer, Slice};
use crate::models::{Headers, Message, Method, Version};
use crate::protocol::h1::{BodyLength, Chunk, Field, Number, Octets, Persistence, StartLine};

/// What one HTTP/1.x connection may spend on the peer's behalf.
///
/// The C half of [`H1Limits`], field for field. Derived from a [`Limits`] when
/// a connection is built, so a caller sets these through that rather than
/// here.
///
/// [`H1Limits`]: crate::protocol::h1::H1Limits
/// [`Limits`]: crate::ffi::models::Limits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct H1Limits {
    /// How large one whole message may grow.
    pub max_message_size: u64,
    /// How large one message body may grow.
    pub max_message_body_size: u64,
    /// How large one message body may grow once its content coding is undone.
    pub max_decompressed_body_size: u64,
    /// How long the start line may be.
    pub max_startline_size: u32,
    /// How large the field section may grow.
    pub max_headers_size: u64,
    /// How many fields one section may hold.
    pub max_header_count: u16,
    /// How long one chunk header may be.
    pub max_chunk_header_size: u32,
    /// How large a body may be before it is streamed rather than held.
    pub inline_body_size: u64,
    /// How many requests may be in flight at once.
    pub max_concurrent_streams: u32,
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

impl H1Limits {
    /// The C half of `limits`.
    pub fn build(limits: &crate::protocol::h1::H1Limits) -> Self {
        Self {
            max_message_size: limits.max_message_size,
            max_message_body_size: limits.max_message_body_size,
            max_decompressed_body_size: limits.max_decompressed_body_size,
            max_startline_size: limits.max_startline_size,
            max_headers_size: limits.max_headers_size,
            max_header_count: limits.max_header_count,
            max_chunk_header_size: limits.max_chunk_header_size,
            inline_body_size: limits.inline_body_size,
            max_concurrent_streams: limits.max_concurrent_streams,
            read_chunk_size: limits.read_chunk_size,
            idle_capacity: limits.idle_capacity,
            read_timeout: limits.read_timeout,
            write_timeout: limits.write_timeout,
            receive_timeout: limits.receive_timeout,
            send_timeout: limits.send_timeout,
        }
    }
}

/// The limits an HTTP/1.x connection takes when nothing narrows them.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h1_limits_default() -> H1Limits {
    H1Limits::build(&crate::protocol::h1::H1Limits::default())
}

/// The limits a [`Limits`] narrows an HTTP/1.x connection to.
///
/// # Safety
///
/// `limits` must either be null or point to a readable [`Limits`].
///
/// [`Limits`]: crate::ffi::models::Limits
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_limits_of(limits: *const crate::ffi::models::Limits) -> H1Limits {
    H1Limits::build(&crate::protocol::h1::H1Limits::from(unsafe { crate::ffi::models::Limits::or_default(limits) }))
}

/// The classification bit for an octet that may appear in a token.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h1_token() -> u8 {
    Octets::TOKEN
}

/// The classification bit for an octet that may appear in a field value.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h1_field() -> u8 {
    Octets::FIELD
}

/// The 256-entry classification table the parsers walk, borrowed from the
/// library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h1_octet_table() -> Slice {
    Slice::new(Octets::TABLE)
}

/// Whether an octet is a control character, which no field may carry.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h1_is_control(octet: u8) -> bool {
    Octets::is_control(octet)
}

/// Whether every octet may appear in a token.
///
/// # Safety
///
/// `text` must either be null or point to `text_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_is_token(text: *const u8, text_len: usize) -> bool {
    Octets::is_token_bytes(unsafe { Slice::borrow(text, text_len) }.unwrap_or_default())
}

/// Whether a message may be followed by another on the same connection.
///
/// A null `headers` reads as a message carrying no fields at all, which for
/// HTTP/1.1 keeps the connection and for HTTP/1.0 does not.
///
/// # Safety
///
/// `headers` must either be null or be a section that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_keep_alive(headers: *const Headers, version: Version) -> bool {
    Persistence::keep_alive(unsafe { headers.as_ref() }, version)
}

/// Writes a message's start line, owned by the caller.
///
/// An empty buffer with a null pointer means the message could not be written
/// — a request with no method or target, or a response with no status code.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_start_line_encode(message: *const Message) -> Buffer {
    let Some(message) = (unsafe { message.as_ref() }) else {
        return Buffer::EMPTY;
    };

    match StartLine::encode(message) {
        Ok(line) => Buffer::new(line.into_bytes()),
        Err(_) => Buffer::EMPTY,
    }
}

/// Reads a start line into a message with nothing else filled in.
///
/// # Safety
///
/// `line` must either be null or point to `line_len` readable octets, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_start_line_parse(line: *const u8, line_len: usize, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    let Some(line) = (unsafe { Slice::borrow(line, line_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match StartLine::parse_bytes(line) {
        Ok(message) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(message)) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The status code a malformed start line is answered with.
///
/// A method this end does not know earns `501`, a version it will not speak
/// `505`, and everything else `400`.
///
/// # Safety
///
/// `line` must either be null or point to `line_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_start_line_error_status(line: *const u8, line_len: usize) -> u16 {
    StartLine::error_status_bytes(unsafe { Slice::borrow(line, line_len) }.unwrap_or_default())
}

/// The version a start line's `HTTP/x.y` token names.
///
/// # Safety
///
/// `text` must either be null or point to `text_len` readable octets, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_version_parse(text: *const u8, text_len: usize, out: *mut Version, error: *mut *mut ErrorHandle) -> Status {
    let Some(text) = (unsafe { Slice::borrow_text(text, text_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match StartLine::version(text) {
        Ok(version) => {
            if !out.is_null() {
                unsafe { *out = version };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Writes one field line, owned by the caller.
///
/// An empty buffer with a null pointer means the name is not a token or the
/// value carries something a field may not.
///
/// # Safety
///
/// `name` and `value` must either be null or point to their stated number of
/// readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_field_encode(name: *const u8, name_len: usize, value: *const u8, value_len: usize, header_case: HeaderCase) -> Buffer {
    let (Some(name), Some(value)) = (unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return Buffer::EMPTY;
    };

    match Field::encode(name, value, header_case.parse()) {
        Ok(line) => Buffer::new(line.into_bytes()),
        Err(_) => Buffer::EMPTY,
    }
}

/// Writes a whole field section, owned by the caller.
///
/// # Safety
///
/// `headers` must either be null or be a section that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_field_encode_all(headers: *const Headers, header_case: HeaderCase) -> Buffer {
    let Some(headers) = (unsafe { headers.as_ref() }) else {
        return Buffer::EMPTY;
    };

    match Field::encode_all(headers, header_case.parse()) {
        Ok(block) => Buffer::new(block.into_bytes()),
        Err(_) => Buffer::EMPTY,
    }
}

/// How many octets a field section costs against the headers ceiling.
///
/// # Safety
///
/// As [`soyokaze_h1_field_encode_all`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_field_size(headers: *const Headers) -> u64 {
    match unsafe { headers.as_ref() } {
        Some(headers) => Field::size(headers),
        None => 0,
    }
}

/// Reads one field line, writing the name and value through `name` and
/// `value`, owned by the caller.
///
/// # Safety
///
/// `line` must either be null or point to `line_len` readable octets, and
/// `name` and `value` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_field_parse(line: *const u8, line_len: usize, name: *mut Buffer, value: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let Some(line) = (unsafe { Slice::borrow(line, line_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Field::parse_bytes(line) {
        Ok((parsed_name, parsed_value)) => {
            if !name.is_null() {
                unsafe { *name = Buffer::new(parsed_name.into_bytes()) };
            }

            if !value.is_null() {
                unsafe { *value = Buffer::new(parsed_value.into_bytes()) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Reads a whole field block into a section.
///
/// The block is the octets between the start line and the empty line that ends
/// the section, the terminator not included.
///
/// # Safety
///
/// `block` must either be null or point to `block_len` readable octets, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_field_parse_block(block: *const u8, block_len: usize, max_count: usize, out: *mut *mut Headers, error: *mut *mut ErrorHandle) -> Status {
    let Some(block) = (unsafe { Slice::borrow(block, block_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Field::parse_block(block, max_count) {
        Ok(headers) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(headers)) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Where a field block ends, if it has.
///
/// Writes where the field lines stop through `fields_end`, and where the
/// section as a whole ends — the blank line included — through `section_end`.
/// Returns whether the section is complete. `searched` carries how far a
/// previous call already looked, so feeding it back makes repeated calls
/// linear rather than quadratic.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `searched`, `fields_end` and `section_end` must either be null or be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_field_block_end(data: *const u8, data_len: usize, searched: *mut usize, fields_end: *mut usize, section_end: *mut usize) -> bool {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    let mut looked = if searched.is_null() { 0 } else { unsafe { *searched } };

    let found = Field::block_end(data, &mut looked);

    if !searched.is_null() {
        unsafe { *searched = looked };
    }

    let Some((fields, section)) = found else {
        return false;
    };

    if !fields_end.is_null() {
        unsafe { *fields_end = fields };
    }

    if !section_end.is_null() {
        unsafe { *section_end = section };
    }

    true
}

/// Writes one chunk, header and terminator included, owned by the caller.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_chunk_encode(data: *const u8, data_len: usize) -> Buffer {
    Buffer::new(Chunk::encode(unsafe { Slice::borrow(data, data_len) }.unwrap_or_default()))
}

/// Reads a chunk header, writing the size through `size` and how many octets
/// the header took through `read`.
///
/// Returns [`Status::Ok`] when a whole header was there, [`Status::Closed`]
/// when more octets are needed, and a protocol failure when it is malformed.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `size` and `read` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_chunk_parse_size(data: *const u8, data_len: usize, size: *mut usize, read: *mut usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Chunk::parse_size(data) {
        Ok(Some((chunk_size, consumed))) => {
            if !size.is_null() {
                unsafe { *size = chunk_size };
            }

            if !read.is_null() {
                unsafe { *read = consumed };
            }

            Status::Ok
        }
        Ok(None) => Status::Closed,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Reads one whole chunk, writing where its data begins and ends through
/// `start` and `end`, and how many octets the chunk took through `read`.
///
/// # Safety
///
/// As [`soyokaze_h1_chunk_parse_size`], and `start` and `end` must either be
/// null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_chunk_decode(data: *const u8, data_len: usize, start: *mut usize, end: *mut usize, read: *mut usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Chunk::decode(data) {
        Ok((consumed, span)) => {
            if !start.is_null() {
                unsafe { *start = span.start };
            }

            if !end.is_null() {
                unsafe { *end = span.end };
            }

            if !read.is_null() {
                unsafe { *read = consumed };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// How the length of a message body is determined.
///
/// The C half of [`BodyLength`], with the fixed length carried alongside
/// rather than inside the variant.
///
/// [`BodyLength`]: crate::protocol::h1::BodyLength
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BodyKind {
    /// There is no body.
    None = 0,
    /// The body is chunked, and ends at a zero-length chunk.
    Chunked = 1,
    /// The body is exactly the octets `length` names.
    Fixed = 2,
    /// The body ends when the connection closes.
    Close = 3,
}

/// Works out how a message's body is framed.
///
/// `method` is the method of the request a response answers, which some
/// responses need in order to be framed at all: a response to `HEAD` has no
/// body however it is labelled, and a successful response to `CONNECT` is
/// followed by tunnelled octets rather than a body. Pass `-1` for a request.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `kind` and `length` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_body_length(message: *const Message, method: i32, kind: *mut BodyKind, length: *mut u64, error: *mut *mut ErrorHandle) -> Status {
    let Some(message) = (unsafe { message.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match BodyLength::of(message, Method::from_code(method)) {
        Ok(framing) => {
            let (framed, fixed) = match framing {
                BodyLength::None => (BodyKind::None, 0),
                BodyLength::Chunked => (BodyKind::Chunked, 0),
                BodyLength::Fixed(length) => (BodyKind::Fixed, length),
                BodyLength::Close => (BodyKind::Close, 0),
            };

            if !kind.is_null() {
                unsafe { *kind = framed };
            }

            if !length.is_null() {
                unsafe { *length = fixed };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Reads a `Content-Length` field value.
///
/// # Safety
///
/// `value` must either be null or point to `value_len` readable octets, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_h1_content_length(value: *const u8, value_len: usize, out: *mut u64, error: *mut *mut ErrorHandle) -> Status {
    let Some(value) = (unsafe { Slice::borrow_text(value, value_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match BodyLength::content_length(value) {
        Ok(length) => {
            if !out.is_null() {
                unsafe { *out = length };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Writes a decimal number, owned by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h1_decimal(value: u64) -> Buffer {
    let mut digits = [0u8; 20];
    let at = Number::decimal(value, &mut digits);
    Buffer::new(digits[at..].to_vec())
}

/// Writes a hexadecimal number, owned by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_h1_hexadecimal(value: u64) -> Buffer {
    let mut digits = [0u8; 16];
    let at = Number::hexadecimal(value, &mut digits);
    Buffer::new(digits[at..].to_vec())
}
