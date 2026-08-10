//! What every HTTP version shares, from C.
//!
//! [`Buffer`] is the read buffer a connection fills from its transport, and
//! [`Fields`] is the pseudo-field vocabulary HTTP/2 and HTTP/3 turn a message
//! into and back — the same two pieces as [`crate::protocol::common`]. The
//! read buffer crosses because a caller resuming a connection by hand has to
//! hand back whatever was read past the end of the last message.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::helpers::fields::Fields as FieldSection;
use crate::ffi::{Buffer as Octets, Slice};
use crate::models::{Message, Version};
use crate::protocol::common::{Buffer, Fields};

/// How many octets one read asks the transport for unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_read_buffer_default_chunk_size() -> usize {
    Buffer::DEFAULT_CHUNK_SIZE
}

/// How many times the chunk size may double as a body keeps arriving.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_read_buffer_chunk_ramp() -> usize {
    Buffer::CHUNK_RAMP
}

/// Whether a buffer of this shape is worth shrinking back.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_read_buffer_oversized(capacity: usize, len: usize, idle_capacity: usize) -> bool {
    Buffer::oversized(capacity, len, idle_capacity)
}

/// Builds an empty read buffer.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_read_buffer_new() -> *mut Buffer {
    Box::into_raw(Box::new(Buffer::new()))
}

/// Builds an empty read buffer that asks the transport for `chunk_size`
/// octets at a time.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_read_buffer_with_chunk_size(chunk_size: usize) -> *mut Buffer {
    Box::into_raw(Box::new(Buffer::with_chunk_size(chunk_size.min(Buffer::MAXIMUM_CHUNK_SIZE))))
}

/// Releases a read buffer.
///
/// # Safety
///
/// `buffer` must come from one of the constructors here and not have been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_free(buffer: *mut Buffer) {
    if !buffer.is_null() {
        drop(unsafe { Box::from_raw(buffer) });
    }
}

/// How many octets one read asks the transport for.
///
/// # Safety
///
/// `buffer` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_chunk_size(buffer: *const Buffer) -> usize {
    unsafe { buffer.as_ref() }.map_or(0, |buffer| buffer.chunk_size())
}

/// Sets how many octets one read asks the transport for.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_set_chunk_size(buffer: *mut Buffer, chunk_size: usize) -> bool {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return false;
    };

    buffer.set_chunk_size(chunk_size);
    true
}

/// How many octets are waiting to be read out.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_len(buffer: *const Buffer) -> usize {
    unsafe { buffer.as_ref() }.map_or(0, |buffer| buffer.len())
}

/// Whether nothing is waiting to be read out.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_is_empty(buffer: *const Buffer) -> bool {
    unsafe { buffer.as_ref() }.is_none_or(|buffer| buffer.is_empty())
}

/// Whether the transport underneath has ended.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_eof(buffer: *const Buffer) -> bool {
    unsafe { buffer.as_ref() }.is_some_and(|buffer| buffer.eof())
}

/// How many octets the buffer has room for without growing.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_capacity(buffer: *const Buffer) -> usize {
    unsafe { buffer.as_ref() }.map_or(0, |buffer| buffer.capacity())
}

/// What is waiting to be read out, borrowed from the buffer.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_bytes(buffer: *const Buffer) -> Slice {
    match unsafe { buffer.as_ref() } {
        Some(buffer) => Slice::new(buffer.as_slice()),
        None => Slice::ABSENT,
    }
}

/// Adds octets to the buffer, as a read from the transport would.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`], and `data` must either be null or
/// point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_extend(buffer: *mut Buffer, data: *const u8, data_len: usize) -> bool {
    let (Some(buffer), Some(data)) = (unsafe { buffer.as_mut() }, unsafe { Slice::borrow(data, data_len) }) else {
        return false;
    };

    buffer.as_bytes_mut().extend_from_slice(data);
    true
}

/// Drops the first `count` octets, which have been dealt with.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_consume(buffer: *mut Buffer, count: usize) -> bool {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return false;
    };

    buffer.consume(count);
    true
}

/// Takes the first `count` octets out, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_take(buffer: *mut Buffer, count: usize) -> Octets {
    match unsafe { buffer.as_mut() } {
        Some(buffer) => Octets::new(buffer.take(count).to_vec()),
        None => Octets::EMPTY,
    }
}

/// Shrinks the buffer back when it has grown past `idle_capacity` and is idle.
///
/// # Safety
///
/// As [`soyokaze_read_buffer_chunk_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_read_buffer_reclaim(buffer: *mut Buffer, idle_capacity: usize) -> bool {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return false;
    };

    buffer.reclaim(idle_capacity);
    true
}

/// How many request pseudo-fields there are.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_pseudo_request_count() -> usize {
    Fields::PSEUDO_REQUEST.len()
}

/// The request pseudo-field at `index`, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_pseudo_request_name(index: usize) -> Slice {
    Slice::maybe(Fields::PSEUDO_REQUEST.get(index).copied())
}

/// How many response pseudo-fields there are.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_pseudo_response_count() -> usize {
    Fields::PSEUDO_RESPONSE.len()
}

/// The response pseudo-field at `index`, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_pseudo_response_name(index: usize) -> Slice {
    Slice::maybe(Fields::PSEUDO_RESPONSE.get(index).copied())
}

/// How many connection-specific field names there are.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_connection_specific_count() -> usize {
    Fields::CONNECTION_SPECIFIC.len()
}

/// The connection-specific field name at `index`, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_connection_specific_name(index: usize) -> Slice {
    Slice::maybe(Fields::CONNECTION_SPECIFIC.get(index).copied())
}

/// Whether a field belongs to one HTTP/1.x connection and so may not be
/// carried over HTTP/2 or HTTP/3.
///
/// # Safety
///
/// `name` must either be null or point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_connection_specific(name: *const u8, name_len: usize) -> bool {
    match unsafe { Slice::borrow_text(name, name_len) } {
        Some(name) => Fields::connection_specific(name),
        None => false,
    }
}

/// A status code as a `:status` value, borrowed from the library for the codes
/// it keeps rendered and owned by the caller otherwise.
///
/// Always comes back owned, so it is always freed with
/// `soyokaze_buffer_free`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_pseudo_status(status_code: u16) -> Octets {
    Octets::new(Fields::status(status_code).into_bytes())
}

/// Turns a message into the field section HTTP/2 and HTTP/3 send it as.
///
/// Pseudo-fields come first, then the ordinary fields with the
/// connection-specific ones dropped.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_of_message(message: *const Message, out: *mut *mut FieldSection, error: *mut *mut ErrorHandle) -> Status {
    let Some(message) = (unsafe { message.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Fields::of(message) {
        Ok(fields) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(FieldSection(fields))) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Turns a decoded field section back into a message.
///
/// `fields` is read, not consumed.
///
/// # Safety
///
/// `fields` must either be null or be a handle that has not been freed, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_to_message(fields: *const FieldSection, version: i32, out: *mut *mut Message, error: *mut *mut ErrorHandle) -> Status {
    let version = Version::of(version);

    let Some(fields) = (unsafe { fields.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Fields::message(&fields.0, version) {
        Ok(message) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(message)) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}
