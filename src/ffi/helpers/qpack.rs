//! QPACK, the HTTP/3 field compression format, from C.
//!
//! Fields cross the same way they do for HPACK — [`Field`] in, [`Fields`] out
//! — and the extra moving part is QPACK's two instruction streams: what an
//! encoder emits rides the encoder stream to the peer's decoder, and what a
//! decoder emits rides back. Both cross here as raw octets, exactly as they
//! travel, so feeding a peer's stream in means passing its bytes along.

use crate::errors::Error;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::helpers::fields::{parse_fields, Field, Fields};
use crate::ffi::{borrow, Buffer};
use crate::helpers::qpack::{Decoder, Encoder};

/// Builds a QPACK encoder that references only the static table until it is
/// given capacity.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_encoder_new() -> *mut Encoder {
    Box::into_raw(Box::new(Encoder::new()))
}

/// Releases a QPACK encoder.
///
/// # Safety
///
/// `encoder` must come from [`soyokaze_qpack_encoder_new`] and not have been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_free(encoder: *mut Encoder) {
    if !encoder.is_null() {
        drop(unsafe { Box::from_raw(encoder) });
    }
}

/// Records the peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, resizing the
/// table under it.
///
/// The instruction octets announcing the new capacity go through
/// `instructions`, and are empty when the capacity did not change; send them
/// down the encoder stream.
///
/// # Safety
///
/// `encoder` must be a handle that has not been freed, and `instructions`
/// must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_set_max_capacity(encoder: *mut Encoder, max_capacity: usize, instructions: *mut Buffer) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    if instructions.is_null() {
        return false;
    }

    unsafe {
        *instructions = match encoder.set_max_capacity(max_capacity) {
            Some(instruction) => Buffer::new(instruction.encode()),
            None => Buffer::EMPTY,
        };
    }

    true
}

/// Bounds the capacity the encoder keeps, whatever the peer permits.
///
/// The instruction octets announcing a shrunk capacity go through
/// `instructions`, and are empty when the capacity did not change.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_set_max_capacity`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_set_capacity_limit(encoder: *mut Encoder, capacity_limit: usize, instructions: *mut Buffer) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    if instructions.is_null() {
        return false;
    }

    unsafe {
        *instructions = match encoder.set_capacity_limit(capacity_limit) {
            Some(instruction) => Buffer::new(instruction.encode()),
            None => Buffer::EMPTY,
        };
    }

    true
}

/// Caps how many unacknowledged sections the encoder tracks before it stops
/// referencing the dynamic table.
///
/// # Safety
///
/// `encoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_set_max_outstanding_sections(encoder: *mut Encoder, max_sections: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.set_max_outstanding_sections(max_sections);
    true
}

/// Caps how large a single instruction on the peer's decoder stream may grow.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_set_max_outstanding_sections`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_set_max_instruction_size(encoder: *mut Encoder, max_size: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.set_max_instruction_size(max_size);
    true
}

/// Encodes one field section.
///
/// The block for the request or push stream goes through `block`, and
/// whatever instructions the encoding produced go through `instructions`,
/// ready for the encoder stream. Returns false when an argument was unusable.
///
/// # Safety
///
/// `encoder` must be a handle that has not been freed, `fields` must point to
/// `field_count` readable [`Field`] values whose own pointers are valid, and
/// `block` and `instructions` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encode(encoder: *mut Encoder, stream_id: u64, fields: *const Field, field_count: usize, block: *mut Buffer, instructions: *mut Buffer) -> bool {
    let (Some(encoder), Some(fields)) = (unsafe { encoder.as_mut() }, unsafe { parse_fields(fields, field_count) }) else {
        return false;
    };

    if block.is_null() || instructions.is_null() {
        return false;
    }

    let (encoded, emitted) = encoder.encode(stream_id, &fields);

    let mut stream = Vec::new();
    for instruction in &emitted {
        instruction.encode_into(&mut stream);
    }

    unsafe {
        *block = Buffer::new(encoded);
        *instructions = if stream.is_empty() { Buffer::EMPTY } else { Buffer::new(stream) };
    }

    true
}

/// Feeds the encoder what arrived on the decoder stream.
///
/// Partial instructions are buffered until the rest arrives, so pass along
/// exactly what arrived, as it arrives.
///
/// # Safety
///
/// `encoder` must be a handle that has not been freed, and `data` must point
/// to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_on_decoder_instructions(encoder: *mut Encoder, data: *const u8, data_len: usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let Some(data) = (unsafe { borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match encoder.on_decoder_stream(data) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &Error::from(failure)) },
    }
}

/// Forgets the outstanding sections of a stream that was reset.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_set_max_capacity`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_cancel(encoder: *mut Encoder, stream_id: u64) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.cancel(stream_id);
    true
}

/// Builds a QPACK decoder with the default ceilings.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_decoder_new() -> *mut Decoder {
    Box::into_raw(Box::new(Decoder::new()))
}

/// Releases a QPACK decoder.
///
/// # Safety
///
/// `decoder` must come from [`soyokaze_qpack_decoder_new`] and not have been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_free(decoder: *mut Decoder) {
    if !decoder.is_null() {
        drop(unsafe { Box::from_raw(decoder) });
    }
}

/// Caps how large one decoded section may grow.
///
/// # Safety
///
/// `decoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_set_max_decoded_size(decoder: *mut Decoder, max_size: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.set_max_decoded_size(max_size);
    true
}

/// Records this side's advertised `SETTINGS_QPACK_MAX_TABLE_CAPACITY`.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_set_max_decoded_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_set_max_capacity(decoder: *mut Decoder, max_capacity: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.set_max_capacity(max_capacity);
    true
}

/// Caps how large a single instruction on the peer's encoder stream may grow.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_set_max_decoded_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_set_max_instruction_size(decoder: *mut Decoder, max_size: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.set_max_instruction_size(max_size);
    true
}

/// Caps how many streams may wait QPACK-blocked at once, which is what
/// `SETTINGS_QPACK_BLOCKED_STREAMS` promises the peer.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_set_max_decoded_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_set_max_blocked_streams(decoder: *mut Decoder, max_streams: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.set_max_blocked_streams(max_streams);
    true
}

/// Feeds the decoder what arrived on the encoder stream.
///
/// Partial instructions are buffered until the rest arrives. Whatever answer
/// the instructions call for — an Insert Count Increment — goes through
/// `instructions`, ready for the decoder stream, and is empty when nothing
/// needs saying.
///
/// # Safety
///
/// `decoder` must be a handle that has not been freed, `data` must point to
/// `data_len` readable octets, and `instructions` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_on_encoder_instructions(decoder: *mut Decoder, data: *const u8, data_len: usize, instructions: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let Some(data) = (unsafe { borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if instructions.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    if let Err(failure) = decoder.on_encoder_stream(data) {
        return unsafe { ErrorHandle::report(error, &Error::from(failure)) };
    }

    let stream = decoder.take_decoder_stream();
    unsafe { *instructions = if stream.is_empty() { Buffer::EMPTY } else { Buffer::new(stream) } };
    Status::Ok
}

/// Decodes one block into a [`Fields`] handle.
///
/// The acknowledgement the block calls for — a Section Acknowledgement — goes
/// through `instructions`, ready for the decoder stream, and is empty when
/// nothing needs saying.
///
/// # Safety
///
/// `decoder` must be a handle that has not been freed, `block` must point to
/// `block_len` readable octets, and `out` and `instructions` must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decode(decoder: *mut Decoder, stream_id: u64, block: *const u8, block_len: usize, out: *mut *mut Fields, instructions: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() || instructions.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(block) = (unsafe { borrow(block, block_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match decoder.decode(stream_id, block) {
        Ok((fields, answer)) => {
            unsafe {
                *out = Box::into_raw(Box::new(Fields(fields)));
                *instructions = match answer {
                    Some(answer) => Buffer::new(answer.encode()),
                    None => Buffer::EMPTY,
                };
            }
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &Error::from(failure)) },
    }
}
