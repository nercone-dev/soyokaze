//! QPACK, the HTTP/3 field compression format, from C.
//!
//! Fields cross the same way they do for HPACK — [`Field`] in, [`Fields`] out
//! — and the extra moving part is QPACK's two instruction streams: what an
//! encoder emits rides the encoder stream to the peer's decoder, and what a
//! decoder emits rides back. Both cross here as raw octets, exactly as they
//! travel, so feeding a peer's stream in means passing its bytes along.

use crate::errors::Error;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::helpers::hpack::{parse_fields, Field, Fields};
use crate::ffi::{borrow, Buffer};
use crate::helpers::qpack::{Decoder, DecoderInstruction, Encoder, EncoderInstruction};

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

/// Records the peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`.
///
/// The encoder may never set a capacity above this.
///
/// # Safety
///
/// `encoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_set_max_capacity(encoder: *mut Encoder, max_capacity: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.set_max_capacity(max_capacity);
    true
}

/// Caps how many unacknowledged sections the encoder tracks before it stops
/// referencing the dynamic table.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_set_max_capacity`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_set_max_outstanding_sections(encoder: *mut Encoder, max_sections: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.set_max_outstanding_sections(max_sections);
    true
}

/// Sets the dynamic table capacity, writing the instruction that announces it.
///
/// The instruction octets go through `instructions`, and are empty when the
/// capacity did not change; send them down the encoder stream.
///
/// # Safety
///
/// `encoder` must be a handle that has not been freed, and `instructions`
/// must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_set_capacity(encoder: *mut Encoder, capacity: usize, instructions: *mut Buffer) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    if instructions.is_null() {
        return false;
    }

    unsafe {
        *instructions = match encoder.set_capacity(capacity) {
            Some(instruction) => Buffer::new(instruction.encode()),
            None => Buffer::EMPTY,
        };
    }

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
/// `data` must hold whole instructions; QPACK's streams deliver them in
/// order, so pass along exactly what arrived.
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

    let Some(mut data) = (unsafe { borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    while !data.is_empty() {
        match DecoderInstruction::decode(data) {
            Ok((consumed, instruction)) => {
                encoder.on_decoder_instruction(instruction);
                data = &data[consumed..];
            }
            Err(failure) => return unsafe { ErrorHandle::report(error, &Error::from(failure)) },
        }
    }

    Status::Ok
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

/// Feeds the decoder what arrived on the encoder stream.
///
/// Whatever answer the instructions call for — an Insert Count Increment —
/// goes through `instructions`, ready for the decoder stream, and is empty
/// when nothing needs saying.
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

    let Some(mut data) = (unsafe { borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if instructions.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let mut stream = Vec::new();

    while !data.is_empty() {
        match EncoderInstruction::decode(data) {
            Ok((consumed, instruction)) => {
                match decoder.on_encoder_instruction(instruction) {
                    Ok(Some(answer)) => answer.encode_into(&mut stream),
                    Ok(None) => {}
                    Err(failure) => return unsafe { ErrorHandle::report(error, &Error::from(failure)) },
                }
                data = &data[consumed..];
            }
            Err(failure) => return unsafe { ErrorHandle::report(error, &Error::from(failure)) },
        }
    }

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
