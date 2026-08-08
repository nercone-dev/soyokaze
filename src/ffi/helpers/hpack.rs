//! HPACK, the HTTP/2 field compression format, from C.
//!
//! Fields cross as [`Field`] in and [`Fields`] out, the shared vocabulary in
//! [`crate::ffi::helpers::fields`]. An encoder and a decoder are stateful —
//! each keeps a dynamic table — so one handle serves one connection's
//! lifetime, blocks fed in the order they travel.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::helpers::fields::{Field, Fields};
use crate::ffi::{Buffer, Slice};
use crate::helpers::hpack::{Decoder, Encoder};

/// Builds an HPACK encoder with the default dynamic table capacity.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_encoder_new() -> *mut Encoder {
    Box::into_raw(Box::new(Encoder::new()))
}

/// Releases an HPACK encoder.
///
/// # Safety
///
/// `encoder` must come from [`soyokaze_hpack_encoder_new`] and not have been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encoder_free(encoder: *mut Encoder) {
    if !encoder.is_null() {
        drop(unsafe { Box::from_raw(encoder) });
    }
}

/// Records the peer's `SETTINGS_HEADER_TABLE_SIZE`.
///
/// The encoder may never size its table above this.
///
/// # Safety
///
/// `encoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encoder_set_max_capacity(encoder: *mut Encoder, max_capacity: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.set_max_capacity(max_capacity);
    true
}

/// Bounds the capacity the encoder keeps, whatever the peer permits.
///
/// # Safety
///
/// As [`soyokaze_hpack_encoder_set_max_capacity`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encoder_set_capacity_limit(encoder: *mut Encoder, capacity_limit: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.set_capacity_limit(capacity_limit);
    true
}

/// Encodes one field section as a block, owned by the caller.
///
/// The block updates the encoder's dynamic table as it is built, so blocks
/// must be sent in the order they were encoded. An empty buffer with a null
/// pointer means an argument was unusable.
///
/// # Safety
///
/// `encoder` must be a handle that has not been freed, and `fields` must
/// point to `field_count` readable [`Field`] values whose own pointers are
/// valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encode(encoder: *mut Encoder, fields: *const Field, field_count: usize) -> Buffer {
    let (Some(encoder), Some(fields)) = (unsafe { encoder.as_mut() }, unsafe { Field::parse_all(fields, field_count) }) else {
        return Buffer::EMPTY;
    };

    Buffer::new(encoder.encode(&fields))
}

/// Builds an HPACK decoder with the default ceilings.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_decoder_new() -> *mut Decoder {
    Box::into_raw(Box::new(Decoder::new()))
}

/// Releases an HPACK decoder.
///
/// # Safety
///
/// `decoder` must come from [`soyokaze_hpack_decoder_new`] and not have been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_decoder_free(decoder: *mut Decoder) {
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
pub unsafe extern "C" fn soyokaze_hpack_decoder_set_max_decoded_size(decoder: *mut Decoder, max_size: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.set_max_decoded_size(max_size);
    true
}

/// Records this side's advertised `SETTINGS_HEADER_TABLE_SIZE`.
///
/// # Safety
///
/// As [`soyokaze_hpack_decoder_set_max_decoded_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_decoder_set_max_capacity(decoder: *mut Decoder, max_capacity: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.set_max_capacity(max_capacity);
    true
}

/// Decodes one block into a [`Fields`] handle.
///
/// Blocks must be fed in the order they arrived, since each updates the
/// decoder's dynamic table.
///
/// # Safety
///
/// `decoder` must be a handle that has not been freed, `block` must point to
/// `block_len` readable octets, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_decode(decoder: *mut Decoder, block: *const u8, block_len: usize, out: *mut *mut Fields, error: *mut *mut ErrorHandle) -> Status {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(block) = (unsafe { Slice::borrow(block, block_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match decoder.decode(block) {
        Ok(fields) => {
            unsafe { *out = Box::into_raw(Box::new(Fields(fields))) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &crate::errors::Error::from(failure)) },
    }
}
