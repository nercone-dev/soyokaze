//! HPACK, the HTTP/2 field compression format, from C.
//!
//! [`Field`] carries one name and value pair in, and [`Fields`] carries a
//! decoded block back out; QPACK borrows both, the way
//! [`crate::helpers::qpack`] borrows [`HeaderField`] from
//! [`crate::helpers::hpack`]. An encoder and a decoder are stateful — each
//! keeps a dynamic table — so one handle serves one connection's lifetime,
//! blocks fed in the order they travel.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{borrow, borrow_text, Buffer, Slice};
use crate::helpers::hpack::{Decoder, Encoder, HeaderField};

/// One field going in: a name and a value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Field {
    /// The field name.
    pub name: Slice,
    /// The field value.
    pub value: Slice,
}

/// Reads `count` fields out of a C array.
///
/// `None` when the array is null with a non-zero count, or any name or value
/// is null or not UTF-8.
///
/// # Safety
///
/// `fields` must either be null or point to `count` readable [`Field`] values
/// whose own pointers are valid.
pub unsafe fn parse_fields(fields: *const Field, count: usize) -> Option<Vec<HeaderField>> {
    if fields.is_null() {
        return (count == 0).then(Vec::new);
    }

    let mut parsed = Vec::with_capacity(count);

    for index in 0..count {
        let field = unsafe { *fields.add(index) };
        let name = unsafe { borrow_text(field.name.data, field.name.len) }?;
        let value = unsafe { borrow_text(field.value.data, field.value.len) }?;
        parsed.push(HeaderField::new(name, value));
    }

    Some(parsed)
}

/// A decoded field section, as a decoder hands it back.
pub struct Fields(pub Vec<HeaderField>);

/// Releases a [`Fields`].
///
/// # Safety
///
/// `fields` must come from a decode call and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_free(fields: *mut Fields) {
    if !fields.is_null() {
        drop(unsafe { Box::from_raw(fields) });
    }
}

/// How many fields the section holds.
///
/// # Safety
///
/// `fields` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_count(fields: *const Fields) -> usize {
    unsafe { fields.as_ref() }.map_or(0, |fields| fields.0.len())
}

/// The name of the field at `index`, borrowed from `fields`.
///
/// # Safety
///
/// As [`soyokaze_fields_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_name(fields: *const Fields, index: usize) -> Slice {
    Slice::maybe(unsafe { fields.as_ref() }.and_then(|fields| fields.0.get(index)).map(|field| field.name.as_str()))
}

/// The value of the field at `index`, borrowed from `fields`.
///
/// # Safety
///
/// As [`soyokaze_fields_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_value(fields: *const Fields, index: usize) -> Slice {
    Slice::maybe(unsafe { fields.as_ref() }.and_then(|fields| fields.0.get(index)).map(|field| field.value.as_str()))
}

/// Builds an HPACK encoder with the default dynamic table size.
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

/// Caps the encoder's dynamic table, as a `SETTINGS_HEADER_TABLE_SIZE` would.
///
/// # Safety
///
/// `encoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encoder_set_dynamic_table_size(encoder: *mut Encoder, max_size: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.set_dynamic_table_size(max_size);
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
    let (Some(encoder), Some(fields)) = (unsafe { encoder.as_mut() }, unsafe { parse_fields(fields, field_count) }) else {
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

/// Caps the decoder's dynamic table, as a `SETTINGS_HEADER_TABLE_SIZE` would.
///
/// # Safety
///
/// As [`soyokaze_hpack_decoder_set_max_decoded_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_decoder_set_dynamic_table_size(decoder: *mut Decoder, max_size: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.set_dynamic_table_size(max_size);
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

    let Some(block) = (unsafe { borrow(block, block_len) }) else {
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
