//! HPACK, the HTTP/2 field compression format, from C.
//!
//! Fields cross as [`Field`] in and [`Fields`] out, the shared vocabulary in
//! [`crate::ffi::helpers::fields`]. An encoder and a decoder are stateful —
//! each keeps a dynamic table — so one handle serves one connection's
//! lifetime, blocks fed in the order they travel.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::helpers::fields::{Field, Fields};
use crate::ffi::{Buffer, Slice};
use crate::helpers::hpack::{Decoder, DynamicTable, Encoder, StaticTable};

/// The capacity a dynamic table starts at.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_default_capacity() -> usize {
    DynamicTable::DEFAULT_CAPACITY
}

/// The capacity an encoder bounds itself to unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_default_capacity_limit() -> usize {
    Encoder::DEFAULT_CAPACITY_LIMIT
}

/// How large one decoded section may grow unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_default_max_decoded_size() -> usize {
    Decoder::DEFAULT_MAX_DECODED_SIZE
}

/// How many entries the static table holds.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_static_count() -> usize {
    StaticTable::entries().len()
}

/// The lowest index the static table is numbered from.
///
/// HPACK numbers its static table from one, which is the only way it differs
/// from QPACK here.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_static_base() -> usize {
    1
}

/// The name of the static table entry at `index`, borrowed from the library.
///
/// `index` is the wire index, so it starts at [`soyokaze_hpack_static_base`].
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_static_name(index: usize) -> Slice {
    Slice::maybe(index.checked_sub(1).and_then(|offset| StaticTable::entries().get(offset)).map(|field| field.name.as_str()))
}

/// The value of the static table entry at `index`, borrowed from the library.
///
/// As [`soyokaze_hpack_static_name`] for how `index` is numbered.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_static_value(index: usize) -> Slice {
    Slice::maybe(index.checked_sub(1).and_then(|offset| StaticTable::entries().get(offset)).map(|field| field.value.as_str()))
}

/// The reverse index over the static table, borrowed from the library.
///
/// Passed to `soyokaze_static_index_lookup`, and never freed.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_hpack_static_index() -> *const crate::ffi::helpers::fields::Index {
    StaticTable::index()
}

/// Looks a field up in the static table.
///
/// Writes the index through `out` and whether the value matched too through
/// `exact`, and returns whether the name was found at all.
///
/// # Safety
///
/// `name` and `value` must point to their stated number of readable octets,
/// and `out` and `exact` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_static_find(name: *const u8, name_len: usize, value: *const u8, value_len: usize, out: *mut usize, exact: *mut bool) -> bool {
    let (Some(name), Some(value)) = (unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    let Some((index, matched)) = StaticTable::find(&crate::helpers::fields::HeaderField::new(name, value)) else {
        return false;
    };

    if !out.is_null() {
        unsafe { *out = index };
    }

    if !exact.is_null() {
        unsafe { *exact = matched };
    }

    true
}

/// How many octets the entries in a dynamic table add up to.
///
/// # Safety
///
/// `table` must either be null or be a table one of the accessors here handed
/// back, borrowed from a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_table_size(table: *const DynamicTable) -> usize {
    unsafe { table.as_ref() }.map_or(0, |table| table.size())
}

/// What the dynamic table is currently sized to.
///
/// # Safety
///
/// As [`soyokaze_hpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_table_capacity(table: *const DynamicTable) -> usize {
    unsafe { table.as_ref() }.map_or(0, |table| table.capacity())
}

/// How many entries the dynamic table holds.
///
/// # Safety
///
/// As [`soyokaze_hpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_table_len(table: *const DynamicTable) -> usize {
    unsafe { table.as_ref() }.map_or(0, |table| table.len())
}

/// Whether the dynamic table holds nothing.
///
/// # Safety
///
/// As [`soyokaze_hpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_table_is_empty(table: *const DynamicTable) -> bool {
    unsafe { table.as_ref() }.is_none_or(|table| table.is_empty())
}

/// The name of the dynamic table entry at `index`, borrowed from the table.
///
/// `index` counts from the most recent insertion, as the wire numbers it once
/// the static table is passed.
///
/// # Safety
///
/// As [`soyokaze_hpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_table_name(table: *const DynamicTable, index: usize) -> Slice {
    Slice::maybe(unsafe { table.as_ref() }.and_then(|table| table.get(index)).map(|field| field.name.as_str()))
}

/// The value of the dynamic table entry at `index`, borrowed from the table.
///
/// # Safety
///
/// As [`soyokaze_hpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_table_value(table: *const DynamicTable, index: usize) -> Slice {
    Slice::maybe(unsafe { table.as_ref() }.and_then(|table| table.get(index)).map(|field| field.value.as_str()))
}

/// Looks a field up in a dynamic table.
///
/// As [`soyokaze_hpack_static_find`], over the dynamic table instead.
///
/// # Safety
///
/// As [`soyokaze_hpack_table_size`], and `name` and `value` must point to
/// their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_table_find(table: *const DynamicTable, name: *const u8, name_len: usize, value: *const u8, value_len: usize, out: *mut usize, exact: *mut bool) -> bool {
    let (Some(table), Some(name), Some(value)) = (unsafe { table.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    let Some((index, matched)) = table.find(&crate::helpers::fields::HeaderField::new(name, value)) else {
        return false;
    };

    if !out.is_null() {
        unsafe { *out = index };
    }

    if !exact.is_null() {
        unsafe { *exact = matched };
    }

    true
}

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

/// What the encoder bounds its own table to, whatever the peer permits.
///
/// # Safety
///
/// `encoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encoder_capacity_limit(encoder: *const Encoder) -> usize {
    unsafe { encoder.as_ref() }.map_or(0, |encoder| encoder.capacity_limit())
}

/// The peer's `SETTINGS_HEADER_TABLE_SIZE`, as last recorded.
///
/// # Safety
///
/// As [`soyokaze_hpack_encoder_capacity_limit`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encoder_max_capacity(encoder: *const Encoder) -> usize {
    unsafe { encoder.as_ref() }.map_or(0, |encoder| encoder.max_capacity())
}

/// The encoder's dynamic table, borrowed until the encoder is freed or
/// encodes again.
///
/// # Safety
///
/// As [`soyokaze_hpack_encoder_capacity_limit`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encoder_table(encoder: *const Encoder) -> *const DynamicTable {
    match unsafe { encoder.as_ref() } {
        Some(encoder) => encoder.dynamic_table(),
        None => std::ptr::null(),
    }
}

/// What the encoder would reference a field by, across both tables.
///
/// Writes the index through `out` and whether the value matched too through
/// `exact`, and returns whether either table carries the name.
///
/// # Safety
///
/// As [`soyokaze_hpack_encoder_capacity_limit`], and `name` and `value` must
/// point to their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encoder_reference(encoder: *const Encoder, name: *const u8, name_len: usize, value: *const u8, value_len: usize, out: *mut usize, exact: *mut bool) -> bool {
    let (Some(encoder), Some(name), Some(value)) = (unsafe { encoder.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    let Some((index, matched)) = encoder.reference(&crate::helpers::fields::HeaderField::new(name, value)) else {
        return false;
    };

    if !out.is_null() {
        unsafe { *out = index };
    }

    if !exact.is_null() {
        unsafe { *exact = matched };
    }

    true
}

/// Encodes one field onto the end of a block, owned by the caller.
///
/// Updates the encoder's dynamic table exactly as encoding a whole section
/// would, so a caller assembling a block field by field must send what it
/// builds in order.
///
/// # Safety
///
/// `encoder` must either be null or be a handle that has not been freed, and
/// `name` and `value` must point to their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_encode_field(encoder: *mut Encoder, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> Buffer {
    let (Some(encoder), Some(name), Some(value)) = (unsafe { encoder.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return Buffer::EMPTY;
    };

    let mut out = Vec::new();
    encoder.encode_field(&mut out, &crate::helpers::fields::HeaderField::new(name, value));
    Buffer::new(out)
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

/// The decoder's dynamic table, borrowed until the decoder is freed or decodes
/// again.
///
/// # Safety
///
/// `decoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_decoder_table(decoder: *const Decoder) -> *const DynamicTable {
    match unsafe { decoder.as_ref() } {
        Some(decoder) => decoder.dynamic_table(),
        None => std::ptr::null(),
    }
}

/// The field an index addresses, across both tables.
///
/// Writes the name and value through `name` and `value`, borrowed from the
/// decoder, and returns whether the index addressed anything.
///
/// # Safety
///
/// As [`soyokaze_hpack_decoder_table`], and `name` and `value` must either be
/// null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hpack_decoder_resolve(decoder: *const Decoder, index: u64, name: *mut Slice, value: *mut Slice) -> bool {
    let Some(decoder) = (unsafe { decoder.as_ref() }) else {
        return false;
    };

    let Ok(field) = decoder.resolve(index) else {
        return false;
    };

    if !name.is_null() {
        unsafe { *name = Slice::text(field.name.as_str()) };
    }

    if !value.is_null() {
        unsafe { *value = Slice::text(field.value.as_str()) };
    }

    true
}
