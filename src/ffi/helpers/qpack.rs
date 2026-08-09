//! QPACK, the HTTP/3 field compression format, from C.
//!
//! Fields cross the same way they do for HPACK — [`Field`] in, [`Fields`] out
//! — and the extra moving part is QPACK's two instruction streams: what an
//! encoder emits rides the encoder stream to the peer's decoder, and what a
//! decoder emits rides back. Both cross here as raw octets, exactly as they
//! travel, so feeding a peer's stream in means passing its bytes along.

use crate::errors::Error;
use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::helpers::fields::{Field, Fields};
use crate::ffi::{Buffer, Slice};
use crate::helpers::fields::HeaderField;
use crate::helpers::qpack::{Decoder, DecoderInstruction, DynamicTable, Encoder, EncoderInstruction, Prefix, StaticTable};

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
    let (Some(encoder), Some(fields)) = (unsafe { encoder.as_mut() }, unsafe { Field::parse_all(fields, field_count) }) else {
        return false;
    };

    if block.is_null() || instructions.is_null() {
        return false;
    }

    let encoded = encoder.encode(stream_id, &fields);
    let stream = encoder.take_encoder_stream();

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

    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
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

    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
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

    let Some(block) = (unsafe { Slice::borrow(block, block_len) }) else {
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

/// The capacity a dynamic table starts at: none, until the peer allows one.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_default_capacity() -> usize {
    DynamicTable::DEFAULT_CAPACITY
}

/// The capacity an encoder bounds itself to unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_default_capacity_limit() -> usize {
    Encoder::DEFAULT_CAPACITY_LIMIT
}

/// How many unacknowledged sections an encoder allows unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_default_max_outstanding_sections() -> usize {
    Encoder::DEFAULT_MAX_OUTSTANDING_SECTIONS
}

/// How large one buffered instruction may grow unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_default_max_instruction_size() -> usize {
    Encoder::DEFAULT_MAX_INSTRUCTION_SIZE
}

/// How much of a drained stream buffer is kept for reuse.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_default_idle_capacity() -> usize {
    Encoder::DEFAULT_IDLE_CAPACITY
}

/// The table capacity a decoder advertises unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_default_max_capacity() -> usize {
    Decoder::DEFAULT_MAX_CAPACITY
}

/// How large one decoded section may grow unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_default_max_decoded_size() -> usize {
    Decoder::DEFAULT_MAX_DECODED_SIZE
}

/// How many streams may block on the encoder stream unless told otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_default_max_blocked_streams() -> usize {
    Decoder::DEFAULT_MAX_BLOCKED_STREAMS
}

/// How many entries the static table holds.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_static_count() -> usize {
    StaticTable::entries().len()
}

/// The lowest index the static table is numbered from.
///
/// QPACK numbers its static table from zero, which is the only way it differs
/// from HPACK here.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_static_base() -> usize {
    0
}

/// The name of the static table entry at `index`, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_static_name(index: usize) -> Slice {
    Slice::maybe(StaticTable::entries().get(index).map(|field| field.name.as_str()))
}

/// The value of the static table entry at `index`, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_static_value(index: usize) -> Slice {
    Slice::maybe(StaticTable::entries().get(index).map(|field| field.value.as_str()))
}

/// The reverse index over the static table, borrowed from the library.
///
/// Passed to `soyokaze_static_index_lookup`, and never freed.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_static_index() -> *const crate::ffi::helpers::fields::Index {
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
pub unsafe extern "C" fn soyokaze_qpack_static_find(name: *const u8, name_len: usize, value: *const u8, value_len: usize, out: *mut u64, exact: *mut bool) -> bool {
    let (Some(name), Some(value)) = (unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    let Some((index, matched)) = StaticTable::find(&HeaderField::new(name, value)) else {
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
pub unsafe extern "C" fn soyokaze_qpack_table_size(table: *const DynamicTable) -> usize {
    unsafe { table.as_ref() }.map_or(0, |table| table.size())
}

/// What the dynamic table is currently sized to.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_capacity(table: *const DynamicTable) -> usize {
    unsafe { table.as_ref() }.map_or(0, |table| table.capacity())
}

/// How many entries the dynamic table holds.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_len(table: *const DynamicTable) -> usize {
    unsafe { table.as_ref() }.map_or(0, |table| table.len())
}

/// Whether the dynamic table holds nothing.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_is_empty(table: *const DynamicTable) -> bool {
    unsafe { table.as_ref() }.is_none_or(|table| table.is_empty())
}

/// How many entries have ever been inserted, which is what absolute indices
/// count against.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_inserted_count(table: *const DynamicTable) -> u64 {
    unsafe { table.as_ref() }.map_or(0, |table| table.inserted_count())
}

/// The name of the entry at `absolute_index`, borrowed from the table.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_name(table: *const DynamicTable, absolute_index: u64) -> Slice {
    Slice::maybe(unsafe { table.as_ref() }.and_then(|table| table.get(absolute_index)).map(|field| field.name.as_str()))
}

/// The value of the entry at `absolute_index`, borrowed from the table.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_value(table: *const DynamicTable, absolute_index: u64) -> Slice {
    Slice::maybe(unsafe { table.as_ref() }.and_then(|table| table.get(absolute_index)).map(|field| field.value.as_str()))
}

/// Whether a field would fit in the table as it is sized now.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`], and `name` and `value` must point to
/// their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_fits(table: *const DynamicTable, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(table), Some(name), Some(value)) = (unsafe { table.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    table.fits(&HeaderField::new(name, value))
}

/// The relative index an absolute one is written as, or `-1` when it names no
/// live entry.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_relative(table: *const DynamicTable, index: u64) -> i64 {
    match unsafe { table.as_ref() }.and_then(|table| table.relative(index)) {
        Some(relative) => relative as i64,
        None => -1,
    }
}

/// The absolute index a block's indexed reference names, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_indexed(table: *const DynamicTable, base: u64, index: u64) -> i64 {
    match unsafe { table.as_ref() }.and_then(|table| table.indexed(base, index)) {
        Some(absolute) => absolute as i64,
        None => -1,
    }
}

/// The absolute index a block's post-base reference names, or `-1`.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_size`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_post_base(table: *const DynamicTable, base: u64, index: u64) -> i64 {
    match unsafe { table.as_ref() }.and_then(|table| table.post_base(base, index)) {
        Some(absolute) => absolute as i64,
        None => -1,
    }
}

/// Looks a field up in a dynamic table.
///
/// Writes the absolute index through `out` and whether the value matched too
/// through `exact`, and returns whether the name was found at all.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_fits`], and `out` and `exact` must either be null
/// or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_find(table: *const DynamicTable, name: *const u8, name_len: usize, value: *const u8, value_len: usize, out: *mut u64, exact: *mut bool) -> bool {
    let (Some(table), Some(name), Some(value)) = (unsafe { table.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    let Some((index, matched)) = table.find(&HeaderField::new(name, value)) else {
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

/// Looks a field up among the entries below `below`, reporting whether one
/// above it would have matched.
///
/// Writes the absolute index through `out`, whether the value matched too
/// through `exact`, and whether a blocked entry carried the field through
/// `blocked`. Returns whether anything below `below` was found.
///
/// # Safety
///
/// As [`soyokaze_qpack_table_find`], and `blocked` must either be null or be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_table_probe(table: *const DynamicTable, name: *const u8, name_len: usize, value: *const u8, value_len: usize, below: u64, out: *mut u64, exact: *mut bool, blocked: *mut bool) -> bool {
    let (Some(table), Some(name), Some(value)) = (unsafe { table.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    let (matched, above) = table.probe(&HeaderField::new(name, value), below);

    if !blocked.is_null() {
        unsafe { *blocked = above };
    }

    let Some((index, exactly)) = matched else {
        return false;
    };

    if !out.is_null() {
        unsafe { *out = index };
    }

    if !exact.is_null() {
        unsafe { *exact = exactly };
    }

    true
}

/// The most entries a table of this capacity could ever hold.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_prefix_max_entries(max_capacity: usize) -> u64 {
    Prefix::max_entries(max_capacity)
}

/// The index a field block names an absolute entry by, counted back from
/// `base`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_prefix_relative(base: u64, absolute: u64) -> u64 {
    Prefix::relative(base, absolute)
}

/// Encodes the required insert count that leads a field block.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_prefix_encode_insert_count(required: u64, max_capacity: usize) -> u64 {
    Prefix::encode_insert_count(required, max_capacity)
}

/// Recovers the required insert count from its wrapped form.
///
/// Writes the count through `out`, and returns whether it could have come from
/// a working encoder at all.
///
/// # Safety
///
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_prefix_decode_insert_count(encoded: u64, inserted: u64, max_capacity: usize, out: *mut u64) -> bool {
    let Ok(required) = Prefix::decode_insert_count(encoded, inserted, max_capacity) else {
        return false;
    };

    if !out.is_null() {
        unsafe { *out = required };
    }

    true
}

/// Which instruction an encoder-stream instruction is.
///
/// The C half of the [`EncoderInstruction`] variants.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncoderInstructionKind {
    /// Resize the dynamic table, within what the decoder advertised.
    SetDynamicTableCapacity = 0,
    /// Insert a field whose name is taken from an existing entry.
    InsertWithNameReference = 1,
    /// Insert a field, spelling out both name and value.
    InsertWithLiteralName = 2,
    /// Re-insert an existing entry, so it survives eviction of the original.
    Duplicate = 3,
}

/// Builds a `SetDynamicTableCapacity` instruction.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_encoder_instruction_set_capacity(capacity: usize) -> *mut EncoderInstruction {
    Box::into_raw(Box::new(EncoderInstruction::SetDynamicTableCapacity { capacity }))
}

/// Builds an `InsertWithNameReference` instruction.
///
/// # Safety
///
/// `value` must either be null or point to `value_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_insert_with_name_reference(from_static: bool, name_index: u64, value: *const u8, value_len: usize) -> *mut EncoderInstruction {
    let value = unsafe { Slice::borrow(value, value_len) }.unwrap_or_default().to_vec();
    Box::into_raw(Box::new(EncoderInstruction::InsertWithNameReference { from_static, name_index, value }))
}

/// Builds an `InsertWithLiteralName` instruction.
///
/// # Safety
///
/// `name` and `value` must either be null or point to their stated number of
/// readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_insert_with_literal_name(name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> *mut EncoderInstruction {
    let name = unsafe { Slice::borrow(name, name_len) }.unwrap_or_default().to_vec();
    let value = unsafe { Slice::borrow(value, value_len) }.unwrap_or_default().to_vec();
    Box::into_raw(Box::new(EncoderInstruction::InsertWithLiteralName { name, value }))
}

/// Builds a `Duplicate` instruction.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_encoder_instruction_duplicate(index: u64) -> *mut EncoderInstruction {
    Box::into_raw(Box::new(EncoderInstruction::Duplicate { index }))
}

/// Releases an [`EncoderInstruction`].
///
/// # Safety
///
/// `instruction` must come from one of the constructors here or from
/// [`soyokaze_qpack_encoder_instruction_decode`], and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_free(instruction: *mut EncoderInstruction) {
    if !instruction.is_null() {
        drop(unsafe { Box::from_raw(instruction) });
    }
}

/// Which instruction this is.
///
/// A null handle reads as `SetDynamicTableCapacity`.
///
/// # Safety
///
/// `instruction` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_kind(instruction: *const EncoderInstruction) -> EncoderInstructionKind {
    match unsafe { instruction.as_ref() } {
        Some(EncoderInstruction::SetDynamicTableCapacity { .. }) | None => EncoderInstructionKind::SetDynamicTableCapacity,
        Some(EncoderInstruction::InsertWithNameReference { .. }) => EncoderInstructionKind::InsertWithNameReference,
        Some(EncoderInstruction::InsertWithLiteralName { .. }) => EncoderInstructionKind::InsertWithLiteralName,
        Some(EncoderInstruction::Duplicate { .. }) => EncoderInstructionKind::Duplicate,
    }
}

/// The capacity a `SetDynamicTableCapacity` asks for, or zero.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_capacity(instruction: *const EncoderInstruction) -> usize {
    match unsafe { instruction.as_ref() } {
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity }) => *capacity,
        _ => 0,
    }
}

/// Whether an `InsertWithNameReference` addresses the static table.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_from_static(instruction: *const EncoderInstruction) -> bool {
    match unsafe { instruction.as_ref() } {
        Some(EncoderInstruction::InsertWithNameReference { from_static, .. }) => *from_static,
        _ => false,
    }
}

/// The entry an `InsertWithNameReference` or a `Duplicate` names, or zero.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_index(instruction: *const EncoderInstruction) -> u64 {
    match unsafe { instruction.as_ref() } {
        Some(EncoderInstruction::InsertWithNameReference { name_index, .. }) => *name_index,
        Some(EncoderInstruction::Duplicate { index }) => *index,
        _ => 0,
    }
}

/// The name an `InsertWithLiteralName` spells out, borrowed from the handle.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_name(instruction: *const EncoderInstruction) -> Slice {
    match unsafe { instruction.as_ref() } {
        Some(EncoderInstruction::InsertWithLiteralName { name, .. }) => Slice::new(name),
        _ => Slice::ABSENT,
    }
}

/// The value an insertion spells out, borrowed from the handle.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_value(instruction: *const EncoderInstruction) -> Slice {
    match unsafe { instruction.as_ref() } {
        Some(EncoderInstruction::InsertWithNameReference { value, .. }) => Slice::new(value),
        Some(EncoderInstruction::InsertWithLiteralName { value, .. }) => Slice::new(value),
        _ => Slice::ABSENT,
    }
}

/// Encodes the instruction as it travels the encoder stream, owned by the
/// caller.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_encode(instruction: *const EncoderInstruction) -> Buffer {
    match unsafe { instruction.as_ref() } {
        Some(instruction) => Buffer::new(instruction.encode()),
        None => Buffer::EMPTY,
    }
}

/// Decodes one instruction off the encoder stream.
///
/// Writes the instruction through `out` and how many octets it took through
/// `read`. Returns [`Status::Ok`] when one decoded; a truncated instruction
/// reads as [`Status::Protocol`], since the caller feeds whole instructions.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` and `read` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_instruction_decode(data: *const u8, data_len: usize, out: *mut *mut EncoderInstruction, read: *mut usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match EncoderInstruction::decode(data) {
        Ok((consumed, instruction)) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(instruction)) };
            }

            if !read.is_null() {
                unsafe { *read = consumed };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &Error::from(failure)) },
    }
}

/// Which instruction a decoder-stream instruction is.
///
/// The C half of the [`DecoderInstruction`] variants.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecoderInstructionKind {
    /// A field section on this stream was decoded.
    SectionAcknowledgment = 0,
    /// This stream was abandoned, so its sections will never be acknowledged.
    StreamCancellation = 1,
    /// This many further insertions have been taken in.
    InsertCountIncrement = 2,
}

/// Builds a `SectionAcknowledgment` instruction.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_decoder_instruction_section_acknowledgment(stream_id: u64) -> *mut DecoderInstruction {
    Box::into_raw(Box::new(DecoderInstruction::SectionAcknowledgment { stream_id }))
}

/// Builds a `StreamCancellation` instruction.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_decoder_instruction_stream_cancellation(stream_id: u64) -> *mut DecoderInstruction {
    Box::into_raw(Box::new(DecoderInstruction::StreamCancellation { stream_id }))
}

/// Builds an `InsertCountIncrement` instruction.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_qpack_decoder_instruction_insert_count_increment(increment: u64) -> *mut DecoderInstruction {
    Box::into_raw(Box::new(DecoderInstruction::InsertCountIncrement { increment }))
}

/// Releases a [`DecoderInstruction`].
///
/// # Safety
///
/// `instruction` must come from one of the constructors here or from
/// [`soyokaze_qpack_decoder_instruction_decode`], and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_instruction_free(instruction: *mut DecoderInstruction) {
    if !instruction.is_null() {
        drop(unsafe { Box::from_raw(instruction) });
    }
}

/// Which instruction this is.
///
/// A null handle reads as `SectionAcknowledgment`.
///
/// # Safety
///
/// `instruction` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_instruction_kind(instruction: *const DecoderInstruction) -> DecoderInstructionKind {
    match unsafe { instruction.as_ref() } {
        Some(DecoderInstruction::SectionAcknowledgment { .. }) | None => DecoderInstructionKind::SectionAcknowledgment,
        Some(DecoderInstruction::StreamCancellation { .. }) => DecoderInstructionKind::StreamCancellation,
        Some(DecoderInstruction::InsertCountIncrement { .. }) => DecoderInstructionKind::InsertCountIncrement,
    }
}

/// The stream an acknowledgment or a cancellation names, or zero.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_instruction_stream_id(instruction: *const DecoderInstruction) -> u64 {
    match unsafe { instruction.as_ref() } {
        Some(DecoderInstruction::SectionAcknowledgment { stream_id }) => *stream_id,
        Some(DecoderInstruction::StreamCancellation { stream_id }) => *stream_id,
        _ => 0,
    }
}

/// How many entries an `InsertCountIncrement` reports, or zero.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_instruction_increment(instruction: *const DecoderInstruction) -> u64 {
    match unsafe { instruction.as_ref() } {
        Some(DecoderInstruction::InsertCountIncrement { increment }) => *increment,
        _ => 0,
    }
}

/// Encodes the instruction as it travels the decoder stream, owned by the
/// caller.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_instruction_kind`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_instruction_encode(instruction: *const DecoderInstruction) -> Buffer {
    match unsafe { instruction.as_ref() } {
        Some(instruction) => Buffer::new(instruction.encode()),
        None => Buffer::EMPTY,
    }
}

/// Decodes one instruction off the decoder stream.
///
/// As [`soyokaze_qpack_encoder_instruction_decode`], the other way round.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_instruction_decode`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_instruction_decode(data: *const u8, data_len: usize, out: *mut *mut DecoderInstruction, read: *mut usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match DecoderInstruction::decode(data) {
        Ok((consumed, instruction)) => {
            if !out.is_null() {
                unsafe { *out = Box::into_raw(Box::new(instruction)) };
            }

            if !read.is_null() {
                unsafe { *read = consumed };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &Error::from(failure)) },
    }
}

/// Queues instructions onto the encoder stream, returning whether they were
/// taken.
///
/// The instructions are consumed and must not be freed afterwards. Refused
/// outright when any handle is null, and nothing is consumed then.
///
/// # Safety
///
/// `encoder` must either be null or be a handle that has not been freed, and
/// `instructions` must point to `count` handles that have not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_queue(encoder: *mut Encoder, instructions: *mut *mut EncoderInstruction, count: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    if instructions.is_null() {
        return count == 0;
    }

    let mut queued = Vec::with_capacity(count);

    for index in 0..count {
        let handle = unsafe { *instructions.add(index) };

        if handle.is_null() {
            return false;
        }

        queued.push(*unsafe { Box::from_raw(handle) });
    }

    encoder.queue(&queued);
    true
}

/// What the encoder has waiting on its stream, borrowed until it is taken or
/// the encoder is used again.
///
/// # Safety
///
/// `encoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_stream(encoder: *const Encoder) -> Slice {
    match unsafe { encoder.as_ref() } {
        Some(encoder) => Slice::new(encoder.encoder_stream()),
        None => Slice::ABSENT,
    }
}

/// Takes what the encoder has waiting on its stream, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_take_stream(encoder: *mut Encoder) -> Buffer {
    match unsafe { encoder.as_mut() } {
        Some(encoder) => Buffer::new(encoder.take_encoder_stream()),
        None => Buffer::EMPTY,
    }
}

/// Hands a drained stream buffer back for reuse.
///
/// Consumes `buffer`, which must not be freed afterwards. A buffer larger than
/// the idle capacity is released rather than kept.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`], and `buffer` must be one this library
/// produced and has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_reclaim_stream(encoder: *mut Encoder, buffer: Buffer) -> bool {
    let octets = match buffer.data.is_null() {
        true => Vec::new(),
        false => unsafe { Vec::from_raw_parts(buffer.data, buffer.len, buffer.capacity) },
    };

    match unsafe { encoder.as_mut() } {
        Some(encoder) => {
            encoder.reclaim_encoder_stream(octets);
            true
        }
        None => false,
    }
}

/// How much of a drained stream buffer the encoder keeps for reuse.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_set_idle_capacity(encoder: *mut Encoder, idle_capacity: usize) -> bool {
    let Some(encoder) = (unsafe { encoder.as_mut() }) else {
        return false;
    };

    encoder.set_idle_capacity(idle_capacity);
    true
}

/// How many field sections are still unacknowledged.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_outstanding(encoder: *const Encoder) -> usize {
    unsafe { encoder.as_ref() }.map_or(0, |encoder| encoder.outstanding())
}

/// How many insertions the peer's decoder is known to have taken in.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_known_received_count(encoder: *const Encoder) -> u64 {
    unsafe { encoder.as_ref() }.map_or(0, |encoder| encoder.known_received_count())
}

/// What the encoder bounds its own table to, whatever the peer permits.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_capacity_limit(encoder: *const Encoder) -> usize {
    unsafe { encoder.as_ref() }.map_or(0, |encoder| encoder.capacity_limit())
}

/// The peer's advertised table capacity, as last recorded.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_max_capacity(encoder: *const Encoder) -> usize {
    unsafe { encoder.as_ref() }.map_or(0, |encoder| encoder.max_capacity())
}

/// The encoder's dynamic table, borrowed until the encoder is freed or used
/// again.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_table(encoder: *const Encoder) -> *const DynamicTable {
    match unsafe { encoder.as_ref() } {
        Some(encoder) => encoder.dynamic_table(),
        None => std::ptr::null(),
    }
}

/// What the encoder would reference a field by, across both tables.
///
/// Writes whether the index addresses the static table through `from_static`,
/// the index through `out`, and whether the value matched too through `exact`.
/// Returns whether either table carries the name.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`], and `name` and `value` must point to
/// their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_reference(encoder: *const Encoder, name: *const u8, name_len: usize, value: *const u8, value_len: usize, from_static: *mut bool, out: *mut u64, exact: *mut bool) -> bool {
    let (Some(encoder), Some(name), Some(value)) = (unsafe { encoder.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    let Some((statically, index, matched)) = encoder.reference(&HeaderField::new(name, value)) else {
        return false;
    };

    if !from_static.is_null() {
        unsafe { *from_static = statically };
    }

    if !out.is_null() {
        unsafe { *out = index };
    }

    if !exact.is_null() {
        unsafe { *exact = matched };
    }

    true
}

/// Takes in one decoder-stream instruction.
///
/// Consumes `instruction`, which must not be freed afterwards.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_stream`], and `instruction` must be a handle
/// that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_encoder_on_decoder_instruction(encoder: *mut Encoder, instruction: *mut DecoderInstruction) -> bool {
    if instruction.is_null() {
        return false;
    }

    let instruction = *unsafe { Box::from_raw(instruction) };

    match unsafe { encoder.as_mut() } {
        Some(encoder) => {
            encoder.on_decoder_instruction(instruction);
            true
        }
        None => false,
    }
}

/// Queues instructions onto the decoder stream, returning whether they were
/// taken.
///
/// As [`soyokaze_qpack_encoder_queue`], the other way round.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_queue`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_queue(decoder: *mut Decoder, instructions: *mut *mut DecoderInstruction, count: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    if instructions.is_null() {
        return count == 0;
    }

    let mut queued = Vec::with_capacity(count);

    for index in 0..count {
        let handle = unsafe { *instructions.add(index) };

        if handle.is_null() {
            return false;
        }

        queued.push(*unsafe { Box::from_raw(handle) });
    }

    decoder.queue(&queued);
    true
}

/// What the decoder has waiting on its stream, borrowed until it is taken or
/// the decoder is used again.
///
/// # Safety
///
/// `decoder` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_stream(decoder: *const Decoder) -> Slice {
    match unsafe { decoder.as_ref() } {
        Some(decoder) => Slice::new(decoder.decoder_stream()),
        None => Slice::ABSENT,
    }
}

/// Takes what the decoder has waiting on its stream, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_take_stream(decoder: *mut Decoder) -> Buffer {
    match unsafe { decoder.as_mut() } {
        Some(decoder) => Buffer::new(decoder.take_decoder_stream()),
        None => Buffer::EMPTY,
    }
}

/// Hands a drained stream buffer back for reuse.
///
/// As [`soyokaze_qpack_encoder_reclaim_stream`], the other way round.
///
/// # Safety
///
/// As [`soyokaze_qpack_encoder_reclaim_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_reclaim_stream(decoder: *mut Decoder, buffer: Buffer) -> bool {
    let octets = match buffer.data.is_null() {
        true => Vec::new(),
        false => unsafe { Vec::from_raw_parts(buffer.data, buffer.len, buffer.capacity) },
    };

    match unsafe { decoder.as_mut() } {
        Some(decoder) => {
            decoder.reclaim_decoder_stream(octets);
            true
        }
        None => false,
    }
}

/// How much of a drained stream buffer the decoder keeps for reuse.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_set_idle_capacity(decoder: *mut Decoder, idle_capacity: usize) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.set_idle_capacity(idle_capacity);
    true
}

/// How many streams are waiting on insertions that have not arrived.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_blocked(decoder: *const Decoder) -> usize {
    unsafe { decoder.as_ref() }.map_or(0, |decoder| decoder.blocked())
}

/// Which streams the last insertions unblocked, owned by the caller.
///
/// The buffer holds one stream identifier per eight octets, in native order.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_unblocked(decoder: *const Decoder) -> Buffer {
    let Some(decoder) = (unsafe { decoder.as_ref() }) else {
        return Buffer::EMPTY;
    };

    let streams = decoder.unblocked();
    let mut octets = Vec::with_capacity(streams.len() * size_of::<u64>());

    for stream_id in streams {
        octets.extend_from_slice(&stream_id.to_ne_bytes());
    }

    Buffer::new(octets)
}

/// Forgets a stream that was abandoned before its blocks arrived.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_cancel(decoder: *mut Decoder, stream_id: u64) -> bool {
    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return false;
    };

    decoder.cancel(stream_id);
    true
}

/// Takes in one encoder-stream instruction.
///
/// Consumes `instruction`, which must not be freed afterwards. What the
/// decoder owes back goes through `out`, which is left null when it owes
/// nothing; free it with `soyokaze_qpack_decoder_instruction_free`.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`], `instruction` must be a handle that
/// has not been freed, and `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_on_encoder_instruction(decoder: *mut Decoder, instruction: *mut EncoderInstruction, out: *mut *mut DecoderInstruction, error: *mut *mut ErrorHandle) -> Status {
    if instruction.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let instruction = *unsafe { Box::from_raw(instruction) };

    let Some(decoder) = (unsafe { decoder.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match decoder.on_encoder_instruction(instruction) {
        Ok(answer) => {
            if !out.is_null() {
                unsafe {
                    *out = match answer {
                        Some(answer) => Box::into_raw(Box::new(answer)),
                        None => std::ptr::null_mut(),
                    }
                };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &Error::from(failure)) },
    }
}

/// The decoder's dynamic table, borrowed until the decoder is freed or used
/// again.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_table(decoder: *const Decoder) -> *const DynamicTable {
    match unsafe { decoder.as_ref() } {
        Some(decoder) => decoder.dynamic_table(),
        None => std::ptr::null(),
    }
}

/// The field a block's reference names, across both tables.
///
/// Writes the name and value through `name` and `value`, owned by the caller,
/// and returns whether the reference addressed anything.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`], and `name` and `value` must either be
/// null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_resolve(decoder: *const Decoder, from_static: bool, base: u64, index: u64, name: *mut Buffer, value: *mut Buffer) -> bool {
    let Some(decoder) = (unsafe { decoder.as_ref() }) else {
        return false;
    };

    let Ok(field) = decoder.resolve(from_static, base, index) else {
        return false;
    };

    if !name.is_null() {
        unsafe { *name = Buffer::new(field.name.into_bytes()) };
    }

    if !value.is_null() {
        unsafe { *value = Buffer::new(field.value.into_bytes()) };
    }

    true
}

/// The name a block's reference names, across both tables, owned by the
/// caller.
///
/// An empty buffer with a null pointer means the reference addressed nothing.
///
/// # Safety
///
/// As [`soyokaze_qpack_decoder_stream`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_qpack_decoder_resolve_name(decoder: *const Decoder, from_static: bool, base: u64, index: u64) -> Buffer {
    let Some(decoder) = (unsafe { decoder.as_ref() }) else {
        return Buffer::EMPTY;
    };

    match decoder.resolve_name(from_static, base, index) {
        Ok(name) => Buffer::new(name.into_bytes()),
        Err(_) => Buffer::EMPTY,
    }
}
