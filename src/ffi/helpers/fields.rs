//! The field vocabulary HPACK and QPACK share, from C.
//!
//! [`Field`] carries one name and value pair in, and [`Fields`] carries a
//! decoded block back out. Both compression formats cross the boundary with
//! these, the way [`crate::helpers::hpack`] and [`crate::helpers::qpack`]
//! share [`crate::helpers::fields`].
//!
//! The wire primitives the two formats are built out of cross as well: the
//! prefixed integer, the string literal either format writes a name or a value
//! as, and the reverse index a static table is looked up through.

use crate::ffi::{Buffer, Slice};
use crate::helpers::fields::{HeaderField, StaticIndex};

/// Why a wire primitive would not decode.
///
/// The C half of [`Error`], with [`Error::Ok`] added for the call that
/// succeeded and the Huffman failure flattened into the two ways it happens.
///
/// [`Error`]: crate::helpers::fields::Error
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The primitive decoded.
    Ok = 0,
    /// An integer would not fit in 64 bits.
    IntegerOverflow = 1,
    /// A representation runs past the end of the input.
    Incomplete = 2,
    /// A Huffman string does not end on the all-ones padding.
    HuffmanInvalidPadding = 3,
    /// A Huffman string spells bits that are not a code word.
    HuffmanUnknownSymbol = 4,
    /// An argument was null where it may not be.
    Invalid = 5,
}

impl Error {
    /// The error that stands for `error`.
    pub fn of(error: &crate::helpers::fields::Error) -> Self {
        match error {
            crate::helpers::fields::Error::IntegerOverflow => Self::IntegerOverflow,
            crate::helpers::fields::Error::Incomplete => Self::Incomplete,
            crate::helpers::fields::Error::Huffman(crate::helpers::huffman::DecodeError::InvalidPadding) => Self::HuffmanInvalidPadding,
            crate::helpers::fields::Error::Huffman(crate::helpers::huffman::DecodeError::UnknownSymbol) => Self::HuffmanUnknownSymbol,
        }
    }

    /// Writes an error through an out parameter, which may be null.
    ///
    /// # Safety
    ///
    /// `out` must either be null or be writable.
    pub unsafe fn report(out: *mut Error, error: Self) {
        if !out.is_null() {
            unsafe { *out = error };
        }
    }

    /// A fixed description of the error.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::IntegerOverflow => "integer representation overflowed",
            Self::Incomplete => "representation ends before the input does",
            Self::HuffmanInvalidPadding => "huffman padding is not all one-bits",
            Self::HuffmanUnknownSymbol => "huffman code does not map to a known symbol",
            Self::Invalid => "invalid argument",
        }
    }
}

/// A fixed description of `error`.
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_fields_error_message(error: Error) -> Slice {
    Slice::text(error.message())
}

/// One field going in: a name and a value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Field {
    /// The field name.
    pub name: Slice,
    /// The field value.
    pub value: Slice,
}

impl Field {
    /// Reads `count` fields out of a C array.
    ///
    /// `None` when the array is null with a non-zero count, or any name or
    /// value is null or not UTF-8.
    ///
    /// # Safety
    ///
    /// `fields` must either be null or point to `count` readable [`Field`]
    /// values whose own pointers are valid.
    pub unsafe fn parse_all(fields: *const Field, count: usize) -> Option<Vec<HeaderField>> {
        if fields.is_null() {
            return (count == 0).then(Vec::new);
        }

        let mut parsed = Vec::with_capacity(count);

        for index in 0..count {
            let field = unsafe { *fields.add(index) };
            let name = unsafe { Slice::borrow_text(field.name.data, field.name.len) }?;
            let value = unsafe { Slice::borrow_text(field.value.data, field.value.len) }?;
            parsed.push(HeaderField::new(name, value));
        }

        Some(parsed)
    }
}

/// How many octets a field is charged beyond its name and value.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_field_overhead() -> usize {
    HeaderField::OVERHEAD
}

/// How many field names are treated as sensitive.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_field_sensitive_count() -> usize {
    HeaderField::SENSITIVE.len()
}

/// The sensitive field name at `index`, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_field_sensitive_name(index: usize) -> Slice {
    Slice::maybe(HeaderField::SENSITIVE.get(index).copied())
}

/// What a field costs the dynamic table: its octets plus the overhead.
///
/// # Safety
///
/// `name` and `value` must either be null or point to their stated number of
/// readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_field_size(name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> usize {
    let (Some(name), Some(value)) = (unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return 0;
    };

    HeaderField::new(name, value).size()
}

/// Whether a field carries a credential and must never be indexed.
///
/// # Safety
///
/// `name` must either be null or point to `name_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_field_is_sensitive(name: *const u8, name_len: usize) -> bool {
    let Some(name) = (unsafe { Slice::borrow_text(name, name_len) }) else {
        return false;
    };

    HeaderField::new(name, "").sensitive()
}

/// A decoded field section, as a decoder hands it back.
pub struct Fields(pub Vec<HeaderField>);

/// Builds an empty [`Fields`].
///
/// For a caller assembling a section by hand rather than decoding one.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_fields_new() -> *mut Fields {
    Box::into_raw(Box::new(Fields(Vec::new())))
}

/// Appends one field, returning whether the arguments were usable.
///
/// # Safety
///
/// `fields` must either be null or be a handle that has not been freed, and
/// `name` and `value` must point to their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_append(fields: *mut Fields, name: *const u8, name_len: usize, value: *const u8, value_len: usize) -> bool {
    let (Some(fields), Some(name), Some(value)) = (unsafe { fields.as_mut() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    fields.0.push(HeaderField::new(name, value));
    true
}

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

/// The largest value a prefix of `prefix_bits` can hold on its own.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_integer_limit(prefix_bits: u8) -> u64 {
    crate::helpers::fields::Integer::limit(prefix_bits)
}

/// Encodes a prefixed integer, owned by the caller.
///
/// `flags` fills the bits above the prefix, which is how each format spells
/// out what the representation is.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_integer_encode(value: u64, prefix_bits: u8, flags: u8) -> Buffer {
    let mut out = Vec::new();
    crate::helpers::fields::Integer::encode(&mut out, value, prefix_bits, flags);
    Buffer::new(out)
}

/// Decodes a prefixed integer, writing the value through `out` and how many
/// octets it took through `read`.
///
/// Returns whether it decoded; what went wrong is written through `error`.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out`, `read` and `error` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_integer_decode(data: *const u8, data_len: usize, prefix_bits: u8, out: *mut u64, read: *mut usize, error: *mut Error) -> bool {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        unsafe { Error::report(error, Error::Invalid) };
        return false;
    };

    match crate::helpers::fields::Integer::decode(data, prefix_bits) {
        Ok((consumed, value)) => {
            if !out.is_null() {
                unsafe { *out = value };
            }

            if !read.is_null() {
                unsafe { *read = consumed };
            }

            unsafe { Error::report(error, Error::Ok) };
            true
        }
        Err(failure) => {
            unsafe { Error::report(error, Error::of(&failure)) };
            false
        }
    }
}

/// Whether Huffman coding would make a value shorter.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_string_prefers_huffman(data: *const u8, data_len: usize) -> bool {
    crate::helpers::fields::StringLiteral::prefers_huffman(unsafe { Slice::borrow(data, data_len) }.unwrap_or_default())
}

/// Encodes a string literal, owned by the caller.
///
/// `huffman` picks the coding outright; [`soyokaze_string_encode_shorter`]
/// picks whichever comes out smaller instead.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_string_encode(data: *const u8, data_len: usize, prefix_bits: u8, flags: u8, huffman: bool) -> Buffer {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    let mut out = Vec::new();
    crate::helpers::fields::StringLiteral::encode(&mut out, data, prefix_bits, flags, huffman);
    Buffer::new(out)
}

/// Encodes a string literal with whichever coding comes out shorter.
///
/// # Safety
///
/// As [`soyokaze_string_encode`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_string_encode_shorter(data: *const u8, data_len: usize, prefix_bits: u8, flags: u8) -> Buffer {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    let mut out = Vec::new();
    crate::helpers::fields::StringLiteral::encode_shorter(&mut out, data, prefix_bits, flags);
    Buffer::new(out)
}

/// Decodes a string literal through `out`, and how many octets it took through
/// `read`.
///
/// Returns whether it decoded; what went wrong is written through `error`.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out`, `read` and `error` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_string_decode(data: *const u8, data_len: usize, prefix_bits: u8, out: *mut Buffer, read: *mut usize, error: *mut Error) -> bool {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        unsafe { Error::report(error, Error::Invalid) };
        return false;
    };

    match crate::helpers::fields::StringLiteral::decode(data, prefix_bits) {
        Ok((consumed, octets)) => {
            if !out.is_null() {
                unsafe { *out = Buffer::new(octets) };
            }

            if !read.is_null() {
                unsafe { *read = consumed };
            }

            unsafe { Error::report(error, Error::Ok) };
            true
        }
        Err(failure) => {
            unsafe { Error::report(error, Error::of(&failure)) };
            false
        }
    }
}

/// A reverse index over a static table: field to index.
///
/// Built over whichever table [`soyokaze_hpack_static_index`] or
/// [`soyokaze_qpack_static_index`] hands back, and borrowed from the library
/// rather than owned, so nothing here is freed.
///
/// [`soyokaze_hpack_static_index`]: crate::ffi::helpers::hpack::soyokaze_hpack_static_index
/// [`soyokaze_qpack_static_index`]: crate::ffi::helpers::qpack::soyokaze_qpack_static_index
pub type Index = StaticIndex;

/// Looks a field up in a static index.
///
/// Writes the lowest index carrying the name through `name_index`, and the
/// index carrying both name and value through `exact`. Either is `-1` when
/// there is none. Returns whether the name was found at all.
///
/// # Safety
///
/// `index` must either be null or be an index the library handed back, `name`
/// and `value` must point to their stated number of readable octets, and
/// `name_index` and `exact` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_static_index_lookup(index: *const Index, name: *const u8, name_len: usize, value: *const u8, value_len: usize, name_index: *mut i64, exact: *mut i64) -> bool {
    let (Some(index), Some(name), Some(value)) = (unsafe { index.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    let (first, matched) = index.lookup(name, value);

    if !name_index.is_null() {
        unsafe { *name_index = first.map_or(-1, |first| first as i64) };
    }

    if !exact.is_null() {
        unsafe { *exact = matched.map_or(-1, |matched| matched as i64) };
    }

    first.is_some()
}
