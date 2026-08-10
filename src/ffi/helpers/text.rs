//! The compact string the crate holds field names and values in, from C.
//!
//! [`Text`] stores a short string inside itself and a long one behind a
//! pointer, as [`crate::helpers::text`] does. A C caller rarely needs one —
//! text goes in as a pointer and a length everywhere else — but the crate's own
//! surface is written in terms of it, so it crosses whole: every constructor,
//! including the ones that promise the octets are already ASCII, and every
//! reader.

use crate::ffi::{Buffer, Slice};

pub use crate::helpers::text::Text;

/// How many octets fit inside a [`Text`] before it allocates.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_text_inline() -> usize {
    crate::helpers::text::INLINE
}

/// Builds an empty [`Text`].
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_text_new() -> *mut Text {
    Box::into_raw(Box::new(Text::new()))
}

/// Builds a [`Text`] from octets, or null when they are not UTF-8.
///
/// A null `data` builds an empty one.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_from_utf8(data: *const u8, data_len: usize) -> *mut Text {
    if data.is_null() {
        return soyokaze_text_new();
    }

    match unsafe { Slice::borrow_text(data, data_len) } {
        Some(text) => Box::into_raw(Box::new(Text::from_str(text))),
        None => std::ptr::null_mut(),
    }
}

/// Builds a [`Text`] from octets, replacing whatever is not UTF-8.
///
/// # Safety
///
/// As [`soyokaze_text_from_utf8`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_from_utf8_lossy(data: *const u8, data_len: usize) -> *mut Text {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    Box::into_raw(Box::new(Text::from_utf8_lossy(data)))
}

/// Builds a [`Text`] from octets that are expected to be ASCII.
///
/// Octets that are not ASCII go through lossy UTF-8 decoding, so this never
/// fails.
///
/// # Safety
///
/// As [`soyokaze_text_from_utf8`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_from_ascii(data: *const u8, data_len: usize) -> *mut Text {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    Box::into_raw(Box::new(Text::from_ascii(data)))
}

/// As [`soyokaze_text_from_ascii`], lowercasing as it goes.
///
/// # Safety
///
/// As [`soyokaze_text_from_utf8`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_from_ascii_lowercase(data: *const u8, data_len: usize) -> *mut Text {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    Box::into_raw(Box::new(Text::from_ascii_lowercase(data)))
}

/// Copies octets into the inline layout a short [`Text`] holds.
///
/// Writes [`soyokaze_text_inline`] octets through `out`, and returns whether
/// the input was short enough to fit.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` must either be null or point to [`soyokaze_text_inline`] writable
/// octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_copy_inline(data: *const u8, data_len: usize, out: *mut u8) -> bool {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();

    if data.len() > crate::helpers::text::INLINE {
        return false;
    }

    if !out.is_null() {
        let octets = Text::copy_inline(data);
        unsafe { std::ptr::copy_nonoverlapping(octets.as_ptr(), out, crate::helpers::text::INLINE) };
    }

    true
}

/// Builds a [`Text`] from octets the caller promises are ASCII.
///
/// Skips the check [`soyokaze_text_from_ascii`] makes. Passing octets that are
/// not ASCII is undefined behaviour.
///
/// # Safety
///
/// As [`soyokaze_text_from_utf8`], and every octet must be ASCII.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_from_verified_ascii(data: *const u8, data_len: usize) -> *mut Text {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    Box::into_raw(Box::new(unsafe { Text::from_verified_ascii(data) }))
}

/// As [`soyokaze_text_from_verified_ascii`], lowercasing as it goes.
///
/// # Safety
///
/// As [`soyokaze_text_from_verified_ascii`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_from_verified_ascii_lowercase(data: *const u8, data_len: usize) -> *mut Text {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    Box::into_raw(Box::new(unsafe { Text::from_verified_ascii_lowercase(data) }))
}

/// Releases a [`Text`].
///
/// # Safety
///
/// `text` must come from one of the constructors here and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_free(text: *mut Text) {
    if !text.is_null() {
        drop(unsafe { Box::from_raw(text) });
    }
}

/// The octets, borrowed from `text` and valid until it is freed or modified.
///
/// # Safety
///
/// `text` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_bytes(text: *const Text) -> Slice {
    Slice::maybe(unsafe { text.as_ref() }.map(|text| text.as_str()))
}

/// How many octets there are.
///
/// # Safety
///
/// As [`soyokaze_text_bytes`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_len(text: *const Text) -> usize {
    unsafe { text.as_ref() }.map_or(0, |text| text.len())
}

/// Whether there are no octets at all.
///
/// # Safety
///
/// As [`soyokaze_text_bytes`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_is_empty(text: *const Text) -> bool {
    unsafe { text.as_ref() }.is_none_or(|text| text.is_empty())
}

/// Whether the octets sit inside the handle rather than behind a pointer.
///
/// # Safety
///
/// As [`soyokaze_text_bytes`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_is_inline(text: *const Text) -> bool {
    unsafe { text.as_ref() }.is_some_and(|text| text.is_inline())
}

/// Lowercases the ASCII octets in place, returning whether there was a handle.
///
/// # Safety
///
/// `text` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_make_ascii_lowercase(text: *mut Text) -> bool {
    match unsafe { text.as_mut() } {
        Some(text) => {
            text.make_ascii_lowercase();
            true
        }
        None => false,
    }
}

/// Takes the octets out and releases the handle, owned by the caller.
///
/// Consumes `text`, which must not be freed afterwards.
///
/// # Safety
///
/// `text` must come from one of the constructors here and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_into_bytes(text: *mut Text) -> Buffer {
    if text.is_null() {
        return Buffer::EMPTY;
    }

    Buffer::new(unsafe { Box::from_raw(text) }.into_bytes())
}

/// Whether two handles hold the same octets.
///
/// Two null handles compare equal, and a null one differs from any other.
///
/// # Safety
///
/// Both must either be null or be handles that have not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_equals(text: *const Text, other: *const Text) -> bool {
    match (unsafe { text.as_ref() }, unsafe { other.as_ref() }) {
        (Some(text), Some(other)) => text == other,
        (None, None) => true,
        _ => false,
    }
}

/// How `text` orders against `other`: negative, zero or positive.
///
/// A null handle sorts before any other.
///
/// # Safety
///
/// As [`soyokaze_text_equals`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_text_compare(text: *const Text, other: *const Text) -> i32 {
    match unsafe { text.as_ref() }.cmp(&unsafe { other.as_ref() }) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}
