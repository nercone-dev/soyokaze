//! Scanning octets a word at a time, from C.
//!
//! The word-at-a-time primitives [`crate::helpers::scan`] gives the parsers:
//! finding an octet, copying a run, and classifying a field value. Nothing
//! here knows what it is scanning for.

use crate::ffi::Slice;

/// How many octets one word holds.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_scan_lanes() -> usize {
    crate::helpers::scan::LANES
}

/// The word with the low bit of every octet set.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_scan_low() -> u64 {
    crate::helpers::scan::LOW
}

/// The word with the high bit of every octet set.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_scan_high() -> u64 {
    crate::helpers::scan::HIGH
}

/// A word marking which octets of `word` are zero.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_scan_holds_zero(word: u64) -> u64 {
    crate::helpers::scan::holds_zero(word)
}

/// A word marking which octets of `word` are below `bound`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_scan_holds_less(word: u64, bound: u64) -> u64 {
    crate::helpers::scan::holds_less(word, bound)
}

/// A word marking which octets of `word` are exactly zero.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_scan_marks_zero(word: u64) -> u64 {
    crate::helpers::scan::marks_zero(word)
}

/// The word at `offset`, read in native order.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `offset` must leave a whole word inside them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_scan_word_at(data: *const u8, data_len: usize, offset: usize) -> u64 {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();

    // Checked, because an `offset` near the top of the range would otherwise
    // wrap past the length and let the read through.
    let Some(end) = offset.checked_add(crate::helpers::scan::LANES) else {
        return 0;
    };

    if end > data.len() {
        return 0;
    }

    crate::helpers::scan::word_at(data, offset)
}

/// Where `needle` first appears, or `-1` when it does not.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_scan_find(data: *const u8, data_len: usize, needle: u8) -> isize {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();

    match crate::helpers::scan::find(data, needle) {
        Some(offset) => offset as isize,
        None => -1,
    }
}

/// Copies `len` octets from `source` to `destination`.
///
/// Returns whether the two runs are the same length; a mismatch copies
/// nothing.
///
/// # Safety
///
/// `destination` must point to `len` writable octets and `source` to `len`
/// readable ones, and the two must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_scan_copy(destination: *mut u8, destination_len: usize, source: *const u8, source_len: usize) -> bool {
    if destination.is_null() || source.is_null() || destination_len != source_len {
        return false;
    }

    let destination = unsafe { std::slice::from_raw_parts_mut(destination, destination_len) };
    let source = unsafe { std::slice::from_raw_parts(source, source_len) };

    crate::helpers::scan::copy(destination, source);
    true
}

/// [`soyokaze_scan_classify_field_value`]: an octet below space, or delete.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_scan_value_control() -> u8 {
    crate::helpers::scan::VALUE_CONTROL
}

/// [`soyokaze_scan_classify_field_value`]: an octet at or above `0x80`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_scan_value_obs_text() -> u8 {
    crate::helpers::scan::VALUE_OBS_TEXT
}

/// The or of [`soyokaze_scan_value_control`] and
/// [`soyokaze_scan_value_obs_text`] over every octet.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_scan_classify_field_value(data: *const u8, data_len: usize) -> u8 {
    crate::helpers::scan::classify_field_value(unsafe { Slice::borrow(data, data_len) }.unwrap_or_default())
}

/// Whether every octet may appear in a field value.
///
/// # Safety
///
/// As [`soyokaze_scan_classify_field_value`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_scan_is_field_value(data: *const u8, data_len: usize) -> bool {
    crate::helpers::scan::is_field_value(unsafe { Slice::borrow(data, data_len) }.unwrap_or_default())
}

/// Whether every octet has `mask` set in a 256-entry classification table.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `table` must point to 256 readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_scan_all_in_class(data: *const u8, data_len: usize, table: *const u8, mask: u8) -> bool {
    if table.is_null() {
        return false;
    }

    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    let table = unsafe { &*(table as *const [u8; 256]) };

    crate::helpers::scan::all_in_class(data, table, mask)
}
