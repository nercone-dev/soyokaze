//! Base64, from C.
//!
//! The standard alphabet with padding, as [`crate::helpers::base64`]
//! implements it for the WebSocket handshake. Every piece the Rust module
//! offers crosses: the alphabet and the reverse table, the symbol and sextet
//! conversions either way, the encoded length, the four-symbol group, and the
//! whole-string encode and decode.

use crate::ffi::{Buffer, Slice};

/// Why a base64 string would not decode.
///
/// The C half of [`DecodeError`], with [`DecodeError::Ok`] added for the call
/// that succeeded. The variants that carry a value in Rust report it through
/// the `detail` out parameter of the call that raised them.
///
/// [`DecodeError`]: crate::helpers::base64::DecodeError
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// The input decoded.
    Ok = 0,
    /// The input length is not a multiple of four; `detail` is that length.
    InvalidLength = 1,
    /// A symbol is outside the alphabet; `detail` is that symbol.
    InvalidSymbol = 2,
    /// Padding is misplaced, over-long, or carries non-zero bits.
    InvalidPadding = 3,
    /// The text was null or was not UTF-8.
    Invalid = 4,
}

impl DecodeError {
    /// The error a `soyokaze_base64_error_t` names, or `None` when it names
    /// none.
    ///
    /// As [`crate::ffi::helpers::huffman::DecodeError::from_code`].
    pub fn from_code(code: i32) -> Option<Self> {
        Some(match code {
            0 => Self::Ok,
            1 => Self::InvalidLength,
            2 => Self::InvalidSymbol,
            3 => Self::InvalidPadding,
            4 => Self::Invalid,
            _ => return None,
        })
    }

    /// The error that stands for `error`, with the value it carries.
    pub fn of(error: &crate::helpers::base64::DecodeError) -> (Self, u64) {
        match error {
            crate::helpers::base64::DecodeError::InvalidLength(length) => (Self::InvalidLength, *length as u64),
            crate::helpers::base64::DecodeError::InvalidSymbol(symbol) => (Self::InvalidSymbol, *symbol as u64),
            crate::helpers::base64::DecodeError::InvalidPadding => (Self::InvalidPadding, 0),
        }
    }

    /// Writes an error and the value it carries through out parameters.
    ///
    /// Either out parameter may be null, which drops that half.
    ///
    /// # Safety
    ///
    /// `out` and `detail` must either be null or be writable.
    pub unsafe fn report(out: *mut DecodeError, detail: *mut u64, error: Self, value: u64) {
        if !out.is_null() {
            unsafe { *out = error };
        }

        if !detail.is_null() {
            unsafe { *detail = value };
        }
    }

    /// A fixed description of the error.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidLength => "length is not a multiple of four",
            Self::InvalidSymbol => "symbol is not in the base64 alphabet",
            Self::InvalidPadding => "padding is misplaced or carries non-zero bits",
            Self::Invalid => "invalid argument",
        }
    }
}

/// A fixed description of `error`.
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_base64_error_message(error: i32) -> Slice {
    Slice::maybe(DecodeError::from_code(error).map(|error| error.message()))
}

/// The standard alphabet, indexed by sextet value. Always 64 octets.
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_base64_alphabet() -> Slice {
    Slice::new(crate::helpers::base64::ALPHABET)
}

/// The padding symbol.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_base64_pad() -> u8 {
    crate::helpers::base64::PAD
}

/// The [`soyokaze_base64_values`] entry for an octet outside the alphabet.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_base64_invalid() -> u8 {
    crate::helpers::base64::INVALID
}

/// The sextet value of each octet, or [`soyokaze_base64_invalid`]. Always 256
/// octets.
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_base64_values() -> Slice {
    Slice::new(&crate::helpers::base64::VALUES)
}

/// The symbol for a sextet; only the low six bits of `value` are read.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_base64_symbol(value: u8) -> u8 {
    crate::helpers::base64::symbol(value)
}

/// The sextet a symbol stands for, or `-1` when it is outside the alphabet.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_base64_value(symbol: u8) -> i32 {
    match crate::helpers::base64::value(symbol) {
        Some(value) => value as i32,
        None => -1,
    }
}

/// How many octets encoding this input will produce, padding included.
///
/// A null `data` measures the empty input.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_base64_encoded_len(data: *const u8, data_len: usize) -> usize {
    crate::helpers::base64::encoded_len(unsafe { Slice::borrow(data, data_len) }.unwrap_or_default())
}

/// Decodes one four-symbol group into the 24 bits it stands for.
///
/// Returns whether the group decoded, writing the sextets through `out` and
/// the failure through `error` and `detail`. A group is exactly four symbols;
/// anything else is [`DecodeError::InvalidLength`].
///
/// # Safety
///
/// `group` must either be null or point to `group_len` readable octets, and
/// `out`, `error` and `detail` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_base64_sextets(group: *const u8, group_len: usize, out: *mut u32, error: *mut DecodeError, detail: *mut u64) -> bool {
    let Some(group) = (unsafe { Slice::borrow(group, group_len) }) else {
        unsafe { DecodeError::report(error, detail, DecodeError::Invalid, 0) };
        return false;
    };

    match crate::helpers::base64::sextets(group) {
        Ok(bits) => {
            if !out.is_null() {
                unsafe { *out = bits };
            }

            unsafe { DecodeError::report(error, detail, DecodeError::Ok, 0) };
            true
        }
        Err(failure) => {
            let (failure, value) = DecodeError::of(&failure);
            unsafe { DecodeError::report(error, detail, failure, value) };
            false
        }
    }
}

/// Encodes octets as base64, owned by the caller.
///
/// A null `data` encodes nothing and comes back empty.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_base64_encode(data: *const u8, data_len: usize) -> Buffer {
    match unsafe { Slice::borrow(data, data_len) } {
        Some(data) => Buffer::new(crate::helpers::base64::encode(data).into_bytes()),
        None => Buffer::EMPTY,
    }
}

/// Decodes base64 text through `out`, returning whether it decoded.
///
/// Refused when the text is null, is not UTF-8, or is not valid base64. What
/// went wrong is written through `error` and `detail`, either of which may be
/// null when the caller only wants to know that it failed.
///
/// # Safety
///
/// `text` must either be null or point to `text_len` readable octets, and
/// `out`, `error` and `detail` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_base64_decode(text: *const u8, text_len: usize, out: *mut Buffer, error: *mut DecodeError, detail: *mut u64) -> bool {
    let Some(text) = (unsafe { Slice::borrow_text(text, text_len) }) else {
        unsafe { DecodeError::report(error, detail, DecodeError::Invalid, 0) };
        return false;
    };

    match crate::helpers::base64::decode(text) {
        Ok(octets) => {
            if !out.is_null() {
                unsafe { *out = Buffer::new(octets) };
            }

            unsafe { DecodeError::report(error, detail, DecodeError::Ok, 0) };
            true
        }
        Err(failure) => {
            let (failure, value) = DecodeError::of(&failure);
            unsafe { DecodeError::report(error, detail, failure, value) };
            false
        }
    }
}
