//! Base64, from C.
//!
//! The standard alphabet with padding, as [`crate::helpers::base64`]
//! implements it for the WebSocket handshake.

use crate::ffi::{Buffer, Slice};

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
/// Refused when the text is null, is not UTF-8, or is not valid base64.
///
/// # Safety
///
/// `text` must either be null or point to `text_len` readable octets, and
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_base64_decode(text: *const u8, text_len: usize, out: *mut Buffer) -> bool {
    if out.is_null() {
        return false;
    }

    let Some(text) = (unsafe { Slice::borrow_text(text, text_len) }) else {
        return false;
    };

    match crate::helpers::base64::decode(text) {
        Ok(octets) => {
            unsafe { *out = Buffer::new(octets) };
            true
        }
        Err(_) => false,
    }
}
