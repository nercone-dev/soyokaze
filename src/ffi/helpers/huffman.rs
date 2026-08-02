//! The HPACK and QPACK Huffman code, from C.
//!
//! One code serves both compression formats, as in
//! [`crate::helpers::huffman`].

use crate::ffi::{borrow, Buffer};

/// Huffman-encodes octets, owned by the caller.
///
/// A null `data` encodes nothing and comes back empty.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_huffman_encode(data: *const u8, data_len: usize) -> Buffer {
    match unsafe { borrow(data, data_len) } {
        Some(data) => Buffer::new(crate::helpers::huffman::encode(data).to_vec()),
        None => Buffer::EMPTY,
    }
}

/// Huffman-decodes octets through `out`, returning whether they decoded.
///
/// Refused when the input is null or is not a valid Huffman sequence — a
/// truncated symbol, or padding done wrong.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_huffman_decode(data: *const u8, data_len: usize, out: *mut Buffer) -> bool {
    if out.is_null() {
        return false;
    }

    let Some(data) = (unsafe { borrow(data, data_len) }) else {
        return false;
    };

    match crate::helpers::huffman::decode(data) {
        Ok(octets) => {
            unsafe { *out = Buffer::new(octets.to_vec()) };
            true
        }
        Err(_) => false,
    }
}
