//! SHA-1, from C.
//!
//! Provided because the WebSocket handshake needs it, as
//! [`crate::helpers::sha1`] notes; it is not a general-purpose hash to build
//! anything new on.

use crate::ffi::{Buffer, Slice};

/// The SHA-1 digest of `data`, owned by the caller. Always 20 octets.
///
/// A null `data` hashes the empty input.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_sha1(data: *const u8, data_len: usize) -> Buffer {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    Buffer::new(crate::helpers::sha1::sha1(data).to_vec())
}
