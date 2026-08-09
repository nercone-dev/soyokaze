//! SHA-1, from C.
//!
//! Provided because the WebSocket handshake needs it, as
//! [`crate::helpers::sha1`] notes; it is not a general-purpose hash to build
//! anything new on.
//!
//! [`soyokaze_sha1`] hashes an input in one call, and [`Sha1`] is the same
//! hash driven a block at a time, for an input that does not sit in memory
//! whole.

use crate::ffi::{Buffer, Slice};

pub use crate::helpers::sha1::Sha1;

/// How many octets one compression block holds.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_sha1_block_size() -> usize {
    crate::helpers::sha1::BLOCK_SIZE
}

/// How many octets a digest is.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_sha1_digest_size() -> usize {
    crate::helpers::sha1::DIGEST_SIZE
}

/// The five words the state starts at. Always five words.
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_sha1_initial_state() -> *const u32 {
    crate::helpers::sha1::INITIAL_STATE.as_ptr()
}

/// The four round constants. Always four words.
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_sha1_constants() -> *const u32 {
    crate::helpers::sha1::CONSTANTS.as_ptr()
}

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

/// Builds a [`Sha1`] with nothing fed in yet.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_sha1_new() -> *mut Sha1 {
    Box::into_raw(Box::new(Sha1::new()))
}

/// Releases a [`Sha1`].
///
/// # Safety
///
/// `hash` must come from [`soyokaze_sha1_new`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_sha1_free(hash: *mut Sha1) {
    if !hash.is_null() {
        drop(unsafe { Box::from_raw(hash) });
    }
}

/// Feeds octets in, returning whether the arguments were usable.
///
/// # Safety
///
/// `hash` must either be null or be a handle that has not been freed, and
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_sha1_update(hash: *mut Sha1, data: *const u8, data_len: usize) -> bool {
    let (Some(hash), Some(data)) = (unsafe { hash.as_mut() }, unsafe { Slice::borrow(data, data_len) }) else {
        return false;
    };

    hash.update(data);
    true
}

/// Runs one compression block through the state.
///
/// The block must be exactly [`soyokaze_sha1_block_size`] octets. This moves
/// the state on without counting the octets towards the length the padding
/// carries, so a caller driving the hash by hand counts them itself; feeding
/// the same octets through [`soyokaze_sha1_update`] is what an ordinary caller
/// wants.
///
/// # Safety
///
/// `hash` must either be null or be a handle that has not been freed, and
/// `block` must either be null or point to `block_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_sha1_compress(hash: *mut Sha1, block: *const u8, block_len: usize) -> bool {
    let (Some(hash), Some(block)) = (unsafe { hash.as_mut() }, unsafe { Slice::borrow(block, block_len) }) else {
        return false;
    };

    let Ok(block) = <&[u8; crate::helpers::sha1::BLOCK_SIZE]>::try_from(block) else {
        return false;
    };

    hash.compress(block);
    true
}

/// Finishes the hash and releases it, writing the digest through `out`.
///
/// Consumes `hash`, which must not be freed afterwards. The digest is always
/// 20 octets, owned by the caller.
///
/// # Safety
///
/// `hash` must come from [`soyokaze_sha1_new`] and not have been freed, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_sha1_finish(hash: *mut Sha1, out: *mut Buffer) -> bool {
    if hash.is_null() {
        return false;
    }

    let digest = unsafe { Box::from_raw(hash) }.finish();

    if !out.is_null() {
        unsafe { *out = Buffer::new(digest.to_vec()) };
    }

    true
}
