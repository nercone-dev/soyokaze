//! A C ABI over the crate, for callers outside Rust.
//!
//! Every symbol here is `extern "C"` and prefixed `soyokaze_`, and the shared
//! library the crate builds as (`libsoyokaze.so`, `libsoyokaze.dylib`,
//! `soyokaze.dll`) exports exactly this surface. The C declarations live in
//! `include/soyokaze.h`.
//!
//! # Layout
//!
//! The modules mirror the crate they wrap: [`errors`] carries [`Error`] across
//! the boundary, [`models`] carries [`Url`] and [`Message`], and [`client`] and
//! [`server`] are the two entry points. What every module shares lives here —
//! the [`Slice`] and [`Buffer`] octet views, and the [`Runtime`] that turns the
//! crate's async surface into blocking calls.
//!
//! [`Error`]: crate::errors::Error
//! [`Url`]: crate::models::Url
//! [`Message`]: crate::models::Message
//!
//! # Conventions
//!
//! - A fallible call returns a [`Status`] and writes its result through an out
//!   parameter. Passing a non-null `error` out parameter takes ownership of an
//!   [`Error`] handle describing the failure, which the caller frees with
//!   `soyokaze_error_free`.
//! - Text and octets go in as a pointer and a length, never as a NUL-terminated
//!   string, so a value may hold a NUL and need not be copied to be passed.
//! - Text and octets come back either as a [`Slice`], borrowed from a handle and
//!   valid until that handle is freed or modified, or as a [`Buffer`], owned by
//!   the caller and freed with `soyokaze_buffer_free`.
//! - A handle is freed exactly once, with the `_free` call that matches the
//!   `_new`, `_parse` or `_request` call that produced it. A call documented as
//!   consuming a handle frees it itself, and the caller must not.
//! - A null handle is treated as absent wherever that is meaningful, and is
//!   never dereferenced.

pub mod errors;
pub mod models;
pub mod client;
pub mod server;

pub use errors::Status;

/// A borrowed view of octets.
///
/// Points into whichever handle produced it and stays valid until that handle
/// is freed or modified. A `data` of null means the value was absent, which is
/// how a lookup that found nothing is told apart from one that found an empty
/// value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Slice {
    /// The first octet, or null when the value is absent.
    pub data: *const u8,
    /// How many octets there are.
    pub len: usize,
}

impl Slice {
    /// The slice that stands for an absent value.
    pub const ABSENT: Self = Self { data: std::ptr::null(), len: 0 };

    /// A view of `octets`.
    pub fn new(octets: &[u8]) -> Self {
        Self { data: octets.as_ptr(), len: octets.len() }
    }

    /// A view of `text`.
    pub fn text(text: &str) -> Self {
        Self::new(text.as_bytes())
    }

    /// A view of `text`, or [`Slice::ABSENT`] when there is none.
    pub fn maybe(text: Option<&str>) -> Self {
        match text {
            Some(text) => Self::text(text),
            None => Self::ABSENT,
        }
    }

    /// Whether the value was absent.
    pub fn is_absent(&self) -> bool {
        self.data.is_null()
    }
}

/// Octets owned by the caller.
///
/// Freed with [`soyokaze_buffer_free`]. `capacity` is what the allocation was
/// made with and has to be handed back untouched for the memory to be released.
#[repr(C)]
pub struct Buffer {
    /// The first octet, or null when the buffer is empty.
    pub data: *mut u8,
    /// How many octets there are.
    pub len: usize,
    /// How many octets were allocated.
    pub capacity: usize,
}

impl Buffer {
    /// An empty buffer, which needs no freeing but may be freed anyway.
    pub const EMPTY: Self = Self { data: std::ptr::null_mut(), len: 0, capacity: 0 };

    /// Hands `octets` to the caller.
    pub fn new(octets: Vec<u8>) -> Self {
        let mut octets = std::mem::ManuallyDrop::new(octets);
        Self { data: octets.as_mut_ptr(), len: octets.len(), capacity: octets.capacity() }
    }
}

/// Releases a [`Buffer`].
///
/// A buffer that was already freed, or that never held anything, must not be
/// passed twice; an empty buffer is safe to pass.
///
/// # Safety
///
/// `buffer` must be one this library produced and has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_buffer_free(buffer: Buffer) {
    if !buffer.data.is_null() {
        drop(unsafe { Vec::from_raw_parts(buffer.data, buffer.len, buffer.capacity) });
    }
}

/// The crate's version, as `MAJOR.MINOR.PATCH`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_version() -> Slice {
    Slice::text(env!("CARGO_PKG_VERSION"))
}

/// Borrows `len` octets from `data`.
///
/// A null `data` borrows nothing, which is how an absent argument is passed.
///
/// # Safety
///
/// `data` must either be null or point to `len` readable octets that outlive
/// the returned slice.
pub unsafe fn borrow<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        return None;
    }

    Some(unsafe { std::slice::from_raw_parts(data, len) })
}

/// Borrows `len` octets from `data` as UTF-8.
///
/// Returns `None` when the argument is absent or is not UTF-8, which callers
/// report as [`Status::Invalid`].
///
/// # Safety
///
/// As [`borrow`].
pub unsafe fn borrow_text<'a>(data: *const u8, len: usize) -> Option<&'a str> {
    std::str::from_utf8(unsafe { borrow(data, len) }?).ok()
}

/// The runtime the blocking calls in this module drive.
///
/// The crate's own surface is async; every FFI call that has to wait runs on
/// one of these. It is multi-threaded, so work a call leaves running — the
/// accept loops [`server::soyokaze_server_serve`] starts, most of all — keeps
/// running after that call returns.
pub struct Runtime(pub tokio::runtime::Runtime);

/// Builds a [`Runtime`] with `workers` threads, or one thread per core when
/// `workers` is zero.
///
/// Returns null when the runtime cannot be built.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_runtime_new(workers: u32) -> *mut Runtime {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    if workers > 0 {
        builder.worker_threads(workers as usize);
    }

    match builder.build() {
        Ok(runtime) => Box::into_raw(Box::new(Runtime(runtime))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Releases a [`Runtime`], waiting for the work still on it to finish.
///
/// # Safety
///
/// `runtime` must come from [`soyokaze_runtime_new`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_runtime_free(runtime: *mut Runtime) {
    if !runtime.is_null() {
        drop(unsafe { Box::from_raw(runtime) });
    }
}
