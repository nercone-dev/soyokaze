//! The seam QUIC is consumed through, from C.
//!
//! What HTTP/3 needs of QUIC and nothing more: the variable-length integer
//! every HTTP/3 and QPACK field is written as, how stream identifiers are
//! numbered, and what a completed handshake settled on. The transport itself
//! is driven by the crate, so nothing here opens a connection.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Slice};
use crate::models::{Role, Version};
use crate::protocol::quic::{QUICStreamID, Varint};

/// The largest value a QUIC variable-length integer can hold.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_varint_maximum() -> u64 {
    Varint::MAXIMUM
}

/// The most octets a QUIC variable-length integer takes.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_varint_max_size() -> usize {
    Varint::MAX_SIZE
}

/// How many octets a value takes when it is written out.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_varint_len(value: u64) -> usize {
    Varint::len(value)
}

/// Encodes a variable-length integer, owned by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_varint_encode(value: u64) -> Buffer {
    let mut out = Vec::with_capacity(Varint::len(value));
    Varint::encode(&mut out, value);
    Buffer::new(out)
}

/// Decodes a variable-length integer, writing the value through `out` and how
/// many octets it took through `read`.
///
/// Returns whether a whole integer was there. A truncated one reads nothing
/// and takes no octets.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` and `read` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_varint_decode(data: *const u8, data_len: usize, out: *mut u64, read: *mut usize) -> bool {
    let data = unsafe { Slice::borrow(data, data_len) }.unwrap_or_default();
    let (consumed, value) = Varint::decode(data);

    if consumed == 0 {
        return false;
    }

    if !out.is_null() {
        unsafe { *out = value };
    }

    if !read.is_null() {
        unsafe { *read = consumed };
    }

    true
}

/// Reads a payload that must be exactly one variable-length integer.
///
/// `name` is what the failure calls the frame, so a caller reads which frame
/// was malformed rather than that one was.
///
/// # Safety
///
/// `payload` and `name` must either be null or point to their stated number of
/// readable octets, and `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_varint_only(payload: *const u8, payload_len: usize, name: *const u8, name_len: usize, out: *mut u64, error: *mut *mut ErrorHandle) -> Status {
    let Some(name) = (unsafe { Slice::borrow_text(name, name_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let payload = unsafe { Slice::borrow(payload, payload_len) }.unwrap_or_default();

    match Varint::only(payload, name) {
        Ok(value) => {
            if !out.is_null() {
                unsafe { *out = value };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// How far apart two stream identifiers of the same kind are.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_quic_stream_step() -> u64 {
    QUICStreamID::STEP
}

/// Whether a stream identifier names a bidirectional stream.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_quic_stream_is_bidi(stream_id: u64) -> bool {
    QUICStreamID::is_bidi(stream_id)
}

/// Whether a stream identifier names a unidirectional stream.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_quic_stream_is_uni(stream_id: u64) -> bool {
    QUICStreamID::is_uni(stream_id)
}

/// Whether a stream identifier names one the client opened.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_quic_stream_client_initiated(stream_id: u64) -> bool {
    QUICStreamID::client_initiated(stream_id)
}

/// The first bidirectional stream a role may open.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_quic_stream_first_bidi(role: Role) -> u64 {
    QUICStreamID::first_bidi(role)
}

/// The first unidirectional stream a role may open.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_quic_stream_first_uni(role: Role) -> u64 {
    QUICStreamID::first_uni(role)
}

/// The version a QUIC handshake's ALPN identifier settles on.
///
/// A null `alpn` stands for a handshake that agreed on nothing, which over
/// QUIC is always a failure: there is no version to fall back to.
///
/// # Safety
///
/// `alpn` must either be null or point to `alpn_len` readable octets,
/// `versions` must either be null or point to `count` readable versions, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_quic_handshake_negotiated(alpn: *const u8, alpn_len: usize, versions: *const Version, count: usize, out: *mut Version, error: *mut *mut ErrorHandle) -> Status {
    let Some(versions) = (unsafe { Version::borrow_all(versions, count) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let alpn = unsafe { Slice::borrow(alpn, alpn_len) }.unwrap_or_default().to_vec();
    let handshake = crate::protocol::quic::Handshake { alpn, version: 0 };

    match handshake.negotiated(versions) {
        Ok(version) => {
            if !out.is_null() {
                unsafe { *out = version };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// What a completed QUIC handshake reports as its security.
///
/// QUIC always carries TLS 1.3, but the QUIC stack does not hand its session
/// out, so the cipher suite and group are left unsettled.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_quic_handshake_security(quic_version: u32) -> crate::ffi::tls::Security {
    let handshake = crate::protocol::quic::Handshake { alpn: Vec::new(), version: quic_version };
    crate::ffi::tls::Security::build(&handshake.security())
}
