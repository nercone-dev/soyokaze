//! The WebSocket protocol, from C.
//!
//! A [`WebSocket`] comes out of `soyokaze_client_websocket`,
//! `soyokaze_connection_open_websocket`, or the `on_websocket` callback a
//! server was given, and is driven the same way whichever side produced it —
//! the same symmetry [`crate::websocket`] keeps.
//!
//! Unlike the other blocking calls in this ABI, these take no runtime
//! argument: the handle carries its runtime with it, because the server-side
//! callback runs on a thread that must not block the runtime it was born on.
//! Opcodes and close codes cross as their wire numbers.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Slice};
use crate::models::Role;
use crate::protocol::base::Transport;
use crate::websocket::{CloseCode, Frame, Opcode, WebSocketConnection};

/// A WebSocket connection, over whichever transport its HTTP version left it.
///
/// Carries the runtime handle its blocking calls are driven on.
pub struct WebSocket {
    /// The connection itself.
    pub connection: WebSocketConnection<Box<dyn Transport>>,
    /// The runtime the connection's I/O runs on.
    pub handle: tokio::runtime::Handle,
}

/// Releases a [`WebSocket`], dropping the transport as it stands.
///
/// Call [`soyokaze_websocket_close`] first to run the closing handshake; a
/// freed connection simply vanishes from the peer's point of view.
///
/// # Safety
///
/// `socket` must be a handle the caller owns and has not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_free(socket: *mut WebSocket) {
    if !socket.is_null() {
        drop(unsafe { Box::from_raw(socket) });
    }
}

/// What this end of the connection is doing on it, as a `soyokaze_role_t`.
///
/// A client role masks its frames and a server role does not, which is the
/// difference that matters here. A null `socket` reads as
/// [`Role::UserAgent`].
///
/// # Safety
///
/// `socket` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_role(socket: *const WebSocket) -> u32 {
    match unsafe { socket.as_ref() } {
        Some(socket) => Role::build(socket.connection.role()),
        None => Role::build(Role::UserAgent),
    }
}

/// Whether the closing handshake has begun.
///
/// # Safety
///
/// As [`soyokaze_websocket_role`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_closing(socket: *const WebSocket) -> bool {
    unsafe { socket.as_ref() }.is_some_and(|socket| socket.connection.closing())
}

/// The identifier of the connection this came from, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_websocket_role`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_id(socket: *const WebSocket) -> Buffer {
    match unsafe { socket.as_ref() } {
        Some(socket) => Buffer::new(socket.connection.id().0.to_vec()),
        None => Buffer::EMPTY,
    }
}

/// Sends one frame.
///
/// `opcode` is the wire number: `0x0` continuation, `0x1` text, `0x2` binary,
/// `0x8` close, `0x9` ping, `0xa` pong. The mask is set from the role, so the
/// caller never supplies one.
///
/// # Safety
///
/// `socket` must be a handle that has not been freed, and `payload` must
/// either be null or point to `payload_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_send(socket: *mut WebSocket, fin: bool, opcode: u8, payload: *const u8, payload_len: usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(socket) = (unsafe { socket.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let Some(opcode) = Opcode::from_code(opcode) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    let payload = unsafe { Slice::borrow(payload, payload_len) }.unwrap_or_default().to_vec();
    let frame = Frame { fin, opcode, mask: None, payload: payload.into() };

    match socket.handle.clone().block_on(socket.connection.send(frame)) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Receives one frame, without reassembling or answering anything.
///
/// Writes the frame's payload through `out`, its opcode through `opcode`, and
/// whether it ends its message through `fin`; `opcode` and `fin` may each be
/// null when the caller does not care.
///
/// # Safety
///
/// `socket` must be a handle that has not been freed, `out` must be writable,
/// and `fin` and `opcode` must each either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_receive(socket: *mut WebSocket, fin: *mut bool, opcode: *mut u8, out: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let Some(socket) = (unsafe { socket.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match socket.handle.clone().block_on(socket.connection.receive()) {
        Ok(frame) => {
            if !fin.is_null() {
                unsafe { *fin = frame.fin };
            }
            if !opcode.is_null() {
                unsafe { *opcode = frame.opcode.code() };
            }
            unsafe { *out = Buffer::new(frame.payload.to_vec()) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Sends a whole message as one unfragmented frame.
///
/// # Safety
///
/// As [`soyokaze_websocket_send`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_send_message(socket: *mut WebSocket, opcode: u8, payload: *const u8, payload_len: usize, error: *mut *mut ErrorHandle) -> Status {
    unsafe { soyokaze_websocket_send(socket, true, opcode, payload, payload_len, error) }
}

/// Receives one whole message, reassembling fragments.
///
/// Control frames are dealt with along the way: a ping is answered with a
/// pong, and a close is echoed back and then returned with an opcode of
/// `0x8`, so the caller knows the connection is finishing.
///
/// # Safety
///
/// As [`soyokaze_websocket_receive`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_receive_message(socket: *mut WebSocket, opcode: *mut u8, out: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let Some(socket) = (unsafe { socket.as_mut() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match socket.handle.clone().block_on(socket.connection.receive_message()) {
        Ok((received, payload)) => {
            if !opcode.is_null() {
                unsafe { *opcode = received.code() };
            }
            unsafe { *out = Buffer::new(payload.to_vec()) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Closes the connection, running the closing handshake.
///
/// `code` is the wire number of one of the defined close codes — 1000, 1001,
/// 1002, 1003, 1007, 1008, 1009, 1010 or 1011 — and any other number is
/// refused. The handle is left to be freed with [`soyokaze_websocket_free`].
///
/// # Safety
///
/// `socket` must be a handle that has not been freed, and `reason` must
/// either be null or point to `reason_len` readable octets of UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_close(socket: *mut WebSocket, code: u16, reason: *const u8, reason_len: usize) -> bool {
    let Some(socket) = (unsafe { socket.as_mut() }) else {
        return false;
    };

    let Some(code) = CloseCode::from_code(code) else {
        return false;
    };

    let reason = unsafe { Slice::borrow_text(reason, reason_len) }.unwrap_or_default();
    socket.handle.clone().block_on(socket.connection.close(code, reason));
    true
}

/// The fixed string a `Sec-WebSocket-Accept` is derived with, borrowed from
/// the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_guid() -> Slice {
    Slice::text(crate::websocket::GUID)
}

/// The one protocol version this library speaks, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_version() -> Slice {
    Slice::text(crate::websocket::VERSION)
}

/// The token an upgrade names the protocol by, borrowed from the library.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_protocol() -> Slice {
    Slice::text(crate::websocket::PROTOCOL)
}

/// How large a control frame's payload may be.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_maximum_control_payload() -> usize {
    crate::websocket::MAXIMUM_CONTROL_PAYLOAD
}

/// Whether an opcode names a frame at all.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_opcode_known(opcode: u8) -> bool {
    Opcode::from_code(opcode).is_some()
}

/// Whether an opcode names a control frame, which is never fragmented.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_opcode_control(opcode: u8) -> bool {
    Opcode::from_code(opcode).is_some_and(|opcode| opcode.control())
}

/// Whether a close code names one this library knows.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_close_code_known(code: u16) -> bool {
    CloseCode::from_code(code).is_some()
}

/// Whether a close code may be sent on the wire.
///
/// The codes reserved for local use — a connection that closed without one,
/// and a TLS failure — are refused, as are codes outside the ranges the
/// protocol sets aside.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_close_code_permitted(code: u16) -> bool {
    CloseCode::permitted(code)
}

/// Fills `out` with cryptographically secure random octets.
///
/// Masking keys and handshake nonces both come from here. Returns whether a
/// source of randomness was reachable.
///
/// # Safety
///
/// `out` must either be null or point to `out_len` writable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_random(out: *mut u8, out_len: usize) -> bool {
    if out.is_null() {
        return false;
    }

    Frame::random(unsafe { std::slice::from_raw_parts_mut(out, out_len) }).is_ok()
}

/// A fresh masking key: four unpredictable octets, owned by the caller.
///
/// An empty buffer with a null pointer means no randomness was reachable.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_masking_key() -> Buffer {
    match Frame::masking_key() {
        Ok(key) => Buffer::new(key.to_vec()),
        Err(_) => Buffer::EMPTY,
    }
}

/// Applies a masking key to a payload in place, which also removes one.
///
/// # Safety
///
/// `mask` must point to four readable octets, and `payload` must either be
/// null or point to `payload_len` writable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_apply_mask(mask: *const u8, payload: *mut u8, payload_len: usize) -> bool {
    let Some(mask) = (unsafe { Slice::borrow(mask, 4) }) else {
        return false;
    };

    let Ok(mask) = <[u8; 4]>::try_from(mask) else {
        return false;
    };

    if payload.is_null() {
        return false;
    }

    Frame::apply_mask(mask, unsafe { std::slice::from_raw_parts_mut(payload, payload_len) });
    true
}

/// The head of a frame, as it sits on the wire.
///
/// The C half of [`FrameHead`], with `masked` standing for the mask being
/// present and `mask` carrying it when it is.
///
/// [`FrameHead`]: crate::websocket::FrameHead
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FrameHead {
    /// Whether this frame ends its message.
    pub fin: bool,
    /// What the frame is, as its wire number.
    pub opcode: u8,
    /// Whether a masking key is present.
    pub masked: bool,
    /// The masking key, meaningful only when `masked` is set.
    pub mask: [u8; 4],
    /// Where the payload starts, counted from the front of the frame.
    pub start: usize,
    /// How long the payload is.
    pub length: usize,
}

/// Reads the head of a frame, writing it through `out`.
///
/// Returns [`Status::Ok`] when a whole head was there, [`Status::Closed`] when
/// more octets are needed, and a protocol failure when the head is malformed.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_frame_head(data: *const u8, data_len: usize, out: *mut FrameHead, error: *mut *mut ErrorHandle) -> Status {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match crate::websocket::FrameHead::decode(data) {
        Ok(Some(head)) => {
            if !out.is_null() {
                unsafe {
                    *out = FrameHead {
                        fin: head.fin,
                        opcode: head.opcode.code(),
                        masked: head.mask.is_some(),
                        mask: head.mask.unwrap_or([0; 4]),
                        start: head.start,
                        length: head.length,
                    }
                };
            }

            Status::Ok
        }
        Ok(None) => Status::Closed,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Encodes one frame, owned by the caller.
///
/// A null `mask` writes an unmasked frame, which is what a server sends; a
/// client's frames must carry one.
///
/// # Safety
///
/// `payload` must either be null or point to `payload_len` readable octets,
/// and `mask` must either be null or point to four readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_frame_encode(fin: bool, opcode: u8, mask: *const u8, payload: *const u8, payload_len: usize) -> Buffer {
    let Some(opcode) = Opcode::from_code(opcode) else {
        return Buffer::EMPTY;
    };

    let mask = match unsafe { Slice::borrow(mask, 4) } {
        Some(mask) => match <[u8; 4]>::try_from(mask) {
            Ok(mask) => Some(mask),
            Err(_) => return Buffer::EMPTY,
        },
        None => None,
    };

    let payload = unsafe { Slice::borrow(payload, payload_len) }.unwrap_or_default();
    let frame = Frame { fin, opcode, mask, payload: bytes::Bytes::copy_from_slice(payload) };

    Buffer::new(frame.encode())
}

/// Decodes one frame, writing its head through `out` and its unmasked payload
/// through `payload`.
///
/// Returns [`Status::Ok`] when a whole frame was there, [`Status::Closed`]
/// when more octets are needed, and a protocol failure when the frame is
/// malformed. `out`'s `start` is where the payload began and `length` how long
/// it was; the octets themselves come back in `payload`, owned by the caller.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out`, `payload` and `read` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_frame_decode(data: *const u8, data_len: usize, out: *mut FrameHead, payload: *mut Buffer, read: *mut usize, error: *mut *mut ErrorHandle) -> Status {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Frame::decode(data) {
        Ok(Some((consumed, frame))) => {
            if !out.is_null() {
                unsafe {
                    *out = FrameHead {
                        fin: frame.fin,
                        opcode: frame.opcode.code(),
                        masked: frame.mask.is_some(),
                        mask: frame.mask.unwrap_or([0; 4]),
                        start: consumed - frame.payload.len(),
                        length: frame.payload.len(),
                    }
                };
            }

            if !payload.is_null() {
                unsafe { *payload = Buffer::new(frame.payload.to_vec()) };
            }

            if !read.is_null() {
                unsafe { *read = consumed };
            }

            Status::Ok
        }
        Ok(None) => Status::Closed,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`, owned
/// by the caller.
///
/// This is not a security mechanism — it only shows the peer read the request
/// and is speaking WebSocket rather than something that stumbled onto the
/// port.
///
/// # Safety
///
/// `key` must either be null or point to `key_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_accept_key(key: *const u8, key_len: usize) -> Buffer {
    match unsafe { Slice::borrow_text(key, key_len) } {
        Some(key) => Buffer::new(crate::websocket::Upgrade::accept_key(key).into_bytes()),
        None => Buffer::EMPTY,
    }
}

/// A fresh `Sec-WebSocket-Key`, owned by the caller.
///
/// Sixteen unpredictable octets, base64 encoded. An empty buffer with a null
/// pointer means no randomness was reachable.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_nonce() -> Buffer {
    match crate::websocket::Upgrade::nonce() {
        Ok(nonce) => Buffer::new(nonce.into_bytes()),
        Err(_) => Buffer::EMPTY,
    }
}

/// The HTTP/1.1 upgrade request that opens a WebSocket.
///
/// # Safety
///
/// `host`, `target` and `key` must point to their stated number of readable
/// octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_upgrade_request(host: *const u8, host_len: usize, target: *const u8, target_len: usize, key: *const u8, key_len: usize, version: i32) -> *mut crate::models::Message {
    let (Some(host), Some(target), Some(key)) = (unsafe { Slice::borrow_text(host, host_len) }, unsafe { Slice::borrow_text(target, target_len) }, unsafe { Slice::borrow_text(key, key_len) }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(crate::websocket::Upgrade::request(host, target, key, crate::models::Version::of(version))))
}

/// The `101 Switching Protocols` that accepts an upgrade.
///
/// # Safety
///
/// `key` must point to `key_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_upgrade_response(key: *const u8, key_len: usize, version: i32) -> *mut crate::models::Message {
    let Some(key) = (unsafe { Slice::borrow_text(key, key_len) }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(crate::websocket::Upgrade::response(key, crate::models::Version::of(version))))
}

/// Checks an upgrade request, handing back the key it carried.
///
/// The key comes back through `key`, owned by the caller.
///
/// # Safety
///
/// `request` must either be null or be a handle that has not been freed, and
/// `key` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_verify_upgrade_request(request: *const crate::models::Message, key: *mut Buffer, error: *mut *mut ErrorHandle) -> Status {
    let Some(request) = (unsafe { request.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match crate::websocket::Upgrade::verify_request(request) {
        Ok(accepted) => {
            if !key.is_null() {
                unsafe { *key = Buffer::new(accepted.into_bytes()) };
            }

            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Checks the response to an upgrade request against the key that was sent.
///
/// # Safety
///
/// `response` must either be null or be a handle that has not been freed, and
/// `key` must point to `key_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_verify_upgrade_response(response: *const crate::models::Message, key: *const u8, key_len: usize, error: *mut *mut ErrorHandle) -> Status {
    let (Some(response), Some(key)) = (unsafe { response.as_ref() }, unsafe { Slice::borrow_text(key, key_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match crate::websocket::Upgrade::verify_response(response, key) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The extended CONNECT request that opens a WebSocket over HTTP/2 or HTTP/3.
///
/// # Safety
///
/// `authority` and `target` must point to their stated number of readable
/// octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_connect_request(authority: *const u8, authority_len: usize, target: *const u8, target_len: usize, version: i32) -> *mut crate::models::Message {
    let (Some(authority), Some(target)) = (unsafe { Slice::borrow_text(authority, authority_len) }, unsafe { Slice::borrow_text(target, target_len) }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(crate::websocket::Connect::request(authority, target, crate::models::Version::of(version))))
}

/// The `200 OK` that accepts an extended CONNECT.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_connect_response(version: i32) -> *mut crate::models::Message {
    Box::into_raw(Box::new(crate::websocket::Connect::response(crate::models::Version::of(version))))
}

/// Checks an extended CONNECT request.
///
/// # Safety
///
/// `request` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_verify_connect_request(request: *const crate::models::Message, error: *mut *mut ErrorHandle) -> Status {
    let Some(request) = (unsafe { request.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match crate::websocket::Connect::verify_request(request) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Checks the response to an extended CONNECT.
///
/// # Safety
///
/// `response` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_verify_connect_response(response: *const crate::models::Message, error: *mut *mut ErrorHandle) -> Status {
    let Some(response) = (unsafe { response.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match crate::websocket::Connect::verify_response(response) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Whether a request is asking to open a WebSocket at all.
///
/// True for both shapes the handshake takes: the HTTP/1.1 upgrade and the
/// extended CONNECT above it.
///
/// # Safety
///
/// `request` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_requested(request: *const crate::models::Message) -> bool {
    unsafe { request.as_ref() }.is_some_and(crate::websocket::Handshake::requested)
}

/// Checks a handshake request, whichever shape it takes.
///
/// # Safety
///
/// As [`soyokaze_websocket_requested`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_verify(request: *const crate::models::Message, error: *mut *mut ErrorHandle) -> Status {
    let Some(request) = (unsafe { request.as_ref() }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match crate::websocket::Handshake::verify(request) {
        Ok(()) => Status::Ok,
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// The response that turns a handshake away.
///
/// # Safety
///
/// As [`soyokaze_websocket_requested`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_refusal(request: *const crate::models::Message, version: i32) -> *mut crate::models::Message {
    let Some(request) = (unsafe { request.as_ref() }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(crate::websocket::Handshake::refusal(request, crate::models::Version::of(version))))
}

/// Whether a comma-separated field carries a token, matched
/// case-insensitively.
///
/// # Safety
///
/// `headers` must either be null or be a section that has not been freed, and
/// `name` and `token` must point to their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_token_present(headers: *const crate::models::Headers, name: *const u8, name_len: usize, token: *const u8, token_len: usize) -> bool {
    let (Some(headers), Some(name), Some(token)) = (unsafe { headers.as_ref() }, unsafe { Slice::borrow_text(name, name_len) }, unsafe { Slice::borrow_text(token, token_len) }) else {
        return false;
    };

    crate::websocket::Handshake::token_present(headers, name, token)
}

/// What one WebSocket connection may spend on the peer's behalf.
///
/// The C half of [`WebSocketLimits`], field for field. Derived from a
/// [`Limits`] when a connection is built, so a caller sets these through that
/// rather than here.
///
/// [`WebSocketLimits`]: crate::websocket::WebSocketLimits
/// [`Limits`]: crate::ffi::models::Limits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WebSocketLimits {
    /// How large one reassembled message may grow.
    pub max_message_size: u64,
    /// How many fragments one message may arrive in.
    pub ws_max_fragments: u16,
    /// How long to wait for the peer's close frame after sending one.
    pub ws_linger_timeout: f64,
    /// How long one read may take.
    pub read_timeout: f64,
    /// How long one write may take.
    pub write_timeout: f64,
    /// How many octets one read asks the transport for.
    pub read_chunk_size: u64,
    /// How much of a drained buffer is kept for reuse.
    pub idle_capacity: u64,
}

impl WebSocketLimits {
    /// The C half of `limits`.
    pub fn build(limits: &crate::websocket::WebSocketLimits) -> Self {
        Self {
            max_message_size: limits.max_message_size,
            ws_max_fragments: limits.ws_max_fragments,
            ws_linger_timeout: limits.ws_linger_timeout,
            read_timeout: limits.read_timeout,
            write_timeout: limits.write_timeout,
            read_chunk_size: limits.read_chunk_size,
            idle_capacity: limits.idle_capacity,
        }
    }
}

/// The limits a WebSocket connection takes when nothing narrows them.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_websocket_limits_default() -> WebSocketLimits {
    WebSocketLimits::build(&crate::websocket::WebSocketLimits::default())
}

/// The limits a [`Limits`] narrows a WebSocket connection to.
///
/// # Safety
///
/// `limits` must either be null or point to a readable [`Limits`].
///
/// [`Limits`]: crate::ffi::models::Limits
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_limits_of(limits: *const crate::ffi::models::Limits) -> WebSocketLimits {
    WebSocketLimits::build(&crate::websocket::WebSocketLimits::from(unsafe { crate::ffi::models::Limits::or_default(limits) }))
}

/// The limits this connection is running under.
///
/// # Safety
///
/// `socket` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_limits(socket: *const WebSocket) -> WebSocketLimits {
    match unsafe { socket.as_ref() } {
        Some(socket) => WebSocketLimits::build(&socket.connection.limits()),
        None => WebSocketLimits::build(&crate::websocket::WebSocketLimits::default()),
    }
}
