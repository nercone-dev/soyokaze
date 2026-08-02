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
use crate::ffi::{borrow, borrow_text, Buffer};
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

/// Which end of the connection this is: `0` when this end is a client and
/// masks its frames, `1` when it is a server.
///
/// # Safety
///
/// `socket` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_websocket_role(socket: *const WebSocket) -> u32 {
    match unsafe { socket.as_ref() } {
        Some(socket) if socket.connection.role().is_client() => 0,
        _ => 1,
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

    let payload = unsafe { borrow(payload, payload_len) }.unwrap_or_default().to_vec();
    let frame = Frame { fin, opcode, mask: None, payload };

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
            unsafe { *out = Buffer::new(frame.payload) };
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

    let reason = unsafe { borrow_text(reason, reason_len) }.unwrap_or_default();
    socket.handle.clone().block_on(socket.connection.close(code, reason));
    true
}
