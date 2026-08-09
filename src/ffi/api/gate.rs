//! The server's admission control, from C.
//!
//! A [`Gate`] decides whether one more connection is let in: how many are
//! open, how many one address may hold, and how fast one address may open
//! them. A server builds its own from its [`ServerLimits`], so nothing here
//! needs calling for an ordinary server; it is here for a caller that admits
//! connections itself, and for reading what a running server's gate is doing.
//!
//! An admitted connection hands back a [`Permit`], which releases its place
//! when it is freed. Dropping the permit without freeing it leaks a place in
//! the gate, which is what the count never falling back would look like.
//!
//! [`ServerLimits`]: crate::ffi::api::server::ServerLimits

use std::net::IpAddr;
use std::sync::Arc;

use crate::api::gate::{Gate, Permit};
use crate::ffi::Slice;

/// A gate handle, which several callers may share.
pub struct GateHandle(pub Arc<Gate>);

/// A permit handle, which releases its place in the gate when it is freed.
pub struct PermitHandle(pub Permit);

/// One sliding-window rate limit: `count` connections per `period` seconds.
///
/// The same shape [`ServerLimits`] carries them in.
///
/// [`ServerLimits`]: crate::ffi::api::server::ServerLimits
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rate {
    /// How long the window is, in seconds.
    pub period: f64,
    /// How many connections may be opened within it.
    pub count: u32,
}

/// Builds a [`Gate`].
///
/// A `max_connections` or `max_connections_per_ip` of zero lets any number
/// through, and an empty `rates` rate-limits nothing.
/// `max_connection_history` bounds how many addresses are remembered for
/// rate limiting, so the memory a gate uses stays bounded whatever the peer
/// does.
///
/// # Safety
///
/// `rates` must either be null or point to `rate_count` readable [`Rate`]
/// values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_new(max_connections: u32, max_connections_per_ip: u32, rates: *const Rate, rate_count: usize, max_connection_history: usize) -> *mut GateHandle {
    let mut limits = Vec::with_capacity(rate_count);

    if !rates.is_null() {
        for index in 0..rate_count {
            let rate = unsafe { *rates.add(index) };
            limits.push((rate.period, rate.count));
        }
    }

    Box::into_raw(Box::new(GateHandle(Gate::new(max_connections, max_connections_per_ip, limits, max_connection_history))))
}

/// Releases a [`GateHandle`].
///
/// The gate itself lives on while any permit or server still holds it.
///
/// # Safety
///
/// `gate` must come from [`soyokaze_gate_new`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_free(gate: *mut GateHandle) {
    if !gate.is_null() {
        drop(unsafe { Box::from_raw(gate) });
    }
}

/// How many connections are open through this gate.
///
/// # Safety
///
/// `gate` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_count(gate: *const GateHandle) -> u32 {
    unsafe { gate.as_ref() }.map_or(0, |gate| gate.0.count())
}

/// How many connections may be open at once, or zero for no ceiling.
///
/// # Safety
///
/// As [`soyokaze_gate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_max_connections(gate: *const GateHandle) -> u32 {
    unsafe { gate.as_ref() }.map_or(0, |gate| gate.0.max_connections)
}

/// How many connections one address may hold, or zero for no ceiling.
///
/// # Safety
///
/// As [`soyokaze_gate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_max_connections_per_ip(gate: *const GateHandle) -> u32 {
    unsafe { gate.as_ref() }.map_or(0, |gate| gate.0.max_connections_per_ip)
}

/// How many addresses the gate remembers for rate limiting.
///
/// # Safety
///
/// As [`soyokaze_gate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_max_connection_history(gate: *const GateHandle) -> usize {
    unsafe { gate.as_ref() }.map_or(0, |gate| gate.0.max_connection_history)
}

/// How many rate limits the gate applies.
///
/// # Safety
///
/// As [`soyokaze_gate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_rate_count(gate: *const GateHandle) -> usize {
    unsafe { gate.as_ref() }.map_or(0, |gate| gate.0.max_connection_rate.len())
}

/// The rate limit at `index`.
///
/// An index past the end reads as a period and count of zero.
///
/// # Safety
///
/// As [`soyokaze_gate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_rate(gate: *const GateHandle, index: usize) -> Rate {
    match unsafe { gate.as_ref() }.and_then(|gate| gate.0.max_connection_rate.get(index)) {
        Some(&(period, count)) => Rate { period, count },
        None => Rate { period: 0.0, count: 0 },
    }
}

/// The longest window any rate limit spans, in seconds.
///
/// Nothing older than this matters, which is what bounds the history.
///
/// # Safety
///
/// As [`soyokaze_gate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_window(gate: *const GateHandle) -> f64 {
    unsafe { gate.as_ref() }.map_or(0.0, |gate| gate.0.window())
}

/// How many connections `ip` currently holds.
///
/// A null `ip` counts the connections admitted without an address.
///
/// # Safety
///
/// As [`soyokaze_gate_count`], and `ip` must either be null or point to
/// `ip_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_count_for(gate: *const GateHandle, ip: *const u8, ip_len: usize) -> u32 {
    let (Some(gate), Some(ip)) = (unsafe { gate.as_ref() }, unsafe { address(ip, ip_len) }) else {
        return 0;
    };

    crate::helpers::sync::Lock::on(&gate.0.state).per_ip.get(&ip).copied().unwrap_or(0)
}

/// Reads an address out of its text form.
///
/// # Safety
///
/// `ip` must either be null or point to `ip_len` readable octets.
unsafe fn address(ip: *const u8, ip_len: usize) -> Option<IpAddr> {
    unsafe { Slice::borrow_text(ip, ip_len) }?.parse().ok()
}

/// Admits one more connection, or refuses it.
///
/// Returns a [`PermitHandle`] when the connection is let in, and null when it
/// is turned away. The permit holds a place in the gate until it is freed with
/// [`soyokaze_permit_free`]. A null `ip` admits without an address, which
/// counts against the total but against no per-address ceiling.
///
/// # Safety
///
/// As [`soyokaze_gate_count_for`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_admit(gate: *const GateHandle, ip: *const u8, ip_len: usize) -> *mut PermitHandle {
    let Some(gate) = (unsafe { gate.as_ref() }) else {
        return std::ptr::null_mut();
    };

    match gate.0.admit(unsafe { address(ip, ip_len) }, std::time::Instant::now()) {
        Some(permit) => Box::into_raw(Box::new(PermitHandle(permit))),
        None => std::ptr::null_mut(),
    }
}

/// Drops every address whose history has fallen outside the window.
///
/// # Safety
///
/// As [`soyokaze_gate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_gate_sweep(gate: *const GateHandle) {
    if let Some(gate) = unsafe { gate.as_ref() } {
        gate.0.sweep(std::time::Instant::now());
    }
}

/// Releases a [`PermitHandle`], giving its place back to the gate.
///
/// # Safety
///
/// `permit` must come from [`soyokaze_gate_admit`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_permit_free(permit: *mut PermitHandle) {
    if !permit.is_null() {
        drop(unsafe { Box::from_raw(permit) });
    }
}

/// The address the permit was admitted for, owned by the caller.
///
/// An empty buffer with a null pointer means it was admitted without one.
///
/// # Safety
///
/// `permit` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_permit_address(permit: *const PermitHandle) -> crate::ffi::Buffer {
    match unsafe { permit.as_ref() }.and_then(|permit| permit.0.ip) {
        Some(ip) => crate::ffi::Buffer::new(ip.to_string().into_bytes()),
        None => crate::ffi::Buffer::EMPTY,
    }
}

/// The gate the permit was admitted through, as a handle of its own.
///
/// Freed with [`soyokaze_gate_free`]; the gate itself lives on while the
/// permit does.
///
/// # Safety
///
/// As [`soyokaze_permit_address`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_permit_gate(permit: *const PermitHandle) -> *mut GateHandle {
    match unsafe { permit.as_ref() } {
        Some(permit) => Box::into_raw(Box::new(GateHandle(Arc::clone(&permit.0.gate)))),
        None => std::ptr::null_mut(),
    }
}
