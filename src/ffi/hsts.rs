//! HTTP Strict Transport Security, from C.
//!
//! [`HSTSPolicy`] is the `Strict-Transport-Security` field itself, crossing
//! by value since it is three plain fields, and [`HSTSStore`] is the
//! client-side memory of which hosts insist on TLS — the same two halves as
//! [`crate::hsts`]. The store reads the clock itself, so the caller
//! never passes a timestamp.

use std::time::Instant;

use crate::ffi::models::Limits;
use crate::ffi::{Buffer, Slice};
use crate::hsts::HSTSStore;

/// One `Strict-Transport-Security` policy.
///
/// The C half of [`HSTSPolicy`], field for field.
///
/// [`HSTSPolicy`]: crate::hsts::HSTSPolicy
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HSTSPolicy {
    /// How many seconds the policy holds for. Zero withdraws it.
    pub max_age: i64,
    /// Whether the policy covers subdomains as well as the host itself.
    pub include_subdomains: bool,
    /// Whether the host asks to be added to browser preload lists.
    pub preload: bool,
}

impl HSTSPolicy {
    /// The [`HSTSPolicy`] this stands for.
    ///
    /// [`HSTSPolicy`]: crate::hsts::HSTSPolicy
    pub fn parse(&self) -> crate::hsts::HSTSPolicy {
        crate::hsts::HSTSPolicy {
            max_age: self.max_age,
            include_subdomains: self.include_subdomains,
            preload: self.preload,
        }
    }

    /// The C half of `policy`.
    pub fn build(policy: &crate::hsts::HSTSPolicy) -> Self {
        Self {
            max_age: policy.max_age,
            include_subdomains: policy.include_subdomains,
            preload: policy.preload,
        }
    }
}

/// Reads a `Strict-Transport-Security` field value through `out`, returning
/// whether it parsed.
///
/// Refused when a directive repeats, when `max-age` is missing or malformed,
/// or when the text is null or not UTF-8 — a field that cannot be trusted
/// must not be acted on at all.
///
/// # Safety
///
/// `value` must either be null or point to `value_len` readable octets, and
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hsts_policy_parse(value: *const u8, value_len: usize, out: *mut HSTSPolicy) -> bool {
    if out.is_null() {
        return false;
    }

    let Some(value) = (unsafe { Slice::borrow_text(value, value_len) }) else {
        return false;
    };

    match crate::hsts::HSTSPolicy::parse(value) {
        Some(policy) => {
            unsafe { *out = HSTSPolicy::build(&policy) };
            true
        }
        None => false,
    }
}

/// Writes the policy out as a field value, owned by the caller.
///
/// # Safety
///
/// `policy` must either be null or point to a readable [`HSTSPolicy`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hsts_policy_build(policy: *const HSTSPolicy) -> Buffer {
    match unsafe { policy.as_ref() } {
        Some(policy) => Buffer::new(policy.parse().build().into_bytes()),
        None => Buffer::EMPTY,
    }
}

/// Builds an empty [`HSTSStore`].
///
/// A null `limits` takes every default. The store reads the clock itself, so
/// lifetimes count from the moment a policy is learned.
///
/// # Safety
///
/// `limits` must either be null or point to a readable [`Limits`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hsts_store_new(limits: *const Limits) -> *mut HSTSStore {
    Box::into_raw(Box::new(HSTSStore::new().with_limits(unsafe { Limits::or_default(limits) })))
}

/// Releases an [`HSTSStore`].
///
/// # Safety
///
/// `store` must come from `soyokaze_hsts_store_new` and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hsts_store_free(store: *mut HSTSStore) {
    if !store.is_null() {
        drop(unsafe { Box::from_raw(store) });
    }
}

/// Takes in the `Strict-Transport-Security` field a response carried.
///
/// Ignored outright unless `secure` says the response arrived over a secure
/// transport. Returns whether the arguments were usable at all — an ignored
/// field still returns true.
///
/// # Safety
///
/// `store` must be a handle that has not been freed, and `host` and `header`
/// must point to their stated number of readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hsts_store_learn(store: *const HSTSStore, host: *const u8, host_len: usize, header: *const u8, header_len: usize, secure: bool) -> bool {
    let (Some(store), Some(host), Some(header)) = (unsafe { store.as_ref() }, unsafe { Slice::borrow_text(host, host_len) }, unsafe { Slice::borrow_text(header, header_len) })
    else {
        return false;
    };

    store.learn(host, header, secure, Instant::now());
    true
}

/// Whether `host` must be reached over TLS.
///
/// # Safety
///
/// `store` must either be null or be a handle that has not been freed, and
/// `host` must point to `host_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hsts_store_secure(store: *const HSTSStore, host: *const u8, host_len: usize) -> bool {
    let (Some(store), Some(host)) = (unsafe { store.as_ref() }, unsafe { Slice::borrow_text(host, host_len) }) else {
        return false;
    };

    store.secure(host, Instant::now())
}

/// Drops every entry that has expired.
///
/// # Safety
///
/// `store` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_hsts_store_prune(store: *const HSTSStore) {
    if let Some(store) = unsafe { store.as_ref() } {
        store.prune(Instant::now());
    }
}
