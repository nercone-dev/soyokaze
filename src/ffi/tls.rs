//! TLS identities, context details and Encrypted Client Hello, from C.
//!
//! [`Identity`] is what a server serves, [`TlsConfig`] is how either side's
//! context is tuned, [`EchKeys`] is what a server offers ECH with, and
//! [`EchConfigList`] is what a client reads back out of what a server
//! published — the same parts [`crate::tls`] arranges.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Slice};
use crate::tls::{EchConfigList, EchKeys, Identity};

/// The TLS details a context is built with, beyond its identity and roots.
///
/// The C half of [`TlsConfig`], field for field. Each string is an OpenSSL
/// list, entries separated by `:` and most preferred first; an absent slice
/// keeps that field's default, the way [`TlsConfig::default`] would.
///
/// [`TlsConfig`]: crate::tls::TlsConfig
/// [`TlsConfig::default`]: crate::tls::TlsConfig::default
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsConfig {
    /// The cipher suites to allow, for TLS 1.2 and 1.3 in one list. BoringSSL
    /// keeps its built-in order for the TLS 1.3 suites, so what this
    /// restricts and orders is TLS 1.2.
    pub ciphers: Slice,
    /// The key exchange groups to offer, most preferred first.
    pub groups: Slice,
    /// The signature algorithms to accept, as `ecdsa_secp384r1_sha384` names.
    pub signature_algorithms: Slice,
    /// Whether the server's suite order wins over the client's.
    pub prefer_server_ciphers: bool,
    /// Whether sessions may resume over tickets.
    pub session_tickets: bool,
    /// Whether early data is allowed on a resumed session.
    pub early_data: bool,
    /// Whether certificates are compressed with zlib, as RFC 8879 describes.
    pub certificate_compression: bool,
}

impl TlsConfig {
    /// The [`TlsConfig`] this stands for.
    ///
    /// `None` when a string is not UTF-8.
    ///
    /// [`TlsConfig`]: crate::tls::TlsConfig
    ///
    /// # Safety
    ///
    /// Each slice must either be absent or point to its stated number of
    /// readable octets.
    pub unsafe fn parse(&self) -> Option<crate::tls::TlsConfig> {
        let text = |slice: Slice| match slice.data.is_null() {
            true => Some(None),
            false => unsafe { Slice::borrow_text(slice.data, slice.len) }.map(|text| Some(text.to_owned())),
        };

        Some(crate::tls::TlsConfig {
            ciphers: text(self.ciphers)?,
            groups: text(self.groups)?,
            signature_algorithms: text(self.signature_algorithms)?,
            prefer_server_ciphers: self.prefer_server_ciphers,
            session_tickets: self.session_tickets,
            early_data: self.early_data,
            certificate_compression: self.certificate_compression,
        })
    }
}

/// The default [`TlsConfig`], to be adjusted and passed back.
///
/// [`TlsConfig`]: crate::tls::TlsConfig
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_tls_config_default() -> TlsConfig {
    let config = crate::tls::TlsConfig::default();

    TlsConfig {
        ciphers: Slice::ABSENT,
        groups: Slice::ABSENT,
        signature_algorithms: Slice::ABSENT,
        prefer_server_ciphers: config.prefer_server_ciphers,
        session_tickets: config.session_tickets,
        early_data: config.early_data,
        certificate_compression: config.certificate_compression,
    }
}

/// An identity from a certificate chain and a private key.
///
/// Each chain entry and the key are DER or PEM, so the chain may arrive as one
/// PEM bundle, as one certificate per entry, or as a mixture of the two.
/// Nothing is parsed here; a malformed chain or key surfaces when a context is
/// built from it. Returns null when an argument is null.
///
/// # Safety
///
/// `certificates` must point to `certificate_count` readable slices whose own
/// pointers are valid, and `key` must point to `key_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_identity_new(certificates: *const Slice, certificate_count: usize, key: *const u8, key_len: usize) -> *mut Identity {
    if certificates.is_null() {
        return std::ptr::null_mut();
    }

    let Some(key) = (unsafe { Slice::borrow(key, key_len) }) else {
        return std::ptr::null_mut();
    };

    let mut chain = Vec::with_capacity(certificate_count);
    for index in 0..certificate_count {
        let slice = unsafe { *certificates.add(index) };
        let Some(blob) = (unsafe { Slice::borrow(slice.data, slice.len) }) else {
            return std::ptr::null_mut();
        };
        chain.push(blob.to_vec());
    }

    Box::into_raw(Box::new(Identity::new(chain, key.to_vec())))
}

/// An identity from a PKCS#12 archive, as `.p12` and `.pfx` files carry.
///
/// Pass an empty `passphrase` for an archive protected by none. Everything is
/// parsed here, and kept as DER afterwards, so the passphrase is not retained.
///
/// # Safety
///
/// `data` and `passphrase` must point to their stated number of readable
/// octets, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_identity_from_pkcs12(data: *const u8, data_len: usize, passphrase: *const u8, passphrase_len: usize, out: *mut *mut Identity, error: *mut *mut ErrorHandle) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let (Some(data), Some(passphrase)) = (unsafe { Slice::borrow(data, data_len) }, unsafe { Slice::borrow_text(passphrase, passphrase_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match Identity::from_pkcs12(data, passphrase) {
        Ok(identity) => {
            unsafe { *out = Box::into_raw(Box::new(identity)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Releases an [`Identity`].
///
/// A configuration that borrowed the identity has already copied what it
/// needs, so freeing it does not unsettle a running server.
///
/// # Safety
///
/// `identity` must come from `soyokaze_identity_new` or
/// `soyokaze_identity_from_pkcs12` and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_identity_free(identity: *mut Identity) {
    if !identity.is_null() {
        drop(unsafe { Box::from_raw(identity) });
    }
}

/// Generates a fresh X25519 key pair and the config that publishes it.
///
/// `public_name` is what a watcher sees instead of the real server name, and
/// must be a name the server can present a certificate for. `config_id` lets
/// a server tell its own configs apart while rotating them.
///
/// # Safety
///
/// `public_name` must point to `public_name_len` readable octets, and `out`
/// must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_keys_generate(public_name: *const u8, public_name_len: usize, config_id: u8, out: *mut *mut EchKeys, error: *mut *mut ErrorHandle) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(public_name) = (unsafe { Slice::borrow_text(public_name, public_name_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if public_name.len() > 255 {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match EchKeys::generate(public_name, config_id) {
        Ok(keys) => {
            unsafe { *out = Box::into_raw(Box::new(keys)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Rebuilds ECH keys from a stored config and private key.
///
/// This is how a server keeps offering the same config across restarts:
/// persist `soyokaze_ech_keys_config` and `soyokaze_ech_keys_private_key`, and
/// hand them back here. Returns null when an argument is null.
///
/// # Safety
///
/// `config` and `private_key` must point to their stated number of readable
/// octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_keys_new(config: *const u8, config_len: usize, private_key: *const u8, private_key_len: usize) -> *mut EchKeys {
    let (Some(config), Some(private_key)) = (unsafe { Slice::borrow(config, config_len) }, unsafe { Slice::borrow(private_key, private_key_len) }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(EchKeys { config: config.to_vec(), private_key: private_key.to_vec() }))
}

/// Releases an [`EchKeys`].
///
/// # Safety
///
/// `keys` must come from `soyokaze_ech_keys_generate` or
/// `soyokaze_ech_keys_new` and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_keys_free(keys: *mut EchKeys) {
    if !keys.is_null() {
        drop(unsafe { Box::from_raw(keys) });
    }
}

/// The raw ECHConfig, borrowed from `keys`.
///
/// # Safety
///
/// `keys` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_keys_config(keys: *const EchKeys) -> Slice {
    match unsafe { keys.as_ref() } {
        Some(keys) => Slice::new(&keys.config),
        None => Slice::ABSENT,
    }
}

/// The raw X25519 private key, borrowed from `keys`.
///
/// Handle with care: this is the secret half.
///
/// # Safety
///
/// As [`soyokaze_ech_keys_config`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_keys_private_key(keys: *const EchKeys) -> Slice {
    match unsafe { keys.as_ref() } {
        Some(keys) => Slice::new(&keys.private_key),
        None => Slice::ABSENT,
    }
}

/// The config wrapped as a one-entry `ECHConfigList`, owned by the caller.
///
/// This is what goes in a client configuration's ECH entry, and what a server
/// publishes in DNS.
///
/// # Safety
///
/// As [`soyokaze_ech_keys_config`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_keys_config_list(keys: *const EchKeys) -> Buffer {
    match unsafe { keys.as_ref() } {
        Some(keys) => Buffer::new(keys.config_list()),
        None => Buffer::EMPTY,
    }
}

/// Parses a published `ECHConfigList`.
///
/// Configurations of other versions are skipped rather than rejected.
///
/// # Safety
///
/// `data` must point to `data_len` readable octets, and `out` must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_list_parse(data: *const u8, data_len: usize, out: *mut *mut EchConfigList, error: *mut *mut ErrorHandle) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match EchConfigList::parse(data) {
        Ok(list) => {
            unsafe { *out = Box::into_raw(Box::new(list)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Releases an [`EchConfigList`].
///
/// # Safety
///
/// `list` must come from `soyokaze_ech_config_list_parse` and not have been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_list_free(list: *mut EchConfigList) {
    if !list.is_null() {
        drop(unsafe { Box::from_raw(list) });
    }
}

/// How many configurations the list holds.
///
/// # Safety
///
/// `list` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_list_count(list: *const EchConfigList) -> usize {
    unsafe { list.as_ref() }.map_or(0, |list| list.configs.len())
}

/// The config version at `index`, or zero when there is no such config.
///
/// # Safety
///
/// As [`soyokaze_ech_config_list_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_version(list: *const EchConfigList, index: usize) -> u16 {
    unsafe { list.as_ref() }.and_then(|list| list.configs.get(index)).map_or(0, |config| config.version)
}

/// The public name at `index`, borrowed from `list`.
///
/// # Safety
///
/// As [`soyokaze_ech_config_list_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_public_name(list: *const EchConfigList, index: usize) -> Slice {
    Slice::maybe(unsafe { list.as_ref() }.and_then(|list| list.configs.get(index)).map(|config| config.public_name.as_str()))
}

/// The padded name length at `index`, or `-1` when there is no such config.
///
/// # Safety
///
/// As [`soyokaze_ech_config_list_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_maximum_name_length(list: *const EchConfigList, index: usize) -> i32 {
    unsafe { list.as_ref() }
        .and_then(|list| list.configs.get(index))
        .map_or(-1, |config| config.maximum_name_length as i32)
}

/// One host's ECH configuration list.
///
/// A host of `*` applies wherever no exact entry matches, as
/// [`ClientConfig::ech`] documents.
///
/// [`ClientConfig::ech`]: crate::api::client::ClientConfig::ech
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EchEntry {
    /// The host the list applies to.
    pub host: Slice,
    /// The `ECHConfigList`, as `soyokaze_ech_keys_config_list` produces it.
    pub config_list: Slice,
}
