//! TLS identities, context details and Encrypted Client Hello, from C.
//!
//! [`Identity`] is what a server serves, [`TLSConfig`] is how either side's
//! context is tuned, [`ECHKeys`] is what a server offers ECH with, and
//! [`ECHConfigList`] is what a client reads back out of what a server
//! published — the same parts [`crate::tls`] arranges.

use crate::ffi::errors::{ErrorHandle, Status};
use crate::ffi::{Buffer, Slice};
use crate::tls::{ECHConfigList, ECHKeys, Identity};

/// The TLS details a context is built with, beyond its identity and roots.
///
/// The C half of [`TLSConfig`], field for field. Each string is an OpenSSL
/// list, entries separated by `:` and most preferred first; an absent slice
/// keeps that field's default, the way [`TLSConfig::default`] would.
///
/// [`TLSConfig`]: crate::tls::TLSConfig
/// [`TLSConfig::default`]: crate::tls::TLSConfig::default
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TLSConfig {
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

impl TLSConfig {
    /// The [`TLSConfig`] this stands for.
    ///
    /// `None` when a string is not UTF-8.
    ///
    /// [`TLSConfig`]: crate::tls::TLSConfig
    ///
    /// # Safety
    ///
    /// Each slice must either be absent or point to its stated number of
    /// readable octets.
    pub unsafe fn parse(&self) -> Option<crate::tls::TLSConfig> {
        let text = |slice: Slice| match slice.data.is_null() {
            true => Some(None),
            false => unsafe { Slice::borrow_text(slice.data, slice.len) }.map(|text| Some(text.to_owned())),
        };

        Some(crate::tls::TLSConfig {
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

/// The default [`TLSConfig`], to be adjusted and passed back.
///
/// [`TLSConfig`]: crate::tls::TLSConfig
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_tls_config_default() -> TLSConfig {
    let config = crate::tls::TLSConfig::default();

    TLSConfig {
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
pub unsafe extern "C" fn soyokaze_ech_keys_generate(public_name: *const u8, public_name_len: usize, config_id: u8, out: *mut *mut ECHKeys, error: *mut *mut ErrorHandle) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(public_name) = (unsafe { Slice::borrow_text(public_name, public_name_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    if public_name.len() > 255 {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    match ECHKeys::generate(public_name, config_id) {
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
pub unsafe extern "C" fn soyokaze_ech_keys_new(config: *const u8, config_len: usize, private_key: *const u8, private_key_len: usize) -> *mut ECHKeys {
    let (Some(config), Some(private_key)) = (unsafe { Slice::borrow(config, config_len) }, unsafe { Slice::borrow(private_key, private_key_len) }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(ECHKeys { config: config.to_vec(), private_key: private_key.to_vec() }))
}

/// Releases an [`ECHKeys`].
///
/// # Safety
///
/// `keys` must come from `soyokaze_ech_keys_generate` or
/// `soyokaze_ech_keys_new` and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_keys_free(keys: *mut ECHKeys) {
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
pub unsafe extern "C" fn soyokaze_ech_keys_config(keys: *const ECHKeys) -> Slice {
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
pub unsafe extern "C" fn soyokaze_ech_keys_private_key(keys: *const ECHKeys) -> Slice {
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
pub unsafe extern "C" fn soyokaze_ech_keys_config_list(keys: *const ECHKeys) -> Buffer {
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
pub unsafe extern "C" fn soyokaze_ech_config_list_parse(data: *const u8, data_len: usize, out: *mut *mut ECHConfigList, error: *mut *mut ErrorHandle) -> Status {
    if out.is_null() {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    }

    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        return unsafe { ErrorHandle::raise(error, Status::Invalid) };
    };

    match ECHConfigList::parse(data) {
        Ok(list) => {
            unsafe { *out = Box::into_raw(Box::new(list)) };
            Status::Ok
        }
        Err(failure) => unsafe { ErrorHandle::report(error, &failure) },
    }
}

/// Releases an [`ECHConfigList`].
///
/// # Safety
///
/// `list` must come from `soyokaze_ech_config_list_parse` and not have been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_list_free(list: *mut ECHConfigList) {
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
pub unsafe extern "C" fn soyokaze_ech_config_list_count(list: *const ECHConfigList) -> usize {
    unsafe { list.as_ref() }.map_or(0, |list| list.configs.len())
}

/// The config version at `index`, or zero when there is no such config.
///
/// # Safety
///
/// As [`soyokaze_ech_config_list_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_version(list: *const ECHConfigList, index: usize) -> u16 {
    unsafe { list.as_ref() }.and_then(|list| list.configs.get(index)).map_or(0, |config| config.version)
}

/// The public name at `index`, borrowed from `list`.
///
/// # Safety
///
/// As [`soyokaze_ech_config_list_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_public_name(list: *const ECHConfigList, index: usize) -> Slice {
    Slice::maybe(unsafe { list.as_ref() }.and_then(|list| list.configs.get(index)).map(|config| config.public_name.as_str()))
}

/// The padded name length at `index`, or `-1` when there is no such config.
///
/// # Safety
///
/// As [`soyokaze_ech_config_list_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_config_maximum_name_length(list: *const ECHConfigList, index: usize) -> i32 {
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
pub struct ECHEntry {
    /// The host the list applies to.
    pub host: Slice,
    /// The `ECHConfigList`, as `soyokaze_ech_keys_config_list` produces it.
    pub config_list: Slice,
}

/// The one TLS version this library speaks, as its wire code.
///
/// Nothing below TLS 1.3 is offered or accepted.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_tls_version_1_3() -> u16 {
    crate::tls::TLSVersion::V1_3.0
}

/// Which encoding a certificate or key blob is in.
///
/// The C half of [`Format`]. One DER blob holds exactly one object, while one
/// PEM blob holds as many as were concatenated into it — which is how a chain,
/// or a chain and its key, is usually shipped in a single file.
///
/// [`Format`]: crate::tls::Format
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// Binary DER.
    DER = 0,
    /// Base64 DER between armour lines.
    PEM = 1,
}

impl Format {
    /// The C half of `format`.
    pub fn build(format: crate::tls::Format) -> Self {
        match format {
            crate::tls::Format::DER => Self::DER,
            crate::tls::Format::PEM => Self::PEM,
        }
    }
}

/// The ASN.1 tag every DER object read here opens with: a SEQUENCE.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_format_sequence() -> u8 {
    crate::tls::Format::SEQUENCE
}

/// The format a blob is in, recognised from its contents.
///
/// The first octet that is not whitespace decides it: DER starts with
/// [`soyokaze_format_sequence`], and anything else is read as PEM.
///
/// # Safety
///
/// `raw` must either be null or point to `raw_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_format_of(raw: *const u8, raw_len: usize) -> Format {
    Format::build(crate::tls::Format::of(unsafe { Slice::borrow(raw, raw_len) }.unwrap_or_default()))
}

/// How many certificates a blob holds, or `-1` when it will not parse.
///
/// A DER blob carries exactly one; a PEM blob carries as many as it holds.
/// Sections that are not certificates are skipped, so a file holding a chain
/// and its key counts the chain alone.
///
/// # Safety
///
/// As [`soyokaze_format_of`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_format_certificate_count(raw: *const u8, raw_len: usize) -> isize {
    let raw = unsafe { Slice::borrow(raw, raw_len) }.unwrap_or_default();

    match crate::tls::Format::certificates(raw) {
        Ok(certificates) => certificates.len() as isize,
        Err(_) => -1,
    }
}

/// The certificate at `index` within a blob, as DER, owned by the caller.
///
/// An empty buffer with a null pointer means the blob will not parse or holds
/// no certificate there.
///
/// # Safety
///
/// As [`soyokaze_format_of`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_format_certificate(raw: *const u8, raw_len: usize, index: usize) -> Buffer {
    let raw = unsafe { Slice::borrow(raw, raw_len) }.unwrap_or_default();

    let Ok(certificates) = crate::tls::Format::certificates(raw) else {
        return Buffer::EMPTY;
    };

    match certificates.get(index).and_then(|certificate| certificate.to_der().ok()) {
        Some(der) => Buffer::new(der),
        None => Buffer::EMPTY,
    }
}

/// The private key in a blob, as DER, owned by the caller.
///
/// An empty buffer with a null pointer means the blob carries no key that will
/// parse.
///
/// # Safety
///
/// As [`soyokaze_format_of`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_format_private_key(raw: *const u8, raw_len: usize) -> Buffer {
    let raw = unsafe { Slice::borrow(raw, raw_len) }.unwrap_or_default();

    match crate::tls::Format::private_key(raw).and_then(|key| key.private_key_to_der().map_err(crate::errors::Error::tls)) {
        Ok(der) => Buffer::new(der),
        Err(_) => Buffer::EMPTY,
    }
}

/// What a connection turned out to be underneath.
///
/// The C half of [`Security`], with the codes it carries flattened: a `-1`
/// stands for a value the handshake did not settle. Stamped on every message a
/// connection receives, which is what `soyokaze_message_tls` and its
/// neighbours read out.
///
/// [`Security`]: crate::tls::Security
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Security {
    /// Whether the transport underneath authenticated the peer.
    pub secure: bool,
    /// Whether the message arrived in early data, and so may be a replay.
    pub early_data: bool,
    /// Whether the transport underneath was TLS.
    pub tls: bool,
    /// The negotiated TLS version's wire code, or `-1`.
    pub tls_version: i32,
    /// The negotiated named group's wire code, or `-1`.
    pub tls_group: i32,
    /// The negotiated cipher suite's wire code, or `-1`.
    pub tls_cipher: i32,
    /// Whether the transport underneath was QUIC.
    pub quic: bool,
    /// The negotiated QUIC version, or `-1`.
    pub quic_version: i64,
}

impl Security {
    /// The C half of `security`.
    pub fn build(security: &crate::tls::Security) -> Self {
        Self {
            secure: security.secure,
            early_data: security.early_data,
            tls: security.tls,
            tls_version: security.tls_version.map_or(-1, |version| version.0 as i32),
            tls_group: security.tls_group.map_or(-1, |group| group.0 as i32),
            tls_cipher: security.tls_cipher.map_or(-1, |cipher| cipher.0 as i32),
            quic: security.quic,
            quic_version: security.quic_version.map_or(-1, |version| version as i64),
        }
    }

    /// The [`Security`] this stands for.
    ///
    /// [`Security`]: crate::tls::Security
    pub fn parse(&self) -> crate::tls::Security {
        crate::tls::Security {
            secure: self.secure,
            early_data: self.early_data,
            tls: self.tls,
            tls_version: u16::try_from(self.tls_version).ok().map(crate::tls::TLSVersion),
            tls_group: u16::try_from(self.tls_group).ok().map(crate::tls::TLSGroup),
            tls_cipher: u16::try_from(self.tls_cipher).ok().map(crate::tls::TLSCipher),
            quic: self.quic,
            quic_version: u32::try_from(self.quic_version).ok(),
        }
    }
}

/// What a plain connection reports: nothing negotiated at all.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_security_default() -> Security {
    Security::build(&crate::tls::Security::default())
}

/// What a QUIC connection reports.
///
/// QUIC always carries TLS 1.3, but the QUIC stack does not hand its session
/// out, so the cipher suite and group are left unsettled. A negative
/// `quic_version` stands for a handshake that has not settled one yet.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_security_quic(quic_version: i64) -> Security {
    Security::build(&crate::tls::Security::quic(u32::try_from(quic_version).ok()))
}

/// Stamps what the transport turned out to be onto a message.
///
/// # Safety
///
/// `security` must either be null or point to a readable [`Security`], and
/// `message` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_security_apply(security: *const Security, message: *mut crate::models::Message) -> bool {
    let (Some(security), Some(message)) = (unsafe { security.as_ref() }, unsafe { message.as_mut() }) else {
        return false;
    };

    security.parse().apply(message);
    true
}

/// What a message's connection turned out to be underneath.
///
/// The same values `soyokaze_message_tls` and its neighbours read out, in one
/// call.
///
/// # Safety
///
/// `message` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_message_security(message: *const crate::models::Message) -> Security {
    match unsafe { message.as_ref() } {
        Some(message) => Security::build(&message.security),
        None => Security::build(&crate::tls::Security::default()),
    }
}

/// The version an ECH configuration must carry to be understood.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_ech_config_supported_version() -> u16 {
    crate::tls::ECHConfig::VERSION
}

/// The one key encapsulation mechanism this library generates keys for.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_ech_kem_x25519_hkdf_sha256() -> u16 {
    ECHKeys::KEM_X25519_HKDF_SHA256
}

/// The one key derivation function this library offers.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_ech_kdf_hkdf_sha256() -> u16 {
    ECHKeys::KDF_HKDF_SHA256
}

/// The one AEAD this library offers.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_ech_aead_aes_128_gcm() -> u16 {
    ECHKeys::AEAD_AES_128_GCM
}

/// How long a name a generated configuration says it can cover.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_ech_maximum_name_length() -> u8 {
    ECHKeys::MAXIMUM_NAME_LENGTH
}

/// The configuration list an ECH key pair advertises, encoded, owned by the
/// caller.
///
/// A server publishes this in DNS; a client hands it back through
/// `soyokaze_client_config_t`.
///
/// # Safety
///
/// `public_key` must either be null or point to `public_key_len` readable
/// octets, and `public_name` to `public_name_len` of them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_ech_keys_encode(public_name: *const u8, public_name_len: usize, config_id: u8, public_key: *const u8, public_key_len: usize) -> Buffer {
    let Some(public_name) = (unsafe { Slice::borrow_text(public_name, public_name_len) }) else {
        return Buffer::EMPTY;
    };

    let public_key = unsafe { Slice::borrow(public_key, public_key_len) }.unwrap_or_default();
    Buffer::new(ECHKeys::encode(public_name, config_id, public_key))
}

/// How many certificates the identity's chain holds, or `-1` when it will not
/// parse.
///
/// # Safety
///
/// `identity` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_identity_certificate_count(identity: *const Identity) -> isize {
    let Some(identity) = (unsafe { identity.as_ref() }) else {
        return -1;
    };

    match identity.chain() {
        Ok(chain) => chain.len() as isize,
        Err(_) => -1,
    }
}

/// The certificate at `index` in the identity's chain, as DER, owned by the
/// caller.
///
/// # Safety
///
/// As [`soyokaze_identity_certificate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_identity_certificate(identity: *const Identity, index: usize) -> Buffer {
    let Some(identity) = (unsafe { identity.as_ref() }) else {
        return Buffer::EMPTY;
    };

    let Ok(chain) = identity.chain() else {
        return Buffer::EMPTY;
    };

    match chain.get(index).and_then(|certificate| certificate.to_der().ok()) {
        Some(der) => Buffer::new(der),
        None => Buffer::EMPTY,
    }
}

/// The identity's private key, as DER, owned by the caller.
///
/// # Safety
///
/// As [`soyokaze_identity_certificate_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_identity_private_key(identity: *const Identity) -> Buffer {
    let Some(identity) = (unsafe { identity.as_ref() }) else {
        return Buffer::EMPTY;
    };

    match identity.private_key().and_then(|key| key.private_key_to_der().map_err(crate::errors::Error::tls)) {
        Ok(der) => Buffer::new(der),
        Err(_) => Buffer::EMPTY,
    }
}
