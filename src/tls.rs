//! TLS contexts, identities and Encrypted Client Hello.
//!
//! Everything here builds on BoringSSL. The version of HTTP a connection ends
//! up speaking is decided during the handshake by ALPN, so this module is
//! where negotiation happens: [`client_config`] and [`server_config`] offer
//! the versions, and [`negotiated`] reads back what was chosen.
//!
//! Encrypted Client Hello encrypts the server name in the handshake, so a
//! watcher sees only the public name. [`EchKeys`] is what a server holds,
//! [`EchConfigList`] is what a client is given, and [`EchStatus`] is how
//! either finds out whether it was actually used.
//!
//! Certificates and keys are taken in whichever encoding they arrive in:
//! [`Format`] tells DER and PEM apart by their contents, so nothing has to be
//! declared. [`certificates`] and [`private_key`] are what read them, and
//! [`Identity::from_pkcs12`] unwraps a `.p12` or `.pfx` archive into the same
//! shape.

use boring::hpke::HpkeKey;
use boring::pkcs12::Pkcs12;
use boring::pkey::{PKey, Private};
use boring::ssl::{AlpnError, SslAcceptor, SslConnector, SslContextBuilder, SslEchKeys, SslMethod, SslVerifyMode};
use boring::stack::Stack;
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;
use foreign_types::ForeignType;

use crate::errors::Error;
use crate::models::Version;

/// Wraps a BoringSSL failure as an [`Error`].
pub fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::Tls(error.to_string())
}

/// The ALPN protocol identifiers for a list of versions, one per entry.
pub fn alpn(versions: &[Version]) -> Vec<Vec<u8>> {
    versions.iter().map(|version| version.alpn().as_bytes().to_vec()).collect()
}

/// The ALPN protocol identifiers in wire form: each length-prefixed, run together.
pub fn alpn_wire(versions: &[Version]) -> Vec<u8> {
    let mut out = Vec::new();

    for version in versions {
        let protocol = version.alpn().as_bytes();
        out.push(protocol.len() as u8);
        out.extend_from_slice(protocol);
    }

    out
}

/// Picks a protocol from what a client offered.
///
/// The server's preference wins: `offered` is walked in order and the first
/// entry the client also lists is chosen. `None` when nothing overlaps, which
/// must fail the handshake rather than fall back to something unnegotiated.
pub fn select_alpn<'a>(offered: &[Vec<u8>], client: &'a [u8]) -> Option<&'a [u8]> {
    for wanted in offered {
        let mut index = 0;

        while index < client.len() {
            let length = client[index] as usize;
            let end = index + 1 + length;

            let Some(protocol) = client.get(index + 1..end) else {
                break;
            };

            if protocol == wanted.as_slice() {
                return Some(protocol);
            }

            index = end;
        }
    }

    None
}

/// The version a completed handshake settled on.
///
/// A peer that selected nothing falls back to HTTP/1.x, which predates ALPN,
/// and only when that was on offer.
///
/// # Errors
///
/// Returns [`Error::Version`] when the peer selected nothing and no HTTP/1.x
/// was offered, or selected something outside `versions`.
pub fn negotiated(alpn: Option<&[u8]>, versions: &[Version]) -> Result<Version, Error> {
    let Some(alpn) = alpn else {
        return versions
            .iter()
            .copied()
            .find(|version| version.major() == 1)
            .ok_or_else(|| Error::Version("the peer selected no protocol".into()));
    };

    Version::from_alpn(alpn)
        .filter(|version| versions.contains(version))
        .ok_or_else(|| Error::Version(format!("the peer selected {:?}", String::from_utf8_lossy(alpn))))
}

/// How a certificate or a private key was encoded.
///
/// The two are the same bytes either way round: PEM is DER in Base64 between
/// `-----BEGIN`/`-----END` lines. The difference that matters here is that one
/// DER blob holds exactly one object, while one PEM blob holds as many as were
/// concatenated into it — which is how a chain, or a chain and its key, is
/// usually shipped in a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Binary DER.
    Der,
    /// Base64 DER between armour lines.
    Pem,
}

impl Format {
    /// The ASN.1 tag every DER object read here opens with: a SEQUENCE.
    pub const SEQUENCE: u8 = 0x30;

    /// The format a blob is in, recognised from its contents.
    ///
    /// The first byte that is not whitespace decides it: DER starts with
    /// [`Format::SEQUENCE`], and anything else is text, so it is read as PEM.
    /// Nothing insists on armour coming first, since a PEM file may open with
    /// a human-readable description of what follows.
    pub fn of(raw: &[u8]) -> Self {
        match raw.iter().find(|byte| !byte.is_ascii_whitespace()) {
            Some(&Self::SEQUENCE) => Self::Der,
            _ => Self::Pem,
        }
    }
}

/// Parses every certificate in one blob, DER or PEM.
///
/// A DER blob carries exactly one certificate; a PEM blob carries as many as
/// it holds, returned in the order they appear. PEM sections that are not
/// certificates are skipped, so a file holding a chain and its key parses to
/// the chain alone.
///
/// # Errors
///
/// Returns [`Error::Tls`] when the blob will not parse, or when a PEM blob
/// carries no certificate at all.
pub fn certificates(raw: &[u8]) -> Result<Vec<X509>, Error> {
    match Format::of(raw) {
        Format::Der => Ok(vec![X509::from_der(raw).map_err(tls_error)?]),
        Format::Pem => {
            let parsed = X509::stack_from_pem(raw).map_err(tls_error)?;

            if parsed.is_empty() {
                return Err(Error::Tls("PEM data carries no certificate".into()));
            }

            Ok(parsed)
        }
    }
}

/// Parses every certificate across several blobs, each DER or PEM.
///
/// Certificates come back in the order the blobs give them, so a chain may
/// arrive as one PEM bundle, as one blob per certificate, or as a mixture of
/// the two.
///
/// # Errors
///
/// As [`certificates`].
pub fn certificate_list(blobs: &[Vec<u8>]) -> Result<Vec<X509>, Error> {
    let mut list = Vec::with_capacity(blobs.len());

    for blob in blobs {
        list.extend(certificates(blob)?);
    }

    Ok(list)
}

/// Parses a private key, DER or PEM.
///
/// PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`) and SEC1
/// (`EC PRIVATE KEY`) are all accepted, in either format; which one it is is
/// read off the key itself. A key encrypted under a passphrase is not
/// accepted — decrypt it first, or ship it as PKCS#12 and use
/// [`Identity::from_pkcs12`].
///
/// # Errors
///
/// Returns [`Error::Tls`] when the blob will not parse as any of those.
pub fn private_key(raw: &[u8]) -> Result<PKey<Private>, Error> {
    match Format::of(raw) {
        Format::Der => PKey::private_key_from_der(raw).map_err(tls_error),
        Format::Pem => PKey::private_key_from_pem(raw).map_err(tls_error),
    }
}

/// Points a context at the roots it should verify against.
///
/// An empty `roots` leaves the platform's trust store in place; otherwise only
/// the certificates given are trusted. Each is DER or PEM, so one PEM bundle
/// of roots is as good as one blob apiece.
///
/// # Errors
///
/// Returns [`Error::Tls`] when a certificate will not parse or BoringSSL
/// rejects the store.
pub fn install_roots(roots: &[Vec<u8>], builder: &mut SslContextBuilder) -> Result<(), Error> {
    if roots.is_empty() {
        builder.set_default_verify_paths().map_err(tls_error)?;
        return Ok(());
    }

    let mut store = X509StoreBuilder::new().map_err(tls_error)?;

    for root in certificate_list(roots)? {
        store.add_cert(root).map_err(tls_error)?;
    }

    builder.set_verify_cert_store(store.build()).map_err(tls_error)?;
    Ok(())
}

/// Builds the TLS configuration a client dials with.
///
/// An empty `roots` uses the platform's trust store; otherwise only the
/// certificates given are trusted, each in DER or PEM. Certificates are
/// verified either way.
///
/// # Errors
///
/// Returns [`Error::Tls`] when BoringSSL rejects the configuration or a
/// certificate will not parse.
pub fn client_config(roots: &[Vec<u8>], versions: &[Version]) -> Result<SslConnector, Error> {
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(tls_error)?;
    builder.set_alpn_protos(&alpn_wire(versions)).map_err(tls_error)?;
    install_roots(roots, &mut builder)?;

    Ok(builder.build())
}

/// Builds the TLS configuration a server accepts with.
///
/// A handshake offering none of `versions` is failed rather than completed
/// without a protocol.
///
/// # Errors
///
/// Returns [`Error::Tls`] when the identity carries no certificate, when a
/// certificate or key will not parse, or when BoringSSL rejects the
/// configuration.
pub fn server_config(identity: &Identity, versions: &[Version], ech: Option<&EchKeys>) -> Result<SslAcceptor, Error> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(tls_error)?;
    identity.install(&mut builder)?;

    let offered = alpn(versions);
    builder.set_alpn_select_callback(move |_ssl, client| select_alpn(&offered, client).ok_or(AlpnError::NOACK));

    if let Some(ech) = ech {
        ech.install(&builder)?;
    }

    Ok(builder.build())
}

/// A certificate chain and the private key that goes with it.
///
/// Every blob is read in whichever format it turns out to be, so the chain can
/// arrive as one PEM bundle, as one DER certificate per entry, or as a mixture
/// of the two, and the key in PKCS#8, PKCS#1 or SEC1 either way round. Each
/// side reads only the PEM sections that are its own, so a combined file may
/// be given as both the chain and the key.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The chain, leaf first, then whatever intermediates are needed.
    pub certificates: Vec<Vec<u8>>,
    /// The private key.
    pub key: Vec<u8>,
}

impl Identity {
    /// An identity from a certificate chain and a private key.
    ///
    /// Nothing is parsed here; a malformed chain or key surfaces when a
    /// context is built from it.
    pub fn new(certificates: Vec<Vec<u8>>, key: Vec<u8>) -> Self {
        Self { certificates, key }
    }

    /// An identity from a PKCS#12 archive, as `.p12` and `.pfx` files carry.
    ///
    /// One archive holds the leaf, its chain and the key together under a
    /// single passphrase; pass `""` for an archive protected by none. Unlike
    /// [`Identity::new`], everything is parsed here, and kept as DER
    /// afterwards, so the passphrase is not retained.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the archive will not parse, the passphrase
    /// does not open it, it carries no certificate for its key, or its
    /// contents will not re-encode.
    pub fn from_pkcs12(raw: &[u8], passphrase: &str) -> Result<Self, Error> {
        let archive = Pkcs12::from_der(raw).map_err(tls_error)?;
        let passphrase = std::ffi::CString::new(passphrase).map_err(tls_error)?;

        let mut key = std::ptr::null_mut();
        let mut leaf = std::ptr::null_mut();
        let mut rest = std::ptr::null_mut();

        let opened = unsafe { boring_sys::PKCS12_parse(archive.as_ptr(), passphrase.as_ptr(), &mut key, &mut leaf, &mut rest) };

        let key = (!key.is_null()).then(|| unsafe { PKey::<Private>::from_ptr(key) });
        let leaf = (!leaf.is_null()).then(|| unsafe { X509::from_ptr(leaf) });
        let rest = (!rest.is_null()).then(|| unsafe { Stack::<X509>::from_ptr(rest) });

        if opened != 1 {
            return Err(tls_error(boring::error::ErrorStack::get()));
        }

        let (Some(key), Some(leaf)) = (key, leaf) else {
            return Err(Error::Tls("the PKCS#12 archive carries no certificate for its key".into()));
        };

        let mut certificates = vec![leaf.to_der().map_err(tls_error)?];

        for extra in rest.into_iter().flatten() {
            certificates.push(extra.to_der().map_err(tls_error)?);
        }

        Ok(Self { certificates, key: key.private_key_to_der_pkcs8().map_err(tls_error)? })
    }

    /// The chain as parsed certificates, leaf first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when a certificate will not parse.
    pub fn chain(&self) -> Result<Vec<X509>, Error> {
        certificate_list(&self.certificates)
    }

    /// The private key, parsed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the key will not parse.
    pub fn private_key(&self) -> Result<PKey<Private>, Error> {
        private_key(&self.key)
    }

    /// Gives a context the chain and key to serve.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the identity carries no certificate, when a
    /// certificate or the key will not parse, or when BoringSSL rejects them.
    pub fn install(&self, builder: &mut SslContextBuilder) -> Result<(), Error> {
        let mut chain = self.chain()?.into_iter();
        let leaf = chain.next().ok_or_else(|| Error::Tls("identity has no certificate".into()))?;
        builder.set_certificate(&leaf).map_err(tls_error)?;

        for extra in chain {
            builder.add_extra_chain_cert(extra).map_err(tls_error)?;
        }

        let key = self.private_key()?;
        builder.set_private_key(&key).map_err(tls_error)?;
        Ok(())
    }
}

/// The ECHConfig version this crate understands.
pub const ECH_VERSION: u16 = 0xfe0d;

/// One ECH configuration, as far as a client needs to read it.
///
/// The public key and cipher suites stay in the raw config that BoringSSL is
/// given; only the fields a caller might want to inspect are lifted out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    /// The config version; always [`ECH_VERSION`] here.
    pub version: u16,
    /// The name that appears in the outer, visible handshake.
    pub public_name: String,
    /// The length the real server name is padded to, so its size leaks nothing.
    pub maximum_name_length: u8,
}

/// A list of ECH configurations, as published for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfigList {
    /// The configurations of a version this crate understands.
    pub configs: Vec<EchConfig>,
}

impl EchConfigList {
    /// Parses a published `ECHConfigList`.
    ///
    /// Configurations of other versions are skipped rather than rejected,
    /// since a list is expected to carry several.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the list is too short, its declared length
    /// disagrees with its contents, a config runs past the end, or nothing in
    /// it is of a supported version.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < 2 {
            return Err(Error::Tls("ECHConfigList is too short".into()));
        }

        let declared = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        let body = &raw[2..];
        if declared != body.len() {
            return Err(Error::Tls("ECHConfigList length does not match its contents".into()));
        }

        let mut configs = Vec::new();
        let mut offset = 0;

        while offset + 4 <= body.len() {
            let version = u16::from_be_bytes([body[offset], body[offset + 1]]);
            let size = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
            offset += 4;

            let contents = body
                .get(offset..offset + size)
                .ok_or_else(|| Error::Tls("an ECHConfig runs past the list".into()))?;

            if version == ECH_VERSION {
                configs.push(Self::contents(contents)?);
            }

            offset += size;
        }

        if configs.is_empty() {
            return Err(Error::Tls("ECHConfigList carries no supported ECHConfig".into()));
        }

        Ok(Self { configs })
    }

    /// Reads the fields this crate needs out of one ECHConfig's contents.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the config is too short or any of its
    /// length-prefixed parts runs past the end.
    pub fn contents(raw: &[u8]) -> Result<EchConfig, Error> {
        if raw.len() < 5 {
            return Err(Error::Tls("ECHConfig is too short".into()));
        }

        let key_length = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        let mut offset = 5 + key_length;

        let cipher_length = raw
            .get(offset..offset + 2)
            .map(|slice| u16::from_be_bytes([slice[0], slice[1]]) as usize)
            .ok_or_else(|| Error::Tls("ECHConfig ends inside its cipher suites".into()))?;
        offset += 2 + cipher_length;

        let maximum_name_length = *raw.get(offset).ok_or_else(|| Error::Tls("ECHConfig has no maximum name length".into()))?;
        offset += 1;

        let name_length = *raw.get(offset).ok_or_else(|| Error::Tls("ECHConfig has no public name".into()))? as usize;
        offset += 1;

        let name = raw
            .get(offset..offset + name_length)
            .ok_or_else(|| Error::Tls("ECHConfig public name runs past the config".into()))?;

        Ok(EchConfig {
            version: ECH_VERSION,
            public_name: String::from_utf8_lossy(name).into_owned(),
            maximum_name_length,
        })
    }
}

/// A server's ECH key pair, and the config that publishes its public half.
///
/// The config is what a client needs in order to encrypt its ClientHello; the
/// private key is what the server decrypts it with. Publish
/// [`EchKeys::config_list`] where clients can reach it.
#[derive(Debug, Clone)]
pub struct EchKeys {
    /// One ECHConfig: version(2) || length(2) || contents.
    pub config: Vec<u8>,
    /// The raw X25519 HPKE private key (32 bytes).
    pub private_key: Vec<u8>,
}

impl EchKeys {
    /// The KEM identifier written into the config: X25519 with HKDF-SHA256.
    pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
    /// The KDF identifier written into the config: HKDF-SHA256.
    pub const KDF_HKDF_SHA256: u16 = 0x0001;
    /// The AEAD identifier written into the config: AES-128-GCM.
    pub const AEAD_AES_128_GCM: u16 = 0x0001;

    /// The name length clients pad to, so the real name's size leaks nothing.
    pub const MAXIMUM_NAME_LENGTH: u8 = 64;

    /// Generates a fresh X25519 key pair and the config that publishes it.
    ///
    /// `public_name` is what a watcher sees instead of the real server name,
    /// and must be a name the server can present a certificate for, since a
    /// client that fails ECH falls back to it. `config_id` lets a server tell
    /// its own configs apart while rotating them.
    ///
    /// # Errors
    ///
    /// Currently infallible; the signature leaves room for key generation to
    /// report failure.
    pub fn generate(public_name: &str, config_id: u8) -> Result<Self, Error> {
        let mut public = [0u8; 32];
        let mut private = [0u8; 32];
        unsafe { boring_sys::X25519_keypair(public.as_mut_ptr(), private.as_mut_ptr()) };

        Ok(Self { config: Self::encode(public_name, config_id, &public), private_key: private.to_vec() })
    }

    /// Builds one ECHConfig around a public key.
    ///
    /// # Panics
    ///
    /// A `public_name` longer than 255 octets does not fit its length prefix.
    pub fn encode(public_name: &str, config_id: u8, public_key: &[u8]) -> Vec<u8> {
        let mut contents = Vec::new();
        contents.push(config_id);
        contents.extend_from_slice(&Self::KEM_X25519_HKDF_SHA256.to_be_bytes());
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(public_key);
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&Self::KDF_HKDF_SHA256.to_be_bytes());
        contents.extend_from_slice(&Self::AEAD_AES_128_GCM.to_be_bytes());
        contents.push(Self::MAXIMUM_NAME_LENGTH);
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes());

        let mut config = ECH_VERSION.to_be_bytes().to_vec();
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);
        config
    }

    /// The config wrapped as a one-entry `ECHConfigList`, ready to publish.
    ///
    /// This is what a client puts in [`ClientConfig::ech`].
    ///
    /// [`ClientConfig::ech`]: crate::api::client::ClientConfig::ech
    pub fn config_list(&self) -> Vec<u8> {
        let mut list = (self.config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&self.config);
        list
    }

    /// Installs the keys on a context, so the server can decrypt an inner
    /// ClientHello.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when BoringSSL rejects the key or the config.
    pub fn install(&self, builder: &SslContextBuilder) -> Result<(), Error> {
        let key = HpkeKey::dhkem_p256_sha256(&self.private_key).map_err(tls_error)?;
        let mut keys = SslEchKeys::builder().map_err(tls_error)?;
        keys.add_key(true, &self.config, key).map_err(tls_error)?;
        builder.set_ech_keys(&keys.build()).map_err(tls_error)?;
        Ok(())
    }
}

/// Whether ECH was actually used on a completed handshake.
///
/// A handshake can succeed with ECH rejected, having fallen back to the public
/// name — in which case the real server name travelled in the clear. Check
/// this where that matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchStatus {
    /// Whether the server accepted the encrypted ClientHello.
    pub accepted: bool,
}

impl EchStatus {
    /// Reads the status off a completed handshake.
    pub fn of(ssl: &boring::ssl::SslRef) -> Self {
        Self { accepted: ssl.ech_accepted() }
    }

    /// Whether the server name was in fact encrypted.
    pub fn succeeded(&self) -> bool {
        self.accepted
    }
}

/// Builds the TLS context a QUIC server uses.
///
/// No ALPN callback is installed: `tokio-quiche` handles ALPN itself from the
/// list in its settings. Peer certificates are not requested, since HTTP/3
/// clients do not present them.
///
/// # Errors
///
/// As [`server_config`].
pub fn quic_server_context(identity: &Identity, ech: Option<&EchKeys>) -> Result<SslContextBuilder, Error> {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(tls_error)?;
    identity.install(&mut builder)?;
    builder.set_verify(SslVerifyMode::NONE);

    if let Some(ech) = ech {
        ech.install(&builder)?;
    }

    Ok(builder)
}

/// Builds the TLS context a QUIC client uses.
///
/// The server's certificate is verified, against the platform trust store when
/// `roots` is empty.
///
/// # Errors
///
/// As [`client_config`].
pub fn quic_client_context(roots: &[Vec<u8>]) -> Result<SslContextBuilder, Error> {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(tls_error)?;
    install_roots(roots, &mut builder)?;

    builder.set_verify(SslVerifyMode::PEER);
    Ok(builder)
}

/// Gives a QUIC server its TLS context.
///
/// `tokio-quiche` would otherwise load certificates from paths on disk; this
/// hook supplies a context built from an in-memory [`Identity`] instead, which
/// is also the only way to install ECH keys.
pub struct QuicServerTls {
    /// The certificate chain and key to serve.
    pub identity: Identity,
    /// The ECH keys, if the server offers ECH.
    pub ech: Option<EchKeys>,
}

impl tokio_quiche::quic::ConnectionHook for QuicServerTls {
    /// Builds the context, ignoring the certificate paths in the settings.
    ///
    /// A failure returns `None`, which `tokio-quiche` turns into a failed
    /// connection.
    fn create_custom_ssl_context_builder(&self, _settings: tokio_quiche::settings::TlsCertificatePaths<'_>) -> Option<SslContextBuilder> {
        quic_server_context(&self.identity, self.ech.as_ref()).ok()
    }
}

/// Gives a QUIC client its TLS context.
pub struct QuicClientTls {
    /// The trusted roots, each DER or PEM; empty uses the platform trust store.
    pub roots: Vec<Vec<u8>>,
}

impl tokio_quiche::quic::ConnectionHook for QuicClientTls {
    /// Builds the context, ignoring the certificate paths in the settings.
    ///
    /// A failure returns `None`, which `tokio-quiche` turns into a failed
    /// connection.
    fn create_custom_ssl_context_builder(&self, _settings: tokio_quiche::settings::TlsCertificatePaths<'_>) -> Option<SslContextBuilder> {
        quic_client_context(&self.roots).ok()
    }
}
