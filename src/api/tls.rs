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

use boring::hpke::HpkeKey;
use boring::pkey::PKey;
use boring::ssl::{AlpnError, SslAcceptor, SslConnector, SslContextBuilder, SslEchKeys, SslMethod, SslVerifyMode};
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;

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

/// Builds the TLS configuration a client dials with.
///
/// An empty `roots` uses the platform's trust store; otherwise only the DER
/// certificates given are trusted. Certificates are verified either way.
///
/// # Errors
///
/// Returns [`Error::Tls`] when BoringSSL rejects the configuration or a
/// certificate will not parse.
pub fn client_config(roots: &[Vec<u8>], versions: &[Version]) -> Result<SslConnector, Error> {
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(tls_error)?;
    builder.set_alpn_protos(&alpn_wire(versions)).map_err(tls_error)?;

    if roots.is_empty() {
        builder.set_default_verify_paths().map_err(tls_error)?;
    } else {
        let mut store = X509StoreBuilder::new().map_err(tls_error)?;
        for der in roots {
            store.add_cert(X509::from_der(der).map_err(tls_error)?).map_err(tls_error)?;
        }
        builder.set_verify_cert_store(store.build()).map_err(tls_error)?;
    }

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

    let mut certificates = identity.certificates.iter();
    let leaf = certificates.next().ok_or_else(|| Error::Tls("identity has no certificate".into()))?;
    let leaf = X509::from_der(leaf).map_err(tls_error)?;
    builder.set_certificate(&leaf).map_err(tls_error)?;

    for extra in certificates {
        let extra = X509::from_der(extra).map_err(tls_error)?;
        builder.add_extra_chain_cert(extra).map_err(tls_error)?;
    }

    let key = PKey::private_key_from_pkcs8(&identity.key).map_err(tls_error)?;
    builder.set_private_key(&key).map_err(tls_error)?;

    let offered = alpn(versions);
    builder.set_alpn_select_callback(move |_ssl, client| select_alpn(&offered, client).ok_or(AlpnError::NOACK));

    if let Some(ech) = ech {
        ech.install(&builder)?;
    }

    Ok(builder.build())
}

/// A certificate chain and the private key that goes with it.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The chain in DER, leaf first, then whatever intermediates are needed.
    pub certificates: Vec<Vec<u8>>,
    /// The private key, in PKCS#8 DER.
    pub key: Vec<u8>,
}

impl Identity {
    /// An identity from a DER chain and a PKCS#8 key.
    ///
    /// Nothing is parsed here; a malformed chain or key surfaces when a
    /// context is built from it.
    pub fn new(certificates: Vec<Vec<u8>>, key: Vec<u8>) -> Self {
        Self { certificates, key }
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
    /// This is what a client passes to [`ClientBuilder::ech`].
    ///
    /// [`ClientBuilder::ech`]: crate::api::client::ClientBuilder::ech
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

    let mut certificates = identity.certificates.iter();
    let leaf = certificates.next().ok_or_else(|| Error::Tls("identity has no certificate".into()))?;
    let leaf = X509::from_der(leaf).map_err(tls_error)?;
    builder.set_certificate(&leaf).map_err(tls_error)?;

    for extra in certificates {
        let extra = X509::from_der(extra).map_err(tls_error)?;
        builder.add_extra_chain_cert(extra).map_err(tls_error)?;
    }

    let key = PKey::private_key_from_pkcs8(&identity.key).map_err(tls_error)?;
    builder.set_private_key(&key).map_err(tls_error)?;
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

    if roots.is_empty() {
        builder.set_default_verify_paths().map_err(tls_error)?;
    } else {
        let mut store = X509StoreBuilder::new().map_err(tls_error)?;
        for der in roots {
            store.add_cert(X509::from_der(der).map_err(tls_error)?).map_err(tls_error)?;
        }
        builder.set_verify_cert_store(store.build()).map_err(tls_error)?;
    }

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
    /// The trusted roots in DER; empty uses the platform trust store.
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
