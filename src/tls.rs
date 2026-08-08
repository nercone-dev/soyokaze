//! TLS contexts, identities and Encrypted Client Hello.
//!
//! Everything here builds on BoringSSL. The version of HTTP a connection ends
//! up speaking is decided during the handshake by ALPN, so this module is
//! where negotiation happens: [`TlsConfig::client`] and [`TlsConfig::server`]
//! offer the versions, and [`Alpn::negotiated`] reads back what was chosen.
//!
//! What the handshake settled is read back here too: [`Alpn::negotiated`]
//! gives the HTTP version, and [`Security::of`] the TLS version, group and
//! cipher suite that every message crossing the connection is then stamped
//! with.
//!
//! [`Alpn::negotiated`]: crate::models::Alpn::negotiated
//!
//! How a context is tuned beyond its identity and roots — cipher suites,
//! groups, signature algorithms, session tickets, early data and certificate
//! compression — is what [`TlsConfig`] carries, and both sides take one.
//!
//! Encrypted Client Hello encrypts the server name in the handshake, so a
//! watcher sees only the public name. [`EchKeys`] is what a server holds,
//! [`EchConfigList`] is what a client is given, and [`EchStatus`] is how
//! either finds out whether it was actually used.
//!
//! Certificates and keys are taken in whichever encoding they arrive in:
//! [`Format`] tells DER and PEM apart by their contents, so nothing has to be
//! declared. [`Format::certificates`] and [`Format::private_key`] are what read
//! them, and
//! [`Identity::from_pkcs12`] unwraps a `.p12` or `.pfx` archive into the same
//! shape.

use std::io::Write;

use boring::hpke::HpkeKey;
use boring::pkcs12::Pkcs12;
use boring::pkey::{PKey, Private};
use boring::ssl::{
    AlpnError, CertificateCompressionAlgorithm, CertificateCompressor, SslAcceptor, SslConnector, SslContextBuilder, SslEchKeys,
    SslMethod, SslOptions, SslVerifyMode,
};
use boring::stack::Stack;
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;
use foreign_types::{ForeignType, ForeignTypeRef};

use crate::errors::Error;
use crate::models::{Alpn, Message, Version};

/// A TLS protocol version, as the two-octet code that appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TLSVersion(pub u16);

/// A TLS cipher suite, as the two-octet code that appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TLSCipher(pub u16);

/// A TLS named group, as the two-octet code that appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TLSGroup(pub u16);

/// The wire code for TLS 1.3, which is the version QUIC carries.
///
/// RFC 9001 admits nothing older underneath QUIC version 1.
pub const TLS_1_3: u16 = 0x0304;

/// What the transport underneath a connection turned out to be.
///
/// Read off the handshake once, when the connection is assembled, and stamped
/// onto every message that crosses it by [`Security::apply`] — which is how
/// [`Message::security`] comes to be filled in. A plaintext transport leaves
/// every field at its default, so [`Security::default`] is exactly "nothing
/// underneath".
///
/// [`Security::of`] reads one off a completed TLS handshake, and
/// [`Security::quic`] builds the one a QUIC connection stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Security {
    /// Whether the transport was a secure one, as the `https` scheme and the
    /// `:scheme` pseudo-header reflect it.
    pub secure: bool,
    /// Whether the request arrived in TLS early data, and so may be a replay.
    pub early_data: bool,

    /// Whether the transport underneath was TLS.
    pub tls: bool,
    /// The negotiated TLS version.
    pub tls_version: Option<TLSVersion>,
    /// The negotiated TLS named group.
    pub tls_group: Option<TLSGroup>,
    /// The negotiated TLS cipher suite.
    ///
    /// A QUIC connection leaves this and [`Security::tls_group`] absent: the
    /// QUIC stack does not hand its TLS session out to be read.
    pub tls_cipher: Option<TLSCipher>,

    /// Whether the transport underneath was QUIC.
    pub quic: bool,
    /// The negotiated QUIC version.
    pub quic_version: Option<u32>,
}

impl Security {
    /// Reads the transport facts off a completed handshake.
    ///
    /// The counterpart of [`Alpn::negotiated`]: that reads back which HTTP
    /// version was chosen, this reads back everything else the handshake
    /// settled — the TLS version, named group and cipher suite as their wire
    /// codes, and whether the peer's first flight was accepted as early data. A
    /// code the session does not report is left absent rather than guessed at.
    pub fn of(ssl: &boring::ssl::SslRef) -> Self {
        let version = unsafe { boring_sys::SSL_version(ssl.as_ptr()) };
        let group = unsafe { boring_sys::SSL_get_curve_id(ssl.as_ptr()) };

        Self {
            secure: true,
            early_data: unsafe { boring_sys::SSL_early_data_accepted(ssl.as_ptr()) } != 0,

            tls: true,
            tls_version: u16::try_from(version).ok().filter(|version| *version != 0).map(TLSVersion),
            tls_group: (group != 0).then_some(TLSGroup(group)),
            tls_cipher: ssl.current_cipher().map(|cipher| TLSCipher(cipher.protocol_id())),

            ..Self::default()
        }
    }

    /// What a QUIC connection stands for, of `version` when it is known.
    ///
    /// QUIC is secure by construction and carries TLS 1.3 within it, so both
    /// are set. The cipher suite and named group are left absent: the QUIC
    /// stack does not hand its TLS session out to be read. `None` builds the
    /// facts a connection stands for before its handshake has reported a
    /// version.
    pub fn quic(version: Option<u32>) -> Self {
        Self {
            secure: true,
            tls: true,
            tls_version: Some(TLSVersion(TLS_1_3)),
            quic: true,
            quic_version: version,
            ..Self::default()
        }
    }

    /// Stamps these facts onto a message the connection has just received.
    ///
    /// Every version's connection does this on the way in, which is how
    /// [`Message::security`] comes to be filled in, and doing it here rather
    /// than assigning the field at each of the three keeps the three from
    /// drifting apart.
    pub fn apply(&self, message: &mut Message) {
        message.security = *self;
    }
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

    /// Parses every certificate in one blob, DER or PEM.
    ///
    /// A DER blob carries exactly one certificate; a PEM blob carries as many
    /// as it holds, returned in the order they appear. PEM sections that are
    /// not certificates are skipped, so a file holding a chain and its key
    /// parses to the chain alone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the blob will not parse, or when a PEM blob
    /// carries no certificate at all.
    pub fn certificates(raw: &[u8]) -> Result<Vec<X509>, Error> {
        match Self::of(raw) {
            Self::Der => Ok(vec![X509::from_der(raw).map_err(Error::tls)?]),
            Self::Pem => {
                let parsed = X509::stack_from_pem(raw).map_err(Error::tls)?;

                if parsed.is_empty() {
                    return Err(Error::Tls("PEM data carries no certificate".into()));
                }

                Ok(parsed)
            }
        }
    }

    /// [`Format::certificates`] across several blobs, each DER or PEM.
    ///
    /// Certificates come back in the order the blobs give them, so a chain may
    /// arrive as one PEM bundle, as one blob per certificate, or as a mixture
    /// of the two.
    ///
    /// # Errors
    ///
    /// As [`Format::certificates`].
    pub fn certificate_list(blobs: &[Vec<u8>]) -> Result<Vec<X509>, Error> {
        let mut list = Vec::with_capacity(blobs.len());

        for blob in blobs {
            list.extend(Self::certificates(blob)?);
        }

        Ok(list)
    }

    /// Parses a private key, DER or PEM.
    ///
    /// PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`) and SEC1
    /// (`EC PRIVATE KEY`) are all accepted, in either format; which one it is
    /// is read off the key itself. A key encrypted under a passphrase is not
    /// accepted — decrypt it first, or ship it as PKCS#12 and use
    /// [`Identity::from_pkcs12`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the blob will not parse as any of those.
    pub fn private_key(raw: &[u8]) -> Result<PKey<Private>, Error> {
        match Self::of(raw) {
            Self::Der => PKey::private_key_from_der(raw).map_err(Error::tls),
            Self::Pem => PKey::private_key_from_pem(raw).map_err(Error::tls),
        }
    }
}

/// The TLS details a context is built with, beyond its identity and roots.
///
/// Every field has a working default, so `TlsConfig::default()` changes
/// nothing about how a context would otherwise behave: the profile's cipher
/// suites, BoringSSL's groups, every signature algorithm, the client's suite
/// order, session tickets on, early data off and certificates uncompressed.
///
/// The string fields take the OpenSSL list syntax, entries separated by `:`
/// and most preferred first — the same strings an Nginx `ssl_ciphers`,
/// `ssl_ecdh_curve` or `SignatureAlgorithms` directive would carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// The cipher suites to allow, for TLS 1.2 and 1.3 in one list.
    ///
    /// BoringSSL keeps a built-in preference order for the TLS 1.3 suites, so
    /// entries naming them are tolerated but change nothing; what this
    /// restricts and orders is TLS 1.2. `None` keeps the profile's list.
    pub ciphers: Option<String>,

    /// The key exchange groups to offer, most preferred first.
    ///
    /// Which names exist — `X25519`, `prime256v1`, `secp384r1`, and the
    /// post-quantum hybrids — depends on the BoringSSL linked in. `None`
    /// keeps BoringSSL's defaults.
    pub groups: Option<String>,

    /// The signature algorithms to accept, as `ecdsa_secp384r1_sha384` names.
    ///
    /// `None` accepts everything BoringSSL would.
    pub signature_algorithms: Option<String>,

    /// Whether the server's suite order wins over the client's.
    ///
    /// Read by a server; a client's context ignores it.
    pub prefer_server_ciphers: bool,

    /// Whether sessions may resume over tickets. On by default; turning it
    /// off trades resumption away so no ticket key ever protects a past
    /// session.
    pub session_tickets: bool,

    /// Whether early data is allowed on a resumed session. Off by default;
    /// whether a message actually rode in on it shows in
    /// [`Security::early_data`].
    pub early_data: bool,

    /// Whether certificates are compressed with zlib, as RFC 8879 describes.
    ///
    /// A server compresses what it serves, a client decompresses what it is
    /// served, and either falls back to plain certificates against a peer
    /// that does not join in.
    pub certificate_compression: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ciphers: None,
            groups: None,
            signature_algorithms: None,
            prefer_server_ciphers: false,
            session_tickets: true,
            early_data: false,
            certificate_compression: false,
        }
    }
}

impl TlsConfig {
    /// Applies every setting to a context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when BoringSSL rejects a list — a name it does
    /// not know, or a list that leaves nothing usable.
    pub fn install(&self, builder: &mut SslContextBuilder) -> Result<(), Error> {
        if let Some(ciphers) = &self.ciphers {
            builder.set_cipher_list(ciphers).map_err(Error::tls)?;
        }

        if let Some(groups) = &self.groups {
            builder.set_curves_list(groups).map_err(Error::tls)?;
        }

        if let Some(algorithms) = &self.signature_algorithms {
            builder.set_sigalgs_list(algorithms).map_err(Error::tls)?;
        }

        if self.prefer_server_ciphers {
            builder.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
        }

        if !self.session_tickets {
            builder.set_options(SslOptions::NO_TICKET);
        }

        unsafe { boring_sys::SSL_CTX_set_early_data_enabled(builder.as_ptr(), i32::from(self.early_data)) };

        if self.certificate_compression {
            builder.add_certificate_compression_algorithm(ZlibCertificateCompressor).map_err(Error::tls)?;
        }

        Ok(())
    }

    /// Points a context at the roots it should verify against.
    ///
    /// An empty `roots` leaves the platform's trust store in place; otherwise
    /// only the certificates given are trusted. Each is DER or PEM, so one PEM
    /// bundle of roots is as good as one blob apiece.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when a certificate will not parse or BoringSSL
    /// rejects the store.
    pub fn install_roots(roots: &[Vec<u8>], builder: &mut SslContextBuilder) -> Result<(), Error> {
        if roots.is_empty() {
            builder.set_default_verify_paths().map_err(Error::tls)?;
            return Ok(());
        }

        let mut store = X509StoreBuilder::new().map_err(Error::tls)?;

        for root in Format::certificate_list(roots)? {
            store.add_cert(root).map_err(Error::tls)?;
        }

        builder.set_verify_cert_store(store.build()).map_err(Error::tls)?;
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
    pub fn client(&self, roots: &[Vec<u8>], versions: &[Version]) -> Result<SslConnector, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(Error::tls)?;
        builder.set_alpn_protos(&Alpn::wire(versions)).map_err(Error::tls)?;
        Self::install_roots(roots, &mut builder)?;
        self.install(&mut builder)?;

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
    pub fn server(&self, identity: &Identity, versions: &[Version], ech: Option<&EchKeys>) -> Result<SslAcceptor, Error> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(Error::tls)?;
        identity.install(&mut builder)?;
        self.install(&mut builder)?;

        let offered = Alpn::list(versions);
        builder.set_alpn_select_callback(move |_ssl, client| Alpn::select(&offered, client).ok_or(AlpnError::NOACK));

        if let Some(ech) = ech {
            ech.install(&builder)?;
        }

        Ok(builder.build())
    }

    /// Builds the TLS context a QUIC client uses.
    ///
    /// The server's certificate is verified, against the platform trust store
    /// when `roots` is empty.
    ///
    /// # Errors
    ///
    /// As [`TlsConfig::client`].
    pub fn quic_client(&self, roots: &[Vec<u8>]) -> Result<SslContextBuilder, Error> {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(Error::tls)?;
        Self::install_roots(roots, &mut builder)?;
        self.install(&mut builder)?;

        builder.set_verify(SslVerifyMode::PEER);
        Ok(builder)
    }

    /// Builds the TLS context a QUIC server uses.
    ///
    /// No ALPN callback is installed: `tokio-quiche` handles ALPN itself from
    /// the list in its settings. Peer certificates are not requested, since
    /// HTTP/3 clients do not present them.
    ///
    /// # Errors
    ///
    /// As [`TlsConfig::server`].
    pub fn quic_server(&self, identity: &Identity, ech: Option<&EchKeys>) -> Result<SslContextBuilder, Error> {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(Error::tls)?;
        identity.install(&mut builder)?;
        self.install(&mut builder)?;
        builder.set_verify(SslVerifyMode::NONE);

        if let Some(ech) = ech {
            ech.install(&builder)?;
        }

        Ok(builder)
    }
}

/// Certificate compression with zlib, as RFC 8879 assigns it.
///
/// Works in both directions, so the one algorithm serves a server, which
/// compresses, and a client, which decompresses. [`TlsConfig::install`]
/// registers it when [`TlsConfig::certificate_compression`] asks for it.
pub struct ZlibCertificateCompressor;

impl CertificateCompressor for ZlibCertificateCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        let mut encoder = flate2::write::ZlibEncoder::new(output, flate2::Compression::default());
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        let mut decoder = flate2::write::ZlibDecoder::new(output);
        decoder.write_all(input)?;
        decoder.finish()?;
        Ok(())
    }
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
        let archive = Pkcs12::from_der(raw).map_err(Error::tls)?;
        let passphrase = std::ffi::CString::new(passphrase).map_err(Error::tls)?;

        let mut key = std::ptr::null_mut();
        let mut leaf = std::ptr::null_mut();
        let mut rest = std::ptr::null_mut();

        let opened = unsafe { boring_sys::PKCS12_parse(archive.as_ptr(), passphrase.as_ptr(), &mut key, &mut leaf, &mut rest) };

        let key = (!key.is_null()).then(|| unsafe { PKey::<Private>::from_ptr(key) });
        let leaf = (!leaf.is_null()).then(|| unsafe { X509::from_ptr(leaf) });
        let rest = (!rest.is_null()).then(|| unsafe { Stack::<X509>::from_ptr(rest) });

        if opened != 1 {
            return Err(Error::tls(boring::error::ErrorStack::get()));
        }

        let (Some(key), Some(leaf)) = (key, leaf) else {
            return Err(Error::Tls("the PKCS#12 archive carries no certificate for its key".into()));
        };

        let mut certificates = vec![leaf.to_der().map_err(Error::tls)?];

        for extra in rest.into_iter().flatten() {
            certificates.push(extra.to_der().map_err(Error::tls)?);
        }

        Ok(Self { certificates, key: key.private_key_to_der_pkcs8().map_err(Error::tls)? })
    }

    /// The chain as parsed certificates, leaf first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when a certificate will not parse.
    pub fn chain(&self) -> Result<Vec<X509>, Error> {
        Format::certificate_list(&self.certificates)
    }

    /// The private key, parsed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the key will not parse.
    pub fn private_key(&self) -> Result<PKey<Private>, Error> {
        Format::private_key(&self.key)
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
        builder.set_certificate(&leaf).map_err(Error::tls)?;

        for extra in chain {
            builder.add_extra_chain_cert(extra).map_err(Error::tls)?;
        }

        let key = self.private_key()?;
        builder.set_private_key(&key).map_err(Error::tls)?;
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
        // boring's dhkem_p256_sha256 is misnamed: it initialises the key with
        // EVP_hpke_x25519_hkdf_sha256, matching KEM_X25519_HKDF_SHA256.
        let key = HpkeKey::dhkem_p256_sha256(&self.private_key).map_err(Error::tls)?;
        let mut keys = SslEchKeys::builder().map_err(Error::tls)?;
        keys.add_key(true, &self.config, key).map_err(Error::tls)?;
        builder.set_ech_keys(&keys.build()).map_err(Error::tls)?;
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

