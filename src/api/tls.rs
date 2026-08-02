use boring::hpke::HpkeKey;
use boring::pkey::PKey;
use boring::ssl::{AlpnError, SslAcceptor, SslConnector, SslContextBuilder, SslEchKeys, SslMethod, SslVerifyMode};
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;

use crate::errors::Error;
use crate::models::Version;

pub fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::Tls(error.to_string())
}

pub fn alpn(versions: &[Version]) -> Vec<Vec<u8>> {
    versions.iter().map(|version| version.alpn().as_bytes().to_vec()).collect()
}

pub fn alpn_wire(versions: &[Version]) -> Vec<u8> {
    let mut out = Vec::new();

    for version in versions {
        let protocol = version.alpn().as_bytes();
        out.push(protocol.len() as u8);
        out.extend_from_slice(protocol);
    }

    out
}

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

#[derive(Debug, Clone)]
pub struct Identity {
    pub certificates: Vec<Vec<u8>>,
    pub key: Vec<u8>,
}

impl Identity {
    pub fn new(certificates: Vec<Vec<u8>>, key: Vec<u8>) -> Self {
        Self { certificates, key }
    }
}

pub const ECH_VERSION: u16 = 0xfe0d;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    pub version: u16,
    pub public_name: String,
    pub maximum_name_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfigList {
    pub configs: Vec<EchConfig>,
}

impl EchConfigList {
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

#[derive(Debug, Clone)]
pub struct EchKeys {
    pub config: Vec<u8>,      // one ECHConfig: version(2) || length(2) || contents
    pub private_key: Vec<u8>, // the raw X25519 HPKE private key (32 bytes)
}

impl EchKeys {
    pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
    pub const KDF_HKDF_SHA256: u16 = 0x0001;
    pub const AEAD_AES_128_GCM: u16 = 0x0001;

    pub const MAXIMUM_NAME_LENGTH: u8 = 64;

    pub fn generate(public_name: &str, config_id: u8) -> Result<Self, Error> {
        let mut public = [0u8; 32];
        let mut private = [0u8; 32];
        unsafe { boring_sys::X25519_keypair(public.as_mut_ptr(), private.as_mut_ptr()) };

        Ok(Self { config: Self::encode(public_name, config_id, &public), private_key: private.to_vec() })
    }

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

    pub fn config_list(&self) -> Vec<u8> {
        let mut list = (self.config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&self.config);
        list
    }

    pub fn install(&self, builder: &SslContextBuilder) -> Result<(), Error> {
        let key = HpkeKey::dhkem_p256_sha256(&self.private_key).map_err(tls_error)?;
        let mut keys = SslEchKeys::builder().map_err(tls_error)?;
        keys.add_key(true, &self.config, key).map_err(tls_error)?;
        builder.set_ech_keys(&keys.build()).map_err(tls_error)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchStatus {
    pub accepted: bool,
}

impl EchStatus {
    pub fn of(ssl: &boring::ssl::SslRef) -> Self {
        Self { accepted: ssl.ech_accepted() }
    }

    pub fn succeeded(&self) -> bool {
        self.accepted
    }
}

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

pub struct QuicServerTls {
    pub identity: Identity,
    pub ech: Option<EchKeys>,
}

impl tokio_quiche::quic::ConnectionHook for QuicServerTls {
    fn create_custom_ssl_context_builder(&self, _settings: tokio_quiche::settings::TlsCertificatePaths<'_>) -> Option<SslContextBuilder> {
        quic_server_context(&self.identity, self.ech.as_ref()).ok()
    }
}

pub struct QuicClientTls {
    pub roots: Vec<Vec<u8>>,
}

impl tokio_quiche::quic::ConnectionHook for QuicClientTls {
    fn create_custom_ssl_context_builder(&self, _settings: tokio_quiche::settings::TlsCertificatePaths<'_>) -> Option<SslContextBuilder> {
        quic_client_context(&self.roots).ok()
    }
}
