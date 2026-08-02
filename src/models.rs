use std::fmt;
use std::str::FromStr;

use bytes::Bytes;

use crate::errors::Error;
use crate::helpers::text::Text;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TLSVersion(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TLSCipher(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TLSGroup(pub u16);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Port {
    UDS(String),
    TCP(u16),
    QUIC(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub target: String,
}

impl Url {
    pub fn default_port(scheme: &str) -> u16 {
        match scheme {
            "https" | "wss" => 443,
            _ => 80,
        }
    }

    pub fn secure(&self) -> bool {
        matches!(self.scheme.as_str(), "https" | "wss")
    }

    pub fn authority(&self) -> String {
        let bracketed = self.host.contains(':');
        let default = self.port == Self::default_port(&self.scheme);

        match (bracketed, default) {
            (true, true) => format!("[{}]", self.host),
            (true, false) => format!("[{}]:{}", self.host, self.port),
            (false, true) => self.host.clone(),
            (false, false) => format!("{}:{}", self.host, self.port),
        }
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let (scheme, rest) = text.split_once("://").ok_or_else(|| Error::Protocol(format!("url {text:?} has no scheme")))?;
        let scheme = scheme.to_ascii_lowercase();

        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let target = if tail.is_empty() { "/".to_owned() } else { tail.to_owned() };

        let authority = authority.rsplit('@').next().unwrap_or(authority);

        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| Error::Protocol("IPv6 authority is missing its closing bracket".into()))?;

            let port = match after.strip_prefix(':') {
                Some(digits) => Some(digits.parse().map_err(|_| Error::Protocol(format!("port {digits:?} is not a number")))?),
                None if after.is_empty() => None,
                None => return Err(Error::Protocol("IPv6 authority has trailing characters".into())),
            };

            (host.to_owned(), port)
        } else if let Some((host, digits)) = authority.rsplit_once(':') {
            let port = digits.parse().map_err(|_| Error::Protocol(format!("port {digits:?} is not a number")))?;
            (host.to_owned(), Some(port))
        } else {
            (authority.to_owned(), None)
        };

        if host.is_empty() {
            return Err(Error::Protocol(format!("url {text:?} has no host")));
        }

        let port = port.unwrap_or(Self::default_port(&scheme));
        Ok(Self { scheme, host, port, target })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1_0,
    V1_1,
    V2_0,
    V3_0,
}

impl Version {
    pub fn alpn(&self) -> &'static str {
        match self {
            Self::V1_0 => "http/1.0",
            Self::V1_1 => "http/1.1",
            Self::V2_0 => "h2",
            Self::V3_0 => "h3",
        }
    }

    pub fn from_alpn(alpn: &[u8]) -> Option<Self> {
        match alpn {
            b"http/1.0" => Some(Self::V1_0),
            b"http/1.1" => Some(Self::V1_1),
            b"h2" => Some(Self::V2_0),
            b"h3" => Some(Self::V3_0),
            _ => None,
        }
    }

    pub fn major(&self) -> u8 {
        match self {
            Self::V1_0 | Self::V1_1 => 1,
            Self::V2_0 => 2,
            Self::V3_0 => 3,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1_0 => "HTTP/1.0",
            Self::V1_1 => "HTTP/1.1",
            Self::V2_0 => "HTTP/2",
            Self::V3_0 => "HTTP/3",
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V1_0 => "HTTP/1.0",
            Self::V1_1 => "HTTP/1.1",
            Self::V2_0 => "HTTP/2",
            Self::V3_0 => "HTTP/3",
        })
    }
}

impl FromStr for Version {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "HTTP/1.0" => Ok(Self::V1_0),
            "HTTP/1.1" => Ok(Self::V1_1),
            "HTTP/2" => Ok(Self::V2_0),
            "HTTP/3" => Ok(Self::V3_0),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::HEAD => "HEAD",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::DELETE => "DELETE",
            Self::CONNECT => "CONNECT",
            Self::OPTIONS => "OPTIONS",
            Self::TRACE => "TRACE",
            Self::PATCH => "PATCH",
        }
    }

    pub fn safe(&self) -> bool {
        matches!(self, Self::GET | Self::HEAD | Self::OPTIONS | Self::TRACE)
    }

    pub fn idempotent(&self) -> bool {
        self.safe() || matches!(self, Self::PUT | Self::DELETE)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "GET" => Ok(Self::GET),
            "HEAD" => Ok(Self::HEAD),
            "POST" => Ok(Self::POST),
            "PUT" => Ok(Self::PUT),
            "DELETE" => Ok(Self::DELETE),
            "CONNECT" => Ok(Self::CONNECT),
            "OPTIONS" => Ok(Self::OPTIONS),
            "TRACE" => Ok(Self::TRACE),
            "PATCH" => Ok(Self::PATCH),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    UserAgent,
    Origin,
    Proxy,
    Gateway,
    Tunnel,
}

impl Role {
    pub fn is_client(&self) -> bool {
        matches!(self, Self::UserAgent | Self::Proxy)
    }

    pub fn is_server(&self) -> bool {
        matches!(self, Self::Origin | Self::Gateway)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCase {
    Title,
    Lower,
}

impl HeaderCase {
    pub fn write(&self, name: &str, out: &mut bytes::BytesMut) {
        let start = out.len();
        out.extend_from_slice(name.as_bytes());
        self.apply_in_place(&mut out[start..]);
    }

    pub fn apply_in_place(&self, written: &mut [u8]) {
        written.make_ascii_lowercase();

        if matches!(self, Self::Title) {
            if let Some(first) = written.first_mut() {
                *first = first.to_ascii_uppercase();
            }

            let mut at = 0;
            while let Some(offset) = crate::helpers::scan::find(&written[at..], b'-') {
                at += offset + 1;

                match written.get_mut(at) {
                    Some(octet) => *octet = octet.to_ascii_uppercase(),
                    None => break,
                }
            }
        }
    }

    pub fn apply(&self, name: &str) -> String {
        let mut out = bytes::BytesMut::with_capacity(name.len());
        self.write(name, &mut out);
        String::from_utf8(Vec::from(out)).unwrap_or_default()
    }

    pub fn from_version(version: Version) -> Self {
        match version {
            Version::V1_0 | Version::V1_1 => Self::Title,
            Version::V2_0 => Self::Lower,
            Version::V3_0 => Self::Lower,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Data(Bytes),
    Text(String),
    File(String),
}

impl Body {
    pub fn len(&self) -> Option<usize> {
        match self {
            Self::Data(data) => Some(data.len()),
            Self::Text(text) => Some(text.len()),
            Self::File(_) => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    pub async fn bytes(&self) -> Result<Bytes, std::io::Error> {
        match self {
            Self::Data(data) => Ok(data.clone()),
            Self::Text(text) => Ok(Bytes::copy_from_slice(text.as_bytes())),
            Self::File(path) => Ok(Bytes::from(tokio::fs::read(path).await?)),
        }
    }

    pub async fn into_bytes(self) -> Result<Bytes, std::io::Error> {
        match self.into_inline() {
            Ok(data) => Ok(data),
            Err(path) => Ok(Bytes::from(tokio::fs::read(path).await?)),
        }
    }

    pub fn into_inline(self) -> Result<Bytes, String> {
        match self {
            Self::Data(data) => Ok(data),
            Self::Text(text) => Ok(Bytes::from(text.into_bytes())),
            Self::File(path) => Err(path),
        }
    }

    pub fn inline(&self) -> Option<Bytes> {
        match self {
            Self::Data(data) => Some(data.clone()),
            Self::Text(text) => Some(Bytes::copy_from_slice(text.as_bytes())),
            Self::File(_) => None,
        }
    }
}

#[inline]
pub fn bit(matched: bool, index: u32) -> u32 {
    (matched as u32) << index
}

#[inline]
pub fn well_known(name: &str) -> u32 {
    let octets = name.as_bytes();

    let Some(first) = octets.first() else {
        return 0;
    };

    match (octets.len(), first) {
        (2, b't') => bit(name == "te", 0),
        (4, b'h') => bit(name == "host", 1),
        (4, b'd') => bit(name == "date", 2),
        (6, b's') => bit(name == "server", 3),
        (6, b'c') => bit(name == "cookie", 4),
        (7, b'u') => bit(name == "upgrade", 5),
        (8, b'l') => bit(name == "location", 6),
        (10, b'c') => bit(name == "connection", 7),
        (10, b'k') => bit(name == "keep-alive", 8),
        (10, b's') => bit(name == "set-cookie", 9),
        (12, b'c') => bit(name == "content-type", 10),
        (14, b'c') => bit(name == "content-length", 11),
        (16, b'p') => bit(name == "proxy-connection", 12),
        (17, b't') => bit(name == "transfer-encoding", 13),
        (25, b's') => bit(name == "strict-transport-security", 14),
        _ => 0,
    }
}

#[derive(Debug, Clone)]
pub struct Headers {
    fields: Vec<(Text, Text)>,
    present: u32,
}

impl Headers {
    pub fn new() -> Self {
        Self { fields: Vec::new(), present: 0 }
    }

    pub fn with_capacity(fields: usize) -> Self {
        Self { fields: Vec::with_capacity(fields), present: 0 }
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    #[inline]
    pub fn named(stored: &str, name: &str) -> bool {
        if stored.len() != name.len() {
            return false;
        }

        match (stored.as_bytes().first(), name.as_bytes().first()) {
            (Some(stored), Some(name)) if !stored.eq_ignore_ascii_case(name) => return false,
            _ => {}
        }

        stored == name || stored.eq_ignore_ascii_case(name)
    }

    #[inline]
    pub fn absent(&self, name: &str) -> bool {
        let bit = well_known(name);
        bit != 0 && self.present & bit == 0
    }

    pub fn contains(&self, name: &str) -> bool {
        !self.absent(name) && self.fields.iter().any(|(stored, _)| Self::named(stored, name))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        if self.absent(name) {
            return None;
        }

        self.fields.iter().find(|(stored, _)| Self::named(stored, name)).map(|(_, value)| value.as_str())
    }

    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        let fields = if self.absent(name) { &self.fields[..0] } else { &self.fields[..] };

        fields.iter().filter(move |(stored, _)| Self::named(stored, name)).map(|(_, value)| value.as_str())
    }

    pub fn append(&mut self, name: impl Into<Text>, value: impl Into<Text>) {
        let mut name = name.into();
        name.make_ascii_lowercase();

        self.present |= well_known(&name);
        self.fields.push((name, value.into()));
    }

    pub fn append_lowercase(&mut self, name: impl Into<Text>, value: impl Into<Text>) {
        let name = name.into();
        debug_assert!(!name.bytes().any(|byte| byte.is_ascii_uppercase()), "{name:?} is not lowercase");

        self.present |= well_known(&name);
        self.fields.push((name, value.into()));
    }

    pub fn insert(&mut self, name: impl Into<Text>, value: impl Into<Text>) {
        let mut name = name.into();
        name.make_ascii_lowercase();

        if !self.absent(&name) {
            self.fields.retain(|(stored, _)| *stored != name);
        }

        self.present |= well_known(&name);
        self.fields.push((name, value.into()));
    }

    pub fn remove(&mut self, name: &str) -> bool {
        if self.absent(name) {
            return false;
        }

        let len_before = self.fields.len();
        self.fields.retain(|(stored, _)| !Self::named(stored, name));

        if self.fields.len() == len_before {
            return false;
        }

        self.present = self.fields.iter().fold(0, |present, (stored, _)| present | well_known(stored));
        true
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

impl PartialEq for Headers {
    fn eq(&self, other: &Self) -> bool {
        self.fields == other.fields
    }
}

impl Eq for Headers {}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamID(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionID(pub Bytes);

#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub version: Version,

    pub body: Option<Body>,

    pub headers: Option<Headers>,
    pub trailers: Option<Headers>,

    // Connection
    pub stream_id: Option<StreamID>,
    pub connection_id: Option<ConnectionID>,

    pub secure: bool,
    pub early_data: bool,

    // Request
    pub method: Option<Method>,
    pub target: Option<String>,

    // Response
    pub status_code: Option<u16>,

    // TLS
    pub tls: bool,
    pub tls_version: Option<TLSVersion>,
    pub tls_group: Option<TLSGroup>,
    pub tls_cipher: Option<TLSCipher>,

    // QUIC
    pub quic: bool,
    pub quic_version: Option<u32>,
}

impl Message {
    pub fn new(version: Version) -> Self {
        Self {
            version,

            body: None,

            headers: Some(Headers::new()),
            trailers: None,

            stream_id: None,
            connection_id: None,

            secure: false,
            early_data: false,

            method: None,
            target: None,

            status_code: None,

            tls: false,
            tls_version: None,
            tls_group: None,
            tls_cipher: None,

            quic: false,
            quic_version: None,
        }
    }

    pub fn request(method: Method, target: impl Into<String>, version: Version) -> Self {
        Self { method: Some(method), target: Some(target.into()), ..Self::new(version) }
    }

    pub fn response(status_code: u16, version: Version) -> Self {
        Self { status_code: Some(status_code), ..Self::new(version) }
    }

    pub fn is_request(&self) -> bool {
        self.method.is_some()
    }

    pub fn is_response(&self) -> bool {
        self.status_code.is_some()
    }

    pub fn is_informational(&self) -> bool {
        matches!(self.status_code, Some(100..=199))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    pub max_message_size:      u64, // in bytes, The total size of the HTTP message allowed for reception.
    pub max_message_body_size: u64, // in bytes, The size of the HTTP message body allowed for reception.

    pub max_startline_size:    u32, // in bytes, the request/status line ceiling
    pub max_headers_size:      u64, // in bytes, the whole header (or trailer) block
    pub max_header_count:      u16, // the number of header fields allowed in one block
    pub max_chunk_header_size: u32, // in bytes, the chunk-size line ceiling for chunked transfer encoding

    pub max_pending_handshakes: u32, // the number of connections a listener may negotiate at once (mitigates slow handshake floods)

    pub read_timeout: f64,    // in seconds, how long one read may wait for the peer to deliver more octets (0 waits forever)
    pub write_timeout: f64,   // in seconds, how long one write may wait for the peer to accept more octets (0 waits forever)
    pub receive_timeout: f64, // in seconds, how long one whole message may take to arrive once it has begun (0 waits forever)
    pub send_timeout: f64,    // in seconds, how long one whole message may take to send (0 waits forever)

    // HTTP/2 and HTTP/3
    pub max_concurrent_streams:     u32, // the number of streams a peer may have open at once, per connection
    pub max_connection_buffer_size: u64, // in bytes, the unread message data one connection may hold across all of its streams
    pub max_premature_resets:       u32, // the number of streams a peer may reset before a response was sent, per connection (mitigates rapid reset floods)

    // HTTP/2
    pub max_idle_frames:            u32, // the number of frames a peer may send without advancing a stream, per connection (mitigates PING and SETTINGS floods)

    // HTTP/3
    pub qpack_block_timeout:        f64, // in seconds, how long to wait for a blocking QPACK reference to resolve before failing the connection
    pub max_peer_uni_streams:       u32, // the number of unidirectional streams a peer may open at once, per connection
    pub max_outstanding_sections:   u32, // the number of unacknowledged QPACK field sections the encoder may track before it stops referencing the dynamic table

    // WebSocket
    pub ws_linger_timeout: f64,
    pub ws_max_fragments:  u16, // the number of continuation frames allowed in one message

    // Client state
    pub max_cookies:            u32, // the number of cookies one jar may hold across all origins
    pub max_cookies_per_domain: u16, // the number of cookies one jar may hold for a single domain
    pub max_hsts_entries:       u32, // the number of hosts one HSTS store may remember
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024 * 1024,
            max_message_body_size: 64 * 1024 * 1024,

            max_startline_size: 8 * 1024,
            max_headers_size: 64 * 1024,
            max_header_count: 100,
            max_chunk_header_size: 128,

            max_pending_handshakes: 256,

            read_timeout: 30.0,
            write_timeout: 30.0,
            receive_timeout: 300.0,
            send_timeout: 1800.0,

            max_concurrent_streams: 100,
            max_connection_buffer_size: 64 * 1024 * 1024,
            max_premature_resets: 1000,
            max_idle_frames: 1000,

            qpack_block_timeout: 5.0,
            max_peer_uni_streams: 32,
            max_outstanding_sections: 512,

            ws_linger_timeout: 10.0,
            ws_max_fragments: 4096,

            max_cookies: 3000,
            max_cookies_per_domain: 50,
            max_hsts_entries: 4096,
        }
    }
}
