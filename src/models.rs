//! The types every HTTP version shares.
//!
//! A [`Message`] is a request or a response, whichever version framed it, and
//! carries its [`Headers`] and [`Body`] alongside the connection and transport
//! facts a handler may want to see. What one connection may spend on the
//! peer's behalf is bounded by [`Limits`].

use std::fmt;
use std::str::FromStr;

use bytes::Bytes;

use crate::errors::Error;
use crate::helpers::text::Text;
use crate::tls::Security;

/// The transport family a version runs over, and a port carries.
///
/// Which HTTP versions a port can negotiate is exactly the question of
/// whether the two agree here: [`Port::carries`] asks it, and nothing keys on
/// a particular version number, so a future version is routed by what it runs
/// over rather than by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// An ordered byte stream: TCP, or a Unix domain socket.
    Stream,
    /// QUIC, over UDP.
    Quic,
}

/// Somewhere a server listens or a client dials.
///
/// The variant picks the transport, which in turn bounds the HTTP versions
/// that can be negotiated: a port carries exactly the versions whose
/// [`Version::transport`] matches its own, which [`Port::carries`] answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Port {
    /// A Unix domain socket at the given filesystem path.
    UDS(String),
    /// A TCP port.
    TCP(u16),
    /// A UDP port carrying QUIC.
    QUIC(u16),
}

impl Port {
    /// The transport family this port carries.
    pub fn transport(&self) -> TransportKind {
        match self {
            Self::UDS(_) | Self::TCP(_) => TransportKind::Stream,
            Self::QUIC(_) => TransportKind::Quic,
        }
    }

    /// Whether this port can carry `version`, by transport family.
    pub fn carries(&self, version: Version) -> bool {
        self.transport() == version.transport()
    }

    /// The versions this port offers, from those it was configured with.
    ///
    /// A port offers what it [`Port::carries`], in the order given. A QUIC
    /// port keeps only the most preferred of them: QUIC settles its ALPN when
    /// the endpoint is stood up, before any connection arrives, so such a port
    /// has to offer the one version it will actually run rather than offer
    /// several and then turn away whichever a peer picks. A stream transport
    /// negotiates per connection, so it offers them all.
    pub fn offers(&self, versions: &[Version]) -> Vec<Version> {
        let mut offered: Vec<Version> = versions.iter().copied().filter(|version| self.carries(*version)).collect();

        if self.transport() == TransportKind::Quic {
            offered.truncate(1);
        }

        offered
    }
}

/// An absolute URL, split into the parts a request needs.
///
/// `target` is the request target — the path, query and fragment as one string
/// — and is never empty; [`Url::parse`] substitutes `/` when the URL carries
/// no path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// The scheme, lowercased (`http`, `https`, `ws`, `wss`, ...).
    pub scheme: String,
    /// The host, without the brackets an IPv6 literal wears in a URL.
    pub host: String,
    /// The port, defaulted from the scheme when the URL omits one.
    pub port: u16,
    /// The request target, beginning with `/`.
    pub target: String,
}

impl Url {
    /// The port a scheme implies: 443 for `https` and `wss`, 80 otherwise.
    pub fn default_port(scheme: &str) -> u16 {
        match scheme {
            "https" | "wss" => 443,
            _ => 80,
        }
    }

    /// Whether the scheme asks for TLS.
    pub fn secure(&self) -> bool {
        matches!(self.scheme.as_str(), "https" | "wss")
    }

    /// The authority as it belongs in a `Host` field or an `:authority` pseudo-header.
    ///
    /// An IPv6 host is bracketed, and the port is omitted when it is the one
    /// the scheme implies.
    pub fn authority(&self) -> String {
        Self::authority_of(&self.scheme, &self.host, self.port)
    }

    /// [`Url::authority`] for parts that are not held in a [`Url`].
    ///
    /// A caller that dialled a host and a port directly, rather than parsing a
    /// URL, still owes its requests the same authority.
    pub fn authority_of(scheme: &str, host: &str, port: u16) -> String {
        let bracketed = host.contains(':');
        let default = port == Self::default_port(scheme);

        match (bracketed, default) {
            (true, true) => format!("[{host}]"),
            (true, false) => format!("[{host}]:{port}"),
            (false, true) => host.to_owned(),
            (false, false) => format!("{host}:{port}"),
        }
    }

    /// Splits an absolute URL into its parts.
    ///
    /// Userinfo is discarded, an IPv6 literal is unwrapped from its brackets,
    /// and a missing port is filled in from the scheme.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the URL carries no scheme, when an
    /// IPv6 authority is malformed, when the port is not a number, or when
    /// the URL carries no host.
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

/// An HTTP version.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0.
    V1_0,
    /// HTTP/1.1.
    V1_1,
    /// HTTP/2.
    V2_0,
    /// HTTP/3.
    V3_0,
}

impl Version {
    /// The ALPN protocol identifier that selects this version.
    pub fn alpn(&self) -> &'static str {
        match self {
            Self::V1_0 => "http/1.0",
            Self::V1_1 => "http/1.1",
            Self::V2_0 => "h2",
            Self::V3_0 => "h3",
        }
    }

    /// The version an ALPN protocol identifier selects, if it names one.
    pub fn from_alpn(alpn: &[u8]) -> Option<Self> {
        match alpn {
            b"http/1.0" => Some(Self::V1_0),
            b"http/1.1" => Some(Self::V1_1),
            b"h2" => Some(Self::V2_0),
            b"h3" => Some(Self::V3_0),
            _ => None,
        }
    }

    /// The major version number, which is what most version tests care about.
    pub fn major(&self) -> u8 {
        match self {
            Self::V1_0 | Self::V1_1 => 1,
            Self::V2_0 => 2,
            Self::V3_0 => 3,
        }
    }

    /// The transport family this version runs over.
    pub fn transport(&self) -> TransportKind {
        match self {
            Self::V1_0 | Self::V1_1 | Self::V2_0 => TransportKind::Stream,
            Self::V3_0 => TransportKind::Quic,
        }
    }

    /// The version as it is written in an HTTP/1.x start line.
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
        f.write_str(self.as_str())
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

/// ALPN: what versions are offered, and what the handshake settled on.
///
/// The mapping between a [`Version`] and its protocol identifier lives on
/// [`Version::alpn`] and [`Version::from_alpn`]; what is here is the list
/// handling around it — offering several, and reading back the choice.
pub struct Alpn;

impl Alpn {
    /// The ALPN protocol identifiers for a list of versions, one per entry.
    pub fn list(versions: &[Version]) -> Vec<Vec<u8>> {
        versions.iter().map(|version| version.alpn().as_bytes().to_vec()).collect()
    }

    /// [`Alpn::list`] in wire form: each length-prefixed, run together.
    pub fn wire(versions: &[Version]) -> Vec<u8> {
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
    /// entry the client also lists is chosen. `None` when nothing overlaps,
    /// which must fail the handshake rather than fall back to something
    /// unnegotiated.
    pub fn select<'a>(offered: &[Vec<u8>], client: &'a [u8]) -> Option<&'a [u8]> {
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
    /// A peer that selected nothing falls back to HTTP/1.x, which predates
    /// ALPN, and only when that was on offer.
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
}

/// A request method.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    GET,
    /// `HEAD`.
    HEAD,
    /// `POST`.
    POST,
    /// `PUT`.
    PUT,
    /// `DELETE`.
    DELETE,
    /// `CONNECT`, which tunnels rather than carrying a message.
    CONNECT,
    /// `OPTIONS`.
    OPTIONS,
    /// `TRACE`.
    TRACE,
    /// `PATCH`.
    PATCH,
}

impl Method {
    /// The method name as it appears on the wire.
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

    /// Whether the method is read-only, so that issuing it changes nothing.
    pub fn safe(&self) -> bool {
        matches!(self, Self::GET | Self::HEAD | Self::OPTIONS | Self::TRACE)
    }

    /// Whether repeating the method has the same effect as issuing it once.
    ///
    /// Every safe method is idempotent, as are `PUT` and `DELETE`.
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

/// What one end of a connection is doing on it.
///
/// The role decides which side sends requests, which stream identifiers may be
/// opened, and whether the crate fills in server-side fields such as `Date`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Originates requests on its own behalf.
    UserAgent,
    /// Answers requests for the resources it holds.
    Origin,
    /// Forwards requests, acting as a client towards the next hop.
    Proxy,
    /// Answers requests on behalf of something behind it.
    Gateway,
    /// Relays octets without interpreting the messages inside them.
    Tunnel,
}

impl Role {
    /// Whether this role sends requests and reads responses.
    pub fn is_client(&self) -> bool {
        matches!(self, Self::UserAgent | Self::Proxy)
    }

    /// Whether this role reads requests and sends responses.
    pub fn is_server(&self) -> bool {
        matches!(self, Self::Origin | Self::Gateway)
    }
}

/// How field names are cased when they are written out.
///
/// HTTP/1.x field names are case-insensitive but conventionally written in
/// title case; HTTP/2 and HTTP/3 require lowercase. Names are always stored
/// lowercase and re-cased on the way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCase {
    /// `Content-Length`: each dash-separated word capitalised.
    Title,
    /// `content-length`: entirely lowercase.
    Lower,
}

impl HeaderCase {
    /// Appends `name` to `out` in this casing.
    pub fn write(&self, name: &str, out: &mut bytes::BytesMut) {
        let start = out.len();
        out.extend_from_slice(name.as_bytes());
        self.apply_in_place(&mut out[start..]);
    }

    /// Re-cases a field name already written into `written`.
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

    /// Returns `name` in this casing.
    pub fn apply(&self, name: &str) -> String {
        let mut out = bytes::BytesMut::with_capacity(name.len());
        self.write(name, &mut out);
        String::from_utf8(Vec::from(out)).unwrap_or_default()
    }

    /// The casing a version expects: title case for HTTP/1.x, lowercase above.
    pub fn from_version(version: Version) -> Self {
        match version {
            Version::V1_0 | Version::V1_1 => Self::Title,
            Version::V2_0 => Self::Lower,
            Version::V3_0 => Self::Lower,
        }
    }
}

/// The payload of a message.
///
/// [`Body::Data`] and [`Body::Text`] are held in memory and their length is
/// known without doing any work; [`Body::File`] names a path that is read only
/// when the body is actually sent, so its length is not known in advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Octets held in memory.
    Data(Bytes),
    /// A UTF-8 string held in memory.
    Text(String),
    /// A filesystem path, read when the body is needed.
    File(String),
}

impl Body {
    /// The length in octets, or `None` when the body is a file that has not been read.
    pub fn len(&self) -> Option<usize> {
        match self {
            Self::Data(data) => Some(data.len()),
            Self::Text(text) => Some(text.len()),
            Self::File(_) => None,
        }
    }

    /// Whether the body is known to be empty.
    ///
    /// A [`Body::File`] is never reported empty, because its length is unknown
    /// until it is read.
    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    /// The body as octets, reading the file if there is one.
    ///
    /// The filesystem read is boxed, so that a caller awaiting this does not
    /// carry its state machine on the far commoner path where the body is
    /// already in memory.
    ///
    /// # Errors
    ///
    /// Returns the I/O error from reading a [`Body::File`].
    pub async fn bytes(&self) -> Result<Bytes, std::io::Error> {
        match self {
            Self::Data(data) => Ok(data.clone()),
            Self::Text(text) => Ok(Bytes::copy_from_slice(text.as_bytes())),
            Self::File(path) => Ok(Bytes::from(Box::pin(tokio::fs::read(path)).await?)),
        }
    }

    /// Consumes the body and returns its octets, reading the file if there is one.
    ///
    /// The filesystem read is boxed, for the reason [`Body::bytes`] gives.
    ///
    /// # Errors
    ///
    /// Returns the I/O error from reading a [`Body::File`].
    pub async fn into_bytes(self) -> Result<Bytes, std::io::Error> {
        match self.into_inline() {
            Ok(data) => Ok(data),
            Err(path) => Ok(Bytes::from(Box::pin(tokio::fs::read(path)).await?)),
        }
    }

    /// Consumes the body and returns its octets without touching the filesystem.
    ///
    /// # Errors
    ///
    /// Returns the path as the error when the body is a [`Body::File`], so the
    /// caller can decide how to read it.
    pub fn into_inline(self) -> Result<Bytes, String> {
        match self {
            Self::Data(data) => Ok(data),
            Self::Text(text) => Ok(Bytes::from(text.into_bytes())),
            Self::File(path) => Err(path),
        }
    }

    /// The octets already in memory, or `None` for a [`Body::File`].
    pub fn inline(&self) -> Option<Bytes> {
        match self {
            Self::Data(data) => Some(data.clone()),
            Self::Text(text) => Some(Bytes::copy_from_slice(text.as_bytes())),
            Self::File(_) => None,
        }
    }
}

/// A field section: an ordered list of name and value pairs.
///
/// Order is preserved, and a name may repeat — HTTP allows several fields with
/// the same name, and `set-cookie` in particular must never be folded
/// together. Names are stored lowercase and compared case-insensitively.
///
/// Two sections are equal when they hold the same fields in the same order.
#[derive(Debug, Clone)]
pub struct Headers {
    fields: Vec<(Text, Text)>,
    present: u32,
}

impl Headers {

    /// `1 << index` when `matched`, and zero otherwise.
    #[inline]
    pub fn bit(matched: bool, index: u32) -> u32 {
        (matched as u32) << index
    }

    /// The presence bit that stands for a well-known field name, or zero.
    ///
    /// [`Headers`] keeps the bitwise or of these over every field it holds,
    /// which lets a lookup for one of these names rule itself out without
    /// walking the list. The name must already be lowercase. Names outside the
    /// set map to zero, and a zero always forces the full walk.
    #[inline]
    pub fn well_known(name: &str) -> u32 {
        let octets = name.as_bytes();

        let Some(first) = octets.first() else {
            return 0;
        };

        match (octets.len(), first) {
            (2, b't') => Self::bit(name == "te", 0),
            (4, b'h') => Self::bit(name == "host", 1),
            (4, b'd') => Self::bit(name == "date", 2),
            (6, b's') => Self::bit(name == "server", 3),
            (6, b'c') => Self::bit(name == "cookie", 4),
            (7, b'u') => Self::bit(name == "upgrade", 5),
            (8, b'l') => Self::bit(name == "location", 6),
            (10, b'c') => Self::bit(name == "connection", 7),
            (10, b'k') => Self::bit(name == "keep-alive", 8),
            (10, b's') => Self::bit(name == "set-cookie", 9),
            (12, b'c') => Self::bit(name == "content-type", 10),
            (14, b'c') => Self::bit(name == "content-length", 11),
            (16, b'p') => Self::bit(name == "proxy-connection", 12),
            (17, b't') => Self::bit(name == "transfer-encoding", 13),
            (25, b's') => Self::bit(name == "strict-transport-security", 14),
            _ => 0,
        }
    }

    /// An empty section.
    pub fn new() -> Self {
        Self { fields: Vec::new(), present: 0 }
    }

    /// An empty section with room for `fields` entries.
    pub fn with_capacity(fields: usize) -> Self {
        Self { fields: Vec::with_capacity(fields), present: 0 }
    }

    /// The number of fields, counting repeats separately.
    #[inline]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the section holds no fields at all.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Whether a stored name matches `name`, ignoring ASCII case.
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

    /// Whether the presence bits prove `name` is not here.
    ///
    /// Answers `false` for any name outside the well-known set, in which case
    /// the caller still has to walk the list.
    #[inline]
    pub fn absent(&self, name: &str) -> bool {
        let bit = Self::well_known(name);
        bit != 0 && self.present & bit == 0
    }

    /// Whether any field carries this name.
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        !self.absent(name) && self.fields.iter().any(|(stored, _)| Self::named(stored, name))
    }

    /// The value of the first field with this name.
    #[inline]
    pub fn get(&self, name: &str) -> Option<&str> {
        if self.absent(name) {
            return None;
        }

        self.fields.iter().find(|(stored, _)| Self::named(stored, name)).map(|(_, value)| value.as_str())
    }

    /// The values of every field with this name, in order.
    #[inline]
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        let fields = if self.absent(name) { &self.fields[..0] } else { &self.fields[..] };

        fields.iter().filter(move |(stored, _)| Self::named(stored, name)).map(|(_, value)| value.as_str())
    }

    /// Adds a field, keeping any field that already carries this name.
    ///
    /// The name is lowercased on the way in.
    pub fn append(&mut self, name: impl Into<Text>, value: impl Into<Text>) {
        let mut name = name.into();
        name.make_ascii_lowercase();

        self.present |= Self::well_known(&name);
        self.fields.push((name, value.into()));
    }

    /// [`Headers::append`] for a name already known to be lowercase.
    ///
    /// # Panics
    ///
    /// Debug builds assert that the name carries no uppercase ASCII.
    pub fn append_lowercase(&mut self, name: impl Into<Text>, value: impl Into<Text>) {
        let name = name.into();
        debug_assert!(!name.bytes().any(|byte| byte.is_ascii_uppercase()), "{name:?} is not lowercase");

        self.present |= Self::well_known(&name);
        self.fields.push((name, value.into()));
    }

    /// Adds a field, dropping every field that already carries this name.
    ///
    /// The new field goes at the end. The name is lowercased on the way in.
    pub fn insert(&mut self, name: impl Into<Text>, value: impl Into<Text>) {
        let mut name = name.into();
        name.make_ascii_lowercase();

        if !self.absent(&name) {
            self.fields.retain(|(stored, _)| *stored != name);
        }

        self.present |= Self::well_known(&name);
        self.fields.push((name, value.into()));
    }

    /// Drops every field with this name, reporting whether any were there.
    pub fn remove(&mut self, name: &str) -> bool {
        if self.absent(name) {
            return false;
        }

        let len_before = self.fields.len();
        self.fields.retain(|(stored, _)| !Self::named(stored, name));

        if self.fields.len() == len_before {
            return false;
        }

        self.present = self.fields.iter().fold(0, |present, (stored, _)| present | Self::well_known(stored));
        true
    }

    /// Every field in order, as name and value pairs.
    #[inline]
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

/// A stream identifier within one connection.
///
/// HTTP/1.x has no streams and leaves this unset. HTTP/2 numbers streams from
/// 1, and HTTP/3 uses the QUIC stream identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamID(pub u64);

/// An opaque label for one connection, used to tell connections apart in logs
/// and to key state a handler wants to keep per peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionID(pub Bytes);

/// One HTTP request or response, whichever version framed it.
///
/// A message is a request when it carries a [`Message::method`] and a response
/// when it carries a [`Message::status_code`]; exactly one of the two is set
/// on a well-formed message. The remaining fields describe the connection the
/// message arrived on or is going out over, and are filled in by whichever
/// connection handled it.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    /// The version that framed this message, or is about to.
    pub version: Version,

    /// The payload, if there is one.
    pub body: Option<Body>,

    /// The field section that precedes the body.
    pub headers: Option<Headers>,
    /// The field section that follows the body, if the peer sent one.
    pub trailers: Option<Headers>,

    // Connection
    /// The stream this message belongs to, for HTTP/2 and HTTP/3.
    ///
    /// A server answering a request must echo the request's stream identifier
    /// back on the response, so the two are matched up.
    pub stream_id: Option<StreamID>,
    /// The connection this message arrived on.
    pub connection_id: Option<ConnectionID>,

    /// What the transport the message crossed turned out to be.
    ///
    /// Stamped on by whichever connection received it, by [`Security::apply`].
    /// A message the caller built has crossed nothing, so everything here
    /// reads as absent on one until it does.
    pub security: Security,

    // Request
    /// The request method, set on requests only.
    pub method: Option<Method>,
    /// The request target, set on requests only.
    ///
    /// Ordinarily a path; for a `CONNECT` without `:protocol`, an authority.
    pub target: Option<String>,

    // Response
    /// The status code, set on responses only.
    pub status_code: Option<u16>,
}

impl Message {

    /// Whether this message leaves its stream open as a tunnel.
    ///
    /// `method` is the method of the request the stream carries. A `CONNECT`
    /// whose response succeeded is followed by tunnelled octets rather than by
    /// the end of the stream, which is what HTTP/2 and HTTP/3 both have to
    /// account for.
    pub fn tunneling(&self, method: Option<Method>) -> bool {
        method == Some(Method::CONNECT) && (self.is_request() || matches!(self.status_code, Some(200..=299)))
    }

    /// An empty message with an empty field section and nothing else set.
    ///
    /// It is neither a request nor a response until a method or a status code
    /// is set; [`Message::request`] and [`Message::response`] do that for you.
    pub fn new(version: Version) -> Self {
        Self {
            version,

            body: None,

            headers: Some(Headers::new()),
            trailers: None,

            stream_id: None,
            connection_id: None,

            security: Security::default(),

            method: None,
            target: None,

            status_code: None,
        }
    }

    /// A request for `target`.
    pub fn request(method: Method, target: impl Into<String>, version: Version) -> Self {
        Self { method: Some(method), target: Some(target.into()), ..Self::new(version) }
    }

    /// A response carrying `status_code`.
    pub fn response(status_code: u16, version: Version) -> Self {
        Self { status_code: Some(status_code), ..Self::new(version) }
    }

    /// Whether this message is a request.
    pub fn is_request(&self) -> bool {
        self.method.is_some()
    }

    /// Whether this message is a response.
    pub fn is_response(&self) -> bool {
        self.status_code.is_some()
    }

    /// Whether this is a 1xx response, which precedes the real one.
    pub fn is_informational(&self) -> bool {
        matches!(self.status_code, Some(100..=199))
    }
}

/// What one connection is allowed to spend on the peer's behalf.
///
/// Every field is a ceiling: exceeding one produces [`Error::Limit`] and, for
/// the counters that exist to blunt floods, tears the connection down. The
/// defaults are meant to be usable as they stand for a public-facing server.
///
/// Timeouts are in seconds, and zero means wait forever.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    /// In bytes, the total size of the HTTP message allowed for reception.
    pub max_message_size:      u64,
    /// In bytes, the size of the HTTP message body allowed for reception.
    pub max_message_body_size: u64,

    /// In bytes, the request/status line ceiling.
    pub max_startline_size:    u32,
    /// In bytes, the whole header (or trailer) block.
    pub max_headers_size:      u64,
    /// The number of header fields allowed in one block.
    pub max_header_count:      u16,
    /// In bytes, the chunk-size line ceiling for chunked transfer encoding.
    pub max_chunk_header_size: u32,

    /// In bytes, how much room each read from a transport is given.
    ///
    /// Reads start at a fraction of this and ramp up to it as long as they
    /// keep coming back full, so a small message costs a small read while a
    /// large body reaches the full size. It sizes the read rather than capping
    /// it: a read that finds spare room already in the buffer may return more.
    /// See [`Buffer::set_chunk_size`].
    ///
    /// [`Buffer::set_chunk_size`]: crate::protocol::common::Buffer::set_chunk_size
    pub read_chunk_size: u64,
    /// In bytes, the buffer size above which an idle connection gives memory back.
    pub idle_capacity: u64,

    /// The number of connections a listener may negotiate at once (mitigates slow handshake floods).
    pub max_pending_handshakes: u32,

    /// In seconds, how long one read may wait for the peer to deliver more octets (0 waits forever).
    pub read_timeout: f64,
    /// In seconds, how long one write may wait for the peer to accept more octets (0 waits forever).
    pub write_timeout: f64,
    /// In seconds, how long one whole message may take to arrive once it has begun (0 waits forever).
    pub receive_timeout: f64,
    /// In seconds, how long one whole message may take to send (0 waits forever).
    pub send_timeout: f64,

    // HTTP/1
    /// In bytes, the body size up to which the head and the body go out as one write.
    ///
    /// Below this, coalescing saves a syscall and a round trip; above it,
    /// copying the body into the head buffer costs more than the extra write.
    pub inline_body_size: u64,

    // HTTP/2 and HTTP/3
    /// The number of streams a peer may have open at once, per connection.
    pub max_concurrent_streams:     u32,
    /// In bytes, the unread message data one connection may hold across all of its streams.
    pub max_connection_buffer_size: u64,
    /// The number of streams a peer may reset before a response was sent, per connection (mitigates rapid reset floods).
    pub max_premature_resets:       u32,

    /// In bytes, the largest field compression encoder table this end will keep, whatever the peer allows.
    ///
    /// The HPACK table for HTTP/2 and the QPACK one for HTTP/3; both are this
    /// end's own ceiling, held to whether or not the peer permits more.
    pub max_encoder_table_size:     u64,

    // HTTP/2
    /// The number of frames a peer may send without advancing a stream, per connection (mitigates PING and SETTINGS floods).
    pub max_idle_frames:            u32,
    /// In bytes, the buffered output size at which a body write flushes rather than growing.
    pub output_high_water:          u64,

    // HTTP/3
    /// The number of requests one connection may serve over its lifetime before it is wound down with GOAWAY (0 serves forever).
    ///
    /// Distinct from [`Limits::max_concurrent_streams`], which bounds how many
    /// are open at once: this bounds the total. The QUIC stack underneath
    /// keeps a trace of every stream a connection has ever closed, so a
    /// connection that never ends grows without bound under continuous load;
    /// winding it down lets a well-behaved peer reconnect and gives all of
    /// that back.
    pub max_requests_per_connection: u64,
    /// In seconds, how long to wait for a blocking QPACK reference to resolve before failing the connection.
    pub qpack_block_timeout:        f64,
    /// The number of unidirectional streams a peer may open at once, per connection.
    pub max_peer_uni_streams:       u32,
    /// The number of unacknowledged QPACK field sections the encoder may track before it stops referencing the dynamic table.
    pub max_outstanding_sections:   u32,
    /// The number of streams that may wait QPACK-blocked at once, advertised as `SETTINGS_QPACK_BLOCKED_STREAMS`.
    pub max_blocked_streams:        u32,
    /// The number of reads or writes a tunnel will hold before it applies back pressure.
    pub tunnel_backlog:             u32,
    /// The number of commands or events queued between a connection handle and the worker driving it.
    pub command_backlog:            u32,

    // WebSocket
    /// In seconds, how long a close waits for the peer to echo it back before the transport is shut down.
    pub ws_linger_timeout: f64,
    /// The number of continuation frames allowed in one message.
    pub ws_max_fragments:  u16,

    // Client state
    /// The number of cookies one jar may hold across all origins.
    pub max_cookies:            u32,
    /// The number of cookies one jar may hold for a single domain.
    pub max_cookies_per_domain: u16,
    /// The number of hosts one HSTS store may remember.
    pub max_hsts_entries:       u32,
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

            read_chunk_size: 16 * 1024,
            idle_capacity: 64 * 1024,

            max_pending_handshakes: 256,

            read_timeout: 30.0,
            write_timeout: 30.0,
            receive_timeout: 300.0,
            send_timeout: 1800.0,

            inline_body_size: 64 * 1024,

            max_concurrent_streams: 100,
            max_connection_buffer_size: 64 * 1024 * 1024,
            max_premature_resets: 1000,
            max_encoder_table_size: 64 * 1024,
            max_idle_frames: 1000,
            output_high_water: 64 * 1024,

            max_requests_per_connection: 10_000,
            qpack_block_timeout: 5.0,
            max_peer_uni_streams: 32,
            max_outstanding_sections: 512,
            max_blocked_streams: 16,
            tunnel_backlog: 32,
            command_backlog: 256,

            ws_linger_timeout: 10.0,
            ws_max_fragments: 4096,

            max_cookies: 3000,
            max_cookies_per_domain: 50,
            max_hsts_entries: 4096,
        }
    }
}
