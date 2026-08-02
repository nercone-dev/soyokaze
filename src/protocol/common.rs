use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::helpers::hpack::HeaderField;
use crate::helpers::text::Text;
use crate::models::{ConnectionID, Headers, Message, Method, Role, StreamID, Version};
use crate::protocol::{h1::H1Connection, h2::H2Connection, h3::H3Connection};

pub use crate::errors::Error;

pub fn random(out: &mut [u8]) -> Result<(), Error> {
    boring::rand::rand_bytes(out).map_err(|_| Error::Tls("BoringSSL has no source of randomness".into()))
}

pub fn duration(seconds: f64) -> Option<Duration> {
    (seconds.is_finite() && seconds > 0.0).then(|| Duration::from_secs_f64(seconds))
}

pub async fn within<T>(seconds: f64, operation: impl Future<Output = T>) -> Result<T, Error> {
    let Some(wait) = duration(seconds) else {
        return Ok(operation.await);
    };

    let mut operation = std::pin::pin!(operation);

    if let Poll::Ready(value) = std::future::poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx))).await {
        return Ok(value);
    }

    tokio::time::timeout(wait, operation)
        .await
        .map_err(|_| Error::Timeout(format!("nothing arrived within {seconds}s")))
}

#[derive(Default)]
pub struct StreamHasher(u64);

impl std::hash::Hasher for StreamHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, octets: &[u8]) {
        for octet in octets {
            self.write_u64(*octet as u64 ^ self.0);
        }
    }

    fn write_u64(&mut self, value: u64) {
        let mixed = value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = mixed ^ mixed >> 32;
    }

    fn write_u32(&mut self, value: u32) {
        self.write_u64(value as u64);
    }
}

pub type StreamMap<K, V> = std::collections::HashMap<K, V, std::hash::BuildHasherDefault<StreamHasher>>;

pub const IDLE_CAPACITY: usize = 64 * 1024;

pub fn oversized(capacity: usize, len: usize) -> bool {
    capacity > IDLE_CAPACITY && len <= IDLE_CAPACITY / 2
}

pub fn reclaim(buffer: &mut BytesMut) {
    if oversized(buffer.capacity(), buffer.len()) {
        let mut fresh = BytesMut::new();
        fresh.extend_from_slice(buffer);
        *buffer = fresh;
    }
}

pub fn reclaim_octets(buffer: &mut Vec<u8>) {
    if oversized(buffer.capacity(), buffer.len()) {
        buffer.shrink_to(IDLE_CAPACITY / 2);
    }
}

pub struct Buffer {
    data: BytesMut,
    chunk: usize,
    eof: bool,
}

impl Buffer {
    pub const CHUNK_SIZE: usize = 16 * 1024;
    pub const FIRST_CHUNK: usize = 2 * 1024;

    pub fn new() -> Self {
        Self { data: BytesMut::new(), chunk: Self::FIRST_CHUNK, eof: false }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn eof(&self) -> bool {
        self.eof
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn consume(&mut self, count: usize) {
        self.data.advance(count.min(self.data.len()));
    }

    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    pub fn reclaim(&mut self) {
        reclaim(&mut self.data);
    }

    pub fn take(&mut self, count: usize) -> BytesMut {
        self.data.split_to(count.min(self.data.len()))
    }

    pub async fn fill<T>(&mut self, transport: &mut T, timeout: f64) -> Result<bool, Error>
    where
        T: AsyncRead + Unpin,
    {
        if self.eof {
            return Ok(false);
        }

        self.data.reserve(self.chunk);

        let read = within(timeout, transport.read_buf(&mut self.data)).await??;
        if read == 0 {
            self.eof = true;
            return Ok(false);
        }

        if read >= self.chunk {
            self.chunk = self.chunk.saturating_mul(2).min(Self::CHUNK_SIZE);
        }

        Ok(true)
    }

    pub async fn require<T>(&mut self, transport: &mut T, count: usize, timeout: f64) -> Result<&[u8], Error>
    where
        T: AsyncRead + Unpin,
    {
        while self.data.len() < count && self.fill(transport, timeout).await? {}

        if self.data.len() < count {
            return Err(Error::Closed);
        }

        Ok(&self.data[..count])
    }

    pub async fn line_end<T>(&mut self, transport: &mut T, max: usize, timeout: f64) -> Result<usize, Error>
    where
        T: AsyncRead + Unpin,
    {
        let mut searched = 0;

        loop {
            if let Some(offset) = crate::helpers::scan::find(&self.data[searched..], b'\n') {
                let end = searched + offset;
                if end == 0 || self.data[end - 1] != b'\r' {
                    return Err(Error::Protocol("line is not terminated by CRLF".into()));
                }

                if end - 1 > max {
                    return Err(Error::Limit(format!("line exceeds {max} octets")));
                }

                return Ok(end - 1);
            }

            searched = self.data.len();
            if searched > max {
                return Err(Error::Limit(format!("line exceeds {max} octets")));
            }

            if !self.fill(transport, timeout).await? {
                return Err(Error::Closed);
            }
        }
    }

    pub async fn line<T>(&mut self, transport: &mut T, max: usize, timeout: f64) -> Result<String, Error>
    where
        T: AsyncRead + Unpin,
    {
        let mut searched = 0;

        loop {
            if let Some(offset) = crate::helpers::scan::find(&self.data[searched..], b'\n') {
                let end = searched + offset;
                if end == 0 || self.data[end - 1] != b'\r' {
                    return Err(Error::Protocol("line is not terminated by CRLF".into()));
                }

                if end - 1 > max {
                    return Err(Error::Limit(format!("line exceeds {max} octets")));
                }

                let line = String::from_utf8_lossy(&self.data[..end - 1]).into_owned();
                self.consume(end + 1);
                return Ok(line);
            }

            searched = self.data.len();
            if searched > max {
                return Err(Error::Limit(format!("line exceeds {max} octets")));
            }

            if !self.fill(transport, timeout).await? {
                return Err(Error::Closed);
            }
        }
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

pub const PSEUDO_REQUEST: &[&str] = &[":method", ":scheme", ":authority", ":path", ":protocol"];
pub const PSEUDO_RESPONSE: &[&str] = &[":status"];

pub const CONNECTION_SPECIFIC: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

pub fn is_connection_specific(name: &str) -> bool {
    matches!(name.len(), 7 | 10 | 16 | 17) && CONNECTION_SPECIFIC.contains(&name)
}

pub const PSEUDO_METHOD: u8 = 1 << 0;
pub const PSEUDO_STATUS: u8 = 1 << 1;
pub const PSEUDO_SCHEME: u8 = 1 << 2;
pub const PSEUDO_PATH: u8 = 1 << 3;
pub const PSEUDO_AUTHORITY: u8 = 1 << 4;
pub const PSEUDO_PROTOCOL: u8 = 1 << 5;

pub fn status_text(status_code: u16) -> Text {
    if !(100..1000).contains(&status_code) {
        return Text::from_string(status_code.to_string());
    }

    let digits = [
        b'0' + (status_code / 100) as u8,
        b'0' + (status_code / 10 % 10) as u8,
        b'0' + (status_code % 10) as u8,
    ];

    Text::from_verified_ascii(&digits)
}

pub fn fields(message: &Message) -> Result<Vec<HeaderField>, Error> {
    let mut fields = Vec::with_capacity(PSEUDO_REQUEST.len() + message.headers.as_ref().map_or(0, Headers::len));

    if let Some(method) = message.method {
        let target = message.target.as_deref().unwrap_or("/");
        let headers = message.headers.as_ref();

        fields.push(HeaderField::new(":method", method.as_str()));

        let protocol = headers.and_then(|headers| headers.get(":protocol"));
        if method == Method::CONNECT && protocol.is_none() {
            fields.push(HeaderField::new(":authority", target));
        } else {
            fields.push(HeaderField::new(":scheme", if message.secure { "https" } else { "http" }));

            if let Some(authority) = headers.and_then(|headers| headers.get("host")) {
                fields.push(HeaderField::new(":authority", authority));
            }

            fields.push(HeaderField::new(":path", target));

            if let Some(protocol) = protocol {
                fields.push(HeaderField::new(":protocol", protocol));
            }
        }
    } else if let Some(status_code) = message.status_code {
        fields.push(HeaderField::new(":status", status_text(status_code)));
    } else {
        return Err(Error::Protocol("message is neither a request nor a response".into()));
    }

    if let Some(headers) = &message.headers {
        for (name, value) in headers.iter() {
            if name.starts_with(':') || name == "host" {
                continue;
            }

            if is_connection_specific(name) {
                return Err(Error::Protocol(format!("connection-specific field {name:?} cannot be framed")));
            }

            fields.push(HeaderField::new(name, value));
        }
    }

    Ok(fields)
}

pub fn message(fields: &[HeaderField], version: Version) -> Result<Message, Error> {
    message_from(fields.to_vec(), version)
}

pub fn message_from(fields: Vec<HeaderField>, version: Version) -> Result<Message, Error> {
    let mut message = Message::new(version);
    let mut headers = Headers::with_capacity(fields.len() + 1);
    let mut regular = false;

    let mut seen = 0u8;
    let mut authority: Option<Text> = None;
    let mut path: Option<Text> = None;

    for field in fields {
        if field.name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(Error::Protocol(format!("field name {:?} is not lowercase", field.name)));
        }

        if !field.name.starts_with(':') {
            if is_connection_specific(&field.name) {
                return Err(Error::Protocol(format!("connection-specific field {:?} cannot be framed", field.name)));
            }

            if field.name == "te" && field.value != "trailers" {
                return Err(Error::Protocol("TE may only request trailers".into()));
            }

            regular = true;
            headers.append_lowercase(field.name, field.value);
            continue;
        }

        if regular {
            return Err(Error::Protocol(format!("pseudo-header {:?} follows a regular field", field.name)));
        }

        let pseudo = match field.name.as_str() {
            ":method" => PSEUDO_METHOD,
            ":status" => PSEUDO_STATUS,
            ":scheme" => PSEUDO_SCHEME,
            ":path" => PSEUDO_PATH,
            ":authority" => PSEUDO_AUTHORITY,
            ":protocol" => PSEUDO_PROTOCOL,
            name => return Err(Error::Protocol(format!("pseudo-header {name:?} is not defined"))),
        };

        if seen & pseudo != 0 {
            return Err(Error::Protocol(format!("pseudo-header {:?} is repeated", field.name)));
        }
        seen |= pseudo;

        match pseudo {
            PSEUDO_METHOD => {
                message.method = Some(
                    field
                        .value
                        .parse()
                        .map_err(|_| Error::Protocol(format!("method {:?} is not recognised", field.value)))?,
                );
            }
            PSEUDO_STATUS => {
                if field.value.len() != 3 || !field.value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(Error::Protocol(format!("status {:?} is not three digits", field.value)));
                }
                message.status_code = Some(
                    field
                        .value
                        .parse()
                        .map_err(|_| Error::Protocol(format!("status {:?} is not three digits", field.value)))?,
                );
            }
            PSEUDO_SCHEME => message.secure = field.value == "https",
            PSEUDO_AUTHORITY => authority = Some(field.value.clone()),
            PSEUDO_PATH => path = Some(field.value.clone()),
            _ => {}
        }

        headers.append_lowercase(field.name, field.value);
    }

    let stray = if message.method.is_some() {
        (seen & PSEUDO_STATUS != 0).then_some(":status")
    } else {
        [
            (PSEUDO_METHOD, ":method"),
            (PSEUDO_SCHEME, ":scheme"),
            (PSEUDO_PATH, ":path"),
            (PSEUDO_AUTHORITY, ":authority"),
            (PSEUDO_PROTOCOL, ":protocol"),
        ]
        .into_iter()
        .find_map(|(bit, name)| (seen & bit != 0).then_some(name))
    };

    if let Some(name) = stray {
        return Err(Error::Protocol(format!("pseudo-header {name:?} does not belong to this message")));
    }

    if message.method.is_none() && message.status_code.is_none() {
        return Err(Error::Protocol("message has neither :method nor :status".into()));
    }

    if let Some(method) = message.method {
        if method == Method::CONNECT && seen & PSEUDO_PROTOCOL == 0 {
            message.target = authority.as_deref().map(str::to_owned);
            if message.target.is_none() || seen & (PSEUDO_SCHEME | PSEUDO_PATH) != 0 {
                return Err(Error::Protocol("CONNECT carries an authority and nothing else".into()));
            }
        } else {
            let path = path.unwrap_or_default();
            if path.is_empty() || seen & PSEUDO_SCHEME == 0 {
                return Err(Error::Protocol("request needs both a scheme and a non-empty path".into()));
            }
            message.target = Some(path.into_string());
        }

        if let Some(authority) = authority {
            headers.insert("host", authority);
        }
    }

    message.headers = Some(headers);
    Ok(message)
}

#[allow(async_fn_in_trait)]
pub trait Connection {
    fn version(&self) -> Version;
    fn role(&self) -> Role;
    fn id(&self) -> ConnectionID;

    fn reusable(&self) -> bool {
        true
    }

    async fn send(&mut self, message: Message) -> Result<(), Error>;
    async fn receive(&mut self) -> Result<Message, Error>;

    async fn close(&mut self);
}

#[allow(async_fn_in_trait)]
pub trait Stream {
    fn id(&self) -> StreamID;

    async fn reset(&mut self, code: u64);
}

pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

#[allow(clippy::large_enum_variant)]
pub enum AnyConnection {
    H1(H1Connection<Box<dyn Transport>>),
    H2(H2Connection<Box<dyn Transport>>),
    H3(H3Connection),
}

impl Connection for AnyConnection {
    fn version(&self) -> Version {
        match self {
            Self::H1(connection) => connection.version(),
            Self::H2(connection) => connection.version(),
            Self::H3(connection) => connection.version(),
        }
    }

    fn role(&self) -> Role {
        match self {
            Self::H1(connection) => connection.role(),
            Self::H2(connection) => connection.role(),
            Self::H3(connection) => connection.role(),
        }
    }

    fn id(&self) -> ConnectionID {
        match self {
            Self::H1(connection) => connection.id(),
            Self::H2(connection) => connection.id(),
            Self::H3(connection) => connection.id(),
        }
    }

    fn reusable(&self) -> bool {
        match self {
            Self::H1(connection) => connection.reusable(),
            Self::H2(connection) => connection.reusable(),
            Self::H3(connection) => connection.reusable(),
        }
    }

    async fn send(&mut self, message: Message) -> Result<(), Error> {
        match self {
            Self::H1(connection) => connection.send(message).await,
            Self::H2(connection) => connection.send(message).await,
            Self::H3(connection) => connection.send(message).await,
        }
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        match self {
            Self::H1(connection) => connection.receive().await,
            Self::H2(connection) => connection.receive().await,
            Self::H3(connection) => connection.receive().await,
        }
    }

    async fn close(&mut self) {
        match self {
            Self::H1(connection) => connection.close().await,
            Self::H2(connection) => connection.close().await,
            Self::H3(connection) => connection.close().await,
        }
    }
}
