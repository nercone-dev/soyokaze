//! The vocabulary every HTTP version shares.
//!
//! The traits a connection satisfies live in [`base`]; what is here is the
//! machinery the versions share to satisfy them: the [`Buffer`] between a
//! transport and a parser, the timeout plumbing, and the conversion between a
//! [`Message`] and a field list, in [`fields`] and [`message_from`]. HTTP/2
//! and HTTP/3 both carry the start line as pseudo-headers, and both must
//! enforce the same rules about them, so doing it once keeps the two from
//! drifting apart.
//!
//! [`base`]: crate::protocol::base

use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::helpers::hpack::HeaderField;
use crate::helpers::text::Text;
use crate::models::{Headers, Message, Method, Version};

pub use crate::errors::Error;

/// Fills `out` with cryptographically secure random octets.
///
/// # Errors
///
/// Returns [`Error::Tls`] when BoringSSL cannot reach a source of randomness.
pub fn random(out: &mut [u8]) -> Result<(), Error> {
    boring::rand::rand_bytes(out).map_err(|_| Error::Tls("BoringSSL has no source of randomness".into()))
}

/// Whether a timeout in seconds asks for a deadline at all.
///
/// Zero, negative and non-finite values all disable the timeout, which is what
/// the [`Limits`] fields are documented to do.
///
/// [`Limits`]: crate::api::common::Limits
#[inline]
pub fn timed(seconds: f64) -> bool {
    seconds.is_finite() && seconds > 0.0
}

/// A timeout in seconds as a [`Duration`], or `None` when it means "wait forever".
///
/// Values [`timed`] rejects yield `None`. A value too large for a [`Duration`]
/// is capped at [`Duration::MAX`] rather than panicking — a deadline that far
/// out and no deadline at all are the same thing to a connection.
pub fn duration(seconds: f64) -> Option<Duration> {
    timed(seconds).then(|| Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX))
}

/// Runs an operation under a deadline.
///
/// A `seconds` that [`duration`] rejects means no deadline at all, and the
/// operation is simply awaited. The operation is polled once before the timer
/// is armed, so work that is already finished never pays for one.
///
/// The operation is taken by value, so a caller whose operation is a large
/// future — one whole message going out or coming in, rather than a single
/// read — should hand over a `Pin<&mut _>` from [`std::pin::pin!`] instead.
/// That leaves the state machine where the caller built it rather than copying
/// it into this one, which for a message-sized future is kilobytes a message.
///
/// # Errors
///
/// Returns [`Error::Timeout`] when the deadline passes first.
pub async fn within<T>(seconds: f64, operation: impl Future<Output = T>) -> Result<T, Error> {
    if !timed(seconds) {
        return Ok(operation.await);
    }

    let mut operation = std::pin::pin!(operation);

    if let Poll::Ready(value) = std::future::poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx))).await {
        return Ok(value);
    }

    let wait = duration(seconds).unwrap_or(Duration::MAX);

    tokio::time::timeout(wait, operation)
        .await
        .map_err(|_| Error::Timeout(format!("nothing arrived within {seconds}s")))
}

/// A multiplicative hasher for stream identifiers.
///
/// Stream keys are small integers handed out in sequence, where a general
/// purpose hash costs more than the lookup it protects.
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

/// A map keyed by stream, hashed with [`StreamHasher`].
pub type StreamMap<K, V> = std::collections::HashMap<K, V, std::hash::BuildHasherDefault<StreamHasher>>;

/// The buffer size above which an idle connection gives memory back.
pub const IDLE_CAPACITY: usize = 64 * 1024;

/// Whether a buffer has grown past [`IDLE_CAPACITY`] and since emptied out
/// enough to be worth rebuilding.
///
/// One large message would otherwise leave every idle connection holding a
/// buffer sized for it, which across many connections is the difference
/// between idling at a few kilobytes and idling at megabytes.
pub fn oversized(capacity: usize, len: usize) -> bool {
    capacity > IDLE_CAPACITY && len <= IDLE_CAPACITY / 2
}

/// Gives back the memory an outsized buffer is holding, if there is enough to
/// be worth it.
pub fn reclaim(buffer: &mut BytesMut) {
    if oversized(buffer.capacity(), buffer.len()) {
        let mut fresh = BytesMut::new();
        fresh.extend_from_slice(buffer);
        *buffer = fresh;
    }
}

/// [`reclaim`] for a plain octet buffer.
pub fn reclaim_octets(buffer: &mut Vec<u8>) {
    if oversized(buffer.capacity(), buffer.len()) {
        buffer.shrink_to(IDLE_CAPACITY / 2);
    }
}

/// The read buffer sitting between a transport and a parser.
///
/// Holds whatever has arrived but not yet been consumed, which is what lets a
/// parser ask for a line or a frame without caring how the octets were
/// delivered. The read size starts at [`Buffer::FIRST_CHUNK`] and doubles up
/// to [`Buffer::CHUNK_SIZE`] as long as reads keep coming back full, so a
/// small request costs a small read while a large body ramps up.
///
/// It survives a protocol switch: an HTTP/1.1 connection that upgrades to
/// WebSocket, or a plaintext connection sniffed for the HTTP/2 preface, hands
/// its buffer to whatever takes over so the octets already read are not lost.
pub struct Buffer {
    data: BytesMut,
    chunk: usize,
    eof: bool,
}

impl Buffer {
    /// The largest single read.
    pub const CHUNK_SIZE: usize = 16 * 1024;
    /// The first read, before the size has ramped up.
    pub const FIRST_CHUNK: usize = 2 * 1024;

    /// An empty buffer over a transport nothing has been read from yet.
    pub fn new() -> Self {
        Self { data: BytesMut::new(), chunk: Self::FIRST_CHUNK, eof: false }
    }

    /// How many octets are buffered but not yet consumed.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether nothing is buffered right now.
    ///
    /// This says nothing about whether more will arrive; see [`Buffer::eof`].
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether the transport has reported end of file.
    pub fn eof(&self) -> bool {
        self.eof
    }

    /// The buffered octets.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Drops the first `count` octets, or all of them if fewer are buffered.
    pub fn consume(&mut self, count: usize) {
        self.data.advance(count.min(self.data.len()));
    }

    /// How much the buffer has allocated.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Gives back memory the buffer no longer needs; see [`reclaim`].
    pub fn reclaim(&mut self) {
        reclaim(&mut self.data);
    }

    /// Splits the first `count` octets off, or all of them if fewer are buffered.
    pub fn take(&mut self, count: usize) -> BytesMut {
        self.data.split_to(count.min(self.data.len()))
    }

    /// Reads once from the transport.
    ///
    /// Returns `false` at end of file, after which further calls return
    /// `false` without touching the transport.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] when nothing arrives in time, and
    /// [`Error::Io`] when the transport fails.
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

    /// Reads until at least `count` octets are buffered, and returns them.
    ///
    /// The octets stay buffered; consume them with [`Buffer::consume`] or
    /// [`Buffer::take`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the transport ends before `count` octets
    /// arrive, and otherwise as [`Buffer::fill`].
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

    /// Reads until a CRLF-terminated line is buffered, and returns its length
    /// without the terminator.
    ///
    /// The line is left in the buffer, so the caller can parse it in place and
    /// then consume its length plus two. Use [`Buffer::line`] to have it
    /// consumed and copied out instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for a bare LF, [`Error::Limit`] when the
    /// line runs past `max`, [`Error::Closed`] when the transport ends first,
    /// and otherwise as [`Buffer::fill`].
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

    /// [`Buffer::line_end`], consuming the line and returning it as a `String`.
    ///
    /// Octets that are not valid UTF-8 are replaced rather than rejected.
    ///
    /// # Errors
    ///
    /// As [`Buffer::line_end`].
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

/// The pseudo-headers a request may carry.
pub const PSEUDO_REQUEST: &[&str] = &[":method", ":scheme", ":authority", ":path", ":protocol"];
/// The pseudo-headers a response may carry.
pub const PSEUDO_RESPONSE: &[&str] = &[":status"];

/// Fields that describe the HTTP/1.x connection rather than the message.
///
/// These have no meaning above HTTP/1.1 and must not be framed there, since a
/// peer that honoured them could be talked into changing how the connection
/// itself is read.
pub const CONNECTION_SPECIFIC: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/// Whether a field name is one of [`CONNECTION_SPECIFIC`].
pub fn is_connection_specific(name: &str) -> bool {
    matches!(name.len(), 7 | 10 | 16 | 17) && CONNECTION_SPECIFIC.contains(&name)
}

/// Seen-bit for `:method`, so a repeat can be caught.
pub const PSEUDO_METHOD: u8 = 1 << 0;
/// Seen-bit for `:status`.
pub const PSEUDO_STATUS: u8 = 1 << 1;
/// Seen-bit for `:scheme`.
pub const PSEUDO_SCHEME: u8 = 1 << 2;
/// Seen-bit for `:path`.
pub const PSEUDO_PATH: u8 = 1 << 3;
/// Seen-bit for `:authority`.
pub const PSEUDO_AUTHORITY: u8 = 1 << 4;
/// Seen-bit for `:protocol`, which extended CONNECT carries.
pub const PSEUDO_PROTOCOL: u8 = 1 << 5;

/// A status code as the three digits `:status` carries.
///
/// Codes outside three digits fall back to a plain decimal rendering; the
/// message will be rejected elsewhere, but formatting it must not panic.
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

/// Turns a [`Message`] into the field list HTTP/2 and HTTP/3 frame.
///
/// The start line becomes pseudo-headers, which lead the list as the format
/// requires. `Host` is dropped in favour of `:authority`, since the two say
/// the same thing and sending both invites disagreement. A `CONNECT` without
/// `:protocol` carries its authority as `:authority` and nothing else, because
/// it names a tunnel rather than a resource.
///
/// # Errors
///
/// Returns [`Error::Protocol`] when the message is neither a request nor a
/// response, or when it carries a [`CONNECTION_SPECIFIC`] field, which has no
/// meaning above HTTP/1.1.
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

/// [`message_from`] over a borrowed field list.
///
/// # Errors
///
/// As [`message_from`].
pub fn message(fields: &[HeaderField], version: Version) -> Result<Message, Error> {
    message_from(fields.to_vec(), version)
}

/// Turns a decoded field list back into a [`Message`], enforcing the rules
/// HTTP/2 and HTTP/3 share.
///
/// `:authority` is written back out as `Host`, so a handler sees one
/// authority field whatever version delivered it.
///
/// # Errors
///
/// Returns [`Error::Protocol`] when the field list breaks any of the rules
/// both versions impose: an uppercase field name; a [`CONNECTION_SPECIFIC`]
/// field; a `TE` asking for anything but trailers; a pseudo-header after a
/// regular field, repeated, undefined, or belonging to the other kind of
/// message; neither `:method` nor `:status`; a request without both a scheme
/// and a non-empty path; or a `CONNECT` carrying more than an authority.
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
