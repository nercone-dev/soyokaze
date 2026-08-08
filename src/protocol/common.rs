//! The vocabulary every HTTP version shares.
//!
//! The traits a connection satisfies live in [`base`]; what is here is the
//! machinery the versions share to satisfy them: the [`Buffer`] between a
//! transport and a parser, and the conversion between a [`Message`] and a
//! field list, in [`Fields`]. HTTP/2
//! and HTTP/3 both carry the start line as pseudo-headers, and both must
//! enforce the same rules about them, so doing it once keeps the two from
//! drifting apart.
//!
//! [`base`]: crate::protocol::base


use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::helpers::fields::HeaderField;
use crate::helpers::sync::Timeout;
use crate::helpers::text::Text;
use crate::helpers::{hpack, qpack};
use crate::models::{Headers, Message, Method, Version};

pub use crate::errors::Error;

impl From<hpack::Error> for Error {
    fn from(err: hpack::Error) -> Self {
        Self::Protocol(format!("hpack: {err}"))
    }
}

impl From<qpack::Error> for Error {
    fn from(err: qpack::Error) -> Self {
        Self::Protocol(format!("qpack: {err}"))
    }
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

/// The read buffer sitting between a transport and a parser.
///
/// Holds whatever has arrived but not yet been consumed, which is what lets a
/// parser ask for a line or a frame without caring how the octets were
/// delivered. Each read is given room to grow: it starts at a
/// [`Buffer::CHUNK_RAMP`]th of [`Buffer::chunk_size`] and doubles up to it as
/// long as reads keep coming back full, so a small request costs a small read
/// while a large body ramps up. How far it ramps is set by the caller, not
/// fixed: [`Limits::read_chunk_size`] is what a connection passes in. It sizes
/// a read rather than capping one — a read that finds spare room already
/// there may return more.
///
/// It survives a protocol switch: an HTTP/1.1 connection that upgrades to
/// WebSocket, or a plaintext connection sniffed for the HTTP/2 preface, hands
/// its buffer to whatever takes over so the octets already read are not lost.
///
/// [`Limits::read_chunk_size`]: crate::models::Limits::read_chunk_size
pub struct Buffer {
    data: BytesMut,
    chunk: usize,
    chunk_size: usize,
    eof: bool,
}

impl Buffer {
    /// The room a read is given before a caller says otherwise.
    pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024;
    /// How much smaller the first read is than a fully ramped-up one.
    pub const CHUNK_RAMP: usize = 8;

    /// Whether a buffer has grown past `idle_capacity` and since emptied out
    /// enough to be worth rebuilding.
    ///
    /// One large message would otherwise leave every idle connection holding a
    /// buffer sized for it, which across many connections is the difference
    /// between idling at a few kilobytes and idling at megabytes. The threshold
    /// is [`Limits::idle_capacity`].
    ///
    /// [`Limits::idle_capacity`]: crate::models::Limits::idle_capacity
    pub fn oversized(capacity: usize, len: usize, idle_capacity: usize) -> bool {
        capacity > idle_capacity && len <= idle_capacity / 2
    }

    /// Gives back the memory an outsized buffer is holding, if there is enough
    /// to be worth it.
    pub fn reclaim_bytes(buffer: &mut BytesMut, idle_capacity: usize) {
        if Self::oversized(buffer.capacity(), buffer.len(), idle_capacity) {
            let mut fresh = BytesMut::new();
            fresh.extend_from_slice(buffer);
            *buffer = fresh;
        }
    }

    /// [`Buffer::reclaim_bytes`] for a plain octet buffer.
    pub fn reclaim_octets(buffer: &mut Vec<u8>, idle_capacity: usize) {
        if Self::oversized(buffer.capacity(), buffer.len(), idle_capacity) {
            buffer.shrink_to(idle_capacity / 2);
        }
    }

    /// An empty buffer reading [`Buffer::DEFAULT_CHUNK_SIZE`] at a time.
    pub fn new() -> Self {
        Self::with_chunk_size(Self::DEFAULT_CHUNK_SIZE)
    }

    /// An empty buffer whose reads are given room ramping up to `chunk_size`.
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        let mut buffer = Self { data: BytesMut::new(), chunk: 0, chunk_size: 0, eof: false };
        buffer.set_chunk_size(chunk_size);
        buffer
    }

    /// How much room a fully ramped-up read is given.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Sets how much room a fully ramped-up read is given, and starts the ramp
    /// over from a [`Buffer::CHUNK_RAMP`]th of it.
    ///
    /// A `chunk_size` of zero would ask for nothing at all, so one octet is the
    /// floor.
    pub fn set_chunk_size(&mut self, chunk_size: usize) {
        self.chunk_size = chunk_size.max(1);
        self.chunk = (self.chunk_size / Self::CHUNK_RAMP).max(1);
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

    /// The buffered octets, for a parser that takes from the front itself.
    ///
    /// A parser that splits a whole frame off the front — as
    /// [`h2::Frame::parse`] and [`h3::Frame::parse`] do — cannot go through
    /// [`Buffer::as_slice`] and [`Buffer::consume`] without working out the
    /// length a second time.
    ///
    /// [`h2::Frame::parse`]: crate::protocol::h2::Frame::parse
    /// [`h3::Frame::parse`]: crate::protocol::h3::Frame::parse
    pub fn as_bytes_mut(&mut self) -> &mut BytesMut {
        &mut self.data
    }

    /// Drops the first `count` octets, or all of them if fewer are buffered.
    pub fn consume(&mut self, count: usize) {
        self.data.advance(count.min(self.data.len()));
    }

    /// How much the buffer has allocated.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Gives back memory the buffer no longer needs; see [`Buffer::reclaim_bytes`].
    pub fn reclaim(&mut self, idle_capacity: usize) {
        Self::reclaim_bytes(&mut self.data, idle_capacity);
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

        let read = Timeout::within(timeout, transport.read_buf(&mut self.data)).await??;
        if read == 0 {
            self.eof = true;
            return Ok(false);
        }

        if read >= self.chunk {
            self.chunk = self.chunk.saturating_mul(2).min(self.chunk_size);
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

}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

/// The conversion between a [`Message`] and the field list HTTP/2 and HTTP/3
/// frame.
///
/// Both versions carry the start line as pseudo-headers and both must enforce
/// the same rules about them, so it is done once here rather than twice.
pub struct Fields;

impl Fields {
    /// The pseudo-headers a request may carry.
    pub const PSEUDO_REQUEST: &[&str] = &[":method", ":scheme", ":authority", ":path", ":protocol"];
    /// The pseudo-headers a response may carry.
    pub const PSEUDO_RESPONSE: &[&str] = &[":status"];

    /// Fields that describe the HTTP/1.x connection rather than the message.
    ///
    /// These have no meaning above HTTP/1.1 and must not be framed there, since
    /// a peer that honoured them could be talked into changing how the
    /// connection itself is read.
    pub const CONNECTION_SPECIFIC: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

    /// Whether a field name is one of [`Fields::CONNECTION_SPECIFIC`].
    pub fn connection_specific(name: &str) -> bool {
        matches!(name.len(), 7 | 10 | 16 | 17) && Self::CONNECTION_SPECIFIC.contains(&name)
    }

    /// A status code as the three digits `:status` carries.
    ///
    /// Codes outside three digits fall back to a plain decimal rendering; the
    /// message will be rejected elsewhere, but formatting it must not panic.
    pub fn status(status_code: u16) -> Text {
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
    /// response, or when it carries a [`Fields::CONNECTION_SPECIFIC`] field, which has no
    /// meaning above HTTP/1.1.
    pub fn of(message: &Message) -> Result<Vec<HeaderField>, Error> {
        let mut fields = Vec::with_capacity(Self::PSEUDO_REQUEST.len() + message.headers.as_ref().map_or(0, Headers::len));

        if let Some(method) = message.method {
            let target = message.target.as_deref().unwrap_or("/");
            let headers = message.headers.as_ref();

            fields.push(HeaderField::new(":method", method.as_str()));

            let protocol = headers.and_then(|headers| headers.get(":protocol"));
            if method == Method::CONNECT && protocol.is_none() {
                fields.push(HeaderField::new(":authority", target));
            } else {
                fields.push(HeaderField::new(":scheme", if message.security.secure { "https" } else { "http" }));

                if let Some(authority) = headers.and_then(|headers| headers.get("host")) {
                    fields.push(HeaderField::new(":authority", authority));
                }

                fields.push(HeaderField::new(":path", target));

                if let Some(protocol) = protocol {
                    fields.push(HeaderField::new(":protocol", protocol));
                }
            }
        } else if let Some(status_code) = message.status_code {
            fields.push(HeaderField::new(":status", Self::status(status_code)));
        } else {
            return Err(Error::Protocol("message is neither a request nor a response".into()));
        }

        if let Some(headers) = &message.headers {
            for (name, value) in headers.fields() {
                if name.starts_with(':') || name == "host" {
                    continue;
                }

                if Self::connection_specific(name) {
                    return Err(Error::Protocol(format!("connection-specific field {name:?} cannot be framed")));
                }

                fields.push(HeaderField { name: name.clone(), value: value.clone() });
            }
        }

        Ok(fields)
    }

    /// [`Fields::into_message`] over a borrowed field list.
    ///
    /// # Errors
    ///
    /// As [`Fields::into_message`].
    pub fn message(fields: &[HeaderField], version: Version) -> Result<Message, Error> {
        Self::into_message(fields.to_vec(), version)
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
    /// both versions impose: an uppercase field name; a [`Fields::CONNECTION_SPECIFIC`]
    /// field; a `TE` asking for anything but trailers; a pseudo-header after a
    /// regular field, undefined, repeated, or belonging to the other kind of
    /// message; a `:method` that is not recognised; a `:status` that is not
    /// three digits; neither `:method` nor `:status`; a request without both a
    /// scheme and a non-empty path; or a `CONNECT` carrying more than an
    /// authority.
    pub fn into_message(fields: Vec<HeaderField>, version: Version) -> Result<Message, Error> {
        // Seen-bits for each pseudo-header, so a repeat can be caught.
        const PSEUDO_METHOD: u8 = 1 << 0;
        const PSEUDO_STATUS: u8 = 1 << 1;
        const PSEUDO_SCHEME: u8 = 1 << 2;
        const PSEUDO_PATH: u8 = 1 << 3;
        const PSEUDO_AUTHORITY: u8 = 1 << 4;
        const PSEUDO_PROTOCOL: u8 = 1 << 5;

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
                if Self::connection_specific(&field.name) {
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
                PSEUDO_SCHEME => message.security.secure = field.value == "https",
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
}
