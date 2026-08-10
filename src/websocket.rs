//! The WebSocket protocol, over all three versions of HTTP.
//!
//! The handshake differs by version and the framing does not. Over HTTP/1.1 it
//! is an `Upgrade`; over HTTP/2 and HTTP/3 it is an extended `CONNECT` naming
//! `websocket` in `:protocol`. [`AnyConnection::accept_websocket`] and
//! [`AnyConnection::open_websocket`] do whichever applies, and both hand back
//! the same [`WebSocketConnection`].
//!
//! What the connection runs over differs too: HTTP/1.1 gives up its transport
//! outright, HTTP/2 turns the whole connection into a tunnel over one stream,
//! and HTTP/3 tunnels one stream and leaves the rest of the connection
//! running.
//!
//! Framing is enforced in both directions: clients must mask and servers must
//! not, control frames must be short and unfragmented, text must be valid
//! UTF-8, and close codes must be ones that may appear on the wire.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::helpers::{base64, sha1};
use crate::models::{ConnectionID, Headers, Limits, Message, Method, Role, Version};
use crate::protocol::base::{AnyConnection, Connection, Transport};
use crate::protocol::common::{Buffer, Error};

/// The fixed string a server hashes with the client's nonce to prove it read
/// the handshake.
pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The protocol version this implements, as `Sec-WebSocket-Version` carries it.
pub const VERSION: &str = "13";

/// The protocol name, in `Upgrade` and in `:protocol`.
pub const PROTOCOL: &str = "websocket";

/// The largest payload a control frame may carry.
pub const MAXIMUM_CONTROL_PAYLOAD: usize = 125;

/// What a frame is.
///
/// Control opcodes have the high bit of their code set, which is what
/// [`Opcode::control`] tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// More of the message the previous frame began.
    Continuation,
    /// A message that must be valid UTF-8.
    Text,
    /// A message of arbitrary octets.
    Binary,
    /// Begin the closing handshake.
    Close,
    /// A liveness probe, to be answered with [`Opcode::Pong`].
    Ping,
    /// An answer to a [`Opcode::Ping`], or an unsolicited keepalive.
    Pong,
}

impl Opcode {
    /// The opcode as it appears in a frame header.
    pub fn code(&self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xa,
        }
    }

    /// The opcode a code names, or `None` when it is reserved.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xa => Some(Self::Pong),
            _ => None,
        }
    }

    /// Whether this is a control frame, which may interleave with a message
    /// but must be short and unfragmented.
    pub fn control(&self) -> bool {
        self.code() & 0x8 != 0
    }
}

/// Why a connection is being closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// 1000: the exchange finished.
    Normal,
    /// 1001: this end is going away.
    GoingAway,
    /// 1002: the peer broke the protocol.
    ProtocolError,
    /// 1003: the peer sent data of a kind this end cannot accept.
    UnsupportedData,
    /// 1007: a message did not match its type, such as text that is not UTF-8.
    InvalidPayload,
    /// 1008: a message broke a policy this end enforces.
    PolicyViolation,
    /// 1009: a message was too large to process.
    MessageTooBig,
    /// 1010: the server did not agree to a required extension.
    MandatoryExtension,
    /// 1011: something failed on this end.
    InternalError,
}

impl CloseCode {
    /// The numeric code as it appears in a close payload.
    pub fn code(&self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::GoingAway => 1001,
            Self::ProtocolError => 1002,
            Self::UnsupportedData => 1003,
            Self::InvalidPayload => 1007,
            Self::PolicyViolation => 1008,
            Self::MessageTooBig => 1009,
            Self::MandatoryExtension => 1010,
            Self::InternalError => 1011,
        }
    }

    /// The close code a number names, or `None` when it is not one of these.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            1000 => Some(Self::Normal),
            1001 => Some(Self::GoingAway),
            1002 => Some(Self::ProtocolError),
            1003 => Some(Self::UnsupportedData),
            1007 => Some(Self::InvalidPayload),
            1008 => Some(Self::PolicyViolation),
            1009 => Some(Self::MessageTooBig),
            1010 => Some(Self::MandatoryExtension),
            1011 => Some(Self::InternalError),
            _ => None,
        }
    }

    /// Whether a close code may appear on the wire.
    ///
    /// The defined codes, plus 3000–4999, which are left to applications and
    /// registered use. Codes such as 1005 and 1006 stand for "no code was
    /// sent" and must never be sent as one.
    pub fn permitted(code: u16) -> bool {
        Self::from_code(code).is_some() || (3000..5000).contains(&code)
    }
}

/// Where a frame's payload sits within the octets that carry it.
///
/// [`FrameHead::decode`] reads everything but the payload, so a caller that
/// holds the octets in a buffer can split the payload off in place rather
/// than copy it out — which is what [`Frame::take`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHead {
    /// Whether the frame ends its message.
    pub fin: bool,
    /// What the frame is.
    pub opcode: Opcode,
    /// The masking key, if the payload is masked.
    pub mask: Option<[u8; 4]>,
    /// Where the payload starts.
    pub start: usize,
    /// How long the payload is.
    pub length: usize,
}

impl FrameHead {
    /// Reads a frame's header, leaving the payload where it is.
    ///
    /// `None` when the header — or, judged by the length it declares, the
    /// payload — has not fully arrived yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when a reserved bit is set with no
    /// extension negotiated, when the opcode is reserved, when the length has
    /// its high bit set, or when a control frame is longer than
    /// [`MAXIMUM_CONTROL_PAYLOAD`] or fragmented.
    pub fn decode(data: &[u8]) -> Result<Option<Self>, Error> {
        if data.len() < 2 {
            return Ok(None);
        }

        if data[0] & 0x70 != 0 {
            return Err(Error::Protocol("a reserved bit is set with no extension negotiated".into()));
        }

        let fin = data[0] & 0x80 != 0;
        let opcode = Opcode::from_code(data[0] & 0x0f)
            .ok_or_else(|| Error::Protocol(format!("opcode {:#x} is reserved", data[0] & 0x0f)))?;

        let masked = data[1] & 0x80 != 0;
        let (mut start, length) = match data[1] & 0x7f {
            126 => match Frame::octets::<2>(data, 2) {
                Some(octets) => (4, u16::from_be_bytes(octets) as u64),
                None => return Ok(None),
            },

            127 => {
                let Some(octets) = Frame::octets::<8>(data, 2) else {
                    return Ok(None);
                };

                let length = u64::from_be_bytes(octets);
                if length & 0x8000_0000_0000_0000 != 0 {
                    return Err(Error::Protocol("the payload length has its high bit set".into()));
                }

                (10, length)
            }

            length => (2, length as u64),
        };

        if opcode.control() {
            if length > MAXIMUM_CONTROL_PAYLOAD as u64 {
                return Err(Error::Protocol(format!("control frame carries {length} octets")));
            }
            if !fin {
                return Err(Error::Protocol("control frame is fragmented".into()));
            }
        }

        let mask = if masked {
            let Some(mask) = Frame::octets::<4>(data, start) else {
                return Ok(None);
            };

            start += 4;
            Some(mask)
        } else {
            None
        };

        let Ok(length) = usize::try_from(length) else {
            return Ok(None);
        };

        if start.checked_add(length).filter(|end| *end <= data.len()).is_none() {
            return Ok(None);
        }

        Ok(Some(Self { fin, opcode, mask, start, length }))
    }
}

/// One WebSocket frame.
///
/// The payload is always unmasked here; masking is applied on the way out and
/// undone on the way in, so nothing above the framing layer sees it.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    /// Whether this frame ends its message.
    pub fin: bool,
    /// What the frame is.
    pub opcode: Opcode,
    /// The masking key, which a client must set and a server must not.
    pub mask: Option<[u8; 4]>,
    /// The payload, unmasked.
    pub payload: Bytes,
}

impl Frame {
    /// Fills `out` with cryptographically secure random octets.
    ///
    /// Masking keys and handshake nonces both come from here, so the one
    /// place that needs a source of randomness is this module.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TLS`] when BoringSSL cannot reach a source of randomness.
    pub fn random(out: &mut [u8]) -> Result<(), Error> {
        boring::rand::rand_bytes(out).map_err(|_| Error::TLS("BoringSSL has no source of randomness".into()))
    }

    /// A complete, unmasked frame.
    ///
    /// The mask is filled in by [`WebSocketConnection::send`] according to the
    /// role, so it need not be set here.
    pub fn new(opcode: Opcode, payload: impl Into<Bytes>) -> Self {
        Self { fin: true, opcode, mask: None, payload: payload.into() }
    }

    /// Applies a masking key in place, which also removes one.
    ///
    /// The key is applied a word at a time, with a byte loop for the tail.
    pub fn apply_mask(mask: [u8; 4], payload: &mut [u8]) {
        let [a, b, c, d] = mask;
        let key = u64::from_ne_bytes([a, b, c, d, a, b, c, d]);

        let mut chunks = payload.chunks_exact_mut(8);
        for chunk in &mut chunks {
            let masked = u64::from_ne_bytes(chunk.try_into().unwrap()) ^ key;
            chunk.copy_from_slice(&masked.to_ne_bytes());
        }

        for (offset, octet) in chunks.into_remainder().iter_mut().enumerate() {
            *octet ^= mask[offset & 3];
        }
    }

    /// The whole frame as its own buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 14);
        self.encode_into(&mut out);
        out
    }

    /// Appends the whole frame, masking the payload if a key is set.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let length = self.payload.len();

        out.reserve(length + 14);
        out.push(u8::from(self.fin) << 7 | self.opcode.code());

        let masked = u8::from(self.mask.is_some()) << 7;
        match length {
            0..=125 => out.push(masked | length as u8),
            126..=65_535 => {
                out.push(masked | 126);
                out.extend_from_slice(&(length as u16).to_be_bytes());
            }
            _ => {
                out.push(masked | 127);
                out.extend_from_slice(&(length as u64).to_be_bytes());
            }
        }

        match self.mask {
            Some(mask) => {
                out.extend_from_slice(&mask);
                let start = out.len();
                out.extend_from_slice(&self.payload);
                Self::apply_mask(mask, &mut out[start..]);
            }
            None => out.extend_from_slice(&self.payload),
        }
    }

    /// Reads one frame, returning how many octets it took.
    ///
    /// `None` when the frame has not fully arrived; the caller should read
    /// more and try again. The payload comes back unmasked, copied out of
    /// `data`; a caller holding the octets in a buffer should prefer
    /// [`Frame::take`], which does not copy.
    ///
    /// # Errors
    ///
    /// As [`FrameHead::decode`].
    pub fn decode(data: &[u8]) -> Result<Option<(usize, Self)>, Error> {
        let Some(head) = FrameHead::decode(data)? else {
            return Ok(None);
        };

        let end = head.start + head.length;
        let mut payload = BytesMut::from(&data[head.start..end]);
        if let Some(mask) = head.mask {
            Self::apply_mask(mask, &mut payload);
        }

        Ok(Some((end, Self { fin: head.fin, opcode: head.opcode, mask: head.mask, payload: payload.freeze() })))
    }

    /// Takes one frame off the front of a buffer, without copying its payload.
    ///
    /// `None` when the frame has not fully arrived; the buffer is left
    /// untouched so the call can be repeated as more octets come in. The
    /// payload is split out of the buffer in place and unmasked there.
    ///
    /// # Errors
    ///
    /// As [`FrameHead::decode`].
    pub fn take(buffer: &mut BytesMut) -> Result<Option<Self>, Error> {
        use bytes::Buf;

        let Some(head) = FrameHead::decode(buffer)? else {
            return Ok(None);
        };

        buffer.advance(head.start);
        let mut payload = buffer.split_to(head.length);
        if let Some(mask) = head.mask {
            Self::apply_mask(mask, &mut payload);
        }

        Ok(Some(Self { fin: head.fin, opcode: head.opcode, mask: head.mask, payload: payload.freeze() }))
    }

    /// Reads `N` octets at `offset`, or `None` when they are not all there.
    pub fn octets<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
        let end = offset.checked_add(N)?;
        data.get(offset..end).and_then(|slice| <[u8; N]>::try_from(slice).ok())
    }

    /// A fresh masking key.
    ///
    /// It has to be unpredictable: masking exists so that a client cannot be
    /// tricked into putting attacker-chosen octets on the wire verbatim, which
    /// a guessable key would undo.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TLS`] when no randomness is available.
    pub fn masking_key() -> Result<[u8; 4], Error> {
        let mut key = [0u8; 4];
        Frame::random(&mut key)?;
        Ok(key)
    }
}

/// The HTTP/1.1 `Upgrade` handshake.
///
/// The client offers a nonce and the server answers with the accept key
/// derived from it, which is what shows the peer read the request rather than
/// having stumbled onto the port.
///
/// RFC 6455 §1.7 requires HTTP/1.1 or later: HTTP/1.0 has no `Upgrade` to
/// build on, so [`Handshake`] turns it away rather than trying this on it.
pub struct Upgrade;

impl Upgrade {
    /// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`.
    ///
    /// The base64 of the SHA-1 of the key concatenated with [`GUID`]. This is
    /// not a security mechanism — it only shows the peer read the request and
    /// is speaking WebSocket rather than something that stumbled onto the port.
    pub fn accept_key(key: &str) -> String {
        base64::encode(&sha1::sha1(format!("{key}{GUID}").as_bytes()))
    }

    /// A fresh `Sec-WebSocket-Key`: sixteen random octets, base64 encoded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TLS`] when no randomness is available.
    pub fn nonce() -> Result<String, Error> {
        let mut key = [0u8; 16];
        Frame::random(&mut key)?;
        Ok(base64::encode(&key))
    }

    /// The upgrade request that opens a WebSocket.
    pub fn request(host: &str, target: &str, key: &str, version: Version) -> Message {
        let mut headers = Headers::new();
        headers.append("host", host);
        headers.append("upgrade", PROTOCOL);
        headers.append("connection", "Upgrade");
        headers.append("sec-websocket-key", key);
        headers.append("sec-websocket-version", VERSION);

        let mut request = Message::request(Method::GET, target, version);
        request.headers = Some(headers);
        request
    }

    /// The `101 Switching Protocols` that accepts an upgrade.
    pub fn response(key: &str, version: Version) -> Message {
        let mut headers = Headers::new();
        headers.append("upgrade", PROTOCOL);
        headers.append("connection", "Upgrade");
        headers.append("sec-websocket-accept", Self::accept_key(key));

        let mut response = Message::response(101, version);
        response.headers = Some(headers);
        response
    }

    /// Checks an upgrade request and returns its `Sec-WebSocket-Key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the request has no fields, is not a
    /// `GET`, does not ask for a WebSocket upgrade, offers a version other than
    /// [`VERSION`], or carries a key that is not sixteen base64 encoded octets.
    pub fn verify_request(request: &Message) -> Result<String, Error> {
        let headers = request.headers.as_ref().ok_or_else(|| Error::Protocol("the request has no fields".into()))?;

        if request.method != Some(Method::GET) {
            return Err(Error::Protocol("a WebSocket handshake is a GET".into()));
        }

        if !Handshake::token_present(headers, "upgrade", PROTOCOL)
            || !Handshake::token_present(headers, "connection", "upgrade")
        {
            return Err(Error::Protocol("the request does not ask for an upgrade to WebSocket".into()));
        }

        if headers.get("sec-websocket-version") != Some(VERSION) {
            return Err(Error::Protocol("the request does not offer WebSocket version 13".into()));
        }

        let key = headers
            .get("sec-websocket-key")
            .ok_or_else(|| Error::Protocol("the request carries no Sec-WebSocket-Key".into()))?;

        if base64::decode(key).map(|key| key.len()) != Ok(16) {
            return Err(Error::Protocol("Sec-WebSocket-Key is not sixteen base64 encoded octets".into()));
        }

        Ok(key.to_owned())
    }

    /// Checks the server's answer to an upgrade.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the response has no fields, is not
    /// `101`, does not confirm the upgrade, or carries a `Sec-WebSocket-Accept`
    /// that does not match the nonce that was sent.
    pub fn verify_response(response: &Message, key: &str) -> Result<(), Error> {
        let headers = response.headers.as_ref().ok_or_else(|| Error::Protocol("the response has no fields".into()))?;

        if response.status_code != Some(101) {
            return Err(Error::Protocol(format!("the server answered {:?} rather than 101", response.status_code)));
        }

        if !Handshake::token_present(headers, "upgrade", PROTOCOL)
            || !Handshake::token_present(headers, "connection", "upgrade")
        {
            return Err(Error::Protocol("the response does not confirm the upgrade".into()));
        }

        if headers.get("sec-websocket-accept") != Some(Self::accept_key(key).as_str()) {
            return Err(Error::Protocol("Sec-WebSocket-Accept does not match the nonce".into()));
        }

        Ok(())
    }
}

/// The extended `CONNECT` handshake, over HTTP/2 and HTTP/3.
///
/// There is no nonce and no accept key: the stream is already authenticated by
/// the connection it runs on, so the HTTP/1.1 proof of understanding is not
/// needed. Otherwise this mirrors [`Upgrade`] method for method.
pub struct Connect;

impl Connect {
    /// The extended `CONNECT` that opens a WebSocket.
    ///
    /// Nothing is assumed about the transport: the `:scheme` the request is
    /// framed with follows [`Message::security`], which the caller stamps from
    /// the connection this is going out over, so an extended `CONNECT` over a
    /// plaintext connection is not framed as though it were secure.
    ///
    /// [`Message::security`]: crate::models::Message::security
    pub fn request(authority: &str, target: &str, version: Version) -> Message {
        let mut headers = Headers::new();
        headers.append("host", authority);
        headers.append(":protocol", PROTOCOL);
        headers.append("sec-websocket-version", VERSION);

        let mut request = Message::request(Method::CONNECT, target, version);
        request.headers = Some(headers);
        request
    }

    /// The `200 OK` that accepts an extended `CONNECT`.
    ///
    /// The caller must set [`Message::stream_id`] to the request's before
    /// sending.
    ///
    /// [`Message::stream_id`]: crate::models::Message::stream_id
    pub fn response(version: Version) -> Message {
        let mut response = Message::response(200, version);
        response.headers = Some(Headers::new());
        response
    }

    /// Checks an extended `CONNECT` request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the request has no fields, is not a
    /// `CONNECT`, or does not name [`PROTOCOL`] in `:protocol`.
    pub fn verify_request(request: &Message) -> Result<(), Error> {
        let headers = request.headers.as_ref().ok_or_else(|| Error::Protocol("the request has no fields".into()))?;

        if request.method != Some(Method::CONNECT) {
            return Err(Error::Protocol("an extended CONNECT is a CONNECT".into()));
        }

        if headers.get(":protocol") != Some(PROTOCOL) {
            return Err(Error::Protocol("the request does not name the WebSocket protocol".into()));
        }

        Ok(())
    }

    /// Checks the server's answer to an extended `CONNECT`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for any status outside 2xx.
    pub fn verify_response(response: &Message) -> Result<(), Error> {
        match response.status_code {
            Some(200..=299) => Ok(()),
            status_code => Err(Error::Protocol(format!("the server answered {status_code:?} rather than 2xx"))),
        }
    }
}

/// The handshake, whichever version it arrives on.
///
/// Dispatches to [`Upgrade`] for HTTP/1.x and to [`Connect`] above it, so a
/// caller that does not care which one it got need not ask.
pub struct Handshake;

impl Handshake {
    /// Whether a request is asking for a WebSocket.
    ///
    /// A cheap test meant for routing; it does not check that the handshake is
    /// well formed. Use [`Handshake::verify`] before accepting one.
    ///
    /// The two ways in are enumerated rather than assumed: HTTP/1.1 asks with
    /// the RFC 6455 §4.1 upgrade, and HTTP/2 and HTTP/3 with the extended
    /// `CONNECT` of RFC 8441 and RFC 9220. HTTP/1.0 has neither, and is turned
    /// away rather than being taken for HTTP/1.1. A version that bootstraps
    /// WebSocket some third way has to be added here rather than falling into
    /// either.
    pub fn requested(request: &Message) -> bool {
        let Some(headers) = request.headers.as_ref() else {
            return false;
        };

        match request.version {
            Version::V1_1 => {
                request.method == Some(Method::GET)
                    && Self::token_present(headers, "upgrade", PROTOCOL)
                    && Self::token_present(headers, "connection", "upgrade")
            }
            Version::V2_0 | Version::V3_0 => request.method == Some(Method::CONNECT) && headers.get(":protocol") == Some(PROTOCOL),
            Version::V1_0 => false,
        }
    }

    /// Checks a WebSocket handshake.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for a version that carries no WebSocket
    /// handshake at all, and otherwise as [`Upgrade::verify_request`] for
    /// HTTP/1.1 and [`Connect::verify_request`] above it.
    pub fn verify(request: &Message) -> Result<(), Error> {
        match request.version {
            Version::V1_1 => Upgrade::verify_request(request).map(|_| ()),
            Version::V2_0 | Version::V3_0 => Connect::verify_request(request),
            Version::V1_0 => Err(Error::Protocol("WebSocket needs HTTP/1.1 or later".into())),
        }
    }

    /// The `426 Upgrade Required` refusing a WebSocket handshake.
    ///
    /// [`Message::upgrade_required`] with what WebSocket owes on top: the
    /// `Sec-WebSocket-Version` the client should retry with.
    pub fn refusal(request: &Message, version: Version) -> Message {
        let mut response = Message::upgrade_required(request, version, PROTOCOL);
        response.headers.get_or_insert_with(Headers::new).append("sec-websocket-version", VERSION);
        response
    }

    /// Answers a WebSocket handshake on a server connection.
    ///
    /// A handshake that checks out upgrades the connection into the returned
    /// socket; one that does not is answered with [`Handshake::refusal`] and
    /// the connection is handed back to keep serving.
    pub async fn answer(connection: AnyConnection, request: &Message, limits: impl Into<WebSocketLimits>) -> Answer {
        let mut connection = connection;

        if Self::verify(request).is_err() {
            let refusal = Self::refusal(request, connection.version());
            return match connection.send(refusal).await {
                Ok(()) => Answer::Refused(connection),
                Err(_) => Answer::Failed,
            };
        }

        match connection.accept_websocket(request, limits).await {
            Ok(socket) => Answer::Accepted(socket),
            Err(_) => Answer::Failed,
        }
    }

    /// Whether a field carries a token, across repeats and comma-separated
    /// lists.
    ///
    /// Matching ignores case, as these tokens are case-insensitive.
    pub fn token_present(headers: &Headers, name: &str, token: &str) -> bool {
        headers
            .get_all(name)
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case(token))
    }
}

/// What answering a WebSocket handshake left behind.
#[allow(clippy::large_enum_variant)]
pub enum Answer {
    /// The upgrade was accepted; the connection has become this socket.
    Accepted(WebSocketConnection<Box<dyn Transport>>),
    /// The handshake did not check out; the refusal was sent and the
    /// connection keeps serving.
    Refused(AnyConnection),
    /// The connection failed while answering, and is gone.
    Failed,
}

impl AnyConnection {
    /// Accepts a WebSocket handshake and takes the connection over.
    ///
    /// What the socket ends up running over depends on the version: HTTP/1.1
    /// gives up its transport along with anything already buffered, HTTP/2
    /// turns the whole connection into a tunnel over the request's stream, and
    /// HTTP/3 tunnels that one stream while the connection keeps running.
    ///
    /// The connection is consumed either way, so a caller that wants to keep
    /// serving other HTTP/3 streams should tunnel the stream itself rather
    /// than going through here.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the handshake does not check out or
    /// the request names no stream, and otherwise as [`Connection::send`] and
    /// [`AnyConnection::into_transport`].
    pub async fn accept_websocket(self, request: &Message, limits: impl Into<WebSocketLimits>) -> Result<WebSocketConnection<Box<dyn Transport>>, Error> {
        let id = self.id();
        let limits = limits.into();
        let mut connection = self;

        let stream_id = match connection.version() {
            Version::V1_1 => {
                let key = Upgrade::verify_request(request)?;
                connection.send(Upgrade::response(&key, connection.version())).await?;
                None
            }

            Version::V2_0 | Version::V3_0 => {
                Connect::verify_request(request)?;
                let stream_id = request.stream_id.ok_or_else(|| Error::Protocol("the request names no stream".into()))?;

                let mut response = Connect::response(connection.version());
                response.stream_id = Some(stream_id);
                connection.send(response).await?;

                Some(stream_id)
            }

            Version::V1_0 => return Err(Error::Protocol("WebSocket needs HTTP/1.1 or later".into())),
        };

        let (transport, buffered) = connection.into_transport(stream_id)?;

        Ok(match buffered {
            Some(buffer) => WebSocketConnection::resume(transport, Role::Origin, id, limits, buffer),
            None => WebSocketConnection::new(transport, Role::Origin, id, limits),
        })
    }

    /// Opens a WebSocket and takes the connection over.
    ///
    /// The client-side counterpart of [`AnyConnection::accept_websocket`], and
    /// it takes the connection over in the same way.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TLS`] when no randomness is available for the nonce,
    /// [`Error::Protocol`] when the server's answer does not check out or
    /// names no stream, and otherwise as [`Connection::send`],
    /// [`Connection::receive`] and [`AnyConnection::into_transport`].
    pub async fn open_websocket(self, authority: &str, target: &str, limits: impl Into<WebSocketLimits>) -> Result<WebSocketConnection<Box<dyn Transport>>, Error> {
        let id = self.id();
        let limits = limits.into();
        let mut connection = self;

        let stream_id = match connection.version() {
            Version::V1_1 => {
                let key = Upgrade::nonce()?;
                connection.send(Upgrade::request(authority, target, &key, connection.version())).await?;

                let response = connection.receive().await?;
                Upgrade::verify_response(&response, &key)?;
                None
            }

            Version::V2_0 | Version::V3_0 => {
                let mut request = Connect::request(authority, target, connection.version());
                request.security = connection.security();
                connection.send(request).await?;

                let response = connection.receive().await?;
                Connect::verify_response(&response)?;

                Some(response.stream_id.ok_or_else(|| Error::Protocol("the response names no stream".into()))?)
            }

            Version::V1_0 => return Err(Error::Protocol("WebSocket needs HTTP/1.1 or later".into())),
        };

        let (transport, buffered) = connection.into_transport(stream_id)?;

        Ok(match buffered {
            Some(buffer) => WebSocketConnection::resume(transport, Role::UserAgent, id, limits, buffer),
            None => WebSocketConnection::new(transport, Role::UserAgent, id, limits),
        })
    }
}

/// The ceilings a [`WebSocketConnection`] keeps itself under.
///
/// The socket's own, so this module reads as the WebSocket library it is:
/// RFC 6455 framing has nothing to say about QPACK tables or HTTP/2 windows,
/// and none of them appear here. [`Limits`] converts into one for a caller
/// configuring everything at once.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WebSocketLimits {
    /// In bytes, the largest message that may be reassembled.
    pub max_message_size: u64,
    /// The number of continuation frames allowed in one message.
    pub ws_max_fragments: u16,
    /// In seconds, how long a close waits for the peer to echo it back.
    pub ws_linger_timeout: f64,
    /// In seconds, how long one read may wait for more octets.
    pub read_timeout: f64,
    /// In seconds, how long one write may wait for the peer.
    pub write_timeout: f64,
    /// In bytes, how much room each read from the transport is given.
    pub read_chunk_size: u64,
    /// In bytes, the buffer size above which an idle socket gives memory back.
    pub idle_capacity: u64,
}

impl Default for WebSocketLimits {
    fn default() -> Self {
        Limits::default().into()
    }
}

impl From<Limits> for WebSocketLimits {
    fn from(limits: Limits) -> Self {
        Self {
            max_message_size: limits.max_message_size,
            ws_max_fragments: limits.ws_max_fragments,
            ws_linger_timeout: limits.ws_linger_timeout,
            read_timeout: limits.read_timeout,
            write_timeout: limits.write_timeout,
            read_chunk_size: limits.read_chunk_size,
            idle_capacity: limits.idle_capacity,
        }
    }
}

/// A WebSocket connection.
///
/// Generic over its transport, because the three HTTP versions leave it
/// running over three different things — a bare transport, an HTTP/2 tunnel,
/// or an HTTP/3 stream — and the protocol above them is the same.
///
/// Work in messages with [`WebSocketConnection::receive_message`], which
/// reassembles fragments and answers pings on its own, or in frames with
/// [`WebSocketConnection::receive`] where that control is wanted.
pub struct WebSocketConnection<T> {
    transport: T,
    role: Role,
    id: ConnectionID,
    limits: WebSocketLimits,
    buffer: Buffer,
    fragments: Option<(Opcode, BytesMut)>,
    fragment_count: usize,
    closing: bool,
    scratch: Vec<u8>,
}

impl<T> WebSocketConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// A connection over a transport nothing has been read from yet.
    pub fn new(transport: T, role: Role, id: ConnectionID, limits: impl Into<WebSocketLimits>) -> Self {
        Self::resume(transport, role, id, limits, Buffer::new())
    }

    /// A connection over a transport that has already been read from.
    ///
    /// This is what an HTTP/1.1 upgrade needs: whatever the peer sent
    /// immediately after the handshake is already buffered.
    pub fn resume(transport: T, role: Role, id: ConnectionID, limits: impl Into<WebSocketLimits>, buffer: Buffer) -> Self {
        let limits = limits.into();

        let mut buffer = buffer;
        buffer.set_chunk_size(limits.read_chunk_size as usize);

        Self {
            transport,
            role,
            id,
            limits,
            buffer,
            fragments: None,
            fragment_count: 0,
            closing: false,
            scratch: Vec::new(),
        }
    }

    /// Which end of the connection this is, which decides masking.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The identifier of the connection this came from.
    pub fn id(&self) -> ConnectionID {
        self.id.clone()
    }

    /// The limits this connection holds itself to.
    pub fn limits(&self) -> WebSocketLimits {
        self.limits
    }

    /// Whether the closing handshake has begun.
    pub fn closing(&self) -> bool {
        self.closing
    }

    /// Sends one frame.
    ///
    /// The mask is set from the role, whatever the frame carried: a client
    /// always masks and a server never does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TLS`] when no randomness is available for the mask,
    /// and [`Error::IO`] when the transport fails.
    pub async fn send(&mut self, mut frame: Frame) -> Result<(), Error> {
        frame.mask = if self.role.is_client() { Some(Frame::masking_key()?) } else { None };

        let mut out = std::mem::take(&mut self.scratch);
        out.clear();
        frame.encode_into(&mut out);

        let result = self.transport.write_all(&out).await;
        self.scratch = out;

        result?;
        self.transport.flush().await?;
        Ok(())
    }

    /// Receives one frame, without reassembling or answering anything.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the frame is malformed or masked the
    /// wrong way round for the peer's role, [`Error::Limit`] when it grows
    /// past [`WebSocketLimits::max_message_size`], and [`Error::Closed`] when
    /// the transport ends mid-frame. Otherwise as [`Buffer::fill`].
    pub async fn receive(&mut self) -> Result<Frame, Error> {
        loop {
            if let Some(frame) = Frame::take(self.buffer.as_bytes_mut())? {
                if self.role.is_client() == frame.mask.is_some() {
                    return Err(Error::Protocol(match frame.mask {
                        Some(_) => "a masked frame arrived from a server".into(),
                        None => "an unmasked frame arrived from a client".into(),
                    }));
                }

                return Ok(frame);
            }

            if self.buffer.len() as u64 > self.limits.max_message_size {
                return Err(Error::Limit(format!("frame exceeds {} octets", self.limits.max_message_size)));
            }

            if !self.buffer.fill(&mut self.transport, self.limits.read_timeout).await? {
                return Err(Error::Closed);
            }
        }
    }

    /// Sends a whole message as one unfragmented frame.
    ///
    /// # Errors
    ///
    /// As [`WebSocketConnection::send`].
    pub async fn send_message(&mut self, opcode: Opcode, payload: impl Into<Bytes>) -> Result<(), Error> {
        self.send(Frame::new(opcode, payload)).await
    }

    /// Receives one whole message, reassembling fragments.
    ///
    /// Control frames are dealt with along the way: a ping is answered with a
    /// pong, and a close is echoed back and then returned as
    /// `(Opcode::Close, payload)` so the caller knows the connection is
    /// finishing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when the message goes past
    /// [`WebSocketLimits::max_message_size`] or spans more than
    /// [`WebSocketLimits::ws_max_fragments`] frames, and [`Error::Protocol`]
    /// when fragmentation is misused — a new message beginning inside one, or
    /// a continuation beginning one — or when a text message is not valid
    /// UTF-8, in which case the connection is closed with
    /// [`CloseCode::InvalidPayload`] first. Otherwise as
    /// [`WebSocketConnection::receive`], [`WebSocketConnection::verify_close`]
    /// and [`WebSocketConnection::send`].
    pub async fn receive_message(&mut self) -> Result<(Opcode, Bytes), Error> {
        loop {
            let frame = self.receive().await?;

            if frame.opcode.control() {
                match frame.opcode {
                    Opcode::Close => {
                        self.verify_close(&frame.payload)?;

                        if !self.closing {
                            self.closing = true;
                            self.send(Frame::new(Opcode::Close, frame.payload.clone())).await?;
                        }

                        return Ok((Opcode::Close, frame.payload));
                    }

                    Opcode::Ping => self.send(Frame::new(Opcode::Pong, frame.payload)).await?,

                    _ => {}
                }

                continue;
            }

            let reassembled_len = match &self.fragments {
                Some((_, pending)) => pending.len() + frame.payload.len(),
                None => frame.payload.len(),
            };

            if reassembled_len as u64 > self.limits.max_message_size {
                return Err(Error::Limit(format!("message exceeds {} octets", self.limits.max_message_size)));
            }

            if frame.fin && self.fragments.is_none() && frame.opcode != Opcode::Continuation {
                if frame.opcode == Opcode::Text && std::str::from_utf8(&frame.payload).is_err() {
                    self.close(CloseCode::InvalidPayload, "invalid utf-8").await;
                    return Err(Error::Protocol("a text message is not valid UTF-8".into()));
                }

                return Ok((frame.opcode, frame.payload));
            }

            let opcode = match (&mut self.fragments, frame.opcode) {
                (Some(_), Opcode::Text | Opcode::Binary) => {
                    return Err(Error::Protocol("a new message began before the last one ended".into()));
                }

                (None, Opcode::Continuation) => {
                    return Err(Error::Protocol("a continuation frame began a message".into()));
                }

                (Some((opcode, pending)), Opcode::Continuation) => {
                    pending.extend_from_slice(&frame.payload);
                    self.fragment_count += 1;
                    *opcode
                }

                (fragments, opcode) => {
                    *fragments = Some((opcode, BytesMut::from(&frame.payload[..])));
                    self.fragment_count = 1;
                    opcode
                }
            };

            if self.fragment_count > self.limits.ws_max_fragments as usize {
                return Err(Error::Limit(format!("message spans more than {} frames", self.limits.ws_max_fragments)));
            }

            if !frame.fin {
                continue;
            }

            self.fragment_count = 0;
            let Some((_, payload)) = self.fragments.take() else {
                return Err(Error::Protocol("a message ended before it began".into()));
            };

            if opcode == Opcode::Text && std::str::from_utf8(&payload).is_err() {
                self.close(CloseCode::InvalidPayload, "invalid utf-8").await;
                return Err(Error::Protocol("a text message is not valid UTF-8".into()));
            }

            return Ok((opcode, payload.freeze()));
        }
    }

    /// Checks a close frame's payload.
    ///
    /// An empty payload is allowed and means no code was given.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the payload is a single octet, carries
    /// a code that may not appear on the wire, or has a reason that is not
    /// valid UTF-8.
    pub fn verify_close(&self, payload: &[u8]) -> Result<(), Error> {
        if payload.is_empty() {
            return Ok(());
        }

        if payload.len() == 1 {
            return Err(Error::Protocol("a close payload cannot be a single octet".into()));
        }

        let code = u16::from_be_bytes([payload[0], payload[1]]);
        if !CloseCode::permitted(code) {
            return Err(Error::Protocol(format!("close code {code} must not appear on the wire")));
        }

        if std::str::from_utf8(&payload[2..]).is_err() {
            return Err(Error::Protocol("the close reason is not valid UTF-8".into()));
        }

        Ok(())
    }

    /// As much of a close reason as fits alongside its code.
    ///
    /// A close frame is a control frame, so the whole payload is held to
    /// [`MAXIMUM_CONTROL_PAYLOAD`] and the code takes the first two octets of
    /// it. The cut is made on a character boundary: RFC 6455 §5.5.1 requires
    /// the reason to be valid UTF-8, and half a character is not.
    pub fn reason(reason: &str) -> &str {
        let room = MAXIMUM_CONTROL_PAYLOAD - size_of::<u16>();

        let mut end = reason.len().min(room);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }

        &reason[..end]
    }

    /// Closes the connection, running the closing handshake.
    ///
    /// Sends a close frame and then waits, for up to
    /// [`WebSocketLimits::ws_linger_timeout`], for the peer to echo one back,
    /// so both ends agree the exchange ended rather than the transport simply
    /// vanishing. The reason is cut to what fits, per
    /// [`WebSocketConnection::reason`].
    ///
    /// The transport is shut down either way, and failures are swallowed:
    /// there is nothing left to report them to.
    pub async fn close(&mut self, code: CloseCode, reason: &str) {
        if !self.closing {
            self.closing = true;

            let mut payload = code.code().to_be_bytes().to_vec();
            payload.extend_from_slice(Self::reason(reason).as_bytes());

            if self.send(Frame::new(Opcode::Close, payload)).await.is_err() {
                let _ = self.transport.shutdown().await;
                return;
            }

            let linger = std::time::Duration::from_secs_f64(self.limits.ws_linger_timeout.max(0.0));
            let _ = tokio::time::timeout(linger, async {
                while let Ok(frame) = self.receive().await {
                    if frame.opcode == Opcode::Close {
                        break;
                    }
                }
            })
            .await;
        }

        let _ = self.transport.shutdown().await;
    }
}
