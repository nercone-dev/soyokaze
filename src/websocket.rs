use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::helpers::{base64, sha1};
use crate::models::{ConnectionID, Headers, Limits, Message, Method, Role, Version};
use crate::protocol::common::{self, AnyConnection, Buffer, Connection, Error, Transport};

pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const VERSION: &str = "13";

pub const PROTOCOL: &str = "websocket";

pub const MAXIMUM_CONTROL_PAYLOAD: usize = 125;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
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

    pub fn control(&self) -> bool {
        self.code() & 0x8 != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    Normal,
    GoingAway,
    ProtocolError,
    UnsupportedData,
    InvalidPayload,
    PolicyViolation,
    MessageTooBig,
    MandatoryExtension,
    InternalError,
}

impl CloseCode {
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

    pub fn permitted(code: u16) -> bool {
        Self::from_code(code).is_some() || (3000..5000).contains(&code)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: Opcode,
    pub mask: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(opcode: Opcode, payload: impl Into<Vec<u8>>) -> Self {
        Self { fin: true, opcode, mask: None, payload: payload.into() }
    }

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

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 14);
        self.encode_into(&mut out);
        out
    }

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

    pub fn decode(data: &[u8]) -> Result<Option<(usize, Self)>, Error> {
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
        let (mut consumed, length) = match data[1] & 0x7f {
            126 => match octets::<2>(data, 2) {
                Some(octets) => (4, u16::from_be_bytes(octets) as u64),
                None => return Ok(None),
            },

            127 => {
                let Some(octets) = octets::<8>(data, 2) else {
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
            let Some(mask) = octets::<4>(data, consumed) else {
                return Ok(None);
            };

            consumed += 4;
            Some(mask)
        } else {
            None
        };

        let Ok(length) = usize::try_from(length) else {
            return Ok(None);
        };

        let Some(end) = consumed.checked_add(length).filter(|end| *end <= data.len()) else {
            return Ok(None);
        };

        let mut payload = data[consumed..end].to_vec();
        if let Some(mask) = mask {
            Self::apply_mask(mask, &mut payload);
        }

        Ok(Some((end, Self { fin, opcode, mask, payload })))
    }
}

pub fn octets<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    data.get(offset..end).and_then(|slice| <[u8; N]>::try_from(slice).ok())
}

pub fn accept_key(key: &str) -> String {
    base64::encode(&sha1::sha1(format!("{key}{GUID}").as_bytes()))
}

pub fn nonce() -> Result<String, Error> {
    let mut key = [0u8; 16];
    common::random(&mut key)?;
    Ok(base64::encode(&key))
}

pub fn masking_key() -> Result<[u8; 4], Error> {
    let mut key = [0u8; 4];
    common::random(&mut key)?;
    Ok(key)
}

pub fn handshake_request(host: &str, target: &str, key: &str) -> Message {
    let mut headers = Headers::new();
    headers.append("host", host);
    headers.append("upgrade", PROTOCOL);
    headers.append("connection", "Upgrade");
    headers.append("sec-websocket-key", key);
    headers.append("sec-websocket-version", VERSION);

    let mut request = Message::request(Method::GET, target, Version::V1_1);
    request.headers = Some(headers);
    request
}

pub fn handshake_response(key: &str) -> Message {
    let mut headers = Headers::new();
    headers.append("upgrade", PROTOCOL);
    headers.append("connection", "Upgrade");
    headers.append("sec-websocket-accept", accept_key(key));

    let mut response = Message::response(101, Version::V1_1);
    response.headers = Some(headers);
    response
}

pub fn verify_request(request: &Message) -> Result<String, Error> {
    let headers = request.headers.as_ref().ok_or_else(|| Error::Protocol("the request has no fields".into()))?;

    if request.method != Some(Method::GET) {
        return Err(Error::Protocol("a WebSocket handshake is a GET".into()));
    }

    if !token_present(headers, "upgrade", PROTOCOL) || !token_present(headers, "connection", "upgrade") {
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

pub fn verify_response(response: &Message, key: &str) -> Result<(), Error> {
    let headers = response.headers.as_ref().ok_or_else(|| Error::Protocol("the response has no fields".into()))?;

    if response.status_code != Some(101) {
        return Err(Error::Protocol(format!("the server answered {:?} rather than 101", response.status_code)));
    }

    if !token_present(headers, "upgrade", PROTOCOL) || !token_present(headers, "connection", "upgrade") {
        return Err(Error::Protocol("the response does not confirm the upgrade".into()));
    }

    if headers.get("sec-websocket-accept") != Some(accept_key(key).as_str()) {
        return Err(Error::Protocol("Sec-WebSocket-Accept does not match the nonce".into()));
    }

    Ok(())
}

pub fn token_present(headers: &Headers, name: &str, token: &str) -> bool {
    headers
        .get_all(name)
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case(token))
}

pub fn connect_request(authority: &str, target: &str, version: Version) -> Message {
    let mut headers = Headers::new();
    headers.append("host", authority);
    headers.append(":protocol", PROTOCOL);
    headers.append("sec-websocket-version", VERSION);

    let mut request = Message::request(Method::CONNECT, target, version);
    request.secure = true;
    request.headers = Some(headers);
    request
}

pub fn connect_response(version: Version) -> Message {
    let mut response = Message::response(200, version);
    response.headers = Some(Headers::new());
    response
}

pub fn verify_connect_request(request: &Message) -> Result<(), Error> {
    let headers = request.headers.as_ref().ok_or_else(|| Error::Protocol("the request has no fields".into()))?;

    if request.method != Some(Method::CONNECT) {
        return Err(Error::Protocol("an extended CONNECT is a CONNECT".into()));
    }

    if headers.get(":protocol") != Some(PROTOCOL) {
        return Err(Error::Protocol("the request does not name the WebSocket protocol".into()));
    }

    Ok(())
}

pub fn verify_connect_response(response: &Message) -> Result<(), Error> {
    match response.status_code {
        Some(200..=299) => Ok(()),
        status_code => Err(Error::Protocol(format!("the server answered {status_code:?} rather than 2xx"))),
    }
}

pub fn upgrade_requested(request: &Message) -> bool {
    let Some(headers) = request.headers.as_ref() else {
        return false;
    };

    match request.version.major() {
        1 => {
            request.method == Some(Method::GET)
                && token_present(headers, "upgrade", PROTOCOL)
                && token_present(headers, "connection", "upgrade")
        }
        _ => request.method == Some(Method::CONNECT) && headers.get(":protocol") == Some(PROTOCOL),
    }
}

pub fn verify_upgrade(request: &Message) -> Result<(), Error> {
    match request.version.major() {
        1 => verify_request(request).map(|_| ()),
        _ => verify_connect_request(request),
    }
}


impl AnyConnection {
    pub async fn accept_websocket(self, request: &Message) -> Result<WebSocketConnection<Box<dyn Transport>>, Error> {
        let id = self.id();

        match self {
            Self::H1(mut connection) => {
                let key = verify_request(request)?;
                connection.send(handshake_response(&key)).await?;

                let limits = *connection.limits();
                let (transport, buffer) = connection.upgrade();
                Ok(WebSocketConnection::resume(transport, Role::Origin, id, limits, buffer))
            }

            Self::H2(mut connection) => {
                verify_connect_request(request)?;
                let stream_id = request.stream_id.ok_or_else(|| Error::Protocol("the request names no stream".into()))?;

                let mut response = connect_response(Version::V2_0);
                response.stream_id = Some(stream_id);
                connection.send(response).await?;

                let limits = *connection.limits();
                Ok(WebSocketConnection::new(Box::new(connection.tunnel(stream_id)), Role::Origin, id, limits))
            }

            Self::H3(mut connection) => {
                verify_connect_request(request)?;
                let stream_id = request.stream_id.ok_or_else(|| Error::Protocol("the request names no stream".into()))?;

                let mut response = connect_response(Version::V3_0);
                response.stream_id = Some(stream_id);
                connection.send(response).await?;

                let limits = *connection.limits();
                let stream = connection.tunnel(stream_id)?;
                Ok(WebSocketConnection::new(Box::new(stream), Role::Origin, id, limits))
            }
        }
    }

    pub async fn open_websocket(self, authority: &str, target: &str) -> Result<WebSocketConnection<Box<dyn Transport>>, Error> {
        let id = self.id();

        match self {
            Self::H1(mut connection) => {
                let key = nonce()?;
                connection.send(handshake_request(authority, target, &key)).await?;

                let response = connection.receive().await?;
                verify_response(&response, &key)?;

                let limits = *connection.limits();
                let (transport, buffer) = connection.upgrade();
                Ok(WebSocketConnection::resume(transport, Role::UserAgent, id, limits, buffer))
            }

            Self::H2(mut connection) => {
                connection.send(connect_request(authority, target, Version::V2_0)).await?;

                let response = connection.receive().await?;
                verify_connect_response(&response)?;
                let stream_id = response.stream_id.ok_or_else(|| Error::Protocol("the response names no stream".into()))?;

                let limits = *connection.limits();
                Ok(WebSocketConnection::new(Box::new(connection.tunnel(stream_id)), Role::UserAgent, id, limits))
            }

            Self::H3(mut connection) => {
                connection.send(connect_request(authority, target, Version::V3_0)).await?;

                let response = connection.receive().await?;
                verify_connect_response(&response)?;
                let stream_id = response.stream_id.ok_or_else(|| Error::Protocol("the response names no stream".into()))?;

                let limits = *connection.limits();
                let stream = connection.tunnel(stream_id)?;
                Ok(WebSocketConnection::new(Box::new(stream), Role::UserAgent, id, limits))
            }
        }
    }
}

pub struct WebSocketConnection<T> {
    transport: T,
    role: Role,
    id: ConnectionID,
    limits: Limits,
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
    pub fn new(transport: T, role: Role, id: ConnectionID, limits: Limits) -> Self {
        Self::resume(transport, role, id, limits, Buffer::new())
    }

    pub fn resume(transport: T, role: Role, id: ConnectionID, limits: Limits, buffer: Buffer) -> Self {
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

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn id(&self) -> ConnectionID {
        self.id.clone()
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn closing(&self) -> bool {
        self.closing
    }

    pub async fn send(&mut self, mut frame: Frame) -> Result<(), Error> {
        frame.mask = if self.role.is_client() { Some(masking_key()?) } else { None };

        let mut out = std::mem::take(&mut self.scratch);
        out.clear();
        frame.encode_into(&mut out);

        let result = self.transport.write_all(&out).await;
        self.scratch = out;

        result?;
        self.transport.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Frame, Error> {
        loop {
            if let Some((consumed, frame)) = Frame::decode(self.buffer.as_slice())? {
                self.buffer.consume(consumed);

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

    pub async fn send_message(&mut self, opcode: Opcode, payload: impl Into<Vec<u8>>) -> Result<(), Error> {
        self.send(Frame::new(opcode, payload)).await
    }

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

                        return Ok((Opcode::Close, Bytes::from(frame.payload)));
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

    pub async fn close(&mut self, code: CloseCode, reason: &str) {
        if !self.closing {
            self.closing = true;

            let mut payload = code.code().to_be_bytes().to_vec();
            payload.extend_from_slice(reason.as_bytes());
            payload.truncate(MAXIMUM_CONTROL_PAYLOAD);

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
