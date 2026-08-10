//! HTTP/1.0 and HTTP/1.1.
//!
//! One message at a time in each direction, framed as a start line, a field
//! section, and a body whose length comes from `Content-Length`,
//! `Transfer-Encoding`, or the connection closing — which is what
//! [`BodyLength::of`] works out.
//!
//! [`H1Connection`] tracks pipelined requests so that a response can be
//! matched to the method that asked for it, which some bodies need in order to
//! be framed at all: a response to `HEAD` has no body however it is labelled.
//!
//! The parsers here are strict on the things that let two intermediaries read
//! one byte stream as two different messages — bare LF, obsolete line folding,
//! `Content-Length` alongside `Transfer-Encoding`, `Content-Length` values that
//! disagree — since that is what request smuggling is built out of.

use std::collections::VecDeque;
use std::ops::Range;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::helpers::compression::Compression;
use crate::helpers::scan;
use crate::helpers::text::Text;
use crate::models::{Body, ConnectionID, HeaderCase, Headers, Limits, Message, Method, Role, Version};
use crate::tls::Security;
use crate::protocol::base::Connection;
use crate::protocol::common::{self, Buffer, Error};
use crate::helpers::sync;

/// The ceilings an [`H1Connection`] holds itself to.
///
/// RFC 9112 framing and nothing else. The start line and chunk ceilings are
/// HTTP/1.x's alone, and no HTTP/2 window or QPACK setting appears here — a
/// connection carries the numbers it uses, not the whole crate's.
///
/// [`Limits`] converts into one, so a caller configuring everything at once
/// still passes the one struct and each connection takes its own share.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct H1Limits {
    /// In bytes, the total size of a message allowed for reception.
    pub max_message_size: u64,
    /// In bytes, the message body size allowed for reception.
    pub max_message_body_size: u64,
    /// In bytes, the size a received body may reach once its content coding is undone.
    pub max_decompressed_body_size: u64,
    /// In bytes, the request/status line ceiling.
    pub max_startline_size: u32,
    /// In bytes, the whole header (or trailer) block.
    pub max_headers_size: u64,
    /// The number of header fields allowed in one block.
    pub max_header_count: u16,
    /// In bytes, the chunk-size line ceiling for chunked transfer encoding.
    pub max_chunk_header_size: u32,
    /// In bytes, the body size up to which head and body go out as one write.
    pub inline_body_size: u64,
    /// The number of requests that may be pipelined at once.
    pub max_concurrent_streams: u32,
    /// In bytes, how much room each read from the transport is given.
    pub read_chunk_size: u64,
    /// In bytes, the buffer size above which an idle connection gives memory back.
    pub idle_capacity: u64,
    /// In seconds, how long one read may wait (0 waits forever).
    pub read_timeout: f64,
    /// In seconds, how long one write may wait (0 waits forever).
    pub write_timeout: f64,
    /// In seconds, how long one whole message may take to arrive (0 waits forever).
    pub receive_timeout: f64,
    /// In seconds, how long one whole message may take to send (0 waits forever).
    pub send_timeout: f64,
}

impl Default for H1Limits {
    fn default() -> Self {
        Limits::default().into()
    }
}

impl From<Limits> for H1Limits {
    fn from(limits: Limits) -> Self {
        Self {
            max_message_size: limits.max_message_size,
            max_message_body_size: limits.max_message_body_size,
            max_decompressed_body_size: limits.max_decompressed_body_size,
            max_startline_size: limits.max_startline_size,
            max_headers_size: limits.max_headers_size,
            max_header_count: limits.max_header_count,
            max_chunk_header_size: limits.max_chunk_header_size,
            inline_body_size: limits.inline_body_size,
            max_concurrent_streams: limits.max_concurrent_streams,
            read_chunk_size: limits.read_chunk_size,
            idle_capacity: limits.idle_capacity,
            read_timeout: limits.read_timeout,
            write_timeout: limits.write_timeout,
            receive_timeout: limits.receive_timeout,
            send_timeout: limits.send_timeout,
        }
    }
}

/// Finding the end of a CRLF-terminated line in a buffer.
///
/// This is HTTP/1.x parsing and lives with HTTP/1.x: a line terminator is not
/// vocabulary the binary versions share, and [`Buffer`] is a byte buffer that
/// knows nothing about lines. It is written against the buffer's public
/// surface, as any other caller would be.
pub struct Line;

impl Line {
    /// Reads until a CRLF-terminated line is buffered, and returns its length
    /// without the terminator.
    ///
    /// The line is left in the buffer, so the caller can parse it in place and
    /// then consume its length plus two.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for a bare LF, which is what lets two
    /// intermediaries disagree about where a message ends; [`Error::Limit`]
    /// when the line runs past `max`; [`Error::Closed`] when the transport ends
    /// first; and otherwise as [`Buffer::fill`].
    pub async fn end<T>(buffer: &mut Buffer, transport: &mut T, max: usize, timeout: f64) -> Result<usize, Error>
    where
        T: AsyncRead + Unpin,
    {
        let mut searched = 0;

        loop {
            if let Some(offset) = scan::find(&buffer.as_slice()[searched..], b'\n') {
                let end = searched + offset;
                if end == 0 || buffer.as_slice()[end - 1] != b'\r' {
                    return Err(Error::Protocol("line is not terminated by CRLF".into()));
                }

                if end - 1 > max {
                    return Err(Error::Limit(format!("line exceeds {max} octets")));
                }

                return Ok(end - 1);
            }

            searched = buffer.len();
            if searched > max {
                return Err(Error::Limit(format!("line exceeds {max} octets")));
            }

            if !buffer.fill(transport, timeout).await? {
                return Err(Error::Closed);
            }
        }
    }
}

/// Whether an HTTP/1.x connection survives a message.
pub struct Persistence;

impl Persistence {
    /// Whether the connection survives this message.
    ///
    /// A `close` token in `Connection` ends it whatever the version says.
    /// Otherwise HTTP/1.0 needs an explicit `keep-alive` to stay up, and every
    /// later version stays up by default.
    pub fn keep_alive(headers: Option<&Headers>, version: Version) -> bool {
        let mut close = false;
        let mut keep = false;

        if let Some(headers) = headers {
            for value in headers.get_all("connection") {
                for token in value.split(',') {
                    let token = token.trim();

                    if token.eq_ignore_ascii_case("close") {
                        close = true;
                    } else if token.eq_ignore_ascii_case("keep-alive") {
                        keep = true;
                    }
                }
            }
        }

        if close {
            return false;
        }

        match version {
            Version::V1_0 => keep,
            Version::V1_1 | Version::V2_0 | Version::V3_0 => true,
        }
    }
}

/// The start line: a request line or a status line.
///
/// [`StartLine::parse`] tells the two apart by the leading `HTTP/`, since that
/// is the only thing distinguishing them before any field is read.
pub struct StartLine;

impl StartLine {
    /// Appends the start line, without its terminating CRLF.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] for a message that is not HTTP/1.x, and
    /// [`Error::Protocol`] for one that is neither a request nor a response.
    pub fn write(message: &Message, out: &mut BytesMut) -> Result<(), Error> {
        if message.version.major() != 1 {
            return Err(Error::Version(format!("{} has no start line", message.version)));
        }

        let version = message.version.as_str();

        if let Some(method) = message.method {
            let method = method.as_str();
            let target = message.target.as_deref().unwrap_or("/");

            let start = out.len();
            out.resize(start + method.len() + target.len() + version.len() + 2, 0);

            let line = &mut out[start..];
            scan::copy(line, method.as_bytes());
            line[method.len()] = b' ';
            scan::copy(&mut line[method.len() + 1..], target.as_bytes());
            line[method.len() + target.len() + 1] = b' ';
            scan::copy(&mut line[method.len() + target.len() + 2..], version.as_bytes());

            return Ok(());
        }

        if let Some(status_code) = message.status_code {
            let reason = crate::responses::Status::reason(status_code);
            let digits = [
                b'0' + (status_code / 100 % 10) as u8,
                b'0' + (status_code / 10 % 10) as u8,
                b'0' + (status_code % 10) as u8,
            ];

            if (100..1000).contains(&status_code) {
                let start = out.len();
                out.resize(start + version.len() + reason.len() + 5, 0);

                let line = &mut out[start..];
                scan::copy(line, version.as_bytes());
                line[version.len()] = b' ';
                line[version.len() + 1..version.len() + 4].copy_from_slice(&digits);
                line[version.len() + 4] = b' ';
                scan::copy(&mut line[version.len() + 5..], reason.as_bytes());

                return Ok(());
            }

            out.extend_from_slice(version.as_bytes());
            out.extend_from_slice(b" ");
            Number::write_decimal(status_code as u64, out);
            out.extend_from_slice(b" ");
            out.extend_from_slice(reason.as_bytes());
            return Ok(());
        }

        Err(Error::Protocol("message is neither a request nor a response".into()))
    }

    /// [`StartLine::write`], returning the line on its own.
    ///
    /// # Errors
    ///
    /// As [`StartLine::write`].
    pub fn encode(message: &Message) -> Result<String, Error> {
        let mut out = BytesMut::new();
        Self::write(message, &mut out)?;
        Ok(String::from_utf8(out.to_vec()).unwrap_or_default())
    }

    /// Parses a start line into an empty request or response.
    ///
    /// A line beginning `HTTP/` is read as a status line and anything else as a
    /// request line.
    ///
    /// # Errors
    ///
    /// As [`StartLine::parse_bytes`].
    #[inline]
    pub fn parse(line: &str) -> Result<Message, Error> {
        Self::parse_bytes(line.as_bytes())
    }

    /// [`StartLine::parse`] over raw octets.
    ///
    /// A status line is read an octet at a time, so a reason phrase carrying
    /// `obs-text` — which RFC 9112 admits and UTF-8 does not — parses. A
    /// request line still has to be UTF-8, since a target is held as text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for a malformed line — a missing field, a
    /// status code that is not three digits, a control octet other than a tab
    /// in the reason phrase, an unrecognised method, or a request target that
    /// is empty, is not UTF-8, or carries a space or a control octet — and
    /// [`Error::Version`] for a version that is not HTTP/1.x.
    pub fn parse_bytes(line: &[u8]) -> Result<Message, Error> {
        if line.starts_with(b"HTTP/") {
            let Some(first) = scan::find(line, b' ') else {
                return Err(Error::Protocol("status line has no status code".into()));
            };

            let (version, rest) = Self::split(line, first);
            let (status_code, reason) = match scan::find(rest, b' ') {
                Some(second) => Self::split(rest, second),
                None => return Err(Error::Protocol("status line has no reason phrase".into())),
            };

            if status_code.len() != 3 || !status_code.iter().all(u8::is_ascii_digit) {
                return Err(Error::Protocol(format!("status code {:?} is not three digits", String::from_utf8_lossy(status_code))));
            }

            if !Octets::is_reason_bytes(reason) {
                return Err(Error::Protocol("reason phrase contains a control character other than a tab".into()));
            }

            let status_code = u16::from(status_code[0] - b'0') * 100 + u16::from(status_code[1] - b'0') * 10 + u16::from(status_code[2] - b'0');

            return Ok(Message::response(status_code, Self::version_bytes(version)?));
        }

        let Some(first) = scan::find(line, b' ') else {
            return Err(Error::Protocol("request line has no target".into()));
        };

        let (method, rest) = Self::split(line, first);
        let (target, version) = match scan::find(rest, b' ') {
            Some(second) => Self::split(rest, second),
            None => return Err(Error::Protocol("request line has no version".into())),
        };

        let Some(method) = std::str::from_utf8(method).ok().and_then(|method| method.parse::<Method>().ok()) else {
            return Err(Error::Protocol(format!("method {:?} is not recognised", String::from_utf8_lossy(method))));
        };

        let target = match std::str::from_utf8(target) {
            Ok(text) if Octets::is_target(text) => text,
            _ => return Err(Error::Protocol(format!("request target {:?} is malformed", String::from_utf8_lossy(target)))),
        };

        Ok(Message::request(method, target, Self::version_bytes(version)?))
    }

    /// The status a server should answer a request line it could not parse
    /// with.
    ///
    /// 501 for a method that is not recognised, 505 for a version that is not
    /// HTTP/1.x, and 400 for everything else — so the client is told which part
    /// it got wrong rather than just that something was.
    #[inline]
    pub fn error_status(line: &str) -> u16 {
        Self::error_status_bytes(line.as_bytes())
    }

    /// [`StartLine::error_status`] over raw octets.
    pub fn error_status_bytes(line: &[u8]) -> u16 {
        let Some(first) = scan::find(line, b' ') else {
            return 400;
        };

        let (method, rest) = Self::split(line, first);
        let (target, version) = match scan::find(rest, b' ') {
            Some(second) => Self::split(rest, second),
            None => return 400,
        };

        if !matches!(std::str::from_utf8(method), Ok(method) if method.parse::<Method>().is_ok()) {
            return 501;
        }

        if !matches!(std::str::from_utf8(target), Ok(target) if Octets::is_target(target)) {
            return 400;
        }

        if Self::version_bytes(version).is_err() {
            return 505;
        }

        400
    }

    /// Reads an HTTP/1.x version from a start line.
    ///
    /// # Errors
    ///
    /// As [`StartLine::version_bytes`].
    #[inline]
    pub fn version(text: &str) -> Result<Version, Error> {
        Self::version_bytes(text.as_bytes())
    }

    /// [`StartLine::version`] over raw octets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Version`] for anything that is not `HTTP/1.0` or
    /// `HTTP/1.1`.
    pub fn version_bytes(text: &[u8]) -> Result<Version, Error> {
        match text {
            b"HTTP/1.0" => Ok(Version::V1_0),
            b"HTTP/1.1" => Ok(Version::V1_1),
            _ => Err(Error::Version(format!("{:?} is not an HTTP/1.x version", String::from_utf8_lossy(text)))),
        }
    }

    /// Splits a line at `at`, discarding the octet there.
    ///
    /// # Panics
    ///
    /// Panics when `at` is past the end.
    pub fn split(line: &[u8], at: usize) -> (&[u8], &[u8]) {
        (&line[..at], &line[at + 1..])
    }
}

/// What each octet is allowed to be part of.
///
/// [`Octets::TABLE`] is read a lane at a time by [`scan::all_in_class`], so a
/// whole name is classified without branching per octet.
pub struct Octets;

impl Octets {
    /// [`Octets::TABLE`]: the octet may appear in a token, and so in a field
    /// name.
    pub const TOKEN: u8 = 1 << 0;
    /// [`Octets::TABLE`]: the octet may appear in a field value, and so in a
    /// reason phrase.
    ///
    /// `field-vchar = VCHAR / obs-text` with a space or a tab between, and
    /// `reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )`, are the same set of
    /// octets: everything but a control octet, a tab excepted.
    pub const FIELD: u8 = 1 << 1;
    /// [`Octets::TABLE`]: the octet may appear in a request target.
    ///
    /// A target is delimited by the spaces around it, so unlike a field value
    /// it admits neither a space nor a tab.
    pub const TARGET: u8 = 1 << 2;

    /// The or of [`Octets::TOKEN`], [`Octets::FIELD`] and [`Octets::TARGET`] for
    /// each octet.
    pub const TABLE: &'static [u8; 256] = &{
        let mut octets = [0u8; 256];
        let mut value = 0usize;

        while value < 256 {
            let byte = value as u8;

            let token = byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                );

            let field = byte == b'\t' || (byte >= 0x20 && byte != 0x7f);
            let target = byte > 0x20 && byte != 0x7f;

            octets[value] = (token as u8) | (field as u8) << 1 | (target as u8) << 2;
            value += 1;
        }

        octets
    };

    /// Whether an octet is a control character, tab included.
    pub fn is_control(byte: u8) -> bool {
        byte < 0x20 || byte == 0x7f
    }

    /// Whether a string is a non-empty token, and so usable as a field name.
    pub fn is_token(text: &str) -> bool {
        Self::is_token_bytes(text.as_bytes())
    }

    /// Whether a string is a non-empty request target.
    #[inline]
    pub fn is_target(text: &str) -> bool {
        Self::is_target_bytes(text.as_bytes())
    }

    /// Whether a string is usable as a reason phrase, carrying no control octet
    /// other than a tab.
    #[inline]
    pub fn is_reason(text: &str) -> bool {
        Self::is_reason_bytes(text.as_bytes())
    }

    /// [`Octets::is_token`] over raw octets.
    #[inline]
    pub fn is_token_bytes(text: &[u8]) -> bool {
        !text.is_empty() && scan::all_in_class(text, Self::TABLE, Self::TOKEN)
    }

    /// [`Octets::is_target`] over raw octets.
    #[inline]
    pub fn is_target_bytes(text: &[u8]) -> bool {
        !text.is_empty() && scan::all_in_class(text, Self::TABLE, Self::TARGET)
    }

    /// [`Octets::is_reason`] over raw octets.
    #[inline]
    pub fn is_reason_bytes(text: &[u8]) -> bool {
        scan::all_in_class(text, Self::TABLE, Self::FIELD)
    }
}

/// The two numeric formats HTTP/1 writes on the wire.
///
/// Decimal carries `Content-Length` and the status code; hexadecimal carries
/// chunk sizes. Both are written back-to-front into a fixed array so the caller
/// learns the length before committing to a buffer.
pub struct Number;

impl Number {
    /// Writes `value` as decimal into the back of `digits`, and returns where
    /// it starts.
    pub fn decimal(mut value: u64, digits: &mut [u8; 20]) -> usize {
        let mut index = digits.len();

        loop {
            index -= 1;
            digits[index] = b'0' + (value % 10) as u8;
            value /= 10;

            if value == 0 {
                return index;
            }
        }
    }

    /// Appends `value` as decimal.
    pub fn write_decimal(value: u64, out: &mut BytesMut) {
        let mut digits = [0u8; 20];
        let index = Self::decimal(value, &mut digits);
        out.extend_from_slice(&digits[index..]);
    }

    /// Writes `value` as lowercase hexadecimal into the back of `digits`, and
    /// returns where it starts.
    pub fn hexadecimal(mut value: u64, digits: &mut [u8; 16]) -> usize {
        let mut index = digits.len();

        loop {
            index -= 1;
            digits[index] = b"0123456789abcdef"[(value & 0xf) as usize];
            value >>= 4;

            if value == 0 {
                return index;
            }
        }
    }

    /// Appends `value` as lowercase hexadecimal.
    pub fn write_hexadecimal(value: u64, out: &mut Vec<u8>) {
        let mut digits = [0u8; 16];
        let index = Self::hexadecimal(value, &mut digits);
        out.extend_from_slice(&digits[index..]);
    }
}

/// Where the name and value sit within a field line, found without copying.
pub struct FieldSpans {
    /// The field name.
    pub name: Range<usize>,
    /// The field value, with surrounding whitespace already trimmed off.
    pub value: Range<usize>,
    /// Whether the value is ASCII, so it need not be validated again.
    pub ascii: bool,
}

/// One field line, and the section they are gathered into.
///
/// The parsers reject what lets two intermediaries read one section two ways:
/// a name that is not a token, a value carrying a control octet, a line not
/// terminated by CRLF, and obsolete line folding.
pub struct Field;

impl Field {
    /// Appends one field line, terminator included, in the given casing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the name is not a token or the value
    /// carries a control octet — either of which would let the field break out
    /// of its line and inject another.
    pub fn write(name: &str, value: &str, case: HeaderCase, out: &mut BytesMut) -> Result<(), Error> {
        if !Octets::is_token(name) {
            return Err(Error::Protocol(format!("field name {name:?} is not a token")));
        }

        if !scan::is_field_value(value.as_bytes()) {
            return Err(Error::Protocol(format!("field value of {name:?} contains a control character")));
        }

        let start = out.len();
        let line = name.len() + value.len() + 4;
        out.resize(start + line, 0);

        let (head, tail) = out[start..].split_at_mut(name.len());
        scan::copy(head, name.as_bytes());
        case.apply_in_place(head);

        tail[0] = b':';
        tail[1] = b' ';
        scan::copy(&mut tail[2..], value.as_bytes());
        tail[value.len() + 2] = b'\r';
        tail[value.len() + 3] = b'\n';

        Ok(())
    }

    /// [`Field::write`], returning the line on its own.
    ///
    /// # Errors
    ///
    /// As [`Field::write`].
    pub fn encode(name: &str, value: &str, case: HeaderCase) -> Result<String, Error> {
        let mut out = BytesMut::new();
        Self::write(name, value, case, &mut out)?;
        Ok(String::from_utf8(out.to_vec()).unwrap_or_default())
    }

    /// Appends a whole field section, without the blank line that ends it.
    ///
    /// # Errors
    ///
    /// As [`Field::write`]. The buffer may hold a partial section when this
    /// fails.
    pub fn write_all(headers: &Headers, case: HeaderCase, out: &mut BytesMut) -> Result<(), Error> {
        out.reserve(Self::size(headers) as usize);

        for (name, value) in headers.iter() {
            Self::write(name, value, case, out)?;
        }
        Ok(())
    }

    /// [`Field::write_all`], returning the section on its own.
    ///
    /// # Errors
    ///
    /// As [`Field::write`].
    pub fn encode_all(headers: &Headers, case: HeaderCase) -> Result<String, Error> {
        let mut out = BytesMut::new();
        Self::write_all(headers, case, &mut out)?;
        Ok(String::from_utf8(out.to_vec()).unwrap_or_default())
    }

    /// Appends a `Content-Length` field line, terminator included.
    ///
    /// Kept apart from [`Field::write`] because it goes out on nearly every
    /// message and neither the name nor the value can fail validation.
    pub fn write_content_length(length: u64, case: HeaderCase, out: &mut BytesMut) {
        let mut digits = [0u8; 20];
        let index = Number::decimal(length, &mut digits);

        let name = match case {
            HeaderCase::Title => "Content-Length",
            HeaderCase::Lower => "content-length",
        };

        let start = out.len();
        let written = digits.len() - index;
        out.resize(start + name.len() + written + 4, 0);

        let line = &mut out[start..];
        scan::copy(line, name.as_bytes());
        line[name.len()] = b':';
        line[name.len() + 1] = b' ';
        scan::copy(&mut line[name.len() + 2..], &digits[index..]);
        line[name.len() + written + 2] = b'\r';
        line[name.len() + written + 3] = b'\n';
    }

    /// How many octets a field section will take on the wire, terminators
    /// included.
    pub fn size(headers: &Headers) -> u64 {
        headers.iter().map(|(name, value)| (name.len() + value.len() + 4) as u64).sum()
    }

    /// The offset of the colon that ends a field name.
    ///
    /// The colon is found first and the name checked afterwards, since both go
    /// [`scan::LANES`] octets at a time that way, where walking the line once
    /// looking for either would have to stop on every octet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the name is empty, carries a non-token
    /// octet, or the line has no colon at all.
    #[inline]
    pub fn name_end(line: &[u8]) -> Result<usize, Error> {
        let Some(at) = scan::find(line, b':') else {
            return Err(Error::Protocol(format!("field line {:?} has no colon", String::from_utf8_lossy(line))));
        };

        if at == 0 {
            return Err(Error::Protocol("field line has an empty name".into()));
        }

        if !scan::all_in_class(&line[..at], Octets::TABLE, Octets::TOKEN) {
            return Err(Error::Protocol(format!("field name {:?} is not a token", String::from_utf8_lossy(&line[..at]))));
        }

        Ok(at)
    }

    /// Locates the name and value within a field line, and classifies the
    /// value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] as [`Field::name_end`] does, and when the
    /// value carries a control octet.
    #[inline]
    pub fn spans(line: &[u8]) -> Result<FieldSpans, Error> {
        let colon = Self::name_end(line)?;

        let rest = &line[colon + 1..];
        let start = rest.iter().position(|byte| !matches!(byte, b' ' | b'\t')).unwrap_or(rest.len());
        let end = rest.iter().rposition(|byte| !matches!(byte, b' ' | b'\t')).map_or(start, |index| index + 1);

        let class = scan::classify_field_value(&rest[start..end]);
        if class & scan::VALUE_CONTROL != 0 {
            return Err(Error::Protocol(format!(
                "field value of {:?} contains a control character",
                String::from_utf8_lossy(&line[..colon])
            )));
        }

        let value = colon + 1;
        Ok(FieldSpans { name: 0..colon, value: value + start..value + end, ascii: class & scan::VALUE_OBS_TEXT == 0 })
    }

    /// Parses one field line into an owned lowercased name and value.
    ///
    /// # Errors
    ///
    /// As [`Field::spans`].
    pub fn parse(line: &str) -> Result<(String, String), Error> {
        let spans = Self::spans(line.as_bytes())?;

        let name = line.get(spans.name).unwrap_or_default().to_ascii_lowercase();
        let value = line.get(spans.value).unwrap_or_default().to_owned();

        Ok((name, value))
    }

    /// [`Field::parse`] over raw octets, decoding straight into [`Text`].
    ///
    /// # Errors
    ///
    /// As [`Field::spans`].
    pub fn parse_bytes(line: &[u8]) -> Result<(Text, Text), Error> {
        let spans = Self::spans(line)?;

        let name = Text::from_verified_ascii_lowercase(&line[spans.name]);
        let value = match spans.ascii {
            true => Text::from_verified_ascii(&line[spans.value]),
            false => Text::from_utf8_lossy(&line[spans.value]),
        };

        Ok((name, value))
    }

    /// Parses a field section from already-split lines.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] for a folded continuation line, which is
    /// obsolete and a smuggling vector, and otherwise as [`Field::spans`].
    pub fn parse_lines(lines: impl IntoIterator<Item = String>) -> Result<Headers, Error> {
        let mut headers = Headers::new();

        for line in lines {
            if line.starts_with([' ', '\t']) {
                return Err(Error::Protocol("field line is folded onto a continuation line".into()));
            }

            let (name, value) = Self::parse_bytes(line.as_bytes())?;
            headers.append_lowercase(name, value);
        }

        Ok(headers)
    }

    /// Parses a whole field section, without its terminating blank line.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] past `max_count` fields, [`Error::Protocol`]
    /// for a line not terminated by CRLF or folded onto a continuation line,
    /// and otherwise as [`Field::spans`].
    pub fn parse_block(block: &[u8], max_count: usize) -> Result<Headers, Error> {
        let mut headers = Headers::with_capacity((block.len() / 32).min(max_count) + 1);
        let mut rest = block;

        while !rest.is_empty() {
            let Some(end) = scan::find(rest, b'\n') else {
                return Err(Error::Protocol("line is not terminated by CRLF".into()));
            };

            if end == 0 || rest[end - 1] != b'\r' {
                return Err(Error::Protocol("line is not terminated by CRLF".into()));
            }

            let line = &rest[..end - 1];
            rest = &rest[end + 1..];

            if headers.len() >= max_count {
                return Err(Error::Limit(format!("more than {max_count} header fields")));
            }

            if matches!(line.first(), Some(b' ' | b'\t')) {
                return Err(Error::Protocol("field line is folded onto a continuation line".into()));
            }

            let (name, value) = Self::parse_bytes(line)?;
            headers.append_lowercase(name, value);
        }

        Ok(headers)
    }

    /// Finds the blank line that ends a field section.
    ///
    /// Returns where the field lines stop and where the section as a whole
    /// ends, the terminator included. `searched` carries how far the scan
    /// already got, so that repeated calls as more octets arrive do not rescan
    /// from the front.
    pub fn block_end(data: &[u8], searched: &mut usize) -> Option<(usize, usize)> {
        if data.len() >= 2 && data[0] == b'\r' && data[1] == b'\n' {
            return Some((0, 2));
        }

        let mut at = *searched;

        while let Some(offset) = scan::find(&data[at..], b'\n') {
            let line_end = at + offset;

            if data.len() < line_end + 3 {
                break;
            }

            if data[line_end + 1] == b'\r' && data[line_end + 2] == b'\n' {
                return Some((line_end + 1, line_end + 3));
            }

            at = line_end + 1;
        }

        *searched = at;
        None
    }
}

/// The chunked transfer coding: a size line, the data, and a CRLF, repeated
/// until a zero-length chunk ends the body.
pub struct Chunk;

impl Chunk {
    /// Appends one chunk: its size line, the data, and a CRLF.
    ///
    /// A zero-length chunk written this way would end the body, so callers
    /// filter empty data out rather than framing it.
    pub fn write(data: &[u8], out: &mut BytesMut) {
        let mut digits = [0u8; 16];
        let index = Number::hexadecimal(data.len() as u64, &mut digits);

        out.reserve(digits.len() - index + data.len() + 4);
        out.extend_from_slice(&digits[index..]);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
    }

    /// [`Chunk::write`], returning the chunk on its own.
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 20);

        Number::write_hexadecimal(data.len() as u64, &mut out);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");

        out
    }

    /// Reads a chunk size line, returning where the data starts and how long it
    /// is.
    ///
    /// `None` when the line has not fully arrived yet. Any chunk extensions
    /// after a `;` are read past and discarded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the line is not terminated by CRLF or
    /// the size is not hexadecimal.
    pub fn parse_size(data: &[u8]) -> Result<Option<(usize, usize)>, Error> {
        let Some(end) = scan::find(data, b'\n') else {
            return Ok(None);
        };

        if end == 0 || data[end - 1] != b'\r' {
            return Err(Error::Protocol("chunk size line is not terminated by CRLF".into()));
        }

        let line = String::from_utf8_lossy(&data[..end - 1]);
        let (size, _) = line.split_once(';').unwrap_or((&line, ""));

        let size = usize::from_str_radix(size.trim_end_matches([' ', '\t']), 16)
            .map_err(|_| Error::Protocol(format!("chunk size {size:?} is not hexadecimal")))?;

        Ok(Some((end + 1, size)))
    }

    /// Reads one whole chunk.
    ///
    /// Returns how many octets the chunk occupies and where its data sits
    /// within them. A consumed count of zero means the chunk has not fully
    /// arrived yet; an empty range with a non-zero count is the final chunk
    /// that ends the body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] as [`Chunk::parse_size`] does, when the data
    /// is not terminated by CRLF, and when the size is too large to address.
    pub fn decode(data: &[u8]) -> Result<(usize, Range<usize>), Error> {
        let Some((start, size)) = Self::parse_size(data)? else {
            return Ok((0, 0..0));
        };

        if size == 0 {
            return Ok((start, 0..0));
        }

        let overflow = || Error::Protocol("chunk size is too large to address".into());
        let end = start.checked_add(size).ok_or_else(overflow)?;
        let terminator = end.checked_add(2).ok_or_else(overflow)?;

        if data.len() < terminator {
            return Ok((0, 0..0));
        }

        if &data[end..terminator] != b"\r\n" {
            return Err(Error::Protocol("chunk data is not terminated by CRLF".into()));
        }

        Ok((terminator, start..end))
    }
}

/// How the length of a message body is determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLength {
    /// There is no body.
    None,
    /// The body is chunked, and ends at a zero-length chunk.
    Chunked,
    /// The body is exactly this many octets.
    Fixed(u64),
    /// The body ends when the connection closes.
    Close,
}

impl BodyLength {
    /// Works out how a message's body is framed.
    ///
    /// `method` is the method of the request this responds to, which some
    /// responses need in order to be framed at all: a response to `HEAD` has no
    /// body however it is labelled, and a successful response to `CONNECT` is
    /// followed by tunnelled octets rather than a body. Pass `None` for a
    /// request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when `Transfer-Encoding` and
    /// `Content-Length` are both present, when a request's `Transfer-Encoding`
    /// does not end in `chunked`, and when two `Content-Length` values
    /// disagree. Each of these is a way of making one byte stream read as two
    /// different messages. Otherwise as [`BodyLength::content_length`].
    pub fn of(message: &Message, method: Option<Method>) -> Result<Self, Error> {
        let headers = message.headers.as_ref();

        if let Some(status_code) = message.status_code {
            if matches!(status_code, 100..=199 | 204 | 304) || method == Some(Method::HEAD) {
                return Ok(Self::None);
            }

            if method == Some(Method::CONNECT) && (200..300).contains(&status_code) {
                return Ok(Self::None);
            }
        }

        let encoded = headers.is_some_and(|headers| headers.contains("transfer-encoding"));
        let measured = headers.is_some_and(|headers| headers.contains("content-length"));

        if encoded && measured {
            return Err(Error::Protocol("Transfer-Encoding and Content-Length are both present".into()));
        }

        if encoded {
            let last = headers.and_then(|headers| headers.get_all("transfer-encoding").last()).unwrap_or_default();
            let last = last.rsplit(',').next().unwrap_or_default().trim();

            if !last.eq_ignore_ascii_case("chunked") {
                return if message.is_request() {
                    Err(Error::Protocol("Transfer-Encoding on a request does not end with chunked".into()))
                } else {
                    Ok(Self::Close)
                };
            }

            return Ok(Self::Chunked);
        }

        if measured {
            let mut values = headers
                .into_iter()
                .flat_map(|headers| headers.get_all("content-length"))
                .flat_map(|value| value.split(','))
                .map(str::trim);

            let first = values.next().unwrap_or_default();
            let length = Self::content_length(first)?;

            for value in values {
                if Self::content_length(value)? != length {
                    return Err(Error::Protocol("Content-Length values disagree".into()));
                }
            }

            return Ok(Self::Fixed(length));
        }

        if message.is_request() { Ok(Self::None) } else { Ok(Self::Close) }
    }

    /// Reads a `Content-Length` value.
    ///
    /// Only digits are accepted — no sign, no whitespace, no `+` — since
    /// anything looser lets two intermediaries read one field as two different
    /// lengths.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the value is not a run of digits, or
    /// does not fit in a `u64`.
    pub fn content_length(value: &str) -> Result<u64, Error> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Protocol(format!("Content-Length {value:?} is not a number")));
        }

        value.parse().map_err(|_| Error::Protocol(format!("Content-Length {value:?} does not fit")))
    }
}

/// One request awaiting its response.
///
/// A client remembers one as it sends a request and takes it back as the
/// answer arrives; a server does the reverse. What is kept is what a response
/// cannot be framed or coded without: the method that asked for it, and the
/// best coding the request said it would take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exchange {
    /// The method of the request.
    pub method: Method,
    /// The best coding the request's `Accept-Encoding` permits.
    pub accepted: Option<Compression>,
}

impl Exchange {
    /// An exchange for a request with `method`, permitting `accepted`.
    pub fn new(method: Method, accepted: Option<Compression>) -> Self {
        Self { method, accepted }
    }

    /// The exchange a received request opens, or `None` for a response.
    pub fn of(message: &Message) -> Option<Self> {
        Some(Self::new(message.method?, message.accepted()))
    }
}

/// An HTTP/1.0 or HTTP/1.1 connection.
///
/// One message at a time in each direction. As a client it may pipeline, up to
/// [`Limits::max_concurrent_streams`] requests awaiting a response, and it
/// remembers each request's method so the matching response can be framed.
///
/// The connection can be handed over to another protocol with
/// [`H1Connection::upgrade`], which gives up the transport along with whatever
/// has already been buffered.
pub struct H1Connection<T> {
    transport: T,
    role: Role,
    version: Version,
    id: ConnectionID,
    client: Option<std::net::SocketAddr>,
    limits: H1Limits,
    buffer: Buffer,
    scratch: BytesMut,
    pending: VecDeque<Exchange>,
    closing: bool,
    request_finalizer: crate::finalizer::RequestFinalizer,
    response_finalizer: crate::finalizer::ResponseFinalizer,
    security: Security,
}

impl<T> H1Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// A connection over a transport nothing has been read from yet.
    pub fn new(transport: T, role: Role, id: ConnectionID, limits: impl Into<H1Limits>) -> Self {
        let limits = limits.into();
        Self::resume(transport, role, id, limits, Buffer::new())
    }

    /// A connection over a transport that has already been read from.
    ///
    /// This is what version sniffing needs: the octets read to decide the
    /// version are handed over rather than lost.
    pub fn resume(transport: T, role: Role, id: ConnectionID, limits: impl Into<H1Limits>, buffer: Buffer) -> Self {
        let limits = limits.into();
        let mut buffer = buffer;
        buffer.set_chunk_size(limits.read_chunk_size as usize);

        Self {
            transport,
            role,
            version: Version::V1_1,
            id,
            client: None,
            limits,
            buffer,
            scratch: BytesMut::new(),
            pending: VecDeque::new(),
            closing: false,
            request_finalizer: crate::finalizer::RequestFinalizer::default(),
            response_finalizer: crate::finalizer::ResponseFinalizer::new(None),
            security: Security::default(),
        }
    }

    /// Sets which HTTP/1.x version this end speaks.
    ///
    /// HTTP/1.0 and HTTP/1.1 share one connection type, so unlike HTTP/2 and
    /// HTTP/3 the version cannot be read off the type; this is where what was
    /// negotiated or configured is carried in. A connection told nothing speaks
    /// [`Version::V1_1`].
    ///
    /// This is what this end puts in the messages it originates — a server
    /// sends its own version rather than echoing the request's, so a `V1_1`
    /// connection answers an HTTP/1.0 request with `HTTP/1.1`.
    ///
    /// # Panics
    ///
    /// Never, but a version that is not HTTP/1.x is ignored: this connection
    /// cannot speak one, and [`StartLine::write`] would refuse every message.
    pub fn with_version(mut self, version: Version) -> Self {
        if version.major() == 1 {
            self.version = version;
        }
        self
    }

    /// The ceilings this connection holds itself to.
    pub fn limits(&self) -> H1Limits {
        self.limits
    }

    /// Attaches the finalisation applied to requests on the way out.
    ///
    /// What finalising a request means is the finalizer's business, not this
    /// connection's: a connection frames messages and knows nothing of what an
    /// endpoint owes them.
    pub fn with_request_finalizer(mut self, finalizer: crate::finalizer::RequestFinalizer) -> Self {
        self.request_finalizer = finalizer;
        self
    }

    /// Attaches the finalisation applied to responses on the way out.
    ///
    /// The counterpart of [`H1Connection::with_request_finalizer`], and for the
    /// same reason.
    pub fn with_response_finalizer(mut self, finalizer: crate::finalizer::ResponseFinalizer) -> Self {
        self.response_finalizer = finalizer;
        self
    }

    /// Attaches what the handshake settled, to be stamped on every message
    /// this connection receives.
    pub fn with_security(mut self, security: Security) -> Self {
        self.security = security;
        self
    }

    /// Attaches the address the peer connected from, to be stamped on every
    /// request this connection receives.
    ///
    /// A client connection is told none, and neither is one over a Unix
    /// socket, so [`Message::client`] stays absent on both.
    pub fn with_client(mut self, client: Option<std::net::SocketAddr>) -> Self {
        self.client = client;
        self
    }

    /// How much the read buffer has allocated.
    pub fn buffer_capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// How much the write buffer has allocated.
    pub fn scratch_capacity(&self) -> usize {
        self.scratch.capacity()
    }

    /// Gives up the transport and the read buffer, for another protocol to take over.
    ///
    /// This is how a `101 Switching Protocols` is followed through: whatever
    /// the peer sent after the handshake is already buffered and must not be
    /// dropped.
    pub fn upgrade(self) -> (T, Buffer) {
        (self.transport, self.buffer)
    }

    /// Writes octets without flushing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] past [`Limits::write_timeout`], and
    /// [`Error::IO`] when the transport fails.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        sync::Timeout::within(self.limits.write_timeout, self.transport.write_all(data)).await??;
        Ok(())
    }

    /// Writes octets and flushes, both under one deadline.
    ///
    /// # Errors
    ///
    /// As [`H1Connection::write`].
    pub async fn write_flushed(&mut self, data: &[u8]) -> Result<(), Error> {
        let transport = &mut self.transport;

        sync::Timeout::within(self.limits.write_timeout, async move {
            transport.write_all(data).await?;
            transport.flush().await
        })
        .await??;

        Ok(())
    }

    /// Flushes whatever the transport has buffered.
    ///
    /// # Errors
    ///
    /// As [`H1Connection::write`].
    pub async fn flush(&mut self) -> Result<(), Error> {
        sync::Timeout::within(self.limits.write_timeout, self.transport.flush()).await??;
        Ok(())
    }

    /// Answers with a bare status and marks the connection for closing.
    ///
    /// Used where the request could not be parsed, so there is no telling
    /// where the next one would begin.
    ///
    /// # Errors
    ///
    /// As [`H1Connection::send_message`].
    pub async fn reject(&mut self, status_code: u16) -> Result<(), Error> {
        self.closing = true;
        self.send_message(Message::response(status_code, self.version)).await
    }

    /// How many requests may be in flight at once.
    ///
    /// It bounds the pipeline in both directions: what a client may send
    /// before the first answer arrives, and how many received requests a
    /// server remembers before it starts answering them.
    pub fn pipeline_depth(&self) -> usize {
        (self.limits.max_concurrent_streams as usize).max(1)
    }

    /// The coding the exchange a message belongs to permits.
    ///
    /// A server answers from the request it is about to answer, which is the
    /// one at the front of the pipeline. A client has no exchange to consult —
    /// nothing tells it what an origin accepts — and so permits nothing, which
    /// is what leaves [`Compression::Auto`] sending a request body as it
    /// stands.
    pub fn accepted(&self, message: &Message) -> Option<Compression> {
        message.is_response().then(|| self.pending.front()?.accepted).flatten()
    }

    /// Writes one whole message: start line, fields, and body.
    ///
    /// A client-side request is finalised first, so it carries the authority
    /// the connection was dialled with. A server-side response is stamped with
    /// what the transport turned out to be and then finalised, so `Date`,
    /// `Server` and — over a secure transport alone — the HSTS policy are
    /// attached.
    ///
    /// The body is framed as the fields already say, and `Content-Length` is
    /// added when neither `Transfer-Encoding` nor an existing `Content-Length`
    /// says otherwise and the status admits a body. Bodies up to
    /// [`Limits::inline_body_size`] go out together with the head.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when more than [`H1Connection::pipeline_depth`]
    /// requests are already awaiting a response, [`Error::IO`] when a
    /// [`Body::File`] cannot be read, and otherwise as [`StartLine::write`],
    /// [`Field::write`] and [`H1Connection::write_flushed`].
    pub async fn send_message(&mut self, message: Message) -> Result<(), Error> {
        if message.method.is_some() && self.pending.len() >= self.pipeline_depth() {
            let reason = format!("more than {} requests are awaiting a response", self.pipeline_depth());
            return Err(Error::Limit(reason));
        }

        let mut message = message;
        self.request_finalizer.finalize(self.role, &mut message);
        self.response_finalizer.finalize(self.role, self.security.secure, &mut message);

        message.materialize().await?;
        message.compress(self.accepted(&message))?;

        let body = match message.body.take().map(Body::into_inline) {
            Some(Ok(data)) => Some(data),
            Some(Err(path)) => Some(Bytes::from(Box::pin(tokio::fs::read(path)).await?)),
            None => None,
        };

        let case = HeaderCase::from_version(message.version);
        let headers = message.headers.as_ref();

        let chunked = headers.is_some_and(|headers| {
            headers
                .get_all("transfer-encoding")
                .any(|value| value.rsplit(',').next().unwrap_or_default().trim().eq_ignore_ascii_case("chunked"))
        });

        let bodyless = matches!(message.status_code, Some(100..=199 | 204 | 304));
        let has_length = headers.is_some_and(|headers| headers.contains("content-length"));

        let inline = body.as_ref().is_some_and(|body| body.len() <= self.limits.inline_body_size as usize);

        let estimate = 64
            + headers.map_or(0, |headers| headers.len() * 40)
            + if inline { body.as_ref().map_or(0, Bytes::len) + 16 } else { 0 };

        let mut out = std::mem::take(&mut self.scratch);
        out.clear();
        out.reserve(estimate);

        let closing = self.closing;
        let head = (|| -> Result<(), Error> {
            StartLine::write(&message, &mut out)?;
            out.extend_from_slice(b"\r\n");

            if let Some(headers) = headers {
                Field::write_all(headers, case, &mut out)?;
            }

            if !chunked && !has_length && !bodyless {
                match &body {
                    Some(body) => Field::write_content_length(body.len() as u64, case, &mut out),
                    None if message.is_response() => Field::write_content_length(0, case, &mut out),
                    None => {}
                }
            }

            if closing && !headers.is_some_and(|headers| headers.contains("connection")) {
                Field::write("connection", "close", case, &mut out)?;
            }

            out.extend_from_slice(b"\r\n");
            Ok(())
        })();

        if let Err(error) = head {
            self.scratch = out;
            return Err(error);
        }

        let trailing = match (chunked, body) {
            (true, body) => {
                if let Some(body) = body.filter(|body| !body.is_empty()) {
                    Chunk::write(&body, &mut out);
                }

                out.extend_from_slice(b"0\r\n");
                if let Some(trailers) = &message.trailers {
                    Field::write_all(trailers, case, &mut out)?;
                }
                out.extend_from_slice(b"\r\n");

                None
            }

            (false, Some(body)) if inline => {
                out.extend_from_slice(&body);
                None
            }

            (false, body) => body,
        };

        let method = message.method;
        let informational = message.is_informational();
        drop(message);

        if let Some(body) = trailing {
            self.write(&out).await?;
            self.write_flushed(&body).await?;
        } else {
            self.write_flushed(&out).await?;
        }

        out.clear();
        common::Buffer::reclaim_bytes(&mut out, self.limits.idle_capacity as usize);
        self.scratch = out;

        match method {
            Some(method) => self.pending.push_back(Exchange::new(method, None)),
            None if self.role.is_server() && !informational => drop(self.pending.pop_front()),
            None => {}
        }

        Ok(())
    }

    /// Reads one whole message.
    ///
    /// A server that cannot parse the request line answers with the status
    /// [`StartLine::error_status`] picks before reporting the failure, since
    /// a client that sent something malformed is owed an explanation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the peer is done, [`Error::Limit`] when
    /// the message goes past [`Limits::max_message_size`] or one of the other
    /// ceilings, and otherwise as the parsers above.
    pub async fn receive_message(&mut self) -> Result<Message, Error> {
        let length = Line::end(&mut self.buffer, &mut self.transport, self.limits.max_startline_size as usize, self.limits.read_timeout).await?;

        let mut message = match StartLine::parse_bytes(&self.buffer.as_slice()[..length]) {
            Ok(message) => {
                self.buffer.consume(length + 2);
                message
            }
            Err(error) => {
                let status = self
                    .role
                    .is_server()
                    .then(|| StartLine::error_status_bytes(&self.buffer.as_slice()[..length]));

                self.buffer.consume(length + 2);

                if let Some(status) = status {
                    let _ = Box::pin(self.reject(status)).await;
                }

                return Err(error);
            }
        };

        let (headers, block) = self.read_header_block().await?;
        let head = length as u64 + 4 + block as u64;

        message.headers = Some(headers);
        message.connection_id = Some(self.id.clone());
        message.client = self.client;
        self.security.apply(&mut message);

        self.closing = self.closing || !Persistence::keep_alive(message.headers.as_ref(), message.version);

        let limit = self.limits.max_message_size;
        let Some(budget) = limit.checked_sub(head) else {
            return Err(Error::Limit(format!("message head of {head} octets exceeds {limit}")));
        };

        if let Some(exchange) = self.role.is_server().then(|| Exchange::of(&message)).flatten() {
            if self.pending.len() >= self.pipeline_depth() {
                let reason = format!("more than {} requests are awaiting an answer", self.pipeline_depth());
                return Err(Error::Limit(reason));
            }

            self.pending.push_back(exchange);
        }

        let method = if message.is_response() { self.pending.pop_front().map(|exchange| exchange.method) } else { None };

        let length = BodyLength::of(&message, method)?;

        message.body = match length {
            BodyLength::None => None,
            _ => self.receive_body(length, budget).await?.map(Body::Data),
        };

        if length == BodyLength::Chunked {
            message.trailers = Some(self.read_header_block().await?.0);
        }

        message.decompress(self.limits.max_decompressed_body_size)?;

        self.buffer.reclaim(self.limits.idle_capacity as usize);
        Ok(message)
    }

    /// Reads a field section on its own, such as a trailer section.
    ///
    /// # Errors
    ///
    /// As [`H1Connection::read_header_block`].
    pub async fn receive_headers(&mut self) -> Result<Headers, Error> {
        Ok(self.read_header_block().await?.0)
    }

    /// Reads a field section, returning it and how many octets it occupied.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] past [`Limits::max_headers_size`],
    /// [`Error::Closed`] when the transport ends first, and otherwise as
    /// [`Buffer::fill`] and [`Field::parse_block`].
    pub async fn read_header_block(&mut self) -> Result<(Headers, usize), Error> {
        let max = self.limits.max_headers_size;
        let mut searched = 0usize;

        let (fields, consumed) = loop {
            if let Some(found) = Field::block_end(self.buffer.as_slice(), &mut searched) {
                break found;
            }

            if self.buffer.len() as u64 > max {
                return Err(Error::Limit(format!("header block exceeds {max} octets")));
            }

            if !self.buffer.fill(&mut self.transport, self.limits.read_timeout).await? {
                return Err(Error::Closed);
            }
        };

        if fields as u64 > max {
            return Err(Error::Limit(format!("header block exceeds {max} octets")));
        }

        let headers = Field::parse_block(&self.buffer.as_slice()[..fields], self.limits.max_header_count as usize)?;
        self.buffer.consume(consumed);

        Ok((headers, consumed))
    }

    /// [`H1Connection::read_body`], reporting an empty body as no body at all.
    ///
    /// # Errors
    ///
    /// As [`H1Connection::read_body`].
    pub async fn receive_body(&mut self, length: BodyLength, budget: u64) -> Result<Option<Bytes>, Error> {
        Ok(self.read_body(length, budget).await?.filter(|body| !body.is_empty()))
    }

    /// Reads a message body framed as `length` says.
    ///
    /// `budget` is what remains of [`Limits::max_message_size`] once the head
    /// has been counted; the body is held to the lesser of that and
    /// [`Limits::max_message_body_size`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when the body goes past that ceiling or a
    /// chunk size line past [`Limits::max_chunk_header_size`],
    /// [`Error::Closed`] when the transport ends mid-body, and otherwise as
    /// [`Buffer::require`], [`Chunk::parse_size`], [`Chunk::decode`] and
    /// [`Buffer::fill`].
    pub async fn read_body(&mut self, length: BodyLength, budget: u64) -> Result<Option<Bytes>, Error> {
        let limit = self.limits.max_message_body_size.min(budget);

        match length {
            BodyLength::None => Ok(None),

            BodyLength::Fixed(size) => {
                if size > limit {
                    return Err(Error::Limit(format!("body of {size} octets exceeds {limit}")));
                }

                let size = usize::try_from(size).map_err(|_| Error::Limit(format!("body of {size} octets exceeds what this platform can address")))?;

                self.buffer.require(&mut self.transport, size, self.limits.read_timeout).await?;
                Ok(Some(self.buffer.take(size).freeze()))
            }

            BodyLength::Chunked => {
                let mut body = BytesMut::new();

                loop {
                    match Chunk::parse_size(self.buffer.as_slice())? {
                        Some((_, size)) if (body.len() as u64).saturating_add(size as u64) > limit => {
                            return Err(Error::Limit(format!("chunked body exceeds {limit} octets")));
                        }
                        None if self.buffer.len() > self.limits.max_chunk_header_size as usize => {
                            return Err(Error::Limit(format!("chunk size line exceeds {} octets", self.limits.max_chunk_header_size)));
                        }
                        _ => {}
                    }

                    let (consumed, chunk) = Chunk::decode(self.buffer.as_slice())?;
                    if consumed == 0 {
                        if !self.buffer.fill(&mut self.transport, self.limits.read_timeout).await? {
                            return Err(Error::Closed);
                        }
                        continue;
                    }

                    if chunk.is_empty() {
                        self.buffer.consume(consumed);
                        return Ok(Some(body.freeze()));
                    }

                    body.extend_from_slice(&self.buffer.as_slice()[chunk]);
                    self.buffer.consume(consumed);
                }
            }

            BodyLength::Close => {
                while self.buffer.fill(&mut self.transport, self.limits.read_timeout).await? {
                    if self.buffer.len() as u64 > limit {
                        return Err(Error::Limit(format!("body exceeds {limit} octets")));
                    }
                }

                let size = self.buffer.len();
                Ok(Some(self.buffer.take(size).freeze()))
            }
        }
    }
}

impl<T> Connection for H1Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn version(&self) -> Version {
        self.version
    }

    fn role(&self) -> Role {
        self.role
    }

    fn id(&self) -> ConnectionID {
        self.id.clone()
    }

    fn reusable(&self) -> bool {
        !self.closing
    }

    fn security(&self) -> Security {
        self.security
    }

    fn client(&self) -> Option<std::net::SocketAddr> {
        self.client
    }

    async fn send(&mut self, message: Message) -> Result<(), Error> {
        let timeout = self.limits.send_timeout;
        let sending = std::pin::pin!(self.send_message(message));
        sync::Timeout::within(timeout, sending).await?
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        let timeout = self.limits.receive_timeout;
        let receiving = std::pin::pin!(self.receive_message());
        sync::Timeout::within(timeout, receiving).await?
    }

    async fn close(&mut self) {
        let _ = self.transport.flush().await;
        let _ = self.transport.shutdown().await;
    }
}
