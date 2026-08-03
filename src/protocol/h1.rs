//! HTTP/1.0 and HTTP/1.1.
//!
//! One message at a time in each direction, framed as a start line, a field
//! section, and a body whose length comes from `Content-Length`,
//! `Transfer-Encoding`, or the connection closing — which is what
//! [`body_length`] works out.
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

use crate::api::common::Limits;
use crate::helpers::scan;
use crate::helpers::text::Text;
use crate::models::{Body, ConnectionID, HeaderCase, Headers, Message, Method, Role, Security, Version};
use crate::protocol::base::Connection;
use crate::protocol::common::{self, Buffer, Error};

/// The reason phrase conventionally paired with a status code.
///
/// Unknown codes get `"Unknown"`. The phrase carries no meaning on the wire —
/// recipients act on the code — so this only has to be something sensible.
pub fn reason_phrase(status_code: u16) -> &'static str {
    match status_code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "Unknown",
    }
}

/// Appends a decimal integer.
pub fn write_number(mut value: u64, out: &mut BytesMut) {
    let mut digits = [0u8; 20];
    let mut index = digits.len();

    loop {
        index -= 1;
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;

        if value == 0 {
            break;
        }
    }

    out.extend_from_slice(&digits[index..]);
}

/// Appends the start line, without its terminating CRLF.
///
/// # Errors
///
/// Returns [`Error::Version`] for a message that is not HTTP/1.x, and
/// [`Error::Protocol`] for one that is neither a request nor a response.
pub fn write_start_line_into(message: &Message, out: &mut BytesMut) -> Result<(), Error> {
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
        let reason = reason_phrase(status_code);
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
        write_number(status_code as u64, out);
        out.extend_from_slice(b" ");
        out.extend_from_slice(reason.as_bytes());
        return Ok(());
    }

    Err(Error::Protocol("message is neither a request nor a response".into()))
}

/// [`write_start_line_into`], returning the line as a `String`.
///
/// # Errors
///
/// As [`write_start_line_into`].
pub fn write_start_line(message: &Message) -> Result<String, Error> {
    let mut out = BytesMut::new();
    write_start_line_into(message, &mut out)?;
    Ok(String::from_utf8(out.to_vec()).unwrap_or_default())
}

/// [`parse_start_line`] over raw octets.
///
/// # Errors
///
/// Returns [`Error::Protocol`] when the line is not valid UTF-8, and otherwise
/// as [`parse_start_line`].
#[inline]
pub fn parse_start_line_bytes(line: &[u8]) -> Result<Message, Error> {
    let line = std::str::from_utf8(line).map_err(|_| Error::Protocol("start line is not valid UTF-8".into()))?;
    parse_start_line(line)
}

/// Splits a line at `at`, discarding the octet there.
///
/// # Panics
///
/// Panics when `at` is not a character boundary, or is past the end.
pub fn split_once(line: &str, at: usize) -> (&str, &str) {
    (&line[..at], &line[at + 1..])
}

/// Parses a start line into an empty request or response.
///
/// A line beginning `HTTP/` is read as a status line and anything else as a
/// request line.
///
/// # Errors
///
/// Returns [`Error::Protocol`] for a malformed line — a missing field, a
/// status code that is not three digits, a control octet in the reason phrase,
/// an unrecognised method, or a request target that is empty or carries a
/// space or a control octet — and [`Error::Version`] for a version that is not
/// HTTP/1.x.
pub fn parse_start_line(line: &str) -> Result<Message, Error> {
    if line.as_bytes().starts_with(b"HTTP/") {
        let Some(first) = scan::find(line.as_bytes(), b' ') else {
            return Err(Error::Protocol("status line has no status code".into()));
        };

        let (version, rest) = split_once(line, first);
        let (status_code, reason) = match scan::find(rest.as_bytes(), b' ') {
            Some(second) => split_once(rest, second),
            None => return Err(Error::Protocol("status line has no reason phrase".into())),
        };

        if status_code.len() != 3 || !status_code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Protocol(format!("status code {status_code:?} is not three digits")));
        }

        if reason.bytes().any(is_control) {
            return Err(Error::Protocol("reason phrase contains a control character".into()));
        }

        let status_code = status_code
            .parse()
            .map_err(|_| Error::Protocol(format!("status code {status_code:?} is not three digits")))?;

        return Ok(Message::response(status_code, parse_version(version)?));
    }

    let Some(first) = scan::find(line.as_bytes(), b' ') else {
        return Err(Error::Protocol("request line has no target".into()));
    };

    let (method, rest) = split_once(line, first);
    let (target, version) = match scan::find(rest.as_bytes(), b' ') {
        Some(second) => split_once(rest, second),
        None => return Err(Error::Protocol("request line has no version".into())),
    };

    let method: Method = method.parse().map_err(|_| Error::Protocol(format!("method {method:?} is not recognised")))?;

    if target.is_empty() || target.bytes().any(|byte| byte == b' ' || is_control(byte)) {
        return Err(Error::Protocol(format!("request target {target:?} is malformed")));
    }

    Ok(Message::request(method, target, parse_version(version)?))
}

/// [`request_line_error_status`] over raw octets.
pub fn request_line_error_status_bytes(line: &[u8]) -> u16 {
    match std::str::from_utf8(line) {
        Ok(line) => request_line_error_status(line),
        Err(_) => 400,
    }
}

/// The status a server should answer a request line it could not parse with.
///
/// 501 for a method that is not recognised, 505 for a version that is not
/// HTTP/1.x, and 400 for everything else — so the client is told which part it
/// got wrong rather than just that something was.
pub fn request_line_error_status(line: &str) -> u16 {
    let Some(first) = scan::find(line.as_bytes(), b' ') else {
        return 400;
    };

    let (method, rest) = split_once(line, first);
    let (target, version) = match scan::find(rest.as_bytes(), b' ') {
        Some(second) => split_once(rest, second),
        None => return 400,
    };

    if method.parse::<Method>().is_err() {
        return 501;
    }

    if target.is_empty() || target.bytes().any(|byte| byte == b' ' || is_control(byte)) {
        return 400;
    }

    if parse_version(version).is_err() {
        return 505;
    }

    400
}

/// Reads an HTTP/1.x version from a start line.
///
/// # Errors
///
/// Returns [`Error::Version`] for anything that is not `HTTP/1.0` or
/// `HTTP/1.1`.
pub fn parse_version(text: &str) -> Result<Version, Error> {
    match text {
        "HTTP/1.0" => Ok(Version::V1_0),
        "HTTP/1.1" => Ok(Version::V1_1),
        _ => Err(Error::Version(format!("{text:?} is not an HTTP/1.x version"))),
    }
}

/// Whether an octet is a control character, tab included.
pub fn is_control(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
}

/// [`OCTETS`]: the octet may appear in a token, and so in a field name.
pub const TOKEN: u8 = 1 << 0;
/// [`OCTETS`]: the octet may appear in a field value.
pub const FIELD: u8 = 1 << 1;

/// What each octet is allowed to be part of: the or of [`TOKEN`] and [`FIELD`].
pub static OCTETS: [u8; 256] = {
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

        octets[value] = (token as u8) | (field as u8) << 1;
        value += 1;
    }

    octets
};

/// Whether a string is a non-empty token, and so usable as a field name.
pub fn is_token(text: &str) -> bool {
    is_token_bytes(text.as_bytes())
}

/// [`is_token`] over raw octets.
#[inline]
pub fn is_token_bytes(text: &[u8]) -> bool {
    !text.is_empty() && scan::all_in_class(text, &OCTETS, TOKEN)
}

/// Whether octets may be sent as a field value; see [`scan::is_field_value`].
pub fn is_field_value(text: &[u8]) -> bool {
    scan::is_field_value(text)
}

/// Appends one field line, terminator included, in the given casing.
///
/// # Errors
///
/// Returns [`Error::Protocol`] when the name is not a token or the value
/// carries a control octet — either of which would let the field break out of
/// its line and inject another.
pub fn write_header_line_into(name: &str, value: &str, case: HeaderCase, out: &mut BytesMut) -> Result<(), Error> {
    if !is_token(name) {
        return Err(Error::Protocol(format!("field name {name:?} is not a token")));
    }

    if !is_field_value(value.as_bytes()) {
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

/// [`write_header_line_into`], returning the line as a `String`.
///
/// # Errors
///
/// As [`write_header_line_into`].
pub fn write_header_line(name: &str, value: &str, case: HeaderCase) -> Result<String, Error> {
    let mut out = BytesMut::new();
    write_header_line_into(name, value, case, &mut out)?;
    Ok(String::from_utf8(out.to_vec()).unwrap_or_default())
}

/// Appends a whole field section, without the blank line that ends it.
///
/// # Errors
///
/// As [`write_header_line_into`]. The buffer may hold a partial section when
/// this fails.
pub fn write_headers_into(headers: &Headers, case: HeaderCase, out: &mut BytesMut) -> Result<(), Error> {
    out.reserve(headers_size(headers) as usize);

    for (name, value) in headers.iter() {
        write_header_line_into(name, value, case, out)?;
    }
    Ok(())
}

/// [`write_headers_into`], returning the section as a `String`.
///
/// # Errors
///
/// As [`write_header_line_into`].
pub fn write_headers(headers: &Headers, case: HeaderCase) -> Result<String, Error> {
    let mut out = BytesMut::new();
    write_headers_into(headers, case, &mut out)?;
    Ok(String::from_utf8(out.to_vec()).unwrap_or_default())
}

/// Appends a `Content-Length` field line, terminator included.
///
/// Kept apart from [`write_header_line_into`] because it goes out on nearly
/// every message and neither the name nor the value can fail validation.
pub fn write_content_length_into(length: u64, case: HeaderCase, out: &mut BytesMut) {
    let mut digits = [0u8; 20];
    let mut index = digits.len();
    let mut value = length;

    loop {
        index -= 1;
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;

        if value == 0 {
            break;
        }
    }

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

/// How many octets a field section will take on the wire, terminators included.
pub fn headers_size(headers: &Headers) -> u64 {
    headers.iter().map(|(name, value)| (name.len() + value.len() + 4) as u64).sum()
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

    if !scan::all_in_class(&line[..at], &OCTETS, TOKEN) {
        return Err(Error::Protocol(format!("field name {:?} is not a token", String::from_utf8_lossy(&line[..at]))));
    }

    Ok(at)
}

/// Locates the name and value within a field line, and classifies the value.
///
/// # Errors
///
/// Returns [`Error::Protocol`] as [`name_end`] does, and when the value
/// carries a control octet.
#[inline]
pub fn field_spans(line: &[u8]) -> Result<FieldSpans, Error> {
    let colon = name_end(line)?;

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
/// As [`field_spans`].
pub fn parse_header_line(line: &str) -> Result<(String, String), Error> {
    let spans = field_spans(line.as_bytes())?;

    Ok((
        line.get(spans.name).unwrap_or_default().to_ascii_lowercase(),
        line.get(spans.value).unwrap_or_default().to_owned(),
    ))
}

/// Parses a field section from already-split lines.
///
/// # Errors
///
/// Returns [`Error::Protocol`] for a folded continuation line, which is
/// obsolete and a smuggling vector, and otherwise as [`field_spans`].
pub fn parse_headers(lines: impl IntoIterator<Item = String>) -> Result<Headers, Error> {
    let mut headers = Headers::new();

    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(Error::Protocol("field line is folded onto a continuation line".into()));
        }

        let (name, value) = parse_field(line.as_bytes())?;
        headers.append_lowercase(name, value);
    }

    Ok(headers)
}

/// Parses one field line straight into [`Text`], lowercasing the name.
///
/// # Errors
///
/// As [`field_spans`].
pub fn parse_field(line: &[u8]) -> Result<(Text, Text), Error> {
    let spans = field_spans(line)?;

    let name = Text::from_verified_ascii_lowercase(&line[spans.name]);
    let value = match spans.ascii {
        true => Text::from_verified_ascii(&line[spans.value]),
        false => Text::from_utf8_lossy(&line[spans.value]),
    };

    Ok((name, value))
}

/// Finds the blank line that ends a field section.
///
/// Returns where the field lines stop and where the section as a whole ends,
/// the terminator included. `searched` carries how far the scan already got,
/// so that repeated calls as more octets arrive do not rescan from the front.
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

/// Parses a whole field section, without its terminating blank line.
///
/// # Errors
///
/// Returns [`Error::Limit`] past `max_count` fields, [`Error::Protocol`] for a
/// line not terminated by CRLF or folded onto a continuation line, and
/// otherwise as [`field_spans`].
pub fn parse_header_block(block: &[u8], max_count: usize) -> Result<Headers, Error> {
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

        let (name, value) = parse_field(line)?;
        headers.append_lowercase(name, value);
    }

    Ok(headers)
}

/// Writes `value` as lowercase hexadecimal into the back of `digits`, and
/// returns where it starts.
pub fn hex_digits(mut value: u64, digits: &mut [u8; 16]) -> usize {
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
pub fn write_hex(value: u64, out: &mut Vec<u8>) {
    let mut digits = [0u8; 16];
    let index = hex_digits(value, &mut digits);
    out.extend_from_slice(&digits[index..]);
}

/// Appends one chunk: its size line, the data, and a CRLF.
///
/// A zero-length chunk written this way would end the body, so callers filter
/// empty data out rather than framing it.
pub fn write_chunk_into(data: &[u8], out: &mut BytesMut) {
    let mut digits = [0u8; 16];
    let index = hex_digits(data.len() as u64, &mut digits);

    out.reserve(digits.len() - index + data.len() + 4);
    out.extend_from_slice(&digits[index..]);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// [`write_chunk_into`], returning the chunk on its own.
pub fn encode_chunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 20);

    write_hex(data.len() as u64, &mut out);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");

    out
}

/// Reads a chunk size line, returning where the data starts and how long it is.
///
/// `None` when the line has not fully arrived yet. Any chunk extensions after
/// a `;` are read past and discarded.
///
/// # Errors
///
/// Returns [`Error::Protocol`] when the line is not terminated by CRLF or the
/// size is not hexadecimal.
pub fn parse_chunk_size(data: &[u8]) -> Result<Option<(usize, usize)>, Error> {
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
/// Returns how many octets the chunk occupies and where its data sits within
/// them. A consumed count of zero means the chunk has not fully arrived yet;
/// an empty range with a non-zero count is the final chunk that ends the body.
///
/// # Errors
///
/// Returns [`Error::Protocol`] as [`parse_chunk_size`] does, when the data is
/// not terminated by CRLF, and when the size is too large to address.
pub fn decode_chunk(data: &[u8]) -> Result<(usize, Range<usize>), Error> {
    let Some((start, size)) = parse_chunk_size(data)? else {
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

/// Reads a `Content-Length` value.
///
/// Only digits are accepted — no sign, no whitespace, no `+` — since anything
/// looser lets two intermediaries read one field as two different lengths.
///
/// # Errors
///
/// Returns [`Error::Protocol`] when the value is not a run of digits, or does
/// not fit in a `u64`.
pub fn parse_content_length(value: &str) -> Result<u64, Error> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Protocol(format!("Content-Length {value:?} is not a number")));
    }

    value.parse().map_err(|_| Error::Protocol(format!("Content-Length {value:?} does not fit")))
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

/// Works out how a message's body is framed.
///
/// `method` is the method of the request this responds to, which some
/// responses need in order to be framed at all: a response to `HEAD` has no
/// body however it is labelled, and a successful response to `CONNECT` is
/// followed by tunnelled octets rather than a body. Pass `None` for a request.
///
/// # Errors
///
/// Returns [`Error::Protocol`] when `Transfer-Encoding` and `Content-Length`
/// are both present, when a request's `Transfer-Encoding` does not end in
/// `chunked`, and when two `Content-Length` values disagree. Each of these is
/// a way of making one byte stream read as two different messages.
pub fn body_length(message: &Message, method: Option<Method>) -> Result<BodyLength, Error> {
    let headers = message.headers.as_ref();

    if let Some(status_code) = message.status_code {
        if matches!(status_code, 100..=199 | 204 | 304) || method == Some(Method::HEAD) {
            return Ok(BodyLength::None);
        }

        if method == Some(Method::CONNECT) && (200..300).contains(&status_code) {
            return Ok(BodyLength::None);
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
                Ok(BodyLength::Close)
            };
        }

        return Ok(BodyLength::Chunked);
    }

    if measured {
        let mut values = headers
            .into_iter()
            .flat_map(|headers| headers.get_all("content-length"))
            .flat_map(|value| value.split(','))
            .map(str::trim);

        let first = values.next().unwrap_or_default();
        let length = parse_content_length(first)?;

        for value in values {
            if parse_content_length(value)? != length {
                return Err(Error::Protocol("Content-Length values disagree".into()));
            }
        }

        return Ok(BodyLength::Fixed(length));
    }

    if message.is_request() { Ok(BodyLength::None) } else { Ok(BodyLength::Close) }
}

/// The body size up to which the head and the body go out as one write.
///
/// Below this, coalescing saves a syscall and a round trip; above it, copying
/// the body into the head buffer costs more than the extra write.
pub const INLINE_BODY_LIMIT: usize = 64 * 1024;

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
    id: ConnectionID,
    limits: Limits,
    buffer: Buffer,
    scratch: BytesMut,
    pending: VecDeque<Method>,
    closing: bool,
    hsts: Option<crate::helpers::hsts::HstsPolicy>,
    security: Security,
}

impl<T> H1Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// A connection over a transport nothing has been read from yet.
    pub fn new(transport: T, role: Role, id: ConnectionID, limits: Limits) -> Self {
        Self::resume(transport, role, id, limits, Buffer::new())
    }

    /// A connection over a transport that has already been read from.
    ///
    /// This is what version sniffing needs: the octets read to decide the
    /// version are handed over rather than lost.
    pub fn resume(transport: T, role: Role, id: ConnectionID, limits: Limits, buffer: Buffer) -> Self {
        Self {
            transport,
            role,
            id,
            limits,
            buffer,
            scratch: BytesMut::new(),
            pending: VecDeque::new(),
            closing: false,
            hsts: None,
            security: Security::default(),
        }
    }

    /// Attaches an HSTS policy to be added to the responses this connection
    /// sends, if the transport underneath it is a secure one.
    pub fn with_hsts(mut self, hsts: Option<crate::helpers::hsts::HstsPolicy>) -> Self {
        self.hsts = hsts;
        self
    }

    /// Attaches what the handshake settled, to be stamped on every message
    /// this connection receives.
    pub fn with_security(mut self, security: Security) -> Self {
        self.security = security;
        self
    }

    /// The limits this connection holds itself to.
    pub fn limits(&self) -> &Limits {
        &self.limits
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
    /// [`Error::Io`] when the transport fails.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        common::within(self.limits.write_timeout, self.transport.write_all(data)).await??;
        Ok(())
    }

    /// Writes octets and flushes, both under one deadline.
    ///
    /// # Errors
    ///
    /// As [`H1Connection::write`].
    pub async fn write_flushed(&mut self, data: &[u8]) -> Result<(), Error> {
        let transport = &mut self.transport;

        common::within(self.limits.write_timeout, async move {
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
        common::within(self.limits.write_timeout, self.transport.flush()).await??;
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
        self.send_message(Message::response(status_code, Version::V1_1)).await
    }

    /// How many requests may be in flight at once.
    pub fn pipeline_depth(&self) -> usize {
        (self.limits.max_concurrent_streams as usize).max(1)
    }

    /// Writes one whole message: start line, fields, and body.
    ///
    /// A server-side response is stamped with what the transport turned out to
    /// be and then finalised, so `Date`, `Server` and — over a secure transport
    /// alone — the HSTS policy are attached.
    ///
    /// The body is framed as the fields already say, and `Content-Length` is
    /// added when neither `Transfer-Encoding` nor an existing `Content-Length`
    /// says otherwise and the status admits a body. Bodies up to
    /// [`INLINE_BODY_LIMIT`] go out together with the head.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Limit`] when more than [`H1Connection::pipeline_depth`]
    /// requests are already awaiting a response, [`Error::Io`] when a
    /// [`Body::File`] cannot be read, and otherwise as
    /// [`write_start_line_into`] and [`write_header_line_into`].
    pub async fn send_message(&mut self, message: Message) -> Result<(), Error> {
        if message.method.is_some() && self.pending.len() >= self.pipeline_depth() {
            let reason = format!("more than {} requests are awaiting a response", self.pipeline_depth());
            return Err(Error::Limit(reason));
        }

        let mut message = message;
        if self.role.is_server() && message.is_response() {
            message.secure = self.security.secure;
            crate::finalizer::finalize_response(&mut message, crate::finalizer::date_cache(), self.hsts.as_ref());
        }

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

        let inline = body.as_ref().is_some_and(|body| body.len() <= INLINE_BODY_LIMIT);

        let estimate = 64
            + headers.map_or(0, |headers| headers.len() * 40)
            + if inline { body.as_ref().map_or(0, Bytes::len) + 16 } else { 0 };

        let mut out = std::mem::take(&mut self.scratch);
        out.clear();
        out.reserve(estimate);

        let closing = self.closing;
        let head = (|| -> Result<(), Error> {
            write_start_line_into(&message, &mut out)?;
            out.extend_from_slice(b"\r\n");

            if let Some(headers) = headers {
                write_headers_into(headers, case, &mut out)?;
            }

            if !chunked && !has_length && !bodyless {
                match &body {
                    Some(body) => write_content_length_into(body.len() as u64, case, &mut out),
                    None if message.is_response() => write_content_length_into(0, case, &mut out),
                    None => {}
                }
            }

            if closing && !headers.is_some_and(|headers| headers.contains("connection")) {
                write_header_line_into("connection", "close", case, &mut out)?;
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
                    write_chunk_into(&body, &mut out);
                }

                out.extend_from_slice(b"0\r\n");
                if let Some(trailers) = &message.trailers {
                    write_headers_into(trailers, case, &mut out)?;
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
        drop(message);

        if let Some(body) = trailing {
            self.write(&out).await?;
            self.write_flushed(&body).await?;
        } else {
            self.write_flushed(&out).await?;
        }

        out.clear();
        common::reclaim(&mut out);
        self.scratch = out;

        if let Some(method) = method {
            self.pending.push_back(method);
        }

        Ok(())
    }

    /// Reads one whole message.
    ///
    /// A server that cannot parse the request line answers with the status
    /// [`request_line_error_status`] picks before reporting the failure, since
    /// a client that sent something malformed is owed an explanation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the peer is done, [`Error::Limit`] when
    /// the message goes past [`Limits::max_message_size`] or one of the other
    /// ceilings, and otherwise as the parsers above.
    pub async fn receive_message(&mut self) -> Result<Message, Error> {
        let length = self
            .buffer
            .line_end(&mut self.transport, self.limits.max_startline_size as usize, self.limits.read_timeout)
            .await?;

        let mut message = match parse_start_line_bytes(&self.buffer.as_slice()[..length]) {
            Ok(message) => {
                self.buffer.consume(length + 2);
                message
            }
            Err(error) => {
                let status = self
                    .role
                    .is_server()
                    .then(|| request_line_error_status_bytes(&self.buffer.as_slice()[..length]));

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
        self.security.apply(&mut message);

        self.closing = self.closing || !crate::headers::keep_alive(message.headers.as_ref(), message.version);

        let limit = self.limits.max_message_size;
        let Some(budget) = limit.checked_sub(head) else {
            return Err(Error::Limit(format!("message head of {head} octets exceeds {limit}")));
        };

        let method = if message.is_response() { self.pending.pop_front() } else { None };

        let length = body_length(&message, method)?;

        message.body = match length {
            BodyLength::None => None,
            _ => self.receive_body(length, budget).await?.map(Body::Data),
        };

        if length == BodyLength::Chunked {
            message.trailers = Some(self.read_header_block().await?.0);
        }

        self.buffer.reclaim();
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
    /// [`parse_header_block`].
    pub async fn read_header_block(&mut self) -> Result<(Headers, usize), Error> {
        let max = self.limits.max_headers_size;
        let mut searched = 0usize;

        let (fields, consumed) = loop {
            if let Some(found) = block_end(self.buffer.as_slice(), &mut searched) {
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

        let headers = parse_header_block(&self.buffer.as_slice()[..fields], self.limits.max_header_count as usize)?;
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
    /// [`decode_chunk`].
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
                    match parse_chunk_size(self.buffer.as_slice())? {
                        Some((_, size)) if (body.len() as u64).saturating_add(size as u64) > limit => {
                            return Err(Error::Limit(format!("chunked body exceeds {limit} octets")));
                        }
                        None if self.buffer.len() > self.limits.max_chunk_header_size as usize => {
                            return Err(Error::Limit(format!("chunk size line exceeds {} octets", self.limits.max_chunk_header_size)));
                        }
                        _ => {}
                    }

                    let (consumed, chunk) = decode_chunk(self.buffer.as_slice())?;
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
        Version::V1_1
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

    async fn send(&mut self, message: Message) -> Result<(), Error> {
        let timeout = self.limits.send_timeout;
        let sending = std::pin::pin!(self.send_message(message));
        common::within(timeout, sending).await?
    }

    async fn receive(&mut self) -> Result<Message, Error> {
        let timeout = self.limits.receive_timeout;
        let receiving = std::pin::pin!(self.receive_message());
        common::within(timeout, receiving).await?
    }

    async fn close(&mut self) {
        let _ = self.transport.flush().await;
        let _ = self.transport.shutdown().await;
    }
}
