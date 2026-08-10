use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use soyokaze::models::Limits;
use soyokaze::hsts::HSTSPolicy;
use soyokaze::models::{Body, ConnectionID, HeaderCase, Headers, Message, Method, Role, Version};
use soyokaze::tls::Security;
use soyokaze::protocol::base::Connection;
use soyokaze::protocol::common::Buffer;
use soyokaze::protocol::h1::{self, BodyLength, H1Connection};
use soyokaze::Error;
use soyokaze::helpers::compression::Compression;
use soyokaze::helpers::sync;
use bytes::Bytes;

fn limits() -> Limits {
    Limits { read_timeout: 5.0, write_timeout: 5.0, receive_timeout: 5.0, send_timeout: 5.0, ..Limits::default() }
}

fn id() -> ConnectionID {
    ConnectionID(bytes::Bytes::from_static(b"test"))
}

#[test]
fn parses_a_request_line() {
    let message = h1::StartLine::parse("GET /index.html HTTP/1.1").expect("a request line did not parse");

    assert_eq!(message.method, Some(Method::GET));
    assert_eq!(message.target.as_deref(), Some("/index.html"));
    assert_eq!(message.version, Version::V1_1);
}

#[test]
fn parses_a_status_line() {
    let message = h1::StartLine::parse("HTTP/1.1 404 Not Found").expect("a status line did not parse");

    assert_eq!(message.status_code, Some(404));
    assert_eq!(message.version, Version::V1_1);
    assert!(message.is_response());

    assert!(h1::StartLine::parse("HTTP/1.0 200 ").is_ok());
}

#[test]
fn refuses_a_malformed_start_line() {
    for line in [
        "",
        "GET",
        "GET /",
        "BREW / HTTP/1.1",
        "GET / HTTP/2",
        "GET  HTTP/1.1",
        "HTTP/1.1 20 OK",
        "HTTP/1.1 2xx OK",
        "HTTP/1.1 200",
        "HTTP/1.1 200 O\u{7f}K",
    ] {
        assert!(h1::StartLine::parse(line).is_err(), "{line:?} should not parse");
    }
}

/// `reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )` — RFC 9112 §4, with
/// `VCHAR = %x21-7E` from RFC 5234 and `obs-text = %x80-FF` from RFC 9110
/// §5.6.4. Every other octet, which is to say every control octet but the tab,
/// is outside the grammar.
fn is_reason_octet(octet: u8) -> bool {
    octet == 0x09 || octet == 0x20 || (0x21..=0x7e).contains(&octet) || octet >= 0x80
}

#[test]
fn classifies_every_octet_of_a_reason_phrase_as_the_grammar_does() {
    for octet in 0..=u8::MAX {
        let allowed = h1::Octets::TABLE[octet as usize] & h1::Octets::FIELD != 0;
        assert_eq!(allowed, is_reason_octet(octet), "octet {octet:#04x} is classified against RFC 9112 §4");
        assert_eq!(h1::Octets::is_reason_bytes(&[octet]), is_reason_octet(octet), "octet {octet:#04x} as a reason phrase");
    }
}

/// `obs-text` is `%x80-FF`, which is not UTF-8, so a status line has to be read
/// as octets rather than as text for RFC 9112 §4 to be met.
#[test]
fn accepts_a_reason_phrase_of_raw_obs_text_octets() {
    for octet in 0x80..=u8::MAX {
        let mut line = b"HTTP/1.1 200 Not".to_vec();
        line.push(octet);
        line.extend_from_slice(b"OK");

        assert!(h1::Octets::is_reason_bytes(&line[13..]), "obs-text {octet:#04x} is a reason phrase");

        let message = h1::StartLine::parse_bytes(&line).unwrap_or_else(|error| panic!("obs-text {octet:#04x} did not parse: {error}"));
        assert_eq!(message.status_code, Some(200));
        assert_eq!(message.version, Version::V1_1);
    }

    let every = (0x80..=u8::MAX).collect::<Vec<u8>>();
    let mut line = b"HTTP/1.0 204 ".to_vec();
    line.extend_from_slice(&every);

    assert!(std::str::from_utf8(&line).is_err(), "the fixture should not be valid UTF-8");

    let message = h1::StartLine::parse_bytes(&line).expect("a reason phrase of every obs-text octet did not parse");
    assert_eq!(message.status_code, Some(204));
    assert_eq!(message.version, Version::V1_0);
}

#[tokio::test]
async fn a_status_line_carrying_obs_text_and_a_tab_is_received() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());

    let response = b"HTTP/1.1 503 Service\tUnavailable \xe2\x98\x83 \xff\xfe\r\ncontent-length: 0\r\n\r\n";
    server_pipe.write_all(response).await.expect("the fixture did not write");

    let message = client.receive().await.expect("a status line with obs-text did not arrive");
    assert_eq!(message.status_code, Some(503));
}

#[test]
fn accepts_a_reason_phrase_of_htab_sp_vchar_and_obs_text() {
    for reason in ["OK", "Not Found", "\tOK", "OK\t", "No\tContent", "\t", " ", "", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"] {
        assert!(h1::Octets::is_reason(reason), "{reason:?} is a reason phrase");

        let line = format!("HTTP/1.1 200 {reason}");
        let message = h1::StartLine::parse(&line).unwrap_or_else(|error| panic!("{line:?} did not parse: {error}"));
        assert_eq!(message.status_code, Some(200));
    }

    for octet in (0x21..=0x7e).chain(std::iter::once(0x20)) {
        let reason = String::from_utf8(vec![octet]).expect("an ASCII octet is UTF-8");
        assert!(h1::Octets::is_reason(&reason), "VCHAR {octet:#04x} is a reason phrase");
        assert!(h1::StartLine::parse(&format!("HTTP/1.1 200 {reason}")).is_ok(), "VCHAR {octet:#04x} did not parse");
    }

    for reason in ["理由句", "\u{80}\u{ff}", "Ünicode", "café"] {
        assert!(reason.bytes().any(|octet| octet >= 0x80), "{reason:?} should carry obs-text");
        assert!(h1::Octets::is_reason(reason), "obs-text {reason:?} is a reason phrase");
        assert!(h1::StartLine::parse(&format!("HTTP/1.1 200 {reason}")).is_ok(), "obs-text {reason:?} did not parse");
    }
}

#[test]
fn refuses_a_reason_phrase_carrying_a_control_octet() {
    for octet in (0x00..=0x1fu8).chain(std::iter::once(0x7f)).filter(|octet| *octet != 0x09) {
        let reason = String::from_utf8(vec![b'O', octet, b'K']).expect("an ASCII octet is UTF-8");
        assert!(!h1::Octets::is_reason(&reason), "control octet {octet:#04x} is not a reason phrase");
        assert!(h1::StartLine::parse(&format!("HTTP/1.1 200 {reason}")).is_err(), "control octet {octet:#04x} parsed");
    }
}

/// A reason phrase that could carry a CR or an LF would let a peer write a line
/// terminator into a response another recipient reads as the start of the next
/// message, so the relaxation to RFC 9112 §4 must not reach either.
#[test]
fn refuses_a_reason_phrase_carrying_a_line_terminator() {
    for reason in ["OK\rInjected", "OK\nInjected", "OK\r\nInjected", "\r", "\n", "OK\r", "OK\n", "OK\0Injected", "OK\u{7f}"] {
        assert!(!h1::Octets::is_reason(reason), "{reason:?} is not a reason phrase");
        assert!(h1::StartLine::parse(&format!("HTTP/1.1 200 {reason}")).is_err(), "{reason:?} parsed");
    }

    assert!(h1::Octets::TABLE[0x0d] & h1::Octets::FIELD == 0, "CR is never a reason phrase octet");
    assert!(h1::Octets::TABLE[0x0a] & h1::Octets::FIELD == 0, "LF is never a reason phrase octet");

    for terminator in [b"\r".as_slice(), b"\n", b"\r\n"] {
        let mut line = b"HTTP/1.1 200 OK".to_vec();
        line.extend_from_slice(terminator);
        line.extend_from_slice(b"\xffInjected");

        assert!(h1::StartLine::parse_bytes(&line).is_err(), "{terminator:?} beside obs-text parsed");
    }
}

/// A request target is US-ASCII by RFC 9112 §3.2 and RFC 3986, so unlike a
/// reason phrase it gains nothing from being read as octets, and the octets it
/// is refused for must not depend on where in the line they sit.
#[test]
fn refuses_a_request_target_that_is_not_text() {
    for line in [b"GET /\xff HTTP/1.1".as_slice(), b"GET \xc3\x28 HTTP/1.1", b"GET \xff HTTP/1.1"] {
        assert!(h1::StartLine::parse_bytes(line).is_err(), "{line:?} should not parse");
        assert_eq!(h1::StartLine::error_status_bytes(line), 400, "{line:?} is the client's fault");
    }

    assert_eq!(h1::StartLine::error_status_bytes(b"\xff / HTTP/1.1"), 501, "a method that is not text is not recognised");
    assert_eq!(h1::StartLine::error_status_bytes(b"GET / HTTP/\xff.1"), 505, "a version that is not text is not spoken");
}

#[test]
fn writes_a_start_line_for_each_half() {
    let request = Message::request(Method::POST, "/submit", Version::V1_1);
    assert_eq!(h1::StartLine::encode(&request).ok().as_deref(), Some("POST /submit HTTP/1.1"));

    let response = Message::response(404, Version::V1_1);
    assert_eq!(h1::StartLine::encode(&response).ok().as_deref(), Some("HTTP/1.1 404 Not Found"));

    assert!(h1::StartLine::encode(&Message::request(Method::GET, "/", Version::V2_0)).is_err());
    assert!(h1::StartLine::encode(&Message::new(Version::V1_1)).is_err());
}

#[test]
fn reason_phrases_cover_the_registered_codes_and_fall_back() {
    assert_eq!(soyokaze::responses::Status::reason(200), "OK");
    assert_eq!(soyokaze::responses::Status::reason(418), "I'm a teapot");
    assert_eq!(soyokaze::responses::Status::reason(511), "Network Authentication Required");
    assert_eq!(soyokaze::responses::Status::reason(299), "Unknown");
}

#[test]
fn writes_numbers_without_allocating_a_string() {
    for value in [0u64, 1, 9, 10, 200, 65_535, u64::MAX] {
        let mut out = BytesMut::new();
        h1::Number::write_decimal(value, &mut out);
        assert_eq!(out, value.to_string().as_bytes());
    }
}

#[test]
fn parses_a_field_line_and_lowercases_the_name() {
    assert_eq!(h1::Field::parse("Content-Type: text/html").ok(), Some(("content-type".into(), "text/html".into())));

    assert_eq!(h1::Field::parse("X-A:\t value \t").ok(), Some(("x-a".into(), "value".into())));
    assert_eq!(h1::Field::parse("X-A:").ok(), Some(("x-a".into(), String::new())));
}

#[test]
fn refuses_a_malformed_field_line() {
    for line in [
        "no-colon",
        ": value",
        "bad name: value",
        "x-a\u{7f}: value",
        "x-a: va\u{1}lue",
    ] {
        assert!(h1::Field::parse(line).is_err(), "{line:?} should not parse");
    }
}

#[test]
fn refuses_an_obs_folded_field_line() {
    let folded = ["x-a: one".to_owned(), "  continued".to_owned()];
    assert!(h1::Field::parse_lines(folded).is_err(), "obs-fold must be rejected, not joined");
}

#[test]
fn writes_field_lines_in_the_case_the_version_wants() {
    assert_eq!(h1::Field::encode("content-type", "text/html", HeaderCase::Title).ok(), Some("Content-Type: text/html\r\n".to_owned()));
    assert_eq!(h1::Field::encode("Content-Type", "text/html", HeaderCase::Lower).ok(), Some("content-type: text/html\r\n".to_owned()));

    let mut headers = Headers::new();
    headers.append("host", "example.test");
    headers.append("accept", "*/*");

    assert_eq!(h1::Field::encode_all(&headers, HeaderCase::Title).ok(), Some("Host: example.test\r\nAccept: */*\r\n".to_owned()));
    assert_eq!(h1::Field::size(&headers), (4 + 12 + 4) + (6 + 3 + 4));
}

#[test]
fn refuses_to_write_a_header_value_that_smuggles_a_crlf() {
    assert!(h1::Field::encode("x-evil", "value\r\nInjected: header", HeaderCase::Title).is_err());
    assert!(h1::Field::encode("x-evil\r\nInjected", "value", HeaderCase::Title).is_err());

    let mut headers = Headers::new();
    headers.append("location", "/redirect\r\nSet-Cookie: session=stolen");

    assert!(h1::Field::encode_all(&headers, HeaderCase::Title).is_err());
}

#[test]
fn encodes_and_decodes_a_chunk() {
    assert_eq!(h1::Chunk::encode(b"hello"), b"5\r\nhello\r\n");
    assert_eq!(h1::Chunk::encode(b""), b"0\r\n\r\n");

    let (consumed, range) = h1::Chunk::decode(b"5\r\nhello\r\n").expect("a chunk did not decode");
    assert_eq!(consumed, 10);
    assert_eq!(&b"5\r\nhello\r\n"[range], b"hello");
}

#[test]
fn reads_a_chunk_size_with_extensions() {
    assert_eq!(h1::Chunk::parse_size(b"a\r\n").ok(), Some(Some((3, 10))));
    assert_eq!(h1::Chunk::parse_size(b"A\r\n").ok(), Some(Some((3, 10))));
    assert_eq!(h1::Chunk::parse_size(b"5;name=value\r\n").ok(), Some(Some((14, 5))));

    assert_eq!(h1::Chunk::parse_size(b"5").ok(), Some(None));
}

#[test]
fn refuses_a_malformed_chunk() {
    assert!(h1::Chunk::parse_size(b"\n").is_err(), "a chunk size line needs a CR");
    assert!(h1::Chunk::parse_size(b"zz\r\n").is_err(), "a chunk size must be hexadecimal");
    assert!(h1::Chunk::decode(b"1\r\nab\r\n").is_err(), "chunk data must end at its declared size");
}

#[test]
fn waits_for_a_chunk_that_has_not_fully_arrived() {
    assert_eq!(h1::Chunk::decode(b"5\r\nhel").ok(), Some((0, 0..0)));
    assert_eq!(h1::Chunk::decode(b"").ok(), Some((0, 0..0)));

    assert_eq!(h1::Chunk::decode(b"0\r\n").ok(), Some((3, 0..0)));
}

fn with_headers(mut message: Message, fields: &[(&str, &str)]) -> Message {
    let mut headers = Headers::new();
    for (name, value) in fields {
        headers.append(*name, *value);
    }
    message.headers = Some(headers);
    message
}

fn framing(message: &Message, method: Option<Method>) -> Option<BodyLength> {
    h1::BodyLength::of(message, method).ok()
}

fn refuses_framing(message: &Message) -> bool {
    matches!(h1::BodyLength::of(message, None), Err(Error::Protocol(_)))
}

#[test]
fn a_content_length_frames_a_fixed_body() {
    let request = with_headers(Message::request(Method::POST, "/", Version::V1_1), &[("content-length", "42")]);
    assert_eq!(framing(&request, None), Some(BodyLength::Fixed(42)));

    let agreeing = with_headers(Message::request(Method::POST, "/", Version::V1_1), &[("content-length", "1, 1")]);
    assert_eq!(framing(&agreeing, None), Some(BodyLength::Fixed(1)));

    let disagreeing = with_headers(Message::request(Method::POST, "/", Version::V1_1), &[("content-length", "1, 2")]);
    assert!(refuses_framing(&disagreeing));
}

#[test]
fn a_chunked_transfer_coding_frames_the_body() {
    let request = with_headers(Message::request(Method::POST, "/", Version::V1_1), &[("transfer-encoding", "chunked")]);
    assert_eq!(framing(&request, None), Some(BodyLength::Chunked));

    let unframed = with_headers(Message::request(Method::POST, "/", Version::V1_1), &[("transfer-encoding", "gzip")]);
    assert!(refuses_framing(&unframed));

    let response = with_headers(Message::response(200, Version::V1_1), &[("transfer-encoding", "gzip")]);
    assert_eq!(framing(&response, None), Some(BodyLength::Close));
}

#[test]
fn refuses_a_message_framed_two_ways_at_once() {
    let framing = [("content-length", "5"), ("transfer-encoding", "chunked")];
    let smuggled = with_headers(Message::request(Method::POST, "/", Version::V1_1), &framing);

    assert!(refuses_framing(&smuggled), "request smuggling must be refused");
}

#[test]
fn responses_that_never_carry_a_body_are_recognised() {
    for status_code in [100u16, 199, 204, 304] {
        let response = with_headers(Message::response(status_code, Version::V1_1), &[("content-length", "5")]);
        assert_eq!(framing(&response, None), Some(BodyLength::None), "status {status_code}");
    }

    let head = with_headers(Message::response(200, Version::V1_1), &[("content-length", "5")]);
    assert_eq!(framing(&head, Some(Method::HEAD)), Some(BodyLength::None));
    assert_eq!(framing(&head, Some(Method::CONNECT)), Some(BodyLength::None));
}

#[test]
fn an_unframed_request_has_no_body_and_a_response_runs_to_close() {
    let request = Message::request(Method::GET, "/", Version::V1_1);
    assert_eq!(framing(&request, None), Some(BodyLength::None));

    let response = Message::response(200, Version::V1_1);
    assert_eq!(framing(&response, None), Some(BodyLength::Close));
}

#[test]
fn refuses_a_content_length_that_is_not_a_number() {
    assert!(h1::BodyLength::content_length("").is_err());
    assert!(h1::BodyLength::content_length("+5").is_err());
    assert!(h1::BodyLength::content_length("5.0").is_err());
    assert!(h1::BodyLength::content_length("99999999999999999999999").is_err());
    assert_eq!(h1::BodyLength::content_length("0").ok(), Some(0));
}

#[tokio::test]
async fn a_request_and_response_cross_a_connection() {
    let (client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);

    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits());

    let mut request = Message::request(Method::POST, "/submit", Version::V1_1);
    request.headers = Some(Headers::new());
    request.body = Some(Body::Text("hello".to_owned()));

    client.send(request).await.expect("the request did not send");

    let received = server.receive().await.expect("the request did not arrive");
    assert_eq!(received.method, Some(Method::POST));
    assert_eq!(received.target.as_deref(), Some("/submit"));
    assert_eq!(received.body, Some(Body::Data(bytes::Bytes::from_static(b"hello"))));
    assert_eq!(received.headers.as_ref().and_then(|headers| headers.get("content-length")), Some("5"));

    server.send(Message::text("thanks", Version::V1_1)).await.expect("the response did not send");

    let answer = client.receive().await.expect("the response did not arrive");
    assert_eq!(answer.status_code, Some(200));
    assert_eq!(answer.body, Some(Body::Data(bytes::Bytes::from_static(b"thanks"))));
    assert!(answer.headers.as_ref().is_some_and(|headers| headers.contains("date")), "a server must send a Date");
}

#[tokio::test]
async fn a_configured_hsts_policy_rides_only_on_a_secure_transport() {
    for secure in [false, true] {
        let (client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);

        let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());
        let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits())
            .with_response_finalizer(soyokaze::finalizer::ResponseFinalizer::new(Some(HSTSPolicy::new(600))))
            .with_security(Security { secure, ..Security::default() });

        client.send(Message::request(Method::GET, "/", Version::V1_1)).await.expect("the request did not send");
        server.receive().await.expect("the request did not arrive");

        server.send(Message::text("ok", Version::V1_1)).await.expect("the response did not send");

        let answer = client.receive().await.expect("the response did not arrive");
        let policy = answer.headers.as_ref().and_then(|headers| headers.get("strict-transport-security"));

        match secure {
            false => assert_eq!(policy, None, "a plaintext response must not advertise HSTS"),
            true => assert_eq!(policy, Some("max-age=600"), "a secure response must advertise the configured policy"),
        }
    }
}

#[tokio::test]
async fn a_chunked_body_and_its_trailers_arrive() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());

    let response = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nx-checksum: deadbeef\r\n\r\n";

    server_pipe
        .write_all(response)
        .await
        .expect("the fixture did not write");

    let response = client.receive().await.expect("the response did not arrive");

    assert_eq!(response.body, Some(Body::Data(bytes::Bytes::from_static(b"hello world"))));
    assert_eq!(
        response.trailers.as_ref().and_then(|trailers| trailers.get("x-checksum")),
        Some("deadbeef"),
    );
}

#[tokio::test]
async fn a_connection_close_field_ends_the_connection() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());

    assert!(client.reusable());

    server_pipe
        .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 0\r\n\r\n")
        .await
        .expect("the fixture did not write");

    let _ = client.receive().await.expect("the response did not arrive");
    assert!(!client.reusable(), "a connection that said close must not be reused");
}

#[tokio::test]
async fn a_head_response_is_not_mistaken_for_a_body() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());

    let mut request = Message::request(Method::HEAD, "/", Version::V1_1);
    request.headers = Some(Headers::new());
    client.send(request).await.expect("the request did not send");

    let mut scratch = [0u8; 512];
    let _ = server_pipe.read(&mut scratch).await.expect("the request did not arrive");

    server_pipe
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 12345\r\n\r\n")
        .await
        .expect("the fixture did not write");

    let response = client.receive().await.expect("the response did not arrive");
    assert_eq!(response.body, None, "a response to HEAD must not be read as a body");
}

#[tokio::test]
async fn a_head_of_line_limit_is_enforced() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);

    let limits = Limits { max_startline_size: 32, ..limits() };
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits);

    let long = format!("HTTP/1.1 200 {}\r\n\r\n", "x".repeat(64));
    server_pipe.write_all(long.as_bytes()).await.expect("the fixture did not write");

    assert!(matches!(client.receive().await, Err(Error::Limit(_))), "an over-long status line must be refused");
}

#[tokio::test]
async fn a_field_count_limit_is_enforced() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);

    let limits = Limits { max_header_count: 4, ..limits() };
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits);

    let mut response = "HTTP/1.1 200 OK\r\n".to_owned();
    for index in 0..16 {
        response.push_str(&format!("x-field-{index}: value\r\n"));
    }
    response.push_str("\r\n");

    server_pipe.write_all(response.as_bytes()).await.expect("the fixture did not write");

    assert!(matches!(client.receive().await, Err(Error::Limit(_))), "too many fields must be refused");
}

#[tokio::test]
async fn a_truncated_message_reports_a_closed_connection() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());

    server_pipe.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nshort").await.expect("the fixture did not write");
    drop(server_pipe);

    assert!(matches!(client.receive().await, Err(Error::Closed)));
}

#[tokio::test]
async fn an_unrecognised_method_gets_a_501_before_the_connection_closes() {
    let (mut client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits());

    client_pipe.write_all(b"BREW / HTTP/1.1\r\n\r\n").await.expect("the fixture did not write");

    assert!(server.receive().await.is_err(), "a request with an unknown method must not parse");
    server.close().await;
    drop(server);

    let mut response = Vec::new();
    client_pipe.read_to_end(&mut response).await.expect("reading the response failed");
    let response = String::from_utf8(response).expect("the response was not valid UTF-8");

    assert!(response.starts_with("HTTP/1.1 501 "), "expected a 501 response, got {response:?}");
    assert!(response.to_ascii_lowercase().contains("connection: close"), "expected Connection: close, got {response:?}");
}

#[tokio::test]
async fn a_malformed_request_line_gets_a_400_before_the_connection_closes() {
    let (mut client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits());

    client_pipe.write_all(b"GET \r\n\r\n").await.expect("the fixture did not write");

    assert!(server.receive().await.is_err(), "a request missing its target and version must not parse");
    server.close().await;
    drop(server);

    let mut response = Vec::new();
    client_pipe.read_to_end(&mut response).await.expect("reading the response failed");
    let response = String::from_utf8(response).expect("the response was not valid UTF-8");

    assert!(response.starts_with("HTTP/1.1 400 "), "expected a 400 response, got {response:?}");
}

struct Counting<T> {
    inner: T,
    writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Counting<T> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Counting<T> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let written = std::pin::Pin::new(&mut self.inner).poll_write(context, data);

        if let std::task::Poll::Ready(Ok(_)) = written {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        written
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[tokio::test]
async fn a_response_and_its_body_leave_in_one_write() {
    let (client_pipe, server_pipe) = tokio::io::duplex(256 * 1024);
    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let transport = Counting { inner: server_pipe, writes: writes.clone() };
    let mut server = H1Connection::new(transport, Role::Origin, id(), limits());

    let mut response = Message::response(200, Version::V1_1);
    response.body = Some(Body::Data(bytes::Bytes::from_static(b"hello")));

    server.send_message(response).await.expect("the response did not send");

    assert_eq!(
        writes.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "a head and a small body belong in the same write"
    );

    drop(client_pipe);
}

#[tokio::test]
async fn a_body_too_large_to_copy_is_not_copied() {
    let (client_pipe, server_pipe) = tokio::io::duplex(4 * 1024 * 1024);
    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let transport = Counting { inner: server_pipe, writes: writes.clone() };
    let mut server = H1Connection::new(transport, Role::Origin, id(), limits());

    let mut response = Message::response(200, Version::V1_1);
    response.body = Some(Body::Data(bytes::Bytes::from(vec![b'x'; 2 * 1024 * 1024])));

    server.send_message(response).await.expect("the response did not send");

    assert_eq!(
        writes.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "a body past the inline limit is handed over on its own rather than copied"
    );

    drop(client_pipe);
}

#[tokio::test]
async fn pipelining_without_reading_does_not_queue_without_limit() {
    let limits = Limits { max_concurrent_streams: 4, ..limits() };
    let (client_pipe, mut server_pipe) = tokio::io::duplex(1024 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits);

    let mut sent = 0u32;
    let refused = loop {
        let request = Message::request(Method::GET, "/", Version::V1_1);

        match client.send(request).await {
            Ok(()) => sent += 1,
            Err(error) => break error,
        }

        assert!(sent <= limits.max_concurrent_streams, "{sent} requests went out with no response read");
    };

    assert!(matches!(refused, Error::Limit(_)), "an unread pipeline was refused with {refused:?}");
    assert_eq!(sent, limits.max_concurrent_streams, "the pipeline stopped at the wrong depth");

    let mut drain = Vec::new();
    let _ = server_pipe.read_buf(&mut drain).await;
}

#[tokio::test]
async fn a_large_message_does_not_leave_its_buffer_attached_to_the_connection() {
    let limits = Limits { max_message_size: 8 * 1024 * 1024, max_message_body_size: 8 * 1024 * 1024, ..limits() };
    let (client_pipe, server_pipe) = tokio::io::duplex(4 * 1024 * 1024);

    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits);
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits);

    let mut request = Message::request(Method::POST, "/upload", Version::V1_1);
    request.body = Some(Body::Data(bytes::Bytes::from(vec![b'x'; 2 * 1024 * 1024])));

    let sending = tokio::spawn(async move {
        client.send(request).await.expect("the upload was refused");
        client
    });

    let received = server.receive().await.expect("the upload did not arrive");
    assert_eq!(received.body.expect("the upload carried no body").len(), Some(2 * 1024 * 1024));

    let client = sending.await.expect("the sending task panicked");

    assert!(
        server.buffer_capacity() <= limits.idle_capacity as usize,
        "a finished upload left {} octets of read buffer on the connection",
        server.buffer_capacity()
    );
    assert!(
        client.scratch_capacity() <= limits.idle_capacity as usize,
        "a finished upload left {} octets of write buffer on the connection",
        client.scratch_capacity()
    );
}

#[tokio::test]
async fn a_lowered_idle_capacity_is_honoured_when_buffers_are_reclaimed() {
    let limits = Limits { max_message_size: 8 * 1024 * 1024, max_message_body_size: 8 * 1024 * 1024, idle_capacity: 16 * 1024, ..limits() };
    let (client_pipe, server_pipe) = tokio::io::duplex(4 * 1024 * 1024);

    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits);
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits);

    let mut request = Message::request(Method::POST, "/upload", Version::V1_1);
    request.body = Some(Body::Data(bytes::Bytes::from(vec![b'x'; 2 * 1024 * 1024])));

    let sending = tokio::spawn(async move {
        client.send(request).await.expect("the upload was refused");
        client
    });

    let received = server.receive().await.expect("the upload did not arrive");
    assert_eq!(received.body.expect("the upload carried no body").len(), Some(2 * 1024 * 1024));

    let client = sending.await.expect("the sending task panicked");

    assert!(
        server.buffer_capacity() <= limits.idle_capacity as usize,
        "a finished upload left {} octets of read buffer against a 16 KiB idle capacity",
        server.buffer_capacity()
    );
    assert!(
        client.scratch_capacity() <= limits.idle_capacity as usize,
        "a finished upload left {} octets of write buffer against a 16 KiB idle capacity",
        client.scratch_capacity()
    );
}

#[tokio::test]
async fn a_large_chunked_message_does_not_leave_its_buffer_attached_to_the_connection() {
    let limits = Limits { max_message_size: 8 * 1024 * 1024, max_message_body_size: 8 * 1024 * 1024, ..limits() };
    let (client_pipe, server_pipe) = tokio::io::duplex(8 * 1024 * 1024);

    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits);
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits);

    let mut headers = Headers::new();
    headers.append("host", "example.test");
    headers.append("transfer-encoding", "chunked");

    let mut request = Message::request(Method::POST, "/upload", Version::V1_1);
    request.headers = Some(headers);
    request.body = Some(Body::Data(bytes::Bytes::from(vec![b'x'; 2 * 1024 * 1024])));

    let sending = tokio::spawn(async move {
        client.send(request).await.expect("the upload was refused");
        client
    });

    let received = server.receive().await.expect("the upload did not arrive");
    assert_eq!(received.body.expect("the upload carried no body").len(), Some(2 * 1024 * 1024));

    let client = sending.await.expect("the sending task panicked");

    assert!(
        client.scratch_capacity() <= limits.idle_capacity as usize,
        "a finished chunked upload left {} octets of write buffer on the connection",
        client.scratch_capacity()
    );
}

#[tokio::test]
async fn a_small_request_does_not_reserve_a_large_read_buffer() {
    let (mut client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits());

    for _ in 0..8 {
        client_pipe
            .write_all(b"GET /index.html HTTP/1.1\r\nhost: example.test\r\naccept: */*\r\n\r\n")
            .await
            .expect("the request did not reach the server");

        server.receive().await.expect("the request did not parse");
    }

    assert!(
        server.buffer_capacity() <= 2 * (Buffer::DEFAULT_CHUNK_SIZE / Buffer::CHUNK_RAMP),
        "a keep-alive connection carrying small requests holds {} octets of read buffer",
        server.buffer_capacity()
    );
}

#[test]
fn a_field_name_is_taken_up_to_its_colon() {
    assert_eq!(h1::Field::name_end(b"host: example.com").ok(), Some(4), "a well-formed name did not end at its colon");
    assert_eq!(h1::Field::name_end(b"x:").ok(), Some(1), "a name followed by an empty value did not end at its colon");

    assert_eq!(h1::Field::name_end(b"host: a:b").ok(), Some(4), "a colon in the value moved the end of the name");

    assert!(matches!(h1::Field::name_end(b":empty"), Err(Error::Protocol(_))), "an empty name was accepted");
    assert!(matches!(h1::Field::name_end(b"no-colon"), Err(Error::Protocol(_))), "a line with no colon was accepted");

    for octet in (0..=255u8).filter(|octet| *octet != b':') {
        let token = octet.is_ascii_alphanumeric()
            || matches!(octet, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~');

        for at in 0..14usize {
            let mut line = vec![b'x'; 14];
            line[at] = octet;
            line.extend_from_slice(b": value");

            let end = h1::Field::name_end(&line).ok();
            assert_eq!(end.is_some(), token, "{octet:#04x} at {at} of a field name");

            if token {
                assert_eq!(end, Some(14), "a valid name did not end at its colon");
            }
        }
    }
}

#[test]
fn a_timeout_only_means_a_deadline_when_it_names_one() {
    for seconds in [0.0, -1.0, -0.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(!sync::Timeout::armed(seconds), "{seconds} was read as a deadline");
        assert_eq!(sync::Timeout::duration(seconds), None, "{seconds} yielded a deadline");
    }

    assert_eq!(sync::Timeout::duration(1.5), Some(std::time::Duration::from_millis(1500)), "a plain timeout was not converted");

    assert_eq!(sync::Timeout::duration(f64::MAX), Some(std::time::Duration::MAX), "an enormous timeout did not cap");
}

/// HTTP/1.0 and HTTP/1.1 share one connection type, so the version a connection
/// reports has to be carried rather than read off the type.
///
/// RFC 9112 §2.3 has each end send its own version rather than echo the peer's,
/// so this is what the connection originates with, not what it last received.
#[test]
fn a_connection_reports_the_http_1_version_it_was_told_to_speak() {
    let (_client_pipe, server_pipe) = tokio::io::duplex(1024);

    let connection = H1Connection::new(server_pipe, Role::Origin, id(), limits());
    assert_eq!(connection.version(), Version::V1_1, "a connection told nothing speaks HTTP/1.1");

    let (_client_pipe, server_pipe) = tokio::io::duplex(1024);
    let connection = H1Connection::new(server_pipe, Role::Origin, id(), limits()).with_version(Version::V1_0);
    assert_eq!(connection.version(), Version::V1_0);
}

#[test]
fn a_connection_refuses_a_version_it_cannot_speak() {
    for version in [Version::V2_0, Version::V3_0] {
        let (_client_pipe, server_pipe) = tokio::io::duplex(1024);
        let connection = H1Connection::new(server_pipe, Role::Origin, id(), limits()).with_version(version);

        assert_eq!(
            connection.version().major(),
            1,
            "an HTTP/1.x connection must not claim to speak {version}",
        );
    }
}

#[tokio::test]
async fn a_request_originated_on_a_1_0_connection_carries_http_1_0() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits()).with_version(Version::V1_0);

    let request = Message::request(Method::GET, "/", client.version());
    client.send_message(request).await.expect("the request did not send");

    let mut read = vec![0u8; 64];
    let taken = server_pipe.read(&mut read).await.expect("nothing arrived");

    assert!(
        read[..taken].starts_with(b"GET / HTTP/1.0\r\n"),
        "a connection pinned to HTTP/1.0 sent {:?}",
        String::from_utf8_lossy(&read[..taken]),
    );
}

#[tokio::test]
async fn a_rejection_carries_the_version_the_connection_speaks() {
    let (mut client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits()).with_version(Version::V1_0);

    server.reject(400).await.expect("the rejection did not send");

    let mut read = vec![0u8; 64];
    let taken = client_pipe.read(&mut read).await.expect("nothing arrived");

    assert!(
        read[..taken].starts_with(b"HTTP/1.0 400 "),
        "a rejection went out as {:?}",
        String::from_utf8_lossy(&read[..taken]),
    );
}
#[test]
fn http_1_1_persists_unless_told_otherwise() {
    let mut headers = Headers::new();
    assert!(h1::Persistence::keep_alive(Some(&headers), Version::V1_1));
    assert!(h1::Persistence::keep_alive(None, Version::V1_1));

    headers.append("connection", "close");
    assert!(!h1::Persistence::keep_alive(Some(&headers), Version::V1_1));
}

#[test]
fn http_1_0_persists_only_when_asked() {
    let mut headers = Headers::new();
    assert!(!h1::Persistence::keep_alive(Some(&headers), Version::V1_0));

    headers.append("connection", "Keep-Alive");
    assert!(h1::Persistence::keep_alive(Some(&headers), Version::V1_0));
}

#[test]
fn close_wins_over_keep_alive_wherever_it_appears() {
    let mut headers = Headers::new();
    headers.append("connection", "keep-alive, close");
    assert!(!h1::Persistence::keep_alive(Some(&headers), Version::V1_1));

    let mut split = Headers::new();
    split.append("connection", "keep-alive");
    split.append("connection", "close");
    assert!(!h1::Persistence::keep_alive(Some(&split), Version::V1_1));
}

#[test]
fn later_versions_persist_by_default() {
    let headers = Headers::new();

    assert!(h1::Persistence::keep_alive(Some(&headers), Version::V2_0));
    assert!(h1::Persistence::keep_alive(Some(&headers), Version::V3_0));
    assert!(h1::Persistence::keep_alive(None, Version::V3_0));
}

#[test]
fn an_unknown_connection_token_is_ignored() {
    let mut headers = Headers::new();
    headers.append("connection", "TE, Trailers");

    assert!(h1::Persistence::keep_alive(Some(&headers), Version::V1_1));
    assert!(!h1::Persistence::keep_alive(Some(&headers), Version::V1_0), "HTTP/1.0 still needs keep-alive");
}

/// A connection carries the ceilings it uses, and no others.
///
/// The whole [`Limits`] still configures one — that is the struct a caller
/// fills in — but what an HTTP/1.x connection then holds is HTTP/1.x's own, so
/// the module reads and can be used as the HTTP/1.x library it is.
#[test]
fn a_connection_takes_its_own_share_of_the_configured_limits() {
    let configured = Limits { max_startline_size: 111, inline_body_size: 222, ..Limits::default() };
    let (_client_pipe, server_pipe) = tokio::io::duplex(1024);

    let connection = H1Connection::new(server_pipe, Role::Origin, id(), configured);
    let limits = connection.limits();

    assert_eq!(limits.max_startline_size, 111);
    assert_eq!(limits.inline_body_size, 222);
    assert_eq!(limits.max_message_size, configured.max_message_size, "the shared ceilings come across too");
}

#[test]
fn the_protocol_limits_default_to_what_the_whole_limits_default_to() {
    let whole = Limits::default();

    let h1 = soyokaze::protocol::H1Limits::default();
    assert_eq!(h1.max_startline_size, whole.max_startline_size);
    assert_eq!(h1.read_timeout, whole.read_timeout);

    let h2 = soyokaze::protocol::H2Limits::default();
    assert_eq!(h2.max_encoder_table_size, whole.max_encoder_table_size);

    let h3 = soyokaze::protocol::H3Limits::default();
    assert_eq!(h3.qpack_block_timeout, whole.qpack_block_timeout);
    assert_eq!(h3.command_backlog, whole.command_backlog);
}

/// The address the loopback fixtures pretend a peer dialled from.
fn peer() -> std::net::SocketAddr {
    "203.0.113.7:54321".parse().expect("the fixture address did not parse")
}

/// A client and a server over one pipe, the server told where the peer came from.
fn exchange() -> (H1Connection<tokio::io::DuplexStream>, H1Connection<tokio::io::DuplexStream>) {
    let (client_pipe, server_pipe) = tokio::io::duplex(1024 * 1024);

    let client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());
    let server = H1Connection::new(server_pipe, Role::Origin, id(), limits()).with_client(Some(peer()));

    (client, server)
}

fn payload() -> Bytes {
    Bytes::from(vec![b'a'; 8192])
}

/// A request with a body and the `Accept-Encoding` the caller chose, or the one
/// the client fills in when the caller chooses nothing.
fn request(accept: Option<&str>) -> Message {
    let mut request = Message::request(Method::POST, "/submit", Version::V1_1);

    if let Some(accept) = accept {
        request.headers.get_or_insert_with(Headers::new).append("accept-encoding", accept);
    }

    request
}

/// RFC 9110 §12.5.3: a server codes a response in something the request said it
/// would take, and in nothing else.
#[tokio::test]
async fn a_server_compresses_a_response_in_the_coding_the_request_accepted() {
    for (accept, expected) in [("gzip", Compression::Gzip), ("br, gzip", Compression::Brotli), ("*", Compression::Zstd)] {
        let (mut client, mut server) = exchange();

        client.send(request(Some(accept))).await.expect("the request did not send");
        server.receive().await.expect("the request did not arrive");

        let mut response = Message::response(200, Version::V1_1);
        response.body = Some(Body::Data(payload()));
        response.compression = Some(Compression::Auto);
        server.send(response).await.expect("the response did not send");

        let answer = client.receive().await.expect("the response did not arrive");

        assert_eq!(answer.compression, Some(expected), "{accept:?} must be answered with {expected}");
        assert!(!answer.compressed(), "a decoded body must carry no Content-Encoding");
        assert_eq!(answer.body, Some(Body::Data(payload())), "the body must survive the round trip");
    }
}

#[tokio::test]
async fn a_server_sends_the_body_as_it_stands_when_the_request_accepted_nothing() {
    for accept in ["identity", "*;q=0", "gzip;q=0, br;q=0, zstd;q=0, deflate;q=0"] {
        let (mut client, mut server) = exchange();

        client.send(request(Some(accept))).await.expect("the request did not send");
        server.receive().await.expect("the request did not arrive");

        let mut response = Message::response(200, Version::V1_1);
        response.body = Some(Body::Data(payload()));
        response.compression = Some(Compression::Auto);
        server.send(response).await.expect("the response did not send");

        let answer = client.receive().await.expect("the response did not arrive");

        assert_eq!(answer.compression, None, "{accept:?} permits no coding");
        assert_eq!(answer.headers.as_ref().and_then(|headers| headers.get("content-length")), Some("8192"));
        assert_eq!(answer.body, Some(Body::Data(payload())));
    }
}

#[tokio::test]
async fn an_explicit_coding_is_applied_whatever_the_peer_accepts() {
    let (mut client, mut server) = exchange();

    client.send(request(Some("gzip"))).await.expect("the request did not send");
    server.receive().await.expect("the request did not arrive");

    let mut response = Message::response(200, Version::V1_1);
    response.body = Some(Body::Data(payload()));
    response.compression = Some(Compression::Brotli);
    server.send(response).await.expect("the response did not send");

    let answer = client.receive().await.expect("the response did not arrive");
    assert_eq!(answer.compression, Some(Compression::Brotli), "a caller that named a coding gets it");
}

/// A client cannot know what an origin decodes, so `Auto` on a request sends
/// the body as it stands; a coding the caller named is applied all the same.
#[tokio::test]
async fn auto_never_compresses_a_client_request() {
    let (mut client, mut server) = exchange();

    let mut automatic = request(None);
    automatic.body = Some(Body::Data(payload()));
    automatic.compression = Some(Compression::Auto);
    client.send(automatic).await.expect("the request did not send");

    let received = server.receive().await.expect("the request did not arrive");
    assert_eq!(received.compression, None);
    assert_eq!(received.body, Some(Body::Data(payload())));

    let mut named = request(None);
    named.body = Some(Body::Data(payload()));
    named.compression = Some(Compression::Zstd);
    client.send(named).await.expect("the request did not send");

    let coded = server.receive().await.expect("the request did not arrive");
    assert_eq!(coded.compression, Some(Compression::Zstd), "a request coding the caller named is applied");
    assert_eq!(coded.body, Some(Body::Data(payload())));
}

/// RFC 9112 §6.2: `Content-Length` counts the octets that actually go out.
#[tokio::test]
async fn the_content_length_that_goes_out_counts_the_encoded_octets() {
    let (mut peer_pipe, server_pipe) = tokio::io::duplex(1024 * 1024);
    let mut server = H1Connection::new(server_pipe, Role::Origin, id(), limits());
    let mut wire = vec![0u8; 64 * 1024];

    peer_pipe.write_all(b"GET / HTTP/1.1\r\nhost: example.test\r\naccept-encoding: gzip\r\n\r\n").await.expect("the fixture did not write");
    server.receive().await.expect("the request did not arrive");

    let mut response = Message::response(200, Version::V1_1);
    response.body = Some(Body::Data(payload()));
    response.compression = Some(Compression::Auto);
    server.send(response).await.expect("the response did not send");

    let read = peer_pipe.read(&mut wire).await.expect("nothing came back");
    assert!(read > 0);

    let text = String::from_utf8_lossy(&wire[..read]).into_owned();
    let (head, _) = text.split_once("\r\n\r\n").expect("the response carried no field section");

    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .and_then(|value| value.trim().parse().ok())
        .expect("the response carried no Content-Length");

    assert!(head.contains("Content-Encoding: gzip"), "the coded response must name its coding: {head}");
    assert!(head.contains("Vary: Accept-Encoding"), "a response coded from Accept-Encoding must vary on it: {head}");
    assert!(length < 8192, "Content-Length {length} counts the identity body rather than the coded one");
}

/// RFC 9110 §9.3.2: a response to HEAD carries the fields the GET would carry
/// and no content, so `Content-Encoding` describes a body that is not there.
#[tokio::test]
async fn a_response_to_head_carries_no_encoded_body() {
    let (client_pipe, mut server_pipe) = tokio::io::duplex(64 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), limits());

    client.send(Message::request(Method::HEAD, "/", Version::V1_1)).await.expect("the request did not send");

    let response = b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 40\r\n\r\n";
    server_pipe.write_all(response).await.expect("the fixture did not write");

    let answer = client.receive().await.expect("the response did not arrive");

    assert_eq!(answer.body, None, "a response to HEAD carries no content");
    assert_eq!(answer.compression, None, "nothing was decoded, because nothing arrived");
    assert!(answer.compressed(), "the fields still describe the coded representation a GET would return");
}

#[tokio::test]
async fn a_received_request_carries_the_address_it_came_from() {
    let (mut client, mut server) = exchange();

    client.send(request(None)).await.expect("the request did not send");

    let received = server.receive().await.expect("the request did not arrive");
    assert_eq!(received.client, Some(peer()), "a server must be told where the request came from");
    assert_eq!(server.client(), Some(peer()), "the connection must report the same address");
}

#[tokio::test]
async fn a_message_a_client_receives_carries_no_client_address() {
    let (mut client, mut server) = exchange();

    client.send(request(None)).await.expect("the request did not send");
    server.receive().await.expect("the request did not arrive");
    server.send(Message::text("thanks", Version::V1_1)).await.expect("the response did not send");

    let answer = client.receive().await.expect("the response did not arrive");
    assert_eq!(answer.client, None, "a response names no access source");
    assert_eq!(client.client(), None, "a client connection has no peer to report");
}

/// A client that named no preference still gets one, so that a response may
/// come back coded and be handed over decoded.
#[tokio::test]
async fn a_client_request_advertises_the_codings_it_decodes() {
    let (mut client, mut server) = exchange();

    client.send(request(None)).await.expect("the request did not send");

    let received = server.receive().await.expect("the request did not arrive");
    assert_eq!(received.headers.as_ref().and_then(|headers| headers.get("accept-encoding")), Some(Compression::ACCEPTED));

    let (mut client, mut server) = exchange();
    client.send(request(Some("gzip"))).await.expect("the request did not send");

    let chosen = server.receive().await.expect("the request did not arrive");
    assert_eq!(chosen.headers.as_ref().and_then(|headers| headers.get("accept-encoding")), Some("gzip"), "what the caller chose is not replaced");
}

/// Each pipelined request is answered in the coding it asked for, which is only
/// possible if the connection remembers them in order.
#[tokio::test]
async fn a_pipelined_response_is_coded_for_the_request_that_asked_for_it() {
    let (mut client, mut server) = exchange();

    client.send(request(Some("gzip"))).await.expect("the first request did not send");
    client.send(request(Some("br"))).await.expect("the second request did not send");

    server.receive().await.expect("the first request did not arrive");
    server.receive().await.expect("the second request did not arrive");

    for expected in [Compression::Gzip, Compression::Brotli] {
        let mut response = Message::response(200, Version::V1_1);
        response.body = Some(Body::Data(payload()));
        response.compression = Some(Compression::Auto);
        server.send(response).await.expect("a response did not send");

        let answer = client.receive().await.expect("a response did not arrive");
        assert_eq!(answer.compression, Some(expected), "the answers must follow the order the requests came in");
    }
}

/// RFC 9110 §15.2: a 1xx precedes the real response for the same request, so it
/// must not be taken as the answer that finishes the exchange.
#[tokio::test]
async fn an_informational_response_does_not_consume_the_exchange() {
    let (mut client, mut server) = exchange();

    client.send(request(Some("gzip"))).await.expect("the request did not send");
    server.receive().await.expect("the request did not arrive");

    server.send(Message::response(103, Version::V1_1)).await.expect("the hint did not send");

    let mut response = Message::response(200, Version::V1_1);
    response.body = Some(Body::Data(payload()));
    response.compression = Some(Compression::Auto);
    server.send(response).await.expect("the response did not send");

    client.receive().await.expect("the hint did not arrive");
    let answer = client.receive().await.expect("the response did not arrive");

    assert_eq!(answer.compression, Some(Compression::Gzip), "the exchange must survive an informational response");
}

/// A body that decodes into more than the ceiling allows must be refused rather
/// than held: a small coded body can otherwise become an enormous one.
#[tokio::test]
async fn a_received_body_past_the_decoded_ceiling_is_refused() {
    let ceiling = Limits { max_decompressed_body_size: 1024, ..limits() };
    let (client_pipe, mut server_pipe) = tokio::io::duplex(1024 * 1024);
    let mut client = H1Connection::new(client_pipe, Role::UserAgent, id(), ceiling);

    let bomb = Compression::Gzip.encode(&vec![0u8; 1024 * 1024]).expect("the fixture did not encode");

    let head = format!("HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\n\r\n", bomb.len());
    server_pipe.write_all(head.as_bytes()).await.expect("the fixture did not write");
    server_pipe.write_all(&bomb).await.expect("the fixture did not write");

    let failure = client.receive().await.expect_err("a body past the ceiling was accepted");
    assert!(matches!(failure, Error::Limit(_)), "a body past the ceiling must be a limit failure, not {failure}");
}
