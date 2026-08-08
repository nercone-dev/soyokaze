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
use soyokaze::helpers::sync;

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
