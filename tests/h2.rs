use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

use soyokaze::helpers::hpack::HeaderField;
use soyokaze::api::common::Limits;
use soyokaze::models::{Body, ConnectionID, Headers, Message, Method, Role, StreamID, Version};
use soyokaze::protocol::base::Connection;
use soyokaze::protocol::common;
use soyokaze::protocol::h2::{self, Frame, FrameHeader, FrameType, H2Connection, Settings, StreamState};
use soyokaze::Error;

fn limits() -> Limits {
    Limits { read_timeout: 5.0, write_timeout: 5.0, receive_timeout: 5.0, send_timeout: 5.0, ..Limits::default() }
}

fn id() -> ConnectionID {
    ConnectionID(bytes::Bytes::from_static(b"test"))
}

fn split(encoded: &[u8]) -> (FrameHeader, &[u8]) {
    let octets = <[u8; h2::FRAME_HEADER_SIZE]>::try_from(&encoded[..h2::FRAME_HEADER_SIZE])
        .expect("an encoded frame is shorter than a frame header");

    let (_, header) = FrameHeader::decode(&octets);
    (header.expect("an encoded frame named a frame type that does not exist"), &encoded[h2::FRAME_HEADER_SIZE..])
}

fn reencode(frame: &Frame) -> Option<Frame> {
    let encoded = frame.encode();
    let (header, payload) = split(&encoded);
    Frame::decode(header, payload).ok()
}

#[test]
fn a_frame_header_round_trips() {
    let header = FrameHeader { length: 1234, kind: FrameType::Headers, flags: 0x05, stream_id: StreamID(7) };

    let octets = header.encode();
    assert_eq!(octets.len(), h2::FRAME_HEADER_SIZE);
    assert_eq!(FrameHeader::decode(&octets), (1234, Some(header)));
}

#[test]
fn a_frame_header_masks_off_the_reserved_bit() {
    let octets = [0, 0, 0, 0x04, 0, 0xff, 0xff, 0xff, 0xff];
    let (length, header) = FrameHeader::decode(&octets);

    assert_eq!(length, 0);
    assert_eq!(header.map(|header| header.stream_id), Some(StreamID(h2::MAXIMUM_WINDOW_SIZE as u64)));
}

#[test]
fn an_unknown_frame_type_is_reported_but_still_measured() {
    let octets = [0, 0, 8, 0xfe, 0, 0, 0, 0, 0];
    assert_eq!(FrameHeader::decode(&octets), (8, None), "an unknown type must still yield its length");

    for code in 0..=9u8 {
        assert_eq!(FrameType::from_code(code).map(|kind| kind.code()), Some(code));
    }
    assert_eq!(FrameType::from_code(10), None);
}

#[test]
fn frame_types_know_where_they_belong() {
    assert_eq!(FrameType::Data.streamed(), Some(true));
    assert_eq!(FrameType::Settings.streamed(), Some(false));
    assert_eq!(FrameType::WindowUpdate.streamed(), None, "WINDOW_UPDATE is valid either way");
}

#[test]
fn every_frame_round_trips() {
    let frames = [
        Frame::Data { stream_id: StreamID(1), end_stream: true, data: b"hello".to_vec().into() },
        Frame::Data { stream_id: StreamID(1), end_stream: false, data: Vec::new().into() },
        Frame::Headers { stream_id: StreamID(3), end_stream: false, end_headers: true, block: vec![0x82] },
        Frame::Priority { stream_id: StreamID(5), dependency: StreamID(3), exclusive: true, weight: 16 },
        Frame::RstStream { stream_id: StreamID(7), error_code: h2::CANCEL },
        Frame::Settings { ack: false, params: vec![(h2::SETTINGS_MAX_FRAME_SIZE, 16_384)] },
        Frame::Settings { ack: true, params: Vec::new() },
        Frame::Ping { ack: false, payload: [1, 2, 3, 4, 5, 6, 7, 8] },
        Frame::GoAway { last_stream_id: StreamID(9), error_code: h2::NO_ERROR, debug_data: b"bye".to_vec() },
        Frame::WindowUpdate { stream_id: StreamID(0), increment: 65_535 },
        Frame::Continuation { stream_id: StreamID(3), end_headers: true, block: vec![0x86] },
    ];

    for frame in frames {
        assert_eq!(reencode(&frame).as_ref(), Some(&frame), "{frame:?} did not survive re-encoding");
    }
}

#[test]
fn a_push_promise_round_trips_with_its_promised_stream() {
    let frame = Frame::PushPromise {
        stream_id: StreamID(1),
        promised_stream_id: StreamID(2),
        block: vec![0x82, 0x86],
    };

    assert_eq!(reencode(&frame).as_ref(), Some(&frame));
}

#[test]
fn padding_is_stripped_from_the_payload() {
    let payload = [0x02, b'a', b'b', b'c', 0x00, 0x00];
    let header = FrameHeader { length: payload.len() as u32, kind: FrameType::Data, flags: h2::PADDED, stream_id: StreamID(1) };

    assert_eq!(
        Frame::decode(header, &payload).ok(),
        Some(Frame::Data { stream_id: StreamID(1), end_stream: false, data: b"abc".to_vec().into() }),
    );
}

#[test]
fn refuses_padding_longer_than_the_payload() {
    let payload = [0xff, b'a'];
    let header = FrameHeader { length: payload.len() as u32, kind: FrameType::Data, flags: h2::PADDED, stream_id: StreamID(1) };

    assert!(Frame::decode(header, &payload).is_err());

    let empty = FrameHeader { length: 0, kind: FrameType::Data, flags: h2::PADDED, stream_id: StreamID(1) };
    assert!(Frame::decode(empty, &[]).is_err(), "a padded frame must carry at least the padding length");
}

#[test]
fn a_priority_prefix_is_stripped_from_a_header_block() {
    let payload = [0x00, 0x00, 0x00, 0x03, 0x10, 0x82];
    let header = FrameHeader { length: payload.len() as u32, kind: FrameType::Headers, flags: h2::PRIORITY, stream_id: StreamID(1) };

    assert_eq!(
        Frame::decode(header, &payload).ok(),
        Some(Frame::Headers { stream_id: StreamID(1), end_stream: false, end_headers: false, block: vec![0x82] }),
    );
}

#[test]
fn refuses_a_frame_whose_length_does_not_match_its_payload() {
    let header = FrameHeader { length: 9, kind: FrameType::Data, flags: 0, stream_id: StreamID(1) };
    assert!(Frame::decode(header, b"short").is_err());
}

#[test]
fn refuses_a_frame_on_the_wrong_stream() {
    let on_connection = FrameHeader { length: 0, kind: FrameType::Data, flags: 0, stream_id: StreamID(0) };
    assert!(Frame::decode(on_connection, &[]).is_err());

    let on_stream = FrameHeader { length: 0, kind: FrameType::Settings, flags: 0, stream_id: StreamID(1) };
    assert!(Frame::decode(on_stream, &[]).is_err());
}

#[test]
fn refuses_frames_of_the_wrong_fixed_size() {
    for (kind, length) in [(FrameType::RstStream, 4usize), (FrameType::Ping, 8), (FrameType::WindowUpdate, 4)] {
        let stream_id = if kind == FrameType::Ping { StreamID(0) } else { StreamID(1) };

        for wrong in [length - 1, length + 1] {
            let payload = vec![1u8; wrong];
            let header = FrameHeader { length: wrong as u32, kind, flags: 0, stream_id };
            assert!(Frame::decode(header, &payload).is_err(), "{kind:?} accepted {wrong} octets");
        }
    }
}

#[test]
fn refuses_a_settings_frame_that_is_not_a_run_of_pairs() {
    let payload = [0u8; 7];
    let header = FrameHeader { length: 7, kind: FrameType::Settings, flags: 0, stream_id: StreamID(0) };
    assert!(Frame::decode(header, &payload).is_err());

    let acked = FrameHeader { length: 6, kind: FrameType::Settings, flags: h2::ACK, stream_id: StreamID(0) };
    assert!(Frame::decode(acked, &[0u8; 6]).is_err());
}

#[test]
fn refuses_a_zero_window_update() {
    let header = FrameHeader { length: 4, kind: FrameType::WindowUpdate, flags: 0, stream_id: StreamID(1) };
    assert!(Frame::decode(header, &[0, 0, 0, 0]).is_err());
}

#[test]
fn refuses_a_goaway_or_push_promise_that_is_too_short() {
    let goaway = FrameHeader { length: 7, kind: FrameType::GoAway, flags: 0, stream_id: StreamID(0) };
    assert!(Frame::decode(goaway, &[0u8; 7]).is_err());

    let promise = FrameHeader { length: 3, kind: FrameType::PushPromise, flags: 0, stream_id: StreamID(1) };
    assert!(Frame::decode(promise, &[0u8; 3]).is_err());
}

#[test]
fn decoding_arbitrary_payloads_never_panics() {
    for code in 0..=9u8 {
        let Some(kind) = FrameType::from_code(code) else {
            continue;
        };

        for length in 0..12usize {
            for flags in [0u8, h2::PADDED, h2::PRIORITY, h2::END_STREAM | h2::END_HEADERS, 0xff] {
                for stream_id in [StreamID(0), StreamID(1)] {
                    let payload = vec![0xffu8; length];
                    let header = FrameHeader { length: length as u32, kind, flags, stream_id };
                    let _ = Frame::decode(header, &payload);
                }
            }
        }
    }
}

#[test]
fn settings_carry_the_parameters_that_are_set() {
    let settings = Settings::default();
    let params = settings.parameters();

    assert!(params.iter().any(|(id, _)| *id == h2::SETTINGS_INITIAL_WINDOW_SIZE));
    assert!(!params.iter().any(|(id, _)| *id == h2::SETTINGS_MAX_CONCURRENT_STREAMS), "an unset limit is not advertised");

    let bounded = Settings { max_concurrent_streams: Some(100), max_header_list_size: Some(4096), ..settings };
    let params = bounded.parameters();
    assert!(params.iter().any(|(id, value)| (*id, *value) == (h2::SETTINGS_MAX_CONCURRENT_STREAMS, 100)));
    assert!(params.iter().any(|(id, value)| (*id, *value) == (h2::SETTINGS_MAX_HEADER_LIST_SIZE, 4096)));
}

#[test]
fn applying_a_window_size_reports_the_change_to_apply_to_open_streams() {
    let mut settings = Settings::default();

    let change = settings.apply(h2::SETTINGS_INITIAL_WINDOW_SIZE, 131_070);
    assert_eq!(change.ok(), Some(131_070 - h2::DEFAULT_INITIAL_WINDOW_SIZE as i64));

    let back = settings.apply(h2::SETTINGS_INITIAL_WINDOW_SIZE, 0);
    assert_eq!(back.ok(), Some(-131_070));
}

#[test]
fn refuses_settings_outside_their_permitted_range() {
    let mut settings = Settings::default();

    assert!(settings.apply(h2::SETTINGS_ENABLE_PUSH, 2).is_err());
    assert!(settings.apply(h2::SETTINGS_ENABLE_CONNECT_PROTOCOL, 2).is_err());
    assert!(settings.apply(h2::SETTINGS_INITIAL_WINDOW_SIZE, h2::MAXIMUM_WINDOW_SIZE + 1).is_err());
    assert!(settings.apply(h2::SETTINGS_MAX_FRAME_SIZE, h2::DEFAULT_MAX_FRAME_SIZE - 1).is_err());
    assert!(settings.apply(h2::SETTINGS_MAX_FRAME_SIZE, h2::MAXIMUM_FRAME_SIZE + 1).is_err());

    assert!(settings.apply(0xff, 1).is_ok());
}

#[test]
fn stream_states_close_from_each_side() {
    assert!(StreamState::Idle.receivable() && StreamState::Idle.sendable());
    assert!(StreamState::HalfClosedLocal.receivable() && !StreamState::HalfClosedLocal.sendable());
    assert!(!StreamState::HalfClosedRemote.receivable() && StreamState::HalfClosedRemote.sendable());
    assert!(!StreamState::Closed.receivable() && !StreamState::Closed.sendable());

    assert_eq!(StreamState::Open.close_local(), StreamState::HalfClosedLocal);
    assert_eq!(StreamState::HalfClosedRemote.close_local(), StreamState::Closed);
    assert_eq!(StreamState::Open.close_remote(), StreamState::HalfClosedRemote);
    assert_eq!(StreamState::HalfClosedLocal.close_remote(), StreamState::Closed);
}

#[test]
fn a_request_becomes_pseudo_headers_and_back() {
    let mut headers = Headers::new();
    headers.append("host", "example.test");
    headers.append("accept", "*/*");

    let mut request = Message::request(Method::GET, "/index.html", Version::V2_0);
    request.headers = Some(headers);
    request.secure = true;

    let fields = common::fields(&request).expect("a request did not become fields");
    assert_eq!(fields[0], HeaderField::new(":method", "GET"));
    assert_eq!(fields[1], HeaderField::new(":scheme", "https"));
    assert_eq!(fields[2], HeaderField::new(":authority", "example.test"));
    assert_eq!(fields[3], HeaderField::new(":path", "/index.html"));

    let back = common::message(&fields, Version::V2_0).expect("fields did not become a message");
    assert_eq!(back.method, Some(Method::GET));
    assert_eq!(back.target.as_deref(), Some("/index.html"));
    assert!(back.secure);
    assert_eq!(back.headers.as_ref().and_then(|headers| headers.get("host")), Some("example.test"));
}

#[test]
fn a_connect_request_carries_only_an_authority() {
    let request = Message::request(Method::CONNECT, "example.test:443", Version::V2_0);

    let fields = common::fields(&request).expect("a CONNECT did not become fields");
    assert_eq!(fields, vec![HeaderField::new(":method", "CONNECT"), HeaderField::new(":authority", "example.test:443")]);

    let back = common::message(&fields, Version::V2_0).expect("fields did not become a message");
    assert_eq!(back.method, Some(Method::CONNECT));
    assert_eq!(back.target.as_deref(), Some("example.test:443"));
}

#[test]
fn refuses_a_field_section_that_breaks_the_rules() {
    let cases: &[(&str, Vec<HeaderField>)] = &[
        ("an uppercase field name", vec![HeaderField::new("Accept", "*/*")]),
        ("a connection-specific field", vec![HeaderField::new(":status", "200"), HeaderField::new("connection", "close")]),
        ("a TE that does not ask for trailers", vec![HeaderField::new(":status", "200"), HeaderField::new("te", "gzip")]),
        ("a pseudo-header after a regular field", vec![HeaderField::new("accept", "*/*"), HeaderField::new(":status", "200")]),
        ("a repeated pseudo-header", vec![HeaderField::new(":status", "200"), HeaderField::new(":status", "204")]),
        ("an undefined pseudo-header", vec![HeaderField::new(":nonsense", "1")]),
        ("a status that is not three digits", vec![HeaderField::new(":status", "20")]),
        ("neither a method nor a status", vec![HeaderField::new("accept", "*/*")]),
        ("a request with no scheme", vec![HeaderField::new(":method", "GET"), HeaderField::new(":path", "/")]),
        ("a request with an empty path", vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":path", ""),
        ]),
        ("a response pseudo-header on a request", vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":path", "/"),
            HeaderField::new(":status", "200"),
        ]),
    ];

    for (description, fields) in cases {
        assert!(common::message(fields, Version::V2_0).is_err(), "{description} should be refused");
    }
}

#[test]
fn refuses_to_frame_a_connection_specific_field() {
    let mut headers = Headers::new();
    headers.append("connection", "keep-alive");

    let mut response = Message::response(200, Version::V2_0);
    response.headers = Some(headers);

    assert!(matches!(common::fields(&response), Err(Error::Protocol(_))));
}

async fn pair() -> (H2Connection<tokio::io::DuplexStream>, H2Connection<tokio::io::DuplexStream>) {
    let (client_pipe, server_pipe) = tokio::io::duplex(256 * 1024);

    let mut client = H2Connection::new(client_pipe, Role::UserAgent, id(), limits());
    let mut server = H2Connection::new(server_pipe, Role::Origin, id(), limits());

    client.start().await.expect("the client preface did not send");
    server.start().await.expect("the server did not accept the preface");

    (client, server)
}

#[tokio::test]
async fn a_request_and_response_cross_a_connection() {
    let (mut client, mut server) = pair().await;

    let mut request = Message::request(Method::POST, "/submit", Version::V2_0);
    request.headers = Some(Headers::new());
    request.body = Some(Body::Text("hello".to_owned()));
    request.secure = true;

    client.send(request).await.expect("the request did not send");

    let received = server.receive().await.expect("the request did not arrive");
    assert_eq!(received.method, Some(Method::POST));
    assert_eq!(received.target.as_deref(), Some("/submit"));
    assert_eq!(received.body, Some(Body::Data(bytes::Bytes::from_static(b"hello"))));

    let stream_id = received.stream_id.expect("the request named no stream");
    assert_eq!(stream_id, StreamID(1), "a client opens odd-numbered streams");

    let mut response = Message::text("thanks", Version::V2_0);
    response.stream_id = Some(stream_id);
    server.send(response).await.expect("the response did not send");

    let answer = client.receive().await.expect("the response did not arrive");
    assert_eq!(answer.status_code, Some(200));
    assert_eq!(answer.body, Some(Body::Data(bytes::Bytes::from_static(b"thanks"))));
}

#[tokio::test]
async fn trailers_arrive_after_the_body() {
    let (mut client, mut server) = pair().await;

    let mut trailers = Headers::new();
    trailers.append("x-checksum", "deadbeef");

    let mut request = Message::request(Method::POST, "/submit", Version::V2_0);
    request.headers = Some(Headers::new());
    request.body = Some(Body::Text("hello".to_owned()));
    request.trailers = Some(trailers);

    client.send(request).await.expect("the request did not send");

    let received = server.receive().await.expect("the request did not arrive");
    assert_eq!(received.body, Some(Body::Data(bytes::Bytes::from_static(b"hello"))));
    assert_eq!(
        received.trailers.as_ref().and_then(|trailers| trailers.get("x-checksum")),
        Some("deadbeef"),
    );
}

#[tokio::test]
async fn a_field_block_spanning_continuation_frames_is_reassembled() {
    let (mut client, mut server) = pair().await;

    let mut headers = Headers::new();
    for index in 0..64 {
        headers.append(format!("x-field-{index}"), "x".repeat(512));
    }

    let mut request = Message::request(Method::GET, "/", Version::V2_0);
    request.headers = Some(headers);

    let fields = common::fields(&request).expect("the request did not become fields");
    let block = soyokaze::helpers::hpack::Encoder::new().encode(&fields);
    assert!(block.len() > h2::DEFAULT_MAX_FRAME_SIZE as usize, "the field section fits in one frame after all");

    client.send(request).await.expect("the request did not send");

    let received = server.receive().await.expect("the request did not arrive");
    let headers = received.headers.as_ref().expect("the request lost its fields");
    assert_eq!(headers.get("x-field-63").map(str::len), Some(512));
}

#[tokio::test]
async fn a_ping_is_answered_with_its_own_payload() {
    let (mut client, mut server) = pair().await;

    client.write(&Frame::Ping { ack: false, payload: [9; 8] }).await.expect("the ping did not send");

    for _ in 0..2 {
        assert_eq!(server.pump().await.ok(), Some(None), "neither frame delivers a message");
    }

    let mut acknowledged = None;
    for _ in 0..3 {
        if let Some(Frame::Ping { ack: true, payload }) = client.read_frame().await.expect("nothing came back") {
            acknowledged = Some(payload);
            break;
        }
    }

    assert_eq!(acknowledged, Some([9; 8]), "a ping must come back with the payload it carried");
}

#[tokio::test]
async fn refuses_a_preface_that_is_not_the_preface() {
    let (mut client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
    let mut server = H2Connection::new(server_pipe, Role::Origin, id(), limits());

    client_pipe.write_all(b"GET / HTTP/1.1\r\n\r\nnot the preface").await.expect("the fixture did not write");

    assert!(matches!(server.start().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_a_stream_the_peer_may_not_open() {
    let (mut client, mut server) = pair().await;

    let block = Frame::Headers { stream_id: StreamID(2), end_stream: true, end_headers: true, block: vec![0x82, 0x86, 0x84] };
    client.write(&block).await.expect("the frame did not send");

    assert!(matches!(server.receive().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_a_stream_identifier_that_goes_backwards() {
    let (mut client, mut server) = pair().await;

    let request = |stream_id| Frame::Headers {
        stream_id,
        end_stream: true,
        end_headers: true,
        block: vec![0x82, 0x86, 0x84],
    };

    client.write(&request(StreamID(3))).await.expect("the frame did not send");
    server.receive().await.expect("the first request did not arrive");

    client.write(&request(StreamID(1))).await.expect("the frame did not send");
    assert!(matches!(server.receive().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_a_continuation_that_starts_a_block() {
    let (mut client, mut server) = pair().await;

    let stray = Frame::Continuation { stream_id: StreamID(1), end_headers: true, block: vec![0x82] };
    client.write(&stray).await.expect("the frame did not send");

    assert!(matches!(server.receive().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_data_on_a_stream_that_was_never_opened() {
    let (mut client, mut server) = pair().await;

    client
        .write(&Frame::Data { stream_id: StreamID(1), end_stream: false, data: b"x".to_vec().into() })
        .await
        .expect("the frame did not send");

    assert!(matches!(server.receive().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_a_frame_larger_than_the_advertised_maximum() {
    let (mut client_pipe, server_pipe) = tokio::io::duplex(256 * 1024);
    let mut server = H2Connection::new(server_pipe, Role::Origin, id(), limits());

    let header = FrameHeader {
        length: h2::DEFAULT_MAX_FRAME_SIZE + 1,
        kind: FrameType::Data,
        flags: 0,
        stream_id: StreamID(1),
    };

    let mut out = BytesMut::from(h2::PREFACE);
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(&[0u8; 16]);

    client_pipe.write_all(&out).await.expect("the fixture did not write");

    assert!(matches!(server.receive().await, Err(Error::Limit(_))));
}

#[tokio::test]
async fn an_idle_frame_budget_is_enforced() {
    let (client_pipe, server_pipe) = tokio::io::duplex(256 * 1024);

    let mut client = H2Connection::new(client_pipe, Role::UserAgent, id(), limits());
    let mut server = H2Connection::new(server_pipe, Role::Origin, id(), Limits { max_idle_frames: 4, ..limits() });

    client.start().await.expect("the client preface did not send");
    server.start().await.expect("the server did not accept the preface");

    let mut refused = false;
    for _ in 0..32 {
        if client.write(&Frame::Ping { ack: false, payload: [0; 8] }).await.is_err() {
            break;
        }

        if matches!(server.pump().await, Err(Error::Limit(_))) {
            refused = true;
            break;
        }
    }

    assert!(refused, "a flood of frames that advance nothing must be refused");
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
async fn a_field_block_and_its_data_leave_in_one_write() {
    let (mut client_pipe, server_pipe) = tokio::io::duplex(256 * 1024);
    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    client_pipe.write_all(h2::PREFACE).await.expect("the preface did not send");

    let transport = Counting { inner: server_pipe, writes: writes.clone() };
    let mut server = H2Connection::new(transport, Role::Origin, id(), limits());

    server.start().await.expect("the opening settings did not send");
    writes.store(0, std::sync::atomic::Ordering::Relaxed);

    let mut response = Message::response(200, Version::V2_0);
    response.stream_id = Some(StreamID(2));
    response.body = Some(Body::Data(bytes::Bytes::from_static(b"hello")));

    server.send_message(response).await.expect("the response did not send");

    assert_eq!(
        writes.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "HEADERS and DATA for one message belong in the same write"
    );

    drop(client_pipe);
}

#[tokio::test]
async fn opening_streams_without_reading_them_does_not_grow_without_limit() {
    let (client_pipe, _server_pipe) = tokio::io::duplex(4 * 1024 * 1024);
    let mut client = H2Connection::new(client_pipe, Role::UserAgent, id(), limits());

    let ceiling = client.local_stream_ceiling();
    let mut opened = 0usize;

    let refused = loop {
        let mut request = Message::request(Method::GET, "/", Version::V2_0);
        request.headers = Some(Headers::new());

        match client.send(request).await {
            Ok(()) => opened += 1,
            Err(error) => break error,
        }

        assert!(opened <= ceiling, "{opened} streams are open with nothing read back");
    };

    assert!(matches!(refused, Error::Limit(_)), "an unanswered client was refused with {refused:?}");
    assert_eq!(opened, ceiling, "the client stopped opening streams at the wrong point");
}
