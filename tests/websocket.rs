use soyokaze::models::Limits;
use soyokaze::models::{ConnectionID, Headers, Message, Method, Role, Version};
use soyokaze::protocol::common::Fields;
use soyokaze::websocket::{self, CloseCode, Frame, Opcode, WebSocketConnection};
use soyokaze::Error;

fn limits() -> Limits {
    Limits {
        read_timeout: 5.0,
        write_timeout: 5.0,
        receive_timeout: 5.0,
        send_timeout: 5.0,
        ws_linger_timeout: 0.0,
        ..Limits::default()
    }
}

fn id() -> ConnectionID {
    ConnectionID(bytes::Bytes::from_static(b"test"))
}

fn masked(opcode: Opcode, payload: &[u8]) -> Vec<u8> {
    let mut frame = Frame::new(opcode, payload.to_vec());
    frame.mask = Some([0xa1, 0xb2, 0xc3, 0xd4]);
    frame.encode()
}

#[test]
fn opcodes_map_to_and_from_their_codes() {
    for opcode in [Opcode::Continuation, Opcode::Text, Opcode::Binary, Opcode::Close, Opcode::Ping, Opcode::Pong] {
        assert_eq!(Opcode::from_code(opcode.code()), Some(opcode));
    }

    for code in [0x3u8, 0x7, 0xb, 0xf] {
        assert_eq!(Opcode::from_code(code), None);
    }
}

#[test]
fn control_opcodes_are_recognised() {
    assert!(Opcode::Close.control() && Opcode::Ping.control() && Opcode::Pong.control());
    assert!(!Opcode::Text.control() && !Opcode::Binary.control() && !Opcode::Continuation.control());
}

#[test]
fn close_codes_map_to_and_from_their_numbers() {
    for code in [
        CloseCode::Normal, CloseCode::GoingAway, CloseCode::ProtocolError, CloseCode::UnsupportedData,
        CloseCode::InvalidPayload, CloseCode::PolicyViolation, CloseCode::MessageTooBig,
        CloseCode::MandatoryExtension, CloseCode::InternalError,
    ] {
        assert_eq!(CloseCode::from_code(code.code()), Some(code));
        assert!(CloseCode::permitted(code.code()));
    }

    assert!(CloseCode::permitted(3000) && CloseCode::permitted(4999));
    assert!(!CloseCode::permitted(1005), "1005 must not appear on the wire");
    assert!(!CloseCode::permitted(1006), "1006 must not appear on the wire");
    assert!(!CloseCode::permitted(2999) && !CloseCode::permitted(5000));
}

#[test]
fn frames_round_trip_at_every_length_form() {
    for length in [0usize, 1, 125, 126, 127, 65_535, 65_536] {
        let payload = vec![b'x'; length];

        for mask in [None, Some([1u8, 2, 3, 4])] {
            let frame = Frame { fin: true, opcode: Opcode::Binary, mask, payload: payload.clone().into() };
            let encoded = frame.encode();

            let decoded = Frame::decode(&encoded).ok().flatten().expect("a frame did not decode");
            assert_eq!(decoded, (encoded.len(), frame), "length {length} did not survive");
        }
    }
}

#[test]
fn masking_is_its_own_inverse() {
    let mask = [0xde, 0xad, 0xbe, 0xef];

    let mut payload = b"the quick brown fox".to_vec();
    let original = payload.clone();

    Frame::apply_mask(mask, &mut payload);
    assert_ne!(payload, original, "masking did nothing");

    Frame::apply_mask(mask, &mut payload);
    assert_eq!(payload, original);
}

#[test]
fn a_frame_that_has_not_fully_arrived_yields_nothing() {
    let encoded = masked(Opcode::Text, b"hello there");

    for partial in 0..encoded.len() {
        assert_eq!(Frame::decode(&encoded[..partial]).ok().flatten(), None, "{partial} octets should not decode");
    }
}

#[test]
fn refuses_a_reserved_bit_with_no_extension() {
    for reserved in [0x40u8, 0x20, 0x10] {
        let frame = [0x81 | reserved, 0x00];
        assert!(Frame::decode(&frame).is_err(), "reserved bit {reserved:#x} should be refused");
    }
}

#[test]
fn refuses_a_reserved_opcode() {
    assert!(Frame::decode(&[0x83, 0x00]).is_err());
    assert!(Frame::decode(&[0x8f, 0x00]).is_err());
}

#[test]
fn refuses_a_control_frame_that_is_too_large_or_fragmented() {
    let oversized = [0x89, 0x7e, 0x00, 0xff];
    assert!(Frame::decode(&oversized).is_err());

    let fragmented = [0x08, 0x00];
    assert!(Frame::decode(&fragmented).is_err());
}

#[test]
fn refuses_a_payload_length_with_its_high_bit_set() {
    let frame = [0x82, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(Frame::decode(&frame).is_err());
}

#[test]
fn a_length_that_cannot_be_addressed_waits_rather_than_decoding() {
    let frame = [0x82, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(Frame::decode(&frame).ok().flatten(), None);
}

#[test]
fn decoding_arbitrary_octets_never_panics() {
    for first in 0..=255u8 {
        for second in 0..=255u8 {
            let _ = Frame::decode(&[first, second]);
            let _ = Frame::decode(&[first, second, 0xff, 0xff, 0xff, 0xff]);
        }
    }
}

#[test]
fn the_accept_key_matches_the_specification_example() {
    assert_eq!(websocket::Upgrade::accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn a_nonce_is_sixteen_octets_of_base64() {
    let nonce = websocket::Upgrade::nonce().expect("no randomness was available");
    assert_eq!(soyokaze::helpers::base64::decode(&nonce).map(|key| key.len()), Ok(16));
}

#[test]
fn a_handshake_request_and_response_verify_against_each_other() {
    let key = websocket::Upgrade::nonce().expect("no randomness was available");

    let request = websocket::Upgrade::request("example.test", "/chat", &key, Version::V1_1);
    assert_eq!(websocket::Upgrade::verify_request(&request).ok(), Some(key.clone()));
    assert!(websocket::Handshake::requested(&request));

    let response = websocket::Upgrade::response(&key, Version::V1_1);
    assert_eq!(response.status_code, Some(101));
    assert!(websocket::Upgrade::verify_response(&response, &key).is_ok());
}

#[test]
fn refuses_a_handshake_request_that_is_missing_something() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";

    let strip = |name: &str| {
        let mut request = websocket::Upgrade::request("example.test", "/chat", key, Version::V1_1);
        if let Some(headers) = request.headers.as_mut() {
            headers.remove(name);
        }
        request
    };

    for name in ["upgrade", "connection", "sec-websocket-version", "sec-websocket-key"] {
        assert!(websocket::Upgrade::verify_request(&strip(name)).is_err(), "a request with no {name} should be refused");
    }

    let mut short = websocket::Upgrade::request("example.test", "/chat", "c2hvcnQ=", Version::V1_1);
    assert!(websocket::Upgrade::verify_request(&short).is_err());

    short.method = Some(Method::POST);
    assert!(websocket::Upgrade::verify_request(&short).is_err());

    let mut bare = Message::request(Method::GET, "/chat", Version::V1_1);
    bare.headers = None;
    assert!(websocket::Upgrade::verify_request(&bare).is_err());
}

#[test]
fn refuses_a_response_that_does_not_confirm_the_upgrade() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";

    let mut wrong_status = websocket::Upgrade::response(key, Version::V1_1);
    wrong_status.status_code = Some(200);
    assert!(websocket::Upgrade::verify_response(&wrong_status, key).is_err());

    let mismatched = websocket::Upgrade::response("YW5vdGhlciBub25jZSEh", Version::V1_1);
    assert!(websocket::Upgrade::verify_response(&mismatched, key).is_err());

    let mut without_upgrade = websocket::Upgrade::response(key, Version::V1_1);
    if let Some(headers) = without_upgrade.headers.as_mut() {
        headers.remove("upgrade");
    }
    assert!(websocket::Upgrade::verify_response(&without_upgrade, key).is_err());
}

#[test]
fn an_extended_connect_carries_the_protocol() {
    for version in [Version::V2_0, Version::V3_0] {
        let request = websocket::Connect::request("example.test", "/chat", version);

        assert_eq!(request.method, Some(Method::CONNECT));
        assert!(websocket::Handshake::requested(&request));
        assert!(websocket::Connect::verify_request(&request).is_ok());
        assert!(websocket::Handshake::verify(&request).is_ok());

        assert!(websocket::Connect::verify_response(&websocket::Connect::response(version)).is_ok());
    }
}

#[test]
fn refuses_an_extended_connect_that_names_no_protocol() {
    let mut request = Message::request(Method::CONNECT, "/chat", Version::V2_0);
    request.headers = Some(Headers::new());

    assert!(websocket::Connect::verify_request(&request).is_err());
    assert!(!websocket::Handshake::requested(&request));

    let mut refused = Message::response(403, Version::V2_0);
    refused.headers = Some(Headers::new());
    assert!(websocket::Connect::verify_response(&refused).is_err());
}

#[test]
fn a_token_is_matched_case_insensitively_inside_a_list() {
    let mut headers = Headers::new();
    headers.append("connection", "keep-alive, Upgrade");

    assert!(websocket::Handshake::token_present(&headers, "connection", "upgrade"));
    assert!(!websocket::Handshake::token_present(&headers, "connection", "close"));
}

fn connection() -> (tokio::io::DuplexStream, WebSocketConnection<tokio::io::DuplexStream>) {
    let (peer, transport) = tokio::io::duplex(256 * 1024);
    (peer, WebSocketConnection::new(transport, Role::Origin, id(), limits()))
}

#[tokio::test]
async fn a_fragmented_message_is_reassembled() {
    use tokio::io::AsyncWriteExt;
    let (mut peer, mut connection) = connection();

    let mut first = Frame::new(Opcode::Text, b"hello ".to_vec());
    first.fin = false;
    first.mask = Some([1, 2, 3, 4]);

    let mut last = Frame::new(Opcode::Continuation, b"world".to_vec());
    last.mask = Some([5, 6, 7, 8]);

    peer.write_all(&first.encode()).await.expect("the fixture did not write");
    peer.write_all(&last.encode()).await.expect("the fixture did not write");

    let (opcode, payload) = connection.receive_message().await.expect("no message arrived");
    assert_eq!(opcode, Opcode::Text);
    assert_eq!(payload, bytes::Bytes::from_static(b"hello world"));
}

#[tokio::test]
async fn a_ping_is_answered_between_fragments() {
    use tokio::io::AsyncWriteExt;
    let (mut peer, mut connection) = connection();

    let mut first = Frame::new(Opcode::Text, b"hi".to_vec());
    first.fin = false;
    first.mask = Some([1, 2, 3, 4]);

    let mut ping = Frame::new(Opcode::Ping, b"are you there".to_vec());
    ping.mask = Some([1, 2, 3, 4]);

    let mut last = Frame::new(Opcode::Continuation, b"!".to_vec());
    last.mask = Some([1, 2, 3, 4]);

    peer.write_all(&first.encode()).await.expect("the fixture did not write");
    peer.write_all(&ping.encode()).await.expect("the fixture did not write");
    peer.write_all(&last.encode()).await.expect("the fixture did not write");

    let (_, payload) = connection.receive_message().await.expect("no message arrived");
    assert_eq!(payload, bytes::Bytes::from_static(b"hi!"));

    use tokio::io::AsyncReadExt;
    let mut scratch = [0u8; 64];
    let read = peer.read(&mut scratch).await.expect("nothing came back");

    let pong = Frame::decode(&scratch[..read]).ok().flatten().expect("the answer did not decode");
    assert_eq!(pong.1.opcode, Opcode::Pong);
    assert_eq!(pong.1.payload, b"are you there".as_slice());
}

#[tokio::test]
async fn a_close_is_echoed_once() {
    use tokio::io::AsyncWriteExt;
    let (mut peer, mut connection) = connection();

    let mut close = Frame::new(Opcode::Close, 1000u16.to_be_bytes().to_vec());
    close.mask = Some([1, 2, 3, 4]);

    peer.write_all(&close.encode()).await.expect("the fixture did not write");

    let (opcode, _) = connection.receive_message().await.expect("no message arrived");
    assert_eq!(opcode, Opcode::Close);
    assert!(connection.closing(), "the connection should now be closing");
}

#[tokio::test]
async fn refuses_a_continuation_that_starts_a_message() {
    use tokio::io::AsyncWriteExt;
    let (mut peer, mut connection) = connection();

    peer.write_all(&masked(Opcode::Continuation, b"orphan")).await.expect("the fixture did not write");

    assert!(matches!(connection.receive_message().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_a_message_that_begins_before_the_last_one_ends() {
    use tokio::io::AsyncWriteExt;
    let (mut peer, mut connection) = connection();

    let mut first = Frame::new(Opcode::Text, b"one".to_vec());
    first.fin = false;
    first.mask = Some([1, 2, 3, 4]);

    peer.write_all(&first.encode()).await.expect("the fixture did not write");
    peer.write_all(&masked(Opcode::Text, b"two")).await.expect("the fixture did not write");

    assert!(matches!(connection.receive_message().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_an_unmasked_frame_from_a_client() {
    use tokio::io::AsyncWriteExt;
    let (mut peer, mut connection) = connection();

    peer.write_all(&Frame::new(Opcode::Text, b"bare".to_vec()).encode()).await.expect("the fixture did not write");

    assert!(matches!(connection.receive().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_text_that_is_not_valid_utf8() {
    use tokio::io::AsyncWriteExt;
    let (mut peer, mut connection) = connection();

    peer.write_all(&masked(Opcode::Text, &[0xff, 0xfe])).await.expect("the fixture did not write");

    assert!(matches!(connection.receive_message().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn refuses_a_message_past_the_size_limit() {
    use tokio::io::AsyncWriteExt;
    let (peer, transport) = tokio::io::duplex(256 * 1024);
    let mut connection = WebSocketConnection::new(transport, Role::Origin, id(), Limits { max_message_size: 16, ..limits() });

    let mut peer = peer;
    peer.write_all(&masked(Opcode::Binary, &[0u8; 64])).await.expect("the fixture did not write");

    assert!(matches!(connection.receive_message().await, Err(Error::Limit(_))));
}

#[tokio::test]
async fn refuses_a_message_spread_over_too_many_frames() {
    use tokio::io::AsyncWriteExt;
    let (peer, transport) = tokio::io::duplex(256 * 1024);
    let mut connection = WebSocketConnection::new(transport, Role::Origin, id(), Limits { ws_max_fragments: 2, ..limits() });

    let mut peer = peer;
    let mut opening = Frame::new(Opcode::Text, b"a".to_vec());
    opening.fin = false;
    opening.mask = Some([1, 2, 3, 4]);
    peer.write_all(&opening.encode()).await.expect("the fixture did not write");

    for _ in 0..8 {
        let mut more = Frame::new(Opcode::Continuation, b"a".to_vec());
        more.fin = false;
        more.mask = Some([1, 2, 3, 4]);
        peer.write_all(&more.encode()).await.expect("the fixture did not write");
    }

    assert!(matches!(connection.receive_message().await, Err(Error::Limit(_))));
}

#[tokio::test]
async fn refuses_a_close_payload_that_breaks_the_rules() {
    let (_, connection) = connection();

    assert!(connection.verify_close(&[0x03]).is_err());

    assert!(connection.verify_close(&1006u16.to_be_bytes()).is_err());

    let mut invalid = 1000u16.to_be_bytes().to_vec();
    invalid.extend_from_slice(&[0xff, 0xfe]);
    assert!(connection.verify_close(&invalid).is_err());

    assert!(connection.verify_close(&[]).is_ok());

    let mut valid = 1000u16.to_be_bytes().to_vec();
    valid.extend_from_slice(b"bye");
    assert!(connection.verify_close(&valid).is_ok());
}

/// Each version's way in is enumerated, so neither is reached by default.
///
/// RFC 6455 §4.1 bootstraps WebSocket over HTTP/1.x with a `GET` carrying
/// `Upgrade: websocket`; RFC 8441 and RFC 9220 replace that with an extended
/// `CONNECT` for HTTP/2 and HTTP/3. Neither form may be accepted on a version
/// that does not define it, whichever way round.
#[test]
fn each_version_accepts_only_its_own_handshake() {
    let upgrade = websocket::Upgrade::request("example.test", "/chat", "dGhlIHNhbXBsZSBub25jZQ==", Version::V1_1);
    assert_eq!(upgrade.version, Version::V1_1);
    assert!(websocket::Handshake::requested(&upgrade), "HTTP/1.1 asks with the upgrade");

    // The same upgrade request, relabelled as HTTP/2 or HTTP/3, is not a handshake there.
    for version in [Version::V2_0, Version::V3_0] {
        let mut relabelled = websocket::Upgrade::request("example.test", "/chat", "dGhlIHNhbXBsZSBub25jZQ==", Version::V1_1);
        relabelled.version = version;

        assert!(
            !websocket::Handshake::requested(&relabelled),
            "{version} must not accept the RFC 6455 upgrade, which it does not define",
        );
        assert!(websocket::Handshake::verify(&relabelled).is_err(), "{version} must refuse it too");
    }

    // ...and the extended CONNECT is not a handshake over HTTP/1.x.
    for version in [Version::V1_0, Version::V1_1] {
        let mut relabelled = websocket::Connect::request("example.test", "/chat", Version::V2_0);
        relabelled.version = version;

        assert!(
            !websocket::Handshake::requested(&relabelled),
            "{version} must not accept the extended CONNECT, which it does not define",
        );
        assert!(websocket::Handshake::verify(&relabelled).is_err(), "{version} must refuse it too");
    }
}

#[test]
fn a_websocket_handshake_needs_http_1_1_or_later() {
    // RFC 6455 §1.7 and §4.1: the opening handshake is an HTTP/1.1 upgrade.
    // HTTP/1.0 has no Upgrade to build on, so a request that asks for one over
    // it must be turned away rather than taken for HTTP/1.1.
    let mut request = websocket::Upgrade::request("example.test", "/chat", "dGhlIHNhbXBsZSBub25jZQ==", Version::V1_0);
    request.version = Version::V1_0;

    assert!(!websocket::Handshake::requested(&request), "an HTTP/1.0 request must not be routed to the WebSocket handshake");
    assert!(websocket::Handshake::verify(&request).is_err(), "an HTTP/1.0 handshake must not verify");

    // The same request over HTTP/1.1 is the one the RFC describes.
    let mut later = websocket::Upgrade::request("example.test", "/chat", "dGhlIHNhbXBsZSBub25jZQ==", Version::V1_1);
    later.version = Version::V1_1;

    assert!(websocket::Handshake::requested(&later), "a well-formed HTTP/1.1 upgrade must be recognised");
    assert!(websocket::Handshake::verify(&later).is_ok(), "a well-formed HTTP/1.1 upgrade must verify");
}

#[test]
fn the_handshake_is_framed_with_the_version_it_is_carried_over() {
    // Both halves of both handshakes take the version rather than assuming
    // one, so an upgrade and an extended CONNECT stay interchangeable.
    for version in [Version::V1_0, Version::V1_1] {
        assert_eq!(websocket::Upgrade::request("example.test", "/chat", "a2V5", version).version, version);
        assert_eq!(websocket::Upgrade::response("a2V5", version).version, version);
    }

    for version in [Version::V2_0, Version::V3_0] {
        assert_eq!(websocket::Connect::request("example.test", "/chat", version).version, version);
        assert_eq!(websocket::Connect::response(version).version, version);
    }
}

#[test]
fn an_extended_connect_does_not_assume_its_transport_was_secure() {
    // RFC 8441 §4 frames the request as an ordinary one, so :scheme follows
    // what the connection actually is. Assuming https would frame an h2c
    // WebSocket as though it had crossed TLS.
    let request = websocket::Connect::request("example.test", "/chat", Version::V2_0);
    assert!(!request.security.secure, "an extended CONNECT must not claim a secure transport of its own accord");

    let fields = Fields::of(&request).expect("a well-formed extended CONNECT did not frame");
    assert!(
        fields.iter().any(|field| field.name == ":scheme" && field.value == "http"),
        "over a plaintext connection the scheme must be http",
    );

    let mut secure = websocket::Connect::request("example.test", "/chat", Version::V2_0);
    secure.security.secure = true;

    let fields = Fields::of(&secure).expect("a well-formed extended CONNECT did not frame");
    assert!(
        fields.iter().any(|field| field.name == ":scheme" && field.value == "https"),
        "over a secure connection the scheme must be https",
    );
}

#[test]
fn taking_a_frame_matches_decoding_it_and_consumes_the_buffer() {
    let first = masked(Opcode::Text, b"hello");
    let second = masked(Opcode::Binary, &[0x00, 0xff, 0x7f]);

    let mut stream = first.clone();
    stream.extend_from_slice(&second);

    let mut buffer = bytes::BytesMut::from(&stream[..]);

    let taken = Frame::take(&mut buffer).expect("a whole frame must take").expect("a whole frame was buffered");
    let (consumed, decoded) = Frame::decode(&first).expect("a whole frame must decode").expect("a whole frame was given");

    assert_eq!(consumed, first.len());
    assert_eq!(taken, decoded, "taking and decoding must read one frame the same way");
    assert_eq!(taken.payload, b"hello".as_slice(), "the payload must come back unmasked");
    assert_eq!(buffer, second, "taking a frame must consume exactly that frame");

    let taken = Frame::take(&mut buffer).expect("the second frame must take").expect("the second frame was buffered");
    assert_eq!(taken.payload, [0x00, 0xff, 0x7f].as_slice());
    assert!(buffer.is_empty());
}

#[test]
fn taking_a_partial_frame_leaves_the_buffer_untouched() {
    let encoded = masked(Opcode::Binary, &[b'x'; 300]);

    for partial in 0..encoded.len() {
        let mut buffer = bytes::BytesMut::from(&encoded[..partial]);
        assert_eq!(Frame::take(&mut buffer).expect("a partial frame is not an error"), None);
        assert_eq!(buffer, encoded[..partial], "{partial} octets must be left where they were");
    }
}
