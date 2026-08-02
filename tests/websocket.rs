use soyokaze::models::{ConnectionID, Headers, Limits, Message, Method, Role, Version};
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
            let frame = Frame { fin: true, opcode: Opcode::Binary, mask, payload: payload.clone() };
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
    assert_eq!(websocket::accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn a_nonce_is_sixteen_octets_of_base64() {
    let nonce = websocket::nonce().expect("no randomness was available");
    assert_eq!(soyokaze::helpers::base64::decode(&nonce).map(|key| key.len()), Ok(16));
}

#[test]
fn a_handshake_request_and_response_verify_against_each_other() {
    let key = websocket::nonce().expect("no randomness was available");

    let request = websocket::handshake_request("example.test", "/chat", &key);
    assert_eq!(websocket::verify_request(&request).ok(), Some(key.clone()));
    assert!(websocket::upgrade_requested(&request));

    let response = websocket::handshake_response(&key);
    assert_eq!(response.status_code, Some(101));
    assert!(websocket::verify_response(&response, &key).is_ok());
}

#[test]
fn refuses_a_handshake_request_that_is_missing_something() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";

    let strip = |name: &str| {
        let mut request = websocket::handshake_request("example.test", "/chat", key);
        if let Some(headers) = request.headers.as_mut() {
            headers.remove(name);
        }
        request
    };

    for name in ["upgrade", "connection", "sec-websocket-version", "sec-websocket-key"] {
        assert!(websocket::verify_request(&strip(name)).is_err(), "a request with no {name} should be refused");
    }

    let mut short = websocket::handshake_request("example.test", "/chat", "c2hvcnQ=");
    assert!(websocket::verify_request(&short).is_err());

    short.method = Some(Method::POST);
    assert!(websocket::verify_request(&short).is_err());

    let mut bare = Message::request(Method::GET, "/chat", Version::V1_1);
    bare.headers = None;
    assert!(websocket::verify_request(&bare).is_err());
}

#[test]
fn refuses_a_response_that_does_not_confirm_the_upgrade() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";

    let mut wrong_status = websocket::handshake_response(key);
    wrong_status.status_code = Some(200);
    assert!(websocket::verify_response(&wrong_status, key).is_err());

    let mismatched = websocket::handshake_response("YW5vdGhlciBub25jZSEh");
    assert!(websocket::verify_response(&mismatched, key).is_err());

    let mut without_upgrade = websocket::handshake_response(key);
    if let Some(headers) = without_upgrade.headers.as_mut() {
        headers.remove("upgrade");
    }
    assert!(websocket::verify_response(&without_upgrade, key).is_err());
}

#[test]
fn an_extended_connect_carries_the_protocol() {
    for version in [Version::V2_0, Version::V3_0] {
        let request = websocket::connect_request("example.test", "/chat", version);

        assert_eq!(request.method, Some(Method::CONNECT));
        assert!(websocket::upgrade_requested(&request));
        assert!(websocket::verify_connect_request(&request).is_ok());
        assert!(websocket::verify_upgrade(&request).is_ok());

        assert!(websocket::verify_connect_response(&websocket::connect_response(version)).is_ok());
    }
}

#[test]
fn refuses_an_extended_connect_that_names_no_protocol() {
    let mut request = Message::request(Method::CONNECT, "/chat", Version::V2_0);
    request.headers = Some(Headers::new());

    assert!(websocket::verify_connect_request(&request).is_err());
    assert!(!websocket::upgrade_requested(&request));

    let mut refused = Message::response(403, Version::V2_0);
    refused.headers = Some(Headers::new());
    assert!(websocket::verify_connect_response(&refused).is_err());
}

#[test]
fn a_token_is_matched_case_insensitively_inside_a_list() {
    let mut headers = Headers::new();
    headers.append("connection", "keep-alive, Upgrade");

    assert!(websocket::token_present(&headers, "connection", "upgrade"));
    assert!(!websocket::token_present(&headers, "connection", "close"));
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
    assert_eq!(pong.1.payload, b"are you there");
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
