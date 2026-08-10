use bytes::BytesMut;

use soyokaze::helpers::compression::Compression;
use soyokaze::helpers::fields::HeaderField;
use soyokaze::helpers::qpack::{self, DecoderInstruction, Encoder, EncoderInstruction};
use soyokaze::models::Limits;
use soyokaze::models::{Body, ConnectionID, Headers, Message, Method, Role, StreamID, Version};
use soyokaze::protocol::h3::{self, Frame, FrameType, H3Connection, H3Session, H3Worker, Settings, StreamKind};
use soyokaze::protocol::quic;
use soyokaze::Error;

fn limits() -> Limits {
    Limits::default()
}

fn id() -> ConnectionID {
    ConnectionID(bytes::Bytes::from_static(b"test"))
}

fn server() -> H3Session {
    let mut session = H3Session::new(Role::Origin, id(), limits());

    let settings = Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");

    session
}

#[test]
fn varints_use_the_shortest_form_that_fits() {
    for (value, length) in [(0u64, 1usize), (63, 1), (64, 2), (16_383, 2), (16_384, 4), (1_073_741_823, 4), (1_073_741_824, 8)] {
        assert_eq!(quic::Varint::len(value), length, "{value} should take {length} octets");

        let mut out = BytesMut::new();
        quic::Varint::encode(&mut out, value);
        assert_eq!(out.len(), length);
        assert_eq!(quic::Varint::decode(&out), (length, value));
    }
}

#[test]
fn varints_match_the_specification_vectors() {
    assert_eq!(quic::Varint::decode(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]), (8, 151_288_809_941_952_652));
    assert_eq!(quic::Varint::decode(&[0x9d, 0x7f, 0x3e, 0x7d]), (4, 494_878_333));
    assert_eq!(quic::Varint::decode(&[0x7b, 0xbd]), (2, 15_293));
    assert_eq!(quic::Varint::decode(&[0x25]), (1, 37));
}

#[test]
fn an_incomplete_varint_consumes_nothing() {
    assert_eq!(quic::Varint::decode(&[]), (0, 0));
    assert_eq!(quic::Varint::decode(&[0x40]), (0, 0), "a two-octet varint needs two octets");
    assert_eq!(quic::Varint::decode(&[0xc0, 0, 0, 0]), (0, 0), "an eight-octet varint needs eight octets");
}

#[test]
fn the_largest_varint_round_trips() {
    let mut out = BytesMut::new();
    quic::Varint::encode(&mut out, quic::Varint::MAXIMUM);
    assert_eq!(quic::Varint::decode(&out), (8, quic::Varint::MAXIMUM));
}

fn parse_one(encoded: &[u8]) -> Option<Frame> {
    let mut buffer = BytesMut::from(encoded);
    h3::Frame::parse(&mut buffer).ok().flatten()
}

#[test]
fn every_frame_round_trips() {
    let frames = [
        Frame::Data(b"hello".to_vec().into()),
        Frame::Data(Vec::new().into()),
        Frame::Headers(vec![0x00, 0x00, 0xd1].into()),
        Frame::CancelPush { push_id: 7 },
        Frame::Settings(vec![(h3::Settings::QPACK_MAX_TABLE_CAPACITY, 4096), (h3::Settings::QPACK_BLOCKED_STREAMS, 0)]),
        Frame::PushPromise { push_id: 1, block: vec![0xd1].into() },
        Frame::GoAway { id: 12 },
        Frame::MaxPushID { push_id: 100 },
    ];

    for frame in frames {
        assert_eq!(parse_one(&frame.encode()).as_ref(), Some(&frame), "{frame:?} did not survive re-encoding");
    }
}

#[test]
fn frame_types_map_to_and_from_their_codes() {
    for kind in [
        FrameType::Data, FrameType::Headers, FrameType::CancelPush,
        FrameType::Settings, FrameType::PushPromise, FrameType::GoAway, FrameType::MaxPushID,
    ] {
        assert_eq!(FrameType::from_code(kind.code()), Some(kind));
    }

    assert_eq!(FrameType::from_code(0x02), None);
    assert_eq!(FrameType::from_code(0x21), None);
}

#[test]
fn a_frame_that_has_not_fully_arrived_is_left_in_the_buffer() {
    let encoded = Frame::Data(b"hello".to_vec().into()).encode();

    for partial in 0..encoded.len() {
        let mut buffer = BytesMut::from(&encoded[..partial]);
        assert_eq!(h3::Frame::parse(&mut buffer).ok().flatten(), None, "{partial} octets should not parse");
        assert_eq!(buffer.len(), partial, "an incomplete frame must stay in the buffer");
    }
}

#[test]
fn an_unknown_frame_type_is_skipped() {
    let mut buffer = BytesMut::new();

    quic::Varint::encode(&mut buffer, 0x21);
    quic::Varint::encode(&mut buffer, 3);
    buffer.extend_from_slice(b"abc");
    buffer.extend_from_slice(&Frame::Data(b"hello".to_vec().into()).encode());

    assert_eq!(h3::Frame::parse(&mut buffer).ok().flatten(), Some(Frame::Data(b"hello".to_vec().into())));
}

#[test]
fn a_reserved_frame_type_is_refused() {
    for code in h3::FrameType::RESERVED {
        let mut buffer = BytesMut::new();
        quic::Varint::encode(&mut buffer, *code);
        quic::Varint::encode(&mut buffer, 0);

        assert!(h3::Frame::parse(&mut buffer).is_err(), "frame type {code:#x} should be refused");
    }
}

#[test]
fn refuses_a_frame_whose_payload_is_not_what_it_claims() {
    for kind in [FrameType::CancelPush, FrameType::MaxPushID, FrameType::GoAway] {
        assert!(Frame::decode(kind, &[]).is_err(), "{kind:?} accepted an empty payload");
        assert!(Frame::decode(kind, &[0x01, 0x02]).is_err(), "{kind:?} accepted two varints");
    }

    assert!(Frame::decode(FrameType::Settings, &[0x01]).is_err());

    assert!(Frame::decode(FrameType::PushPromise, &[]).is_err());
}

#[test]
fn refuses_a_repeated_setting() {
    let mut payload = BytesMut::new();
    quic::Varint::encode(&mut payload, h3::Settings::QPACK_BLOCKED_STREAMS);
    quic::Varint::encode(&mut payload, 0);
    quic::Varint::encode(&mut payload, h3::Settings::QPACK_BLOCKED_STREAMS);
    quic::Varint::encode(&mut payload, 1);

    assert!(Frame::decode(FrameType::Settings, &payload).is_err());
}

#[test]
fn parsing_arbitrary_octets_never_panics() {
    for first in 0..=255u8 {
        for second in 0..=255u8 {
            let mut buffer = BytesMut::from(&[first, second, 0xff, 0x00][..]);
            let _ = h3::Frame::parse(&mut buffer);
        }
    }
}

#[test]
fn settings_carry_the_parameters_that_are_set() {
    let settings = Settings::default();
    let params = settings.parameters();

    assert!(params.iter().any(|(id, _)| *id == h3::Settings::QPACK_MAX_TABLE_CAPACITY));
    assert!(!params.iter().any(|(id, _)| *id == h3::Settings::MAX_FIELD_SECTION_SIZE));

    let bounded = Settings { max_field_section_size: Some(65_536), ..settings };
    assert!(bounded.parameters().iter().any(|(id, value)| (*id, *value) == (h3::Settings::MAX_FIELD_SECTION_SIZE, 65_536)));
}

#[test]
fn refuses_a_reserved_or_out_of_range_setting() {
    let mut settings = Settings::default();

    for id in h3::Settings::RESERVED {
        assert!(settings.apply(*id, 0).is_err(), "setting {id:#x} should be refused");
    }

    assert!(settings.apply(h3::Settings::ENABLE_CONNECT_PROTOCOL, 2).is_err());

    assert!(settings.apply(0x4242, 1).is_ok());
}

#[test]
fn stream_kinds_map_to_and_from_their_codes() {
    for kind in [StreamKind::Control, StreamKind::Push, StreamKind::QPACKEncoder, StreamKind::QPACKDecoder] {
        let code = kind.code().expect("a unidirectional stream kind has a code");
        assert_eq!(StreamKind::from_code(code), Some(kind));
    }

    assert_eq!(StreamKind::Request.code(), None, "a request stream carries no type prefix");
    assert_eq!(StreamKind::from_code(0x21), None);
}

fn section(encoder: &mut Encoder, stream_id: u64, fields: &[HeaderField]) -> (Vec<u8>, Vec<u8>) {
    let block = encoder.encode(stream_id, fields);
    (block, encoder.take_encoder_stream())
}

fn permitted() -> Encoder {
    let mut encoder = Encoder::new();
    encoder.set_max_capacity(qpack::Decoder::DEFAULT_MAX_CAPACITY);
    encoder
}

fn request_fields() -> Vec<HeaderField> {
    vec![
        HeaderField::new(":method", "GET"),
        HeaderField::new(":scheme", "https"),
        HeaderField::new(":authority", "example.test"),
        HeaderField::new(":path", "/index.html"),
    ]
}

#[test]
fn a_request_arrives_on_a_request_stream() {
    let mut session = server();
    let mut encoder = Encoder::new();

    let (block, _) = section(&mut encoder, 0, &request_fields());
    let frame = Frame::Headers(block.into()).encode();

    session.on_stream_bytes(StreamID(0), &frame, true).expect("the request was refused");

    let message = session.take_ready().expect("no request arrived");
    assert_eq!(message.method, Some(Method::GET));
    assert_eq!(message.target.as_deref(), Some("/index.html"));
    assert_eq!(message.stream_id, Some(StreamID(0)));
    assert!(message.security.quic && message.security.secure, "HTTP/3 always runs over a secure transport");
}

#[test]
fn a_finished_exchange_leaves_nothing_behind() {
    let mut session = server();
    let mut encoder = Encoder::new();

    let mut response = Message::response(200, Version::V3_0);
    response.body = Some(Body::Text("hello".to_owned()));

    for index in 0..64u64 {
        let stream = StreamID(index * 4);

        let (block, _) = section(&mut encoder, stream.0, &request_fields());
        session.on_stream_bytes(stream, &Frame::Headers(block.into()).encode(), true).expect("the request was refused");
        session.take_ready().expect("no request arrived");

        let (_, fin) = session.encode_message(stream, &mut response).expect("the response did not encode");
        assert!(fin, "an ordinary response ends its stream");

        session.retire(stream);
    }

    assert!(session.streams.is_empty(), "a connection that answered 64 requests still holds their streams");
    assert!(session.blocked_since.is_empty(), "nothing was ever blocked");
}

#[test]
fn a_stream_is_kept_until_both_directions_have_finished() {
    let mut session = server();
    let mut encoder = Encoder::new();

    let (block, _) = section(&mut encoder, 0, &request_fields());

    session.on_stream_bytes(StreamID(0), &Frame::Headers(block.into()).encode(), false).expect("the request was refused");
    session.retire(StreamID(0));
    assert!(session.streams.contains_key(&StreamID(0)), "the peer has not finished sending");

    session.on_stream_bytes(StreamID(0), &[], true).expect("the end of the request was refused");
    session.take_ready().expect("no request arrived");
    session.retire(StreamID(0));
    assert!(session.streams.contains_key(&StreamID(0)), "no response has gone out");

    let mut response = Message::response(200, Version::V3_0);
    response.body = Some(Body::Text("hello".to_owned()));
    session.encode_message(StreamID(0), &mut response).expect("the response did not encode");

    session.retire(StreamID(0));
    assert!(!session.streams.contains_key(&StreamID(0)), "both directions finished");
}

#[test]
fn a_tunnelled_stream_is_never_retired() {
    let mut session = server();
    let mut encoder = Encoder::new();

    let fields = vec![HeaderField::new(":method", "CONNECT"), HeaderField::new(":authority", "example.test:443")];
    let (block, _) = section(&mut encoder, 0, &fields);
    session.on_stream_bytes(StreamID(0), &Frame::Headers(block.into()).encode(), true).expect("the request was refused");
    session.take_ready().expect("no request arrived");

    let mut response = Message::response(200, Version::V3_0);
    let (_, fin) = session.encode_message(StreamID(0), &mut response).expect("the response did not encode");
    assert!(!fin, "an accepted CONNECT keeps its stream open");

    session.retire(StreamID(0));
    assert!(session.streams.contains_key(&StreamID(0)), "a tunnel outlives the exchange that opened it");
}

#[test]
fn a_body_and_its_trailers_arrive_with_the_request() {
    let mut session = server();
    let mut encoder = Encoder::new();

    let (block, _) = section(&mut encoder, 0, &request_fields());
    let (trailers, _) = section(&mut encoder, 0, &[HeaderField::new("x-checksum", "deadbeef")]);

    let mut stream = BytesMut::new();
    stream.extend_from_slice(&Frame::Headers(block.into()).encode());
    stream.extend_from_slice(&Frame::Data(b"hello".to_vec().into()).encode());
    stream.extend_from_slice(&Frame::Headers(trailers.into()).encode());

    session.on_stream_bytes(StreamID(0), &stream, true).expect("the request was refused");

    let message = session.take_ready().expect("no request arrived");
    assert_eq!(message.body, Some(Body::Data(bytes::Bytes::from_static(b"hello"))));
    assert_eq!(
        message.trailers.as_ref().and_then(|trailers| trailers.get("x-checksum")),
        Some("deadbeef"),
    );
}

#[test]
fn a_stream_delivered_one_octet_at_a_time_still_arrives() {
    let mut session = server();
    let mut encoder = Encoder::new();

    let (block, _) = section(&mut encoder, 0, &request_fields());
    let mut stream = BytesMut::new();
    stream.extend_from_slice(&Frame::Headers(block.into()).encode());
    stream.extend_from_slice(&Frame::Data(b"hello".to_vec().into()).encode());

    for (index, octet) in stream.iter().enumerate() {
        let last = index == stream.len() - 1;
        session.on_stream_bytes(StreamID(0), &[*octet], last).expect("the request was refused");
    }

    let message = session.take_ready().expect("no request arrived");
    assert_eq!(message.body, Some(Body::Data(bytes::Bytes::from_static(b"hello"))));
}

#[test]
fn a_section_that_needs_the_dynamic_table_waits_for_the_encoder_stream() {
    let mut session = server();
    let mut encoder = permitted();

    let mut fields = request_fields();
    fields.push(HeaderField::new("x-custom", "value"));

    let (_, stream) = section(&mut encoder, 0, &fields);
    assert!(!stream.is_empty(), "nothing was inserted into the peer's dynamic table");
    encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement {
        increment: encoder.dynamic_table().inserted_count(),
    });

    let (block, _) = section(&mut encoder, 4, &fields);
    session.on_stream_bytes(StreamID(4), &Frame::Headers(block.into()).encode(), true).expect("the stream was refused");

    assert!(session.take_ready().is_none(), "a blocked section must not be delivered");

    session.on_encoder_bytes(&stream).expect("the encoder instructions were refused");

    assert!(session.take_ready().is_some(), "the section did not unblock once the inserts arrived");
}

#[test]
fn a_response_is_framed_for_its_stream() {
    let mut session = H3Session::new(Role::Origin, id(), limits());

    let mut response = Message::response(200, Version::V3_0);
    response.body = Some(Body::Text("hello".to_owned()));

    let (bytes, fin) = session.encode_message(StreamID(0), &mut response).expect("the response did not encode");
    assert!(fin, "an ordinary response ends its stream");

    let mut buffer = BytesMut::from(&bytes[..]);
    assert!(matches!(h3::Frame::parse(&mut buffer).ok().flatten(), Some(Frame::Headers(_))));
    assert_eq!(h3::Frame::parse(&mut buffer).ok().flatten(), Some(Frame::Data(b"hello".to_vec().into())));
}

#[test]
fn an_open_stream_names_the_next_identifier_of_its_role() {
    let mut client = H3Session::new(Role::UserAgent, id(), limits());
    assert_eq!(client.open(), StreamID(0));
    assert_eq!(client.open(), StreamID(4));

    let mut server = H3Session::new(Role::Origin, id(), limits());
    assert_eq!(server.open(), StreamID(1));
    assert_eq!(server.open(), StreamID(5));
}

#[test]
fn the_peers_settings_open_the_encoders_table() {
    let mut session = H3Session::new(Role::Origin, id(), limits());
    assert!(session.take_encoder_out().is_empty(), "the table was sized before the peer permitted one");

    let settings = Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");

    let update = EncoderInstruction::SetDynamicTableCapacity { capacity: qpack::Decoder::DEFAULT_MAX_CAPACITY };
    let queued = session.take_encoder_out();
    assert!(
        queued.starts_with(&update.encode()),
        "the capacity update must reach the peer before anything is inserted",
    );
}

#[test]
fn settings_that_name_no_table_capacity_leave_the_encoder_shut() {
    let mut session = H3Session::new(Role::Origin, id(), limits());

    let settings = Frame::Settings(vec![(h3::Settings::QPACK_BLOCKED_STREAMS, 16)]).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");

    assert!(session.take_encoder_out().is_empty(), "a silent peer permits no dynamic table");

    let mut response = Message::response(200, Version::V3_0);
    response.headers.get_or_insert_with(Headers::new).insert("x-request-id", "0123456789abcdef");
    session.encode_message(StreamID(0), &mut response).expect("the response did not encode");

    assert!(session.take_encoder_out().is_empty(), "the encoder inserted into a table it was never granted");
}

#[test]
fn refuses_a_second_settings_frame_on_the_control_stream() {
    let mut session = server();

    let settings = Frame::Settings(Settings::default().parameters()).encode();
    assert!(matches!(session.on_control_bytes(&settings), Err(Error::Protocol(_))));
}

#[test]
fn refuses_a_request_frame_on_the_control_stream() {
    let mut session = H3Session::new(Role::Origin, id(), limits());
    let headers = Frame::Headers(vec![0x00, 0x00].into()).encode();

    assert!(matches!(session.on_control_bytes(&headers), Err(Error::Protocol(_))));
}

#[test]
fn refuses_a_control_frame_on_a_request_stream() {
    let mut session = server();
    let settings = Frame::Settings(Vec::new()).encode();

    assert!(matches!(session.on_stream_bytes(StreamID(0), &settings, false), Err(Error::Protocol(_))));
}

#[test]
fn refuses_data_that_arrives_before_a_field_section() {
    let mut session = server();
    let data = Frame::Data(b"hello".to_vec().into()).encode();

    assert!(matches!(session.on_stream_bytes(StreamID(0), &data, false), Err(Error::Protocol(_))));
}

#[test]
fn refuses_a_push_promise_with_push_disabled() {
    let mut session = server();
    let promise = Frame::PushPromise { push_id: 1, block: vec![0xd1].into() }.encode();

    assert!(matches!(session.on_stream_bytes(StreamID(0), &promise, false), Err(Error::Protocol(_))));
}

#[test]
fn refuses_a_stream_that_ends_with_no_field_section() {
    let mut session = server();

    let failure = session.on_stream_bytes(StreamID(0), &[], true);
    assert!(matches!(failure, Err(Error::Stream { code, .. }) if code == h3::Code::REQUEST_INCOMPLETE));
}

#[test]
fn a_field_section_past_the_limit_resets_the_stream() {
    let mut session = H3Session::new(Role::Origin, id(), Limits { max_headers_size: 64, ..limits() });

    let settings = Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");

    let block = Frame::Headers(vec![0u8; 128].into()).encode();
    let failure = session.on_stream_bytes(StreamID(0), &block, false);

    assert!(matches!(failure, Err(Error::Stream { code, .. }) if code == h3::Code::EXCESSIVE_LOAD));
}

#[test]
fn a_body_past_the_limit_resets_the_stream() {
    let mut session = H3Session::new(Role::Origin, id(), Limits { max_message_body_size: 8, ..limits() });

    let settings = Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");

    let mut encoder = Encoder::new();
    let (block, _) = section(&mut encoder, 0, &request_fields());

    let mut stream = BytesMut::new();
    stream.extend_from_slice(&Frame::Headers(block.into()).encode());
    stream.extend_from_slice(&Frame::Data(vec![b'x'; 64].into()).encode());

    let failure = session.on_stream_bytes(StreamID(0), &stream, false);
    assert!(matches!(failure, Err(Error::Stream { code, .. }) if code == h3::Code::EXCESSIVE_LOAD));
}

#[test]
fn an_oversized_encoder_stream_is_refused() {
    let mut session = H3Session::new(Role::Origin, id(), Limits { max_headers_size: 32, ..limits() });

    let mut partial = Vec::new();
    partial.push(0x42);
    partial.extend_from_slice(&[b'a'; 128]);

    assert!(matches!(session.on_encoder_bytes(&partial), Err(Error::Limit(_))));
}

#[test]
fn a_connect_request_is_delivered_as_a_raw_stream() {
    let mut session = server();
    let mut encoder = Encoder::new();

    let fields = [
        HeaderField::new(":method", "CONNECT"),
        HeaderField::new(":authority", "example.test:443"),
    ];

    let (block, _) = section(&mut encoder, 0, &fields);
    session.on_stream_bytes(StreamID(0), &Frame::Headers(block.into()).encode(), false).expect("the CONNECT was refused");

    let message = session.take_ready().expect("no request arrived");
    assert_eq!(message.method, Some(Method::CONNECT));

    session.on_stream_bytes(StreamID(0), b"not a frame at all", false).expect("tunnelled octets were parsed as frames");
}

#[test]
fn the_control_frame_advertises_the_local_settings() {
    let session = H3Session::new(Role::Origin, id(), limits());

    let mut buffer = BytesMut::from(&session.control_frame()[..]);
    let frame = h3::Frame::parse(&mut buffer).ok().flatten().expect("the control frame did not parse");

    let Frame::Settings(params) = frame else {
        panic!("the control stream must open with SETTINGS");
    };

    assert!(params.iter().any(|(id, _)| *id == h3::Settings::QPACK_MAX_TABLE_CAPACITY));
}

#[test]
fn the_number_of_tracked_streams_has_a_ceiling() {
    let mut session = server();
    let ceiling = session.stream_ceiling();

    let mut refused = None;
    for index in 0..(ceiling as u64 + 8) {
        if let Err(error) = session.on_stream_bytes(StreamID(index * 4), b"\x01", false) {
            refused = Some(error);
            break;
        }
    }

    assert!(refused.is_some(), "a peer opened streams without ever meeting a limit");
    assert!(session.streams.len() <= ceiling, "{} streams are tracked at once", session.streams.len());
}

#[test]
fn a_forgotten_stream_releases_its_qpack_sections() {
    let mut session = server();
    let stream = StreamID(0);

    session.encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment: 32 });

    let mut response = Message::response(200, Version::V3_0);
    response.headers.get_or_insert_with(Headers::new).append("x-trace", "abc");

    session.encode_message(stream, &mut response).expect("the response did not encode");
    session.encode_message(stream, &mut response).expect("the second response did not encode");

    assert!(session.encoder.outstanding() > 0, "nothing referenced the dynamic table");

    session.forget(stream);
    assert_eq!(session.encoder.outstanding(), 0, "a stream that is gone left its sections behind");
}

fn worker() -> H3Worker {
    let (_connection, worker) = H3Connection::pair(server());
    worker
}

/// A transport that takes every write and delivers nothing, for driving a
/// worker without a QUIC connection underneath.
struct NullTransport;

impl quic::QUICTransport for NullTransport {
    fn send(&mut self, _stream_id: u64, data: &[u8], _fin: bool) -> Result<quic::StreamWrite, Error> {
        Ok(quic::StreamWrite::Sent(data.len()))
    }

    fn receive(&mut self, _stream_id: u64, _out: &mut [u8]) -> Result<quic::StreamRead, Error> {
        Ok(quic::StreamRead::Done)
    }

    fn shutdown_read(&mut self, _stream_id: u64, _code: u64) -> Result<(), Error> {
        Ok(())
    }

    fn shutdown_write(&mut self, _stream_id: u64, _code: u64) -> Result<(), Error> {
        Ok(())
    }

    fn readable(&self) -> impl Iterator<Item = u64> {
        std::iter::empty()
    }

    fn close(&mut self, _code: u64, _reason: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn application_protocol(&self) -> &[u8] {
        b"h3"
    }

    fn version(&self) -> u32 {
        1
    }
}

#[test]
fn a_finished_unidirectional_stream_is_forgotten() {
    let mut worker = worker();

    for index in 0..1024u64 {
        worker.feed_uni(&mut NullTransport, index * 4 + 3, &[0x21], true).expect("a greased stream type was refused");
    }

    assert!(worker.peer_uni.is_empty(), "{} finished streams are still remembered", worker.peer_uni.len());
}

#[test]
fn open_unidirectional_streams_have_a_ceiling() {
    let mut worker = worker();

    let ceiling = worker.session.limits.max_peer_uni_streams as usize;

    let mut refused = None;
    for index in 0..(ceiling as u64 + 8) {
        if let Err(error) = worker.feed_uni(&mut NullTransport, index * 4 + 3, &[0x21], false) {
            refused = Some(error);
            break;
        }
    }

    assert!(refused.is_some(), "a peer opened unidirectional streams without ever meeting a limit");
    assert!(worker.peer_uni.len() <= ceiling, "{} streams are tracked", worker.peer_uni.len());
}

#[test]
fn a_stream_type_that_dribbles_in_is_never_buffered_beyond_a_varint() {
    let mut worker = worker();

    for _ in 0..64 {
        worker.feed_uni(&mut NullTransport, 3, &[0xff], false).expect("a dribbled stream type was refused");

        let held = worker.peer_uni.get(&3).map_or(0, |uni| uni.prefix.len());
        assert!(held <= quic::Varint::MAX_SIZE, "{held} octets are held while a stream type is awaited");
    }
}

#[test]
fn a_frame_that_never_completes_is_not_buffered_without_limit() {
    let ceiling = 8 * 1024u64;
    let mut session = H3Session::new(Role::Origin, id(), Limits { max_message_size: ceiling, ..limits() });

    let mut head = BytesMut::new();
    quic::Varint::encode(&mut head, FrameType::Data.code());
    quic::Varint::encode(&mut head, 1 << 30);
    session.on_stream_bytes(StreamID(0), &head, false).expect("the frame head was refused");

    let chunk = vec![0u8; 512];
    let mut refused = None;

    for _ in 0..((ceiling as usize / 512) * 4) {
        if let Err(error) = session.on_stream_bytes(StreamID(0), &chunk, false) {
            refused = Some(error);
            break;
        }
    }

    let refused = refused.expect("a frame that never completes was buffered without limit");
    assert!(matches!(refused, Error::Stream { .. }), "the stream was not the one refused: {refused:?}");
}

#[test]
fn a_tunnel_nobody_claims_is_not_buffered_without_limit() {
    let ceiling = 8 * 1024u64;
    let mut session = H3Session::new(Role::Origin, id(), Limits { max_message_size: ceiling, ..limits() });
    session.on_control_bytes(&Frame::Settings(Settings::default().parameters()).encode()).expect("the peer settings were refused");

    let mut encoder = Encoder::new();
    let fields = vec![
        HeaderField::new(":method", "CONNECT"),
        HeaderField::new(":protocol", "websocket"),
        HeaderField::new(":scheme", "https"),
        HeaderField::new(":path", "/chat"),
        HeaderField::new(":authority", "example.test"),
    ];

    let (block, _) = section(&mut encoder, 0, &fields);
    session.on_stream_bytes(StreamID(0), &Frame::Headers(block.into()).encode(), false).expect("the CONNECT was refused");
    session.take_ready().expect("no request arrived");

    let chunk = vec![0u8; 512];
    let mut refused = None;

    for _ in 0..((ceiling as usize / 512) * 4) {
        if let Err(error) = session.on_stream_bytes(StreamID(0), &chunk, false) {
            refused = Some(error);
            break;
        }
    }

    assert!(refused.is_some(), "an unclaimed tunnel buffered octets without limit");
}

#[test]
fn unread_data_is_bounded_across_every_stream_together() {
    let ceiling = 4 * 1024u64;

    let mut bounded = limits();
    bounded.max_connection_buffer_size = ceiling;

    let mut session = H3Session::new(Role::Origin, id(), bounded);
    let settings = Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");

    let mut chunk = BytesMut::new();
    quic::Varint::encode(&mut chunk, FrameType::Data.code());
    quic::Varint::encode(&mut chunk, 1 << 20);
    chunk.extend_from_slice(&[0u8; 512]);

    let mut streams = 0u64;

    loop {
        let held = session.buffered();
        let outcome = session.on_stream_bytes(StreamID(streams * 4), &chunk, false);
        let after = held + chunk.len() as u64;

        if after <= ceiling {
            outcome.unwrap_or_else(|error| panic!("{after} octets were refused below the {ceiling} ceiling: {error:?}"));
            assert_eq!(session.buffered(), after, "the connection lost track of what it is holding");
            streams += 1;
            continue;
        }

        let error = outcome.expect_err(&format!("{after} octets passed the {ceiling} ceiling"));
        assert!(matches!(error, Error::Limit(_)), "the ceiling refused with {error:?}");
        break;
    }

    assert!(streams > 1, "the ceiling should be reached across several streams, not one");
}

#[test]
fn the_encoder_table_is_held_to_this_ends_own_ceiling() {
    // RFC 9204 §3.2.3: the encoder sets its capacity to at most what the peer
    // permits. Limits::max_encoder_table_size is this end's own ceiling on top
    // of that, and it must apply here exactly as it applies to HPACK.
    let capped = Limits { max_encoder_table_size: 512, ..limits() };
    let mut session = H3Session::new(Role::Origin, id(), capped);

    let permitted = 64 * 1024;
    let settings = Frame::Settings(vec![(h3::Settings::QPACK_MAX_TABLE_CAPACITY, permitted)]).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");

    let update = EncoderInstruction::SetDynamicTableCapacity { capacity: 512 };
    assert!(
        session.take_encoder_out().starts_with(&update.encode()),
        "the encoder announced a capacity above the one it was configured to keep",
    );

    // A peer that permits less than the ceiling still wins: the capacity is the
    // smaller of the two, never the larger.
    let mut modest = H3Session::new(Role::Origin, id(), capped);
    let settings = Frame::Settings(vec![(h3::Settings::QPACK_MAX_TABLE_CAPACITY, 128)]).encode();
    modest.on_control_bytes(&settings).expect("the peer settings were refused");

    let update = EncoderInstruction::SetDynamicTableCapacity { capacity: 128 };
    assert!(
        modest.take_encoder_out().starts_with(&update.encode()),
        "the encoder must not keep more than the peer permits",
    );
}

#[test]
fn a_connection_reports_the_settings_it_advertised() {
    let session = H3Session::new(Role::Origin, id(), Limits { max_blocked_streams: 7, ..limits() });
    let advertised = session.settings_local;
    let (connection, _worker) = H3Connection::pair(session);

    assert_eq!(*connection.settings_local(), advertised, "the handle must report what its session advertised");
    assert_eq!(connection.settings_local().qpack_blocked_streams, 7, "the advertised blocked-stream ceiling did not follow the limits");
}

#[test]
fn goaway_on_the_control_stream_is_recorded_and_never_grows() {
    let mut session = server();
    assert_eq!(session.goaway, None, "no GOAWAY has arrived yet");

    session.on_control_bytes(&Frame::GoAway { id: 64 }.encode()).expect("GOAWAY was refused");
    assert_eq!(session.goaway, Some(64));

    // RFC 9114 §5.2: an endpoint may send several GOAWAYs with shrinking
    // identifiers, and the identifier must not grow again.
    session.on_control_bytes(&Frame::GoAway { id: 32 }.encode()).expect("a shrinking GOAWAY was refused");
    assert_eq!(session.goaway, Some(32));

    session.on_control_bytes(&Frame::GoAway { id: 128 }.encode()).expect("a growing GOAWAY need not fail the connection");
    assert_eq!(session.goaway, Some(32), "a growing identifier must not widen what the peer already gave up");
}

#[test]
fn request_streams_are_counted_once_over_the_connections_lifetime() {
    let mut session = server();
    let mut encoder = Encoder::new();

    let (block, _) = section(&mut encoder, 0, &request_fields());
    let frame = Frame::Headers(block.into()).encode();

    session.on_stream_bytes(StreamID(0), &frame[..1], false).expect("the first octet was refused");
    session.on_stream_bytes(StreamID(0), &frame[1..], true).expect("the rest of the request was refused");
    session.take_ready().expect("no request arrived");

    assert_eq!(session.total_streams, 1, "several reads of one stream must count it once");
    assert_eq!(session.highest_peer_stream_id, 0);

    let (block, _) = section(&mut encoder, 4, &request_fields());
    session.on_stream_bytes(StreamID(4), &Frame::Headers(block.into()).encode(), true).expect("the second request was refused");
    session.take_ready().expect("no second request arrived");

    assert_eq!(session.total_streams, 2, "the count is the connection's lifetime total");
    assert_eq!(session.highest_peer_stream_id, 4);
}

/// The address the fixtures pretend a peer dialled from.
fn peer() -> std::net::SocketAddr {
    "203.0.113.7:54321".parse().expect("the fixture address did not parse")
}

fn payload() -> bytes::Bytes {
    bytes::Bytes::from(vec![b'a'; 8192])
}

/// A server session that has already taken a request accepting `accept`.
fn asked(accept: Option<&str>) -> H3Session {
    let mut session = server().with_client(Some(peer()));
    let mut encoder = Encoder::new();

    let mut fields = request_fields();
    if let Some(accept) = accept {
        fields.push(HeaderField::new("accept-encoding", accept));
    }

    let (block, _) = section(&mut encoder, 0, &fields);
    session.on_stream_bytes(StreamID(0), &Frame::Headers(block.into()).encode(), true).expect("the request was refused");
    session.take_ready().expect("no request arrived");

    session
}

/// Frames a response coded as `compression` asks, and returns what it settled on.
fn answered(accept: Option<&str>, compression: Option<Compression>) -> (Message, BytesMut) {
    let mut session = asked(accept);

    let mut response = Message::response(200, Version::V3_0);
    response.body = Some(Body::Data(payload()));
    response.compression = compression;

    let mut out = BytesMut::new();
    session.encode_message_into(StreamID(0), &mut response, &mut out).expect("the response did not encode");

    (response, out)
}

/// RFC 9110 §12.5.3: a server codes a response in something the request said it
/// would take, and in nothing else.
#[test]
fn a_server_compresses_a_response_in_the_coding_the_request_accepted() {
    for (accept, expected) in [("gzip", Compression::Gzip), ("br, gzip", Compression::Brotli), ("*", Compression::Zstd)] {
        let (response, wire) = answered(Some(accept), Some(Compression::Auto));

        assert_eq!(response.compression, Some(expected), "{accept:?} must be answered with {expected}");
        assert!(response.compressed(), "the response that goes out names its coding");
        assert!(wire.len() < 8192, "{accept:?} framed {} octets, which is the identity body", wire.len());

        let encoded = response.body.as_ref().and_then(Body::inline).expect("the body went missing");
        assert_eq!(expected.decode(&encoded, 1 << 20).as_deref(), Ok(&payload()[..]));
    }
}

#[test]
fn a_server_sends_the_body_as_it_stands_when_the_request_accepted_nothing() {
    for accept in [None, Some("identity"), Some("*;q=0")] {
        let (response, _) = answered(accept, Some(Compression::Auto));

        assert_eq!(response.compression, None, "{accept:?} permits no coding");
        assert!(!response.compressed());
        assert_eq!(response.body, Some(Body::Data(payload())));
    }
}

#[test]
fn an_explicit_coding_is_applied_whatever_the_peer_accepts() {
    let (response, _) = answered(Some("gzip"), Some(Compression::Brotli));

    assert_eq!(response.compression, Some(Compression::Brotli), "a caller that named a coding gets it");
    assert_eq!(response.headers.as_ref().and_then(|headers| headers.get("content-encoding")), Some("br"));
}

/// RFC 9110 §12.5.5: a response that varies on Accept-Encoding must say so.
#[test]
fn a_response_coded_from_accept_encoding_carries_vary() {
    let (response, _) = answered(Some("zstd"), Some(Compression::Auto));

    assert_eq!(response.headers.as_ref().and_then(|headers| headers.get("vary")), Some("Accept-Encoding"));
}

#[test]
fn a_received_request_carries_the_address_it_came_from() {
    let mut session = server().with_client(Some(peer()));
    let mut encoder = Encoder::new();

    let (block, _) = section(&mut encoder, 0, &request_fields());
    session.on_stream_bytes(StreamID(0), &Frame::Headers(block.into()).encode(), true).expect("the request was refused");

    let message = session.take_ready().expect("no request arrived");
    assert_eq!(message.client, Some(peer()), "a server must be told where the request came from");

    let (connection, _worker) = H3Connection::pair(server().with_client(Some(peer())));
    assert_eq!(connection.client, Some(peer()), "the handle must report what its session was told");

    let (bare, _worker) = H3Connection::pair(server());
    assert_eq!(bare.client, None, "a connection told no address reports none");
}

/// A message only reaches the caller through the handle, which is where the
/// content coding comes off it.
#[tokio::test]
async fn a_received_body_arrives_decoded_with_no_content_encoding_left() {
    let (mut connection, mut worker) = H3Connection::pair(server());
    let mut encoder = Encoder::new();

    let coded = Compression::Gzip.encode(&payload()).expect("the fixture did not encode");

    let mut fields = request_fields();
    fields.push(HeaderField::new("content-encoding", "gzip"));
    fields.push(HeaderField::new("content-length", coded.len().to_string()));

    let (block, _) = section(&mut encoder, 0, &fields);
    let mut wire = Frame::Headers(block.into()).encode().to_vec();
    wire.extend_from_slice(&Frame::Data(coded.to_vec().into()).encode());

    worker.session.on_stream_bytes(StreamID(0), &wire, true).expect("the request was refused");
    worker.deliver_ready();

    let message = connection.receive_message().await.expect("the request did not arrive");

    assert_eq!(message.compression, Some(Compression::Gzip), "the handle must say what came off the body");
    assert!(!message.compressed(), "a decoded body must carry no Content-Encoding");
    assert_eq!(message.body, Some(Body::Data(payload())));
    assert_eq!(message.headers.as_ref().and_then(|headers| headers.get("content-length")), Some("8192"));
}

#[tokio::test]
async fn a_received_body_past_the_decoded_ceiling_is_refused() {
    let ceiling = Limits { max_decompressed_body_size: 1024, ..limits() };
    let mut session = H3Session::new(Role::Origin, id(), ceiling);
    session.on_control_bytes(&Frame::Settings(Settings::default().parameters()).encode()).expect("the peer settings were refused");

    let (mut connection, mut worker) = H3Connection::pair(session);
    let mut encoder = Encoder::new();

    let bomb = Compression::Gzip.encode(&vec![0u8; 1024 * 1024]).expect("the fixture did not encode");

    let mut fields = request_fields();
    fields.push(HeaderField::new("content-encoding", "gzip"));

    let (block, _) = section(&mut encoder, 0, &fields);
    let mut wire = Frame::Headers(block.into()).encode().to_vec();
    wire.extend_from_slice(&Frame::Data(bomb.to_vec().into()).encode());

    worker.session.on_stream_bytes(StreamID(0), &wire, true).expect("the request was refused");
    worker.deliver_ready();

    let failure = connection.receive_message().await.expect_err("a body past the ceiling was accepted");
    assert!(matches!(failure, Error::Limit(_)), "a body past the ceiling must be a limit failure, not {failure}");
}

/// A client cannot know what an origin decodes, so `Auto` on a request sends
/// the body as it stands; a coding the caller named is applied all the same.
#[test]
fn auto_never_compresses_a_client_request() {
    let mut session = H3Session::new(Role::UserAgent, id(), limits());

    let mut automatic = Message::request(Method::POST, "/submit", Version::V3_0);
    automatic.headers = Some(Headers::new());
    automatic.body = Some(Body::Data(payload()));
    automatic.compression = Some(Compression::Auto);

    session.encode_message(StreamID(0), &mut automatic).expect("the request did not encode");
    assert_eq!(automatic.compression, None, "a client has nothing to settle Auto against");
    assert_eq!(automatic.body, Some(Body::Data(payload())));

    let mut named = Message::request(Method::POST, "/submit", Version::V3_0);
    named.headers = Some(Headers::new());
    named.body = Some(Body::Data(payload()));
    named.compression = Some(Compression::Zstd);

    session.encode_message(StreamID(4), &mut named).expect("the request did not encode");
    assert_eq!(named.compression, Some(Compression::Zstd), "a request coding the caller named is applied");
}

// ---------------------------------------------------------------- conformance

fn requested(session: &mut H3Session, stream_id: StreamID, method: &str) {
    let mut encoder = Encoder::new();
    let fields = vec![
        HeaderField::new(":method", method),
        HeaderField::new(":scheme", "https"),
        HeaderField::new(":authority", "example.test"),
        HeaderField::new(":path", "/"),
    ];

    let block = encoder.encode(stream_id.0, &fields);
    session.on_stream_bytes(stream_id, &Frame::Headers(block.into()).encode(), true).expect("the request was refused");
}

fn framed(method: &str, status_code: u16, attach: impl FnOnce(&mut Message)) -> BytesMut {
    let mut session = server();
    let stream_id = StreamID(0);
    requested(&mut session, stream_id, method);

    let mut response = Message::response(status_code, Version::V3_0);
    response.stream_id = Some(stream_id);
    attach(&mut response);

    let mut out = BytesMut::new();
    session.encode_message_into(stream_id, &mut response, &mut out).expect("the response did not frame");
    out
}

#[test]
fn a_message_that_ends_at_its_field_section_frames_no_data() {
    for (method, status_code) in [("GET", 204u16), ("GET", 304), ("HEAD", 200)] {
        let wire = framed(method, status_code, |response| {
            response.body = Some(Body::Data(bytes::Bytes::from_static(b"UNFRAMED-CONTENT")));
        });

        assert!(
            !wire.windows(16).any(|window| window == b"UNFRAMED-CONTENT"),
            "a {status_code} answering {method} carries no content, so no DATA frame may go out"
        );
    }
}

#[test]
fn a_message_that_ends_at_its_field_section_frames_no_trailers() {
    let wire = framed("HEAD", 200, |response| {
        let mut trailers = Headers::new();
        trailers.append("x-trailer", "UNFRAMED-TRAILER");
        response.trailers = Some(trailers);
    });

    assert!(
        !wire.windows(16).any(|window| window == b"UNFRAMED-TRAILER"),
        "RFC 9112 6.3: a response to HEAD carries no trailer section either"
    );
}

#[test]
fn a_trailer_section_may_not_frame_or_route_the_message() {
    for (name, value) in [("content-length", "0"), ("transfer-encoding", "chunked"), ("host", "elsewhere.test"), ("te", "trailers")] {
        let mut session = server();
        let stream_id = StreamID(0);
        requested(&mut session, stream_id, "POST");

        let refused = session.absorb_headers(stream_id, vec![HeaderField::new(name, value)]);
        assert!(
            refused.is_err(),
            "RFC 9110 6.5.1: {name:?} arrives after the message has been framed and routed, so it may not appear in a trailer"
        );
    }
}

#[test]
fn a_field_a_binary_version_may_not_carry_is_refused() {
    for (name, value) in [("x-evil", "a\r\nInjected: yes"), ("bad name", "v"), ("", "v"), ("x", "\0nul"), ("x", " leading")] {
        let mut session = server();

        let fields = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":path", "/"),
            HeaderField::new(name, value),
        ];

        assert!(
            session.absorb_headers(StreamID(0), fields).is_err(),
            "RFC 9114 4.2: a field of {name:?}: {value:?} is malformed and must be refused"
        );
    }
}

#[test]
fn a_path_that_would_write_a_second_request_line_is_refused() {
    let mut session = server();

    let fields = vec![
        HeaderField::new(":method", "GET"),
        HeaderField::new(":scheme", "https"),
        HeaderField::new(":path", "/x HTTP/1.1\r\nX-Smuggled: 1\r\n\r\nGET /admin"),
    ];

    assert!(
        session.absorb_headers(StreamID(0), fields).is_err(),
        "a path carrying a space or a CRLF would frame a request of its own if this message were forwarded over HTTP/1.1"
    );
}

#[test]
fn only_the_commands_that_frame_octets_wait_for_room() {
    use soyokaze::protocol::h3::H3Command;

    assert!(H3Command::Send(Message::response(200, Version::V3_0)).buffers());
    assert!(H3Command::WriteEncoder(bytes::Bytes::from_static(b"x")).buffers());

    assert!(
        !H3Command::Reset(StreamID(0), h3::Code::REQUEST_CANCELLED).buffers(),
        "a reset frees room, so holding it back would leave a stalled connection no way out"
    );
    assert!(!H3Command::Close.buffers(), "and neither may a close be held back");
}
