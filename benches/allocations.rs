//! How many times a request reaches the allocator.
//!
//! A separate binary because it installs a counting global allocator, and
//! counting on every allocation would bias every timing taken alongside it.
//! What is counted is how many times the allocator was asked for something,
//! not for how much: the count is what does not shrink when a body does, and
//! it is what a per-request cost is really made of.
//!
//! The first tenth of each case's rounds runs uncounted, so what is reported is
//! the steady-state cost rather than the tables, buffers and caches a
//! connection grows once and then reuses.
//!
//! ```bash
//! cargo bench --bench allocations
//! ```

mod support;

use bytes::{Bytes, BytesMut};

use soyokaze::helpers::hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder};
use soyokaze::helpers::qpack::{Decoder as QpackDecoder, Encoder as QpackEncoder};
use soyokaze::models::{Body, ConnectionID, HeaderCase, Limits, Message, Role, StreamID, Version};
use soyokaze::protocol::common;
use soyokaze::protocol::h1;
use soyokaze::protocol::h3::{Frame as H3Frame, H3Session, Settings};
use soyokaze::websocket::{Frame as WsFrame, Opcode};

use support::{Counter, Group, Payload, Section, Wire};

#[global_allocator]
static ALLOCATOR: Counter = Counter;

/// How many rounds each case is counted over.
const ROUNDS: u64 = 512;

fn id() -> ConnectionID {
    ConnectionID(Bytes::from_static(b"bench"))
}

fn session(role: Role) -> H3Session {
    let mut session = H3Session::new(role, id(), Limits::default());
    let settings = H3Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");
    session
}

fn response() -> Message {
    let mut response = Section::response().message(Version::V3_0);
    response.body = Some(Body::Data(Payload::of(13)));
    response
}

/// A request as it arrives on an HTTP/3 stream.
fn wire_request(peer: &mut H3Session, stream_id: u64) -> Bytes {
    let block = peer.encoder.encode(stream_id, &Section::request().fields);

    let mut out = BytesMut::with_capacity(block.len() + 8);
    H3Frame::Headers(block.into()).encode_into(&mut out);
    out.freeze()
}

fn field_codecs() {
    let mut group = Group::new("field codec allocations");
    let section = Section::request();

    let mut encoder = HpackEncoder::new();
    group.allocations("hpack::Encoder::encode (warm table)", ROUNDS, |_| encoder.encode(&section.fields));

    let mut encoder = HpackEncoder::new();
    let first = encoder.encode(&section.fields);
    let block = encoder.encode(&section.fields);

    let mut decoder = HpackDecoder::new();
    let _ = decoder.decode(&first);

    group.allocations("hpack::Decoder::decode (warm table)", ROUNDS, |_| decoder.decode(&block));

    let mut encoder = QpackEncoder::new();
    encoder.set_max_capacity(QpackDecoder::DEFAULT_MAX_CAPACITY);
    let mut decoder = QpackDecoder::new();

    let block = encoder.encode(0, &section.fields);
    let stream = encoder.take_encoder_stream();
    decoder.on_encoder_stream(&stream).expect("the encoder stream was refused");
    let _ = decoder.decode(0, &block);

    group.allocations("qpack::Encoder::encode (warm table)", ROUNDS, |round| encoder.encode(round * 4, &section.fields));

    let block = encoder.encode(4, &section.fields);
    group.allocations("qpack::Decoder::decode (warm table)", ROUNDS, |round| decoder.decode(round * 4 + 8, &block));
}

fn message_framing() {
    let mut group = Group::new("message framing allocations");
    let section = Section::request();
    let block = Wire::block(&section);
    let headers = section.headers();

    group.allocations("h1::Field::parse_block (8 fields)", ROUNDS, |_| h1::Field::parse_block(&block, 100));
    group.allocations("h1::Field::write_all (8 fields)", ROUNDS, |_| {
        let mut out = BytesMut::with_capacity(512);
        let _ = h1::Field::write_all(&headers, HeaderCase::Title, &mut out);
        out
    });

    let request = section.message(Version::V2_0);
    let fields = common::Fields::of(&request).expect("the fixture request did not frame");

    group.allocations("common::Fields::of (a request)", ROUNDS, |_| common::Fields::of(&request));
    group.allocations("common::Fields::message (a request)", ROUNDS, |_| common::Fields::message(&fields, Version::V2_0));

    let mut frame = WsFrame::new(Opcode::Binary, Payload::of(4096));
    frame.mask = Some([0xde, 0xad, 0xbe, 0xef]);
    let encoded = frame.encode();

    group.allocations("websocket::Frame::encode (4 KiB)", ROUNDS, |_| frame.encode());
    group.allocations("websocket::Frame::decode (4 KiB)", ROUNDS, |_| WsFrame::decode(&encoded));
}

fn http3_cycle() {
    let mut group = Group::new("http/3 request cycle allocations");
    let response = response();

    let mut peer = session(Role::UserAgent);
    let mut server = session(Role::Origin);
    let mut outbound = BytesMut::with_capacity(4096);

    group.allocations("into a send buffer of its own", ROUNDS, |round| {
        let stream = StreamID(round * 4);
        let wire = wire_request(&mut peer, stream.0);

        server.on_stream_bytes(stream, &wire, true).expect("the request did not parse");
        std::hint::black_box(server.take_ready().expect("the request never completed"));

        server.encode_message_into(stream, &response, &mut outbound).expect("the response did not encode");
        outbound.clear();
        server.retire(stream);
    });

    let mut peer = session(Role::UserAgent);
    let mut server = session(Role::Origin);
    let mut outbound = BytesMut::with_capacity(4096);

    group.allocations("through a shared handle", ROUNDS, |round| {
        let stream = StreamID(round * 4);
        let wire = wire_request(&mut peer, stream.0);

        server.on_stream_bytes(stream, &wire, true).expect("the request did not parse");
        std::hint::black_box(server.take_ready().expect("the request never completed"));

        let (bytes, _) = server.encode_message(stream, &response).expect("the response did not encode");
        outbound.extend_from_slice(&bytes);
        outbound.clear();
        server.retire(stream);
    });
}

fn main() {
    assert!(Counter::installed(), "the counting allocator was not installed");

    field_codecs();
    message_framing();
    http3_cycle();
}
