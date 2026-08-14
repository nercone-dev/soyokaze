//! What a request costs the allocator.
//!
//! A separate binary because it installs a counting global allocator, and
//! counting on every allocation would bias every timing taken alongside it.
//!
//! Two numbers per case, because they move separately. `calls` is how many
//! times the allocator was reached for, which is the part that does not shrink
//! when a body does and is what a per-request cost is really made of. `octets`
//! is how much was asked for, which is what a body's size lands in. A buffer
//! grown once instead of four times moves the first and not the second; a body
//! held twice over moves the second and not the first.
//!
//! Both are counted rather than timed, so they are exact: two runs of the same
//! code report the same number, and a change of one allocation is visible
//! where a timing would have buried it in noise. This is the measurement to
//! reach for when a timing is too noisy to settle an argument.
//!
//! The first tenth of each case's rounds runs uncounted, so what is reported is
//! the steady-state cost rather than the tables, buffers and caches a
//! connection grows once and then reuses.
//!
//! ```bash
//! cargo bench --bench allocations
//! cargo bench --bench allocations -- "request cycle"
//! ```

mod support;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use soyokaze::cookies::{Cookie, SetCookie};
use soyokaze::helpers::compression::Compression;
use soyokaze::helpers::hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder};
use soyokaze::helpers::qpack::{Decoder as QpackDecoder, Encoder as QpackEncoder};
use soyokaze::helpers::text::Text;
use soyokaze::helpers::{base64, huffman};
use soyokaze::models::{Body, ConnectionID, HeaderCase, Headers, Limits, Message, Method, Role, StreamID, URL, Version};
use soyokaze::protocol::base::Connection;
use soyokaze::protocol::common;
use soyokaze::protocol::h1::{self, H1Connection};
use soyokaze::protocol::h2::H2Connection;
use soyokaze::protocol::h3::{Frame as H3Frame, H3Session, Settings};
use soyokaze::websocket::{Frame as WsFrame, Opcode};

use support::{Counter, Group, Payload, Section, Wire};

#[global_allocator]
static ALLOCATOR: Counter = Counter;

/// How many rounds each case is counted over.
const ROUNDS: u64 = 512;

/// How many rounds a case that crosses a whole connection is counted over.
///
/// Fewer, because each round is a whole exchange rather than one call, and the
/// count is exact enough that the rounds are there to average a runtime's
/// bookkeeping rather than any noise of the measurement.
const CYCLES: u64 = 128;

fn id() -> ConnectionID {
    ConnectionID(Bytes::from_static(b"bench"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("no runtime")
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

/// The vocabulary every request is held in.
///
/// None of these is expensive on its own, and every one of them is on the path
/// of every request, so the count here is multiplied by everything above it.
fn vocabulary() {
    let mut group = Group::new("vocabulary allocations");
    let section = Section::request();
    let headers = section.headers();

    group.footprint("Message::request", ROUNDS, |_| Message::request(Method::GET, "/assets/app.7f3c9a2b.module.js", Version::V1_1));
    group.footprint("Message::response", ROUNDS, |_| Message::response(200, Version::V1_1));
    group.footprint("Message::text (13 B)", ROUNDS, |_| Message::text("Hello, World!", Version::V1_1));

    group.footprint("Headers::append (8 fields)", ROUNDS, |_| {
        let mut held = Headers::with_capacity(8);
        for (name, value) in headers.iter() {
            held.append(name, value);
        }
        held
    });

    group.footprint("Headers::clone (8 fields)", ROUNDS, |_| headers.clone());
    group.footprint("Headers::get (a well-known name)", ROUNDS, |_| headers.get("user-agent").map(str::len));

    group.footprint("URL::parse", ROUNDS, |_| URL::parse("https://www.example.com/assets/app.7f3c9a2b.module.js?v=3"));
    group.footprint("Text::from_str (inline, 12 B)", ROUNDS, |_| Text::from_str("content-type"));
    group.footprint("Text::from_str (heap, 96 B)", ROUNDS, |_| Text::from_str(&"content-type".repeat(8)));

    group.footprint("Cookie::parse (4 pairs)", ROUNDS, |_| {
        Cookie::parse("session=8f14e45fceea167a5a36dedd4bea2543; consent=1; locale=en-GB; theme=dark")
    });
    group.footprint("SetCookie::parse (every attribute)", ROUNDS, |_| {
        SetCookie::parse("session=8f14e45fceea167a5a36dedd4bea2543; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax")
    });
}

fn field_codecs() {
    let mut group = Group::new("field codec allocations");
    let section = Section::request();

    group.footprint("huffman::encode (30 B)", ROUNDS, |_| huffman::encode(b"/assets/app.7f3c9a2b.module.js"));

    let encoded = huffman::encode(b"/assets/app.7f3c9a2b.module.js");
    group.footprint("huffman::decode (30 B)", ROUNDS, |_| huffman::decode(&encoded));

    group.footprint("base64::encode (60 B)", ROUNDS, |_| base64::encode(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));

    let mut encoder = HpackEncoder::new();
    group.footprint("hpack::Encoder::encode (warm table)", ROUNDS, |_| encoder.encode(&section.fields));

    let mut encoder = HpackEncoder::new();
    let first = encoder.encode(&section.fields);
    let block = encoder.encode(&section.fields);

    let mut decoder = HpackDecoder::new();
    let _ = decoder.decode(&first);

    group.footprint("hpack::Decoder::decode (warm table)", ROUNDS, |_| decoder.decode(&block));

    group.footprint("hpack::Encoder::encode (cold table)", ROUNDS, |_| HpackEncoder::new().encode(&section.fields));
    group.footprint("hpack::Decoder::decode (cold table)", ROUNDS, |_| HpackDecoder::new().decode(&block));

    let mut encoder = QpackEncoder::new();
    encoder.set_max_capacity(QpackDecoder::DEFAULT_MAX_CAPACITY);
    let mut decoder = QpackDecoder::new();

    let block = encoder.encode(0, &section.fields);
    let stream = encoder.take_encoder_stream();
    decoder.on_encoder_stream(&stream).expect("the encoder stream was refused");
    let _ = decoder.decode(0, &block);

    group.footprint("qpack::Encoder::encode (warm table)", ROUNDS, |round| encoder.encode(round * 4, &section.fields));

    let block = encoder.encode(4, &section.fields);
    group.footprint("qpack::Decoder::decode (warm table)", ROUNDS, |round| decoder.decode(round * 4 + 8, &block));
}

fn message_framing() {
    let mut group = Group::new("message framing allocations");
    let section = Section::request();
    let block = Wire::block(&section);
    let headers = section.headers();

    group.footprint("h1::StartLine::parse_bytes", ROUNDS, |_| h1::StartLine::parse_bytes(Wire::REQUEST_LINE.as_bytes()));
    group.footprint("h1::Field::parse_block (8 fields)", ROUNDS, |_| h1::Field::parse_block(&block, 100));
    group.footprint("h1::Field::write_all (8 fields)", ROUNDS, |_| {
        let mut out = BytesMut::with_capacity(512);
        let _ = h1::Field::write_all(&headers, HeaderCase::Title, &mut out);
        out
    });

    let request = section.message(Version::V2_0);
    let fields = common::Fields::of(&request).expect("the fixture request did not frame");

    group.footprint("common::Fields::of (a request)", ROUNDS, |_| common::Fields::of(&request));
    group.footprint("common::Fields::message (a request)", ROUNDS, |_| common::Fields::message(&fields, Version::V2_0));

    let mut frame = WsFrame::new(Opcode::Binary, Payload::of(4096));
    frame.mask = Some([0xde, 0xad, 0xbe, 0xef]);
    let encoded = frame.encode();

    group.footprint("websocket::Frame::encode (4 KiB)", ROUNDS, |_| frame.encode());
    group.footprint("websocket::Frame::decode (4 KiB)", ROUNDS, |_| WsFrame::decode(&encoded));

    // A content coding is the one place a per-request cost is meant to be
    // large, and the octets column is the only one that says how large.
    let mut group = Group::new("content coding allocations");
    let body = Payload::text(64 * 1024);

    for coding in Compression::CODINGS {
        group.footprint(&format!("{coding}::encode (64 KiB of text)"), 64, |_| coding.encode(&body));

        let encoded = coding.encode(&body).expect("the fixture did not encode");
        group.footprint(&format!("{coding}::decode (64 KiB of text)"), 64, |_| coding.decode(&encoded, 1 << 24));
    }
}

/// One request and its response over an HTTP/3 session, twice over.
///
/// The two differ only in where the response is written, which is the whole
/// point: one hands the caller a buffer of its own and the other writes into
/// one the caller already had.
fn http3_cycle() {
    let mut group = Group::new("http/3 request cycle allocations");
    let mut response = response();

    let mut peer = session(Role::UserAgent);
    let mut server = session(Role::Origin);
    let mut outbound = BytesMut::with_capacity(4096);

    group.footprint("into a send buffer of its own", ROUNDS, |round| {
        let stream = StreamID(round * 4);
        let wire = wire_request(&mut peer, stream.0);

        server.on_stream_bytes(stream, &wire, true).expect("the request did not parse");
        std::hint::black_box(server.take_ready().expect("the request never completed"));

        server.encode_message_into(stream, &mut response, &mut outbound).expect("the response did not encode");
        outbound.clear();
        server.retire(stream);
    });

    let mut peer = session(Role::UserAgent);
    let mut server = session(Role::Origin);
    let mut outbound = BytesMut::with_capacity(4096);

    group.footprint("through a shared handle", ROUNDS, |round| {
        let stream = StreamID(round * 4);
        let wire = wire_request(&mut peer, stream.0);

        server.on_stream_bytes(stream, &wire, true).expect("the request did not parse");
        std::hint::black_box(server.take_ready().expect("the request never completed"));

        let (bytes, _) = server.encode_message(stream, &mut response).expect("the response did not encode");
        outbound.extend_from_slice(&bytes);
        outbound.clear();
        server.retire(stream);
    });
}

/// A whole request and response crossing a real connection.
///
/// The runtime and the in-memory transport allocate too, and both are counted
/// here, so these are the only cases in this benchmark that are not purely the
/// library. What they are for is the shape of the number rather than its last
/// digit: a per-request count that climbs with the body, or with how many
/// requests the connection has already served, is a finding whichever layer it
/// came from.
fn connection_cycles() {
    let mut group = Group::new("http/1 request cycle allocations");
    let runtime = runtime();
    let request = Wire::request();

    for (name, octets) in [("13 B", 13usize), ("4 KiB", 4096), ("64 KiB", 65_536)] {
        let (mut peer, transport) = tokio::io::duplex(4 << 20);
        let mut server = H1Connection::new(transport, Role::Origin, id(), Limits::default());
        let body = Payload::of(octets);
        let mut inbox = vec![0u8; (4 << 20) + 8192];

        group.footprint(&format!("a {name} response body"), CYCLES, |_| {
            runtime.block_on(async {
                peer.write_all(&request).await.expect("the request did not reach the server");

                let received = server.receive().await.expect("the request did not parse");

                let mut response = Message::response(200, Version::V1_1);
                response.stream_id = received.stream_id;
                response.body = Some(Body::Data(body.clone()));
                server.send(response).await.expect("the response did not go out");

                let mut read = 0;
                while read < octets {
                    read += peer.read(&mut inbox).await.expect("the response did not arrive");
                }
            })
        });
    }

    let mut group = Group::new("http/2 request cycle allocations");
    let fields = Section::request().headers();
    let body = Payload::of(13);

    for (name, depth) in [("one request at a time", 1usize), ("16 in flight at once", 16)] {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let mut client = H2Connection::new(client_io, Role::UserAgent, id(), Limits::default());
        let mut server = H2Connection::new(server_io, Role::Origin, id(), Limits::default());

        runtime.block_on(async {
            let (dialled, accepted) = tokio::join!(client.start(), server.start());
            dialled.expect("the client did not start");
            accepted.expect("the server did not start");
        });

        group.footprint(name, CYCLES, |_| {
            runtime.block_on(async {
                let asking = async {
                    for _ in 0..depth {
                        let mut request = Message::request(Method::GET, "/assets/app.7f3c9a2b.module.js", Version::V2_0);
                        request.headers = Some(fields.clone());
                        client.send(request).await.expect("the request did not go out");
                    }
                };

                let taking = async {
                    let mut streams = Vec::with_capacity(depth);
                    for _ in 0..depth {
                        streams.push(server.receive().await.expect("the request did not parse").stream_id);
                    }
                    streams
                };

                let (_, streams) = tokio::join!(asking, taking);

                let answering = async {
                    for stream in streams {
                        let mut response = Message::response(200, Version::V2_0);
                        response.stream_id = stream;
                        response.body = Some(Body::Data(body.clone()));
                        server.send(response).await.expect("the response did not go out");
                    }
                };

                let reading = async {
                    for _ in 0..depth {
                        client.receive().await.expect("the response did not parse");
                    }
                };

                tokio::join!(answering, reading);
            })
        });
    }
}

fn main() {
    assert!(Counter::installed(), "the counting allocator was not installed");

    vocabulary();
    field_codecs();
    message_framing();
    http3_cycle();
    connection_cycles();
}
