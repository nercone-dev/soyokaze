//! The wire formats, and a whole request cycle over each of them.
//!
//! Three halves, kept apart on purpose. The framing groups measure encoding and
//! decoding on their own, with no transport under them; the cycle groups
//! measure a request and its response crossing a real connection over an
//! in-memory transport, which is the framing plus everything a connection does
//! around it; and the age groups measure the same cycle again on a connection
//! that has already served a great many, which is where a cost that is really
//! a leak shows itself. A change that shows in one and not the others says
//! which of the three it landed in.
//!
//! ```bash
//! cargo bench --bench protocol
//! cargo bench --bench protocol -- "http/2"
//! ```

mod support;

use std::hint::black_box;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use soyokaze::helpers::fields::HeaderField;
use soyokaze::models::{Body, ConnectionID, HeaderCase, Limits, Message, Method, Role, StreamID, Version};
use soyokaze::protocol::base::Connection;
use soyokaze::protocol::common::{self, Buffer};
use soyokaze::protocol::h1::{self, H1Connection};
use soyokaze::protocol::h2::{Frame as H2Frame, FrameHeader, FrameType, H2Connection};
use soyokaze::protocol::h3::{Frame as H3Frame, H3Connection, H3Session, Settings, StreamState};
use soyokaze::protocol::quic::Varint;

use support::{Figure, Fixtures, Group, Payload, Section, Wire};

/// The identity every benchmarked connection wears.
fn id() -> ConnectionID {
    ConnectionID(Bytes::from_static(b"bench"))
}

/// A runtime for the cycles, which drive both ends of one transport from one
/// task and so never need a second thread.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("no runtime")
}

/// The limits with every timeout turned off, which is what says how much of a
/// cycle is the timers around it.
fn untimed() -> Limits {
    Limits { read_timeout: 0.0, write_timeout: 0.0, receive_timeout: 0.0, send_timeout: 0.0, ..Limits::default() }
}

fn http1_wire() {
    let section = Section::request();
    let block = Wire::block(&section);
    let framed = Wire::framed(&section);
    let lines = Wire::lines(&section);
    let headers = section.headers();

    let mut group = Group::new("http/1 start lines");
    group.time("StartLine::parse (request)", || h1::StartLine::parse(black_box(Wire::REQUEST_LINE)));
    group.time("StartLine::parse (status)", || h1::StartLine::parse(black_box(Wire::STATUS_LINE)));
    group.time("StartLine::parse_bytes (request)", || h1::StartLine::parse_bytes(black_box(Wire::REQUEST_LINE.as_bytes())));
    group.time("StartLine::parse (a method that is not a token)", || h1::StartLine::parse(black_box("GE T / HTTP/1.1")));
    group.time("StartLine::parse (a version nothing speaks)", || h1::StartLine::parse(black_box("GET / HTTP/9.9")));

    let request = Message::request(Method::GET, "/assets/app.7f3c9a2b.module.js", Version::V1_1);
    group.time("StartLine::write (request)", || {
        let mut out = BytesMut::with_capacity(64);
        let _ = h1::StartLine::write(black_box(&request), &mut out);
        out
    });

    let response = Message::response(200, Version::V1_1);
    group.time("StartLine::write (status)", || {
        let mut out = BytesMut::with_capacity(64);
        let _ = h1::StartLine::write(black_box(&response), &mut out);
        out
    });

    group.growth("StartLine::parse, over the target length", Fixtures::LENGTHS, |octets| format!("GET /{} HTTP/1.1", "a".repeat(octets)), |line| {
        h1::StartLine::parse(black_box(line))
    });

    let mut group = Group::new("http/1 field lines");
    let size = h1::Field::size(&headers) as usize;

    group.time("Field::parse (one line)", || h1::Field::parse(black_box("Content-Type: text/html; charset=utf-8")));
    group.time("Field::parse_bytes (one line)", || h1::Field::parse_bytes(black_box(b"Content-Type: text/html; charset=utf-8")));
    group.time("Field::spans (one line)", || h1::Field::spans(black_box(b"Content-Type: text/html; charset=utf-8")));
    group.time("Field::name_end (one line)", || h1::Field::name_end(black_box(b"Content-Type: text/html; charset=utf-8")));
    group.throughput("Field::parse_lines (8 fields)", size, || h1::Field::parse_lines(black_box(lines.clone())));
    group.throughput("Field::parse_block (8 fields)", size, || h1::Field::parse_block(black_box(&block), 100));
    group.time("Field::block_end (8 fields)", || h1::Field::block_end(black_box(&framed), &mut 0));
    group.time("Field::size (8 fields)", || h1::Field::size(black_box(&headers)));

    group.time("Field::parse (a name with a space before the colon)", || h1::Field::parse(black_box("Content-Type : text/html")));
    group.time("Field::parse (a value holding a control octet)", || h1::Field::parse(black_box("X-Thing: a\u{0}b")));

    for case in [HeaderCase::Lower, HeaderCase::Title] {
        group.throughput(&format!("Field::write_all ({case:?} case)"), size, || {
            let mut out = BytesMut::with_capacity(512);
            let _ = h1::Field::write_all(black_box(&headers), case, &mut out);
            out
        });
    }

    group.time("Field::write_content_length", || {
        let mut out = BytesMut::with_capacity(32);
        h1::Field::write_content_length(black_box(16_384), HeaderCase::Title, &mut out);
        out
    });

    // A peer chooses how many fields it sends, so neither direction may grow
    // worse than with the octets it was handed.
    let mut group = Group::new("http/1 field lines growth");
    group.growth("Field::parse_block, over the field count", Fixtures::COUNTS, |count| Wire::headers(&Section::crowded(count)), |block| {
        h1::Field::parse_block(black_box(block), usize::MAX)
    });
    group.growth("Field::block_end, over the field count", Fixtures::COUNTS, |count| {
        let mut block = Wire::headers(&Section::crowded(count));
        block.extend_from_slice(b"\r\n");
        block
    }, |block| h1::Field::block_end(black_box(block), &mut 0));
    group.growth("Field::write_all, over the field count", Fixtures::COUNTS, Section::crowded, |headers| {
        let mut out = BytesMut::with_capacity(1024);
        let _ = h1::Field::write_all(black_box(&*headers), HeaderCase::Title, &mut out);
        out
    });

    let mut group = Group::new("http/1 message head");
    group.throughput("parse a whole request head", Wire::request().len(), || {
        let start = h1::StartLine::parse_bytes(black_box(Wire::REQUEST_LINE.as_bytes()));
        (start, h1::Field::parse_block(black_box(&block), 100))
    });

    let answer = Section::response().message(Version::V1_1);
    let fields = answer.headers.as_ref().expect("the fixture response lost its fields");
    let size = Wire::STATUS_LINE.len() + 2 + h1::Field::size(fields) as usize;

    group.throughput("write a whole response head", size, || {
        let mut out = BytesMut::with_capacity(512);
        let _ = h1::StartLine::write(black_box(&answer), &mut out);
        out.extend_from_slice(b"\r\n");
        let _ = h1::Field::write_all(fields, HeaderCase::Title, &mut out);
        out.extend_from_slice(b"\r\n");
        out
    });

    let mut group = Group::new("http/1 chunked coding");
    for (name, octets) in Fixtures::SIZES {
        let chunk = Payload::of(*octets);
        group.throughput(&format!("Chunk::encode ({name})"), *octets, || h1::Chunk::encode(black_box(&chunk)));

        let encoded = h1::Chunk::encode(&chunk);
        group.throughput(&format!("Chunk::decode ({name})"), *octets, || h1::Chunk::decode(black_box(&encoded)));
    }

    group.time("Chunk::parse_size (with an extension)", || h1::Chunk::parse_size(black_box(b"1000;name=value\r\n")));
    group.time("Chunk::parse_size (the last chunk)", || h1::Chunk::parse_size(black_box(b"0\r\n")));
    group.time("Chunk::parse_size (a size that is not hexadecimal)", || h1::Chunk::parse_size(black_box(b"zzzz\r\n")));

    let mut group = Group::new("http/1 numbers and octets");
    group.time("Number::write_decimal", || {
        let mut out = BytesMut::with_capacity(24);
        h1::Number::write_decimal(black_box(1_048_576), &mut out);
        out
    });
    group.time("Number::write_hexadecimal", || {
        let mut out = Vec::with_capacity(16);
        h1::Number::write_hexadecimal(black_box(1_048_576), &mut out);
        out
    });
    group.time("Octets::is_token", || h1::Octets::is_token(black_box("content-type")));
    group.time("Octets::is_target", || h1::Octets::is_target(black_box("/assets/app.7f3c9a2b.module.js")));
    group.time("Octets::is_reason", || h1::Octets::is_reason(black_box("Not Found")));
    group.time("Persistence::keep_alive (http/1.1)", || h1::Persistence::keep_alive(black_box(Some(&headers)), Version::V1_1));
    group.time("Expectation::requested", || h1::Expectation::requested(black_box(Some(&headers)), Version::V1_1));
}

/// What HTTP/2 and HTTP/3 share above the frame: the conversion between a
/// message and the field list, and the read buffer under both.
fn shared_pieces() {
    let mut group = Group::new("pseudo-headers");

    for version in [Version::V2_0, Version::V3_0] {
        let request = Section::request().message(version);
        let fields = common::Fields::of(&request).expect("the fixture request did not frame");
        let octets: usize = fields.iter().map(|field| field.name.len() + field.value.len()).sum();

        group.throughput(&format!("Fields::of, request ({version})"), octets, || common::Fields::of(black_box(&request)));
        group.throughput(&format!("Fields::message, request ({version})"), octets, || common::Fields::message(black_box(&fields), version));

        let response = Section::response().message(version);
        let fields = common::Fields::of(&response).expect("the fixture response did not frame");
        let octets: usize = fields.iter().map(|field| field.name.len() + field.value.len()).sum();

        group.throughput(&format!("Fields::of, response ({version})"), octets, || common::Fields::of(black_box(&response)));
        group.throughput(&format!("Fields::message, response ({version})"), octets, || common::Fields::message(black_box(&fields), version));
    }

    let field = HeaderField::new("content-type", "text/html; charset=utf-8");
    group.time("Fields::check (a field that passes)", || common::Fields::check(black_box(&field)));
    group.time("Fields::check (a connection-specific field)", || common::Fields::check(black_box(&HeaderField::new("connection", "close"))));
    group.time("Fields::pseudo (a pseudo-header)", || common::Fields::pseudo(black_box(":method")));
    group.time("Fields::pseudo (an ordinary field)", || common::Fields::pseudo(black_box("content-type")));
    group.time("Fields::connection_specific (one that is)", || common::Fields::connection_specific(black_box("transfer-encoding")));
    group.time("Fields::connection_specific (one that is not)", || common::Fields::connection_specific(black_box("content-type")));
    group.time("Fields::forbidden_trailer", || common::Fields::forbidden_trailer(black_box("content-length")));
    group.time("Fields::status (200)", || common::Fields::status(black_box(200)));
    group.time("Fields::status (a code with no cached text)", || common::Fields::status(black_box(299)));

    group.growth("Fields::of, over the field count", Fixtures::COUNTS, |count| {
        let mut request = Message::request(Method::GET, "/index.html", Version::V2_0);
        request.headers = Some(Section::crowded(count));
        request.security.secure = true;
        request
    }, |request| common::Fields::of(black_box(&*request)));

    let mut group = Group::new("protocol::common::Buffer");
    let octets = Payload::of(64 * 1024);

    group.time("take (16 KiB of 64 KiB)", || {
        let mut buffer = Buffer::new();
        buffer.as_bytes_mut().extend_from_slice(black_box(&octets));
        buffer.take(16 * 1024)
    });

    group.time("consume (16 KiB of 64 KiB)", || {
        let mut buffer = Buffer::new();
        buffer.as_bytes_mut().extend_from_slice(black_box(&octets));
        buffer.consume(16 * 1024);
        buffer.len()
    });

    group.time("reclaim (an idle buffer)", || {
        let mut buffer = Buffer::new();
        buffer.as_bytes_mut().extend_from_slice(black_box(&octets));
        buffer.consume(64 * 1024);
        buffer.reclaim(4096);
        buffer.capacity()
    });

    group.time("oversized", || Buffer::oversized(black_box(1 << 20), 16, 4096));
}

fn http2_frames() {
    let mut group = Group::new("http/2 frames");

    for (name, octets) in Fixtures::SIZES {
        let data = H2Frame::Data { stream_id: StreamID(1), end_stream: false, data: Payload::of(*octets) };
        group.throughput(&format!("encode DATA ({name})"), *octets, || {
            let mut out = BytesMut::with_capacity(octets + FrameHeader::SIZE);
            black_box(&data).encode_into(&mut out);
            out
        });

        let encoded = data.encode();
        let header = FrameHeader { length: *octets as u32, kind: FrameType::Data, flags: 0, stream_id: StreamID(1) };
        group.throughput(&format!("decode DATA ({name})"), *octets, || H2Frame::decode(header, black_box(&encoded[FrameHeader::SIZE..])));

        // Timed rather than measured as a throughput: this path hands the
        // payload on as a shared slice without copying it, so a rate per octet
        // would only say how large the octets it did not touch were.
        let payload = Bytes::copy_from_slice(&encoded[FrameHeader::SIZE..]);
        group.time(&format!("decode DATA, shared ({name})"), || H2Frame::decode_shared(header, black_box(&payload)));
    }

    // Every frame type a connection meets, so that a change to the frame
    // reader is visible wherever it landed rather than only on the two types a
    // request happens to use.
    let block = Bytes::from(Payload::of(256).to_vec());
    let frames: Vec<(&str, H2Frame)> = vec![
        ("HEADERS (256 B block)", H2Frame::Headers { stream_id: StreamID(1), end_stream: true, end_headers: true, block: block.clone() }),
        ("CONTINUATION (256 B block)", H2Frame::Continuation { stream_id: StreamID(1), end_headers: true, block: block.clone() }),
        ("PUSH_PROMISE (256 B block)", H2Frame::PushPromise { stream_id: StreamID(1), promised_stream_id: StreamID(2), block }),
        ("SETTINGS (4 pairs)", H2Frame::Settings { ack: false, params: vec![(1, 4096), (3, 100), (4, 65_535), (5, 16_384)] }),
        ("SETTINGS (an acknowledgement)", H2Frame::Settings { ack: true, params: Vec::new() }),
        ("PING", H2Frame::Ping { ack: false, payload: [0u8; 8] }),
        ("WINDOW_UPDATE", H2Frame::WindowUpdate { stream_id: StreamID(1), increment: 65_535 }),
        ("RST_STREAM", H2Frame::RstStream { stream_id: StreamID(1), error_code: 8 }),
        ("PRIORITY", H2Frame::Priority { stream_id: StreamID(1), dependency: StreamID(0), exclusive: false, weight: 16 }),
        ("GOAWAY", H2Frame::GoAway { last_stream_id: StreamID(101), error_code: 0, debug_data: Vec::new() }),
    ];

    for (name, frame) in &frames {
        group.time(&format!("encode {name}"), || black_box(frame).encode());

        let encoded = frame.encode();
        let (_, header) = FrameHeader::decode(&encoded[..FrameHeader::SIZE].try_into().expect("a frame shorter than its own header"));
        let header = header.expect("the fixture frame has no header");

        group.time(&format!("decode {name}"), || H2Frame::decode(black_box(header), &encoded[FrameHeader::SIZE..]));
    }

    let mut group = Group::new("http/2 frame headers");
    let header = FrameHeader { length: 9, kind: FrameType::Headers, flags: 0x05, stream_id: StreamID(1) };
    let octets = [0u8, 0, 9, 0x01, 0x05, 0, 0, 0, 1];
    group.time("FrameHeader::decode", || FrameHeader::decode(black_box(&octets)));
    group.time("FrameHeader::encode", || black_box(&header).encode());
    group.time("FrameType::from_code (a type there is)", || FrameType::from_code(black_box(0x01)));
    group.time("FrameType::from_code (a type there is not)", || FrameType::from_code(black_box(0xef)));

    let one = H2Frame::Data { stream_id: StreamID(1), end_stream: false, data: Payload::of(4096) }.encode();
    group.time("Frame::parse (one DATA off a buffer)", || {
        let mut buffer = BytesMut::from(&one[..]);
        H2Frame::parse(&mut buffer, 1 << 24)
    });
    group.time("Frame::parse (nothing there yet)", || {
        let mut buffer = BytesMut::from(&one[..4]);
        H2Frame::parse(&mut buffer, 1 << 24)
    });
    group.time("Frame::take (one DATA off a buffer)", || {
        let mut buffer = BytesMut::from(&one[..]);
        H2Frame::take(&mut buffer, 1 << 24)
    });

    group.growth("Frame::parse, over the DATA size", Fixtures::LENGTHS, |octets| {
        H2Frame::Data { stream_id: StreamID(1), end_stream: false, data: Payload::of(octets) }.encode()
    }, |encoded| {
        let mut buffer = BytesMut::from(&encoded[..]);
        H2Frame::parse(&mut buffer, 1 << 24)
    });
}

fn http3_frames() {
    let mut group = Group::new("http/3 varints");
    for (name, value) in [("1 octet", 37u64), ("2 octets", 15_293), ("4 octets", 494_878_333), ("8 octets", Varint::MAXIMUM)] {
        let mut out = BytesMut::with_capacity(16);
        group.time(&format!("Varint::encode ({name})"), || {
            out.clear();
            Varint::encode(&mut out, black_box(value));
        });

        let mut encoded = BytesMut::with_capacity(16);
        Varint::encode(&mut encoded, value);
        group.time(&format!("Varint::decode ({name})"), || Varint::decode(black_box(&encoded)));
    }
    group.time("Varint::decode (cut short)", || Varint::decode(black_box(&[0xc0, 0x00])));

    let mut group = Group::new("http/3 frames");
    for (name, octets) in Fixtures::SIZES {
        let data = H3Frame::Data(Payload::of(*octets));
        group.throughput(&format!("encode DATA ({name})"), *octets, || black_box(&data).encode());

        let encoded = data.encode();
        group.throughput(&format!("Frame::parse DATA ({name})"), *octets, || {
            let mut buffer = BytesMut::from(&encoded[..]);
            H3Frame::parse(&mut buffer)
        });
    }

    let block = Bytes::from(Payload::of(256).to_vec());
    let frames: Vec<(&str, H3Frame)> = vec![
        ("HEADERS (256 B block)", H3Frame::Headers(block.clone())),
        ("SETTINGS", H3Frame::Settings(Settings::default().parameters())),
        ("PUSH_PROMISE (256 B block)", H3Frame::PushPromise { push_id: 1, block }),
        ("CANCEL_PUSH", H3Frame::CancelPush { push_id: 1 }),
        ("GOAWAY", H3Frame::GoAway { id: 101 }),
        ("MAX_PUSH_ID", H3Frame::MaxPushID { push_id: 16 }),
    ];

    for (name, frame) in &frames {
        group.time(&format!("encode {name}"), || black_box(frame).encode());
        group.time(&format!("payload_len {name}"), || black_box(frame).payload_len());

        let encoded = frame.encode();
        group.time(&format!("Frame::parse {name}"), || {
            let mut buffer = BytesMut::from(&encoded[..]);
            H3Frame::parse(&mut buffer)
        });
    }

    group.time("Frame::parse (nothing there yet)", || {
        let mut buffer = BytesMut::from(&[0x01u8][..]);
        H3Frame::parse(&mut buffer)
    });
}

/// An HTTP/1 request and its response, over an in-memory transport.
///
/// The peer writes a canned request and reads whatever comes back, so what is
/// timed is one whole cycle through a real [`H1Connection`] — parse, dispatch,
/// frame, write — and nothing of a second connection.
fn http1_cycle(group: &mut Group) {
    let runtime = runtime();
    let request = Wire::request();
    let body = Payload::of(45);

    for (name, limits) in [("default limits", Limits::default()), ("timeouts off", untimed())] {
        let (mut peer, transport) = tokio::io::duplex(64 * 1024);
        let mut server = H1Connection::new(transport, Role::Origin, id(), limits);
        let mut inbox = [0u8; 8192];
        let octets = request.len() + body.len();

        group.throughput(name, octets, || {
            runtime.block_on(async {
                peer.write_all(black_box(&request)).await.expect("the request did not reach the server");

                let received = server.receive().await.expect("the request did not parse");

                let mut response = Message::response(200, Version::V1_1);
                response.stream_id = received.stream_id;
                response.body = Some(Body::Data(body.clone()));
                server.send(response).await.expect("the response did not go out");

                let read = peer.read(&mut inbox).await.expect("the response did not arrive");
                assert!(read > 0, "the server closed the connection");
            })
        });
    }

    // What a body of each size costs once the head around it is the same, which
    // is what says where the connection stops mattering and the octets start.
    for (name, octets) in Fixtures::SIZES {
        let (mut peer, transport) = tokio::io::duplex(4 << 20);
        let mut server = H1Connection::new(transport, Role::Origin, id(), Limits::default());
        let payload = Payload::of(*octets);
        let mut inbox = vec![0u8; (4 << 20) + 8192];

        group.throughput(&format!("a {name} response body"), *octets, || {
            runtime.block_on(async {
                peer.write_all(black_box(&request)).await.expect("the request did not reach the server");

                let received = server.receive().await.expect("the request did not parse");

                let mut response = Message::response(200, Version::V1_1);
                response.stream_id = received.stream_id;
                response.body = Some(Body::Data(payload.clone()));
                server.send(response).await.expect("the response did not go out");

                let mut read = 0;
                while read < *octets {
                    read += peer.read(&mut inbox).await.expect("the response did not arrive");
                }
            })
        });
    }

    let (mut peer, mut transport) = tokio::io::duplex(64 * 1024);
    let canned = {
        let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        out.extend_from_slice(&body);
        out
    };

    let mut server_inbox = [0u8; 8192];
    let mut peer_inbox = [0u8; 8192];
    let octets = request.len() + body.len();

    group.throughput("transport floor (no parsing)", octets, || {
        runtime.block_on(async {
            peer.write_all(black_box(&request)).await.expect("the request did not reach the server");

            let read = transport.read(&mut server_inbox).await.expect("nothing arrived");
            assert!(read > 0, "the peer closed the connection");

            transport.write_all(&canned).await.expect("the response did not go out");
            transport.flush().await.expect("the response did not flush");

            let read = peer.read(&mut peer_inbox).await.expect("the response did not arrive");
            assert!(read > 0, "the server closed the connection");
        })
    });
}

/// An HTTP/2 request and its response, over an in-memory transport.
///
/// Both ends are real connections driven from one task, so the cycle covers
/// what a client costs as well as what a server does — which is the only way
/// to make an HTTP/2 exchange without hand-writing frames a client would have
/// written anyway.
fn http2_cycle(group: &mut Group) {
    let runtime = runtime();
    let body = Payload::of(45);

    for (name, depth) in [("one request at a time", 1usize), ("16 in flight at once", 16), ("64 in flight at once", 64)] {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let mut client = H2Connection::new(client_io, Role::UserAgent, id(), Limits::default());
        let mut server = H2Connection::new(server_io, Role::Origin, id(), Limits::default());

        runtime.block_on(async {
            let (dialled, accepted) = tokio::join!(client.start(), server.start());
            dialled.expect("the client did not start");
            accepted.expect("the server did not start");
        });

        let fields = Section::request().headers();
        let octets = (h1::Field::size(&fields) as usize + body.len()) * depth;

        let request = || {
            let mut request = Message::request(Method::GET, "/assets/app.7f3c9a2b.module.js", Version::V2_0);
            request.headers = Some(fields.clone());
            request
        };

        group.throughput(name, octets, || {
            runtime.block_on(async {
                let asking = async {
                    for _ in 0..depth {
                        client.send(request()).await.expect("the request did not go out");
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

/// A session with the peer's settings already applied.
fn session(role: Role) -> H3Session {
    let mut session = H3Session::new(role, id(), Limits::default());
    let settings = H3Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");
    session
}

/// A request as it arrives on an HTTP/3 stream.
fn wire_request(peer: &mut H3Session, stream_id: u64) -> Bytes {
    let block = peer.encoder.encode(stream_id, &Section::request().fields);

    let mut out = BytesMut::with_capacity(block.len() + 8);
    H3Frame::Headers(block.into()).encode_into(&mut out);
    out.freeze()
}

/// One request and one response over an HTTP/3 session.
fn h3_cycle(session: &mut H3Session, wire: &Bytes, stream_id: u64, response: &mut Message) {
    let stream = StreamID(stream_id);

    session.on_stream_bytes(stream, wire, true).expect("the request did not parse");
    black_box(session.take_ready().expect("the request never completed"));

    session.encode_message(stream, response).expect("the response did not encode");
    session.retire(stream);
}

fn http3_session() {
    let mut response = Section::response().message(Version::V3_0);
    response.body = Some(Body::Data(Payload::of(13)));

    let mut group = Group::new("http/3 session halves");
    let mut peer = session(Role::UserAgent);
    let wire = wire_request(&mut peer, 0);

    let mut server = session(Role::Origin);
    let mut next = 0u64;
    group.throughput("decode a request (8 fields)", wire.len(), || {
        let stream = StreamID(next);
        next += 4;

        server.on_stream_bytes(stream, black_box(&wire), true).expect("the request did not parse");
        let received = server.take_ready().expect("the request never completed");
        server.forget(stream);
        received
    });

    let mut server = session(Role::Origin);
    let mut next = 1u64;
    group.time("encode a response (body, 13 B)", || {
        let stream = StreamID(next);
        next += 4;

        let encoded = server.encode_message(stream, black_box(&mut response)).expect("the response did not encode");
        server.forget(stream);
        encoded
    });

    let mut server = session(Role::Origin);
    let mut next = 1u64;
    let mut outbound = BytesMut::with_capacity(4096);
    group.time("encode a response, into a buffer of the caller's", || {
        let stream = StreamID(next);
        next += 4;

        outbound.clear();
        let ended = server.encode_message_into(stream, black_box(&mut response), &mut outbound);
        server.forget(stream);
        ended
    });
}

/// What one cycle costs on a connection that has already served a great many.
///
/// A per-request cost that climbs with how long the connection has been open is
/// a leak wearing a timing's clothes, and it is invisible to every case that
/// measures the first request on a fresh connection. Reported as a curve, so
/// the question it answers is whether the cost is bounded rather than what it
/// happens to be at one age.
fn connection_age() {
    let mut group = Group::new("http/3 cost by connection age");

    for served in Fixtures::SERVED {
        if !group.wants(&format!("a cycle after {served} requests")) {
            continue;
        }

        let (mut server, mut peer, mut response, mut next) = aged(*served);
        let wire = wire_request(&mut peer, 1 << 40);

        group.time(&format!("a cycle after {served} requests"), || {
            let stream_id = next;
            next += 4;
            h3_cycle(&mut server, black_box(&wire), stream_id, &mut response);
        });
    }

    // Both of these run once per I/O cycle over every stream a connection
    // holds, so a connection carrying many streams pays them many times over.
    let mut group = Group::new("http/3 per-I/O-cycle scans");
    for held in Fixtures::STREAMS {
        let mut server = session(Role::Origin);
        hold(&mut server, *held);

        let (_connection, worker) = H3Connection::pair(server);
        group.time(&format!("block_deadline ({} held)", Figure::many(*held, "stream")), || black_box(&worker).block_deadline());
    }

    for held in Fixtures::STREAMS {
        let mut server = session(Role::Origin);
        hold(&mut server, *held);

        group.time(&format!("overbuffered ({} held)", Figure::many(*held, "stream")), || black_box(server.overbuffered()));
    }

    group.growth("block_deadline, over the streams held", Fixtures::STREAMS, |held| {
        let mut server = session(Role::Origin);
        hold(&mut server, held);
        H3Connection::pair(server)
    }, |(_connection, worker)| black_box(&*worker).block_deadline());

    group.growth("overbuffered, over the streams held", Fixtures::STREAMS, |held| {
        let mut server = session(Role::Origin);
        hold(&mut server, held);
        server
    }, |server| black_box(server.overbuffered()));
}

/// A server session that has already served this many requests, the peer that
/// sent them, the response it answers with, and the next stream to use.
fn aged(served: usize) -> (H3Session, H3Session, Message, u64) {
    let mut response = Section::response().message(Version::V3_0);
    response.body = Some(Body::Data(Payload::of(13)));

    let mut peer = session(Role::UserAgent);
    let mut server = session(Role::Origin);

    let mut next = 0u64;
    for _ in 0..served {
        let wire = wire_request(&mut peer, next);
        h3_cycle(&mut server, &wire, next, &mut response);
        next += 4;
    }

    (server, peer, response, next)
}

/// Leaves this many streams part way through, each holding a little buffered.
fn hold(session: &mut H3Session, streams: usize) {
    for index in 0..streams {
        let mut state = StreamState::default();
        state.buffer.extend_from_slice(&[0u8; 64]);

        session.streams.insert(StreamID(index as u64 * 4), state);
        session.buffered_bound += 64;
    }
}

fn main() {
    http1_wire();
    shared_pieces();
    http2_frames();
    http3_frames();

    http1_cycle(&mut Group::new("http/1 request cycle (keep-alive)"));
    http2_cycle(&mut Group::new("http/2 request cycle"));

    http3_session();
    connection_age();
}
