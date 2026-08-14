//! WebSocket framing, masking, and the handshakes that open a connection.
//!
//! Framing and masking are measured on their own; the message cycles drive a
//! real pair of [`WebSocketConnection`]s over an in-memory transport, so what
//! they cover is a message crossing both of them, masked one way and unmasked
//! the other, exactly as a client and a server do it.
//!
//! Fragmentation is measured beside the whole-message cases, because how a
//! message is cut up is the peer's choice and not the server's: the same
//! payload delivered in a thousand pieces is the same message and must not be
//! a thousand times the work.
//!
//! ```bash
//! cargo bench --bench websocket
//! cargo bench --bench websocket -- masking
//! ```

mod support;

use std::hint::black_box;

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

use soyokaze::models::{ConnectionID, Limits, Role, Version};
use soyokaze::websocket::{CloseCode, Connect, Frame, FrameHead, Handshake, Opcode, Upgrade, WebSocketConnection};

use support::{Fixtures, Group, Payload};

/// The key an example handshake carries, from RFC 6455.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// The masking key every masked case is measured with.
const MASK: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

fn id() -> ConnectionID {
    ConnectionID(Bytes::from_static(b"bench"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("no runtime")
}

fn frames() {
    let mut group = Group::new("websocket frames");

    for (name, octets) in Fixtures::SIZES {
        for (masking, mask) in [("unmasked", None), ("masked", Some(MASK))] {
            let mut frame = Frame::new(Opcode::Binary, Payload::of(*octets));
            frame.mask = mask;

            group.throughput(&format!("encode {masking} ({name})"), *octets, || black_box(&frame).encode());

            let encoded = frame.encode();
            group.throughput(&format!("decode {masking} ({name})"), *octets, || Frame::decode(black_box(&encoded)));

            group.throughput(&format!("take {masking} ({name})"), *octets, || {
                let mut buffer = BytesMut::from(&encoded[..]);
                Frame::take(black_box(&mut buffer))
            });
        }
    }

    let mut group = Group::new("websocket frames growth");
    group.growth("encode masked, over the payload", Fixtures::LENGTHS, |octets| {
        let mut frame = Frame::new(Opcode::Binary, Payload::of(octets));
        frame.mask = Some(MASK);
        frame
    }, |frame| black_box(&*frame).encode());
    group.growth("decode masked, over the payload", Fixtures::LENGTHS, |octets| {
        let mut frame = Frame::new(Opcode::Binary, Payload::of(octets));
        frame.mask = Some(MASK);
        frame.encode()
    }, |encoded| Frame::decode(black_box(encoded)));

    let mut group = Group::new("websocket frame heads");
    for (name, octets) in [("a 7-bit length", 125usize), ("a 16-bit length", 65_535), ("a 64-bit length", 1 << 20)] {
        let mut frame = Frame::new(Opcode::Binary, Payload::of(octets));
        frame.mask = Some(MASK);

        let encoded = frame.encode();
        group.time(&format!("FrameHead::decode ({name})"), || FrameHead::decode(black_box(&encoded)));
    }

    group.time("FrameHead::decode (nothing there yet)", || FrameHead::decode(black_box(&[0x82])));
    group.time("Opcode::from_code (an opcode there is)", || Opcode::from_code(black_box(0x02)));
    group.time("Opcode::from_code (an opcode there is not)", || Opcode::from_code(black_box(0x0b)));
    group.time("Opcode::control", || black_box(&Opcode::Close).control());
    group.time("CloseCode::from_code", || CloseCode::from_code(black_box(1000)));
    group.time("CloseCode::permitted (a code that is)", || CloseCode::permitted(black_box(1000)));
    group.time("CloseCode::permitted (a code that is not)", || CloseCode::permitted(black_box(1005)));

    // Control frames cross a connection between the message frames and are
    // bounded to 125 octets, so what matters about them is the fixed cost and
    // not any rate.
    let mut group = Group::new("websocket control frames");
    for (name, opcode) in [("PING", Opcode::Ping), ("PONG", Opcode::Pong), ("CLOSE", Opcode::Close)] {
        let mut frame = Frame::new(opcode, Payload::of(32));
        frame.mask = Some(MASK);

        group.time(&format!("encode {name}"), || black_box(&frame).encode());

        let encoded = frame.encode();
        group.time(&format!("decode {name}"), || Frame::decode(black_box(&encoded)));
    }

    let mut close = Vec::with_capacity(2);
    close.extend_from_slice(&1000u16.to_be_bytes());
    close.extend_from_slice(b"going away");

    let (_peer, transport) = tokio::io::duplex(1024);
    let connection = WebSocketConnection::new(transport, Role::Origin, id(), Limits::default());
    group.time("verify_close (a permitted code)", || black_box(&connection).verify_close(&close));
    group.time("verify_close (an empty payload)", || black_box(&connection).verify_close(&[]));
}

fn masking() {
    let mut group = Group::new("websocket masking");

    for (name, octets) in Fixtures::SIZES {
        let mut payload = Payload::of(*octets).to_vec();
        group.throughput(name, *octets, || Frame::apply_mask(black_box(MASK), &mut payload));
    }

    // The word loop leaves a tail of up to seven octets, which is where a
    // masking routine is at its worst per octet.
    for (name, octets) in [("7 B, a tail only", 7usize), ("9 B, one word and a tail", 9), ("63 B, seven words and a tail", 63)] {
        let mut payload = Payload::of(octets).to_vec();
        group.throughput(name, octets, || Frame::apply_mask(black_box(MASK), &mut payload));
    }

    group.growth("over the payload", Fixtures::LENGTHS, |octets| Payload::of(octets).to_vec(), |payload| Frame::apply_mask(black_box(MASK), payload));
}

fn handshake() {
    let mut group = Group::new("websocket handshake");
    group.time("Upgrade::accept_key", || Upgrade::accept_key(black_box(KEY)));
    group.time("Upgrade::nonce", || Upgrade::nonce());
    group.time("Upgrade::request", || Upgrade::request(black_box("www.example.com"), "/socket", KEY, Version::V1_1));
    group.time("Upgrade::response", || Upgrade::response(black_box(KEY), Version::V1_1));

    let request = Upgrade::request("www.example.com", "/socket", KEY, Version::V1_1);
    group.time("Upgrade::verify_request", || Upgrade::verify_request(black_box(&request)));
    group.time("Handshake::requested (an upgrade)", || Handshake::requested(black_box(&request)));
    group.time("Handshake::verify (an upgrade)", || Handshake::verify(black_box(&request)));
    group.time("Handshake::refusal", || Handshake::refusal(black_box(&request), Version::V1_1));

    let response = Upgrade::response(KEY, Version::V1_1);
    group.time("Upgrade::verify_response", || Upgrade::verify_response(black_box(&response), KEY));

    let plain = soyokaze::Message::request(soyokaze::Method::GET, "/index.html", Version::V1_1);
    group.time("Handshake::requested (a plain request)", || Handshake::requested(black_box(&plain)));

    // The extended CONNECT a WebSocket rides in on over HTTP/2 and HTTP/3,
    // which is the same handshake by another spelling and should cost the same.
    let mut group = Group::new("websocket extended CONNECT");
    for version in [Version::V2_0, Version::V3_0] {
        group.time(&format!("Connect::request ({version})"), || Connect::request(black_box("www.example.com"), "/socket", version));
        group.time(&format!("Connect::response ({version})"), || Connect::response(black_box(version)));

        let request = Connect::request("www.example.com", "/socket", version);
        group.time(&format!("Connect::verify_request ({version})"), || Connect::verify_request(black_box(&request)));
        group.time(&format!("Handshake::requested ({version})"), || Handshake::requested(black_box(&request)));

        let response = Connect::response(version);
        group.time(&format!("Connect::verify_response ({version})"), || Connect::verify_response(black_box(&response)));
    }
}

/// One message from a client to a server and back, over an in-memory
/// transport.
///
/// Both ends are real connections driven from one task, so a round covers
/// masking on the way out, unmasking on the way in, and everything the
/// connection does around both.
fn messages() {
    let mut group = Group::new("websocket message cycle");
    let runtime = runtime();

    for (name, octets) in Fixtures::SIZES {
        let (client_io, server_io) = tokio::io::duplex(4 << 20);
        let mut client = WebSocketConnection::new(client_io, Role::UserAgent, id(), Limits::default());
        let mut server = WebSocketConnection::new(server_io, Role::Origin, id(), Limits::default());

        let payload = Payload::of(*octets);

        group.throughput(name, *octets * 2, || {
            runtime.block_on(async {
                let (sent, received) = tokio::join!(client.send_message(Opcode::Binary, payload.clone()), server.receive_message());
                sent.expect("the message did not go out");
                let (opcode, echoed) = received.expect("the message did not arrive");

                let (sent, received) = tokio::join!(server.send_message(opcode, echoed), client.receive_message());
                sent.expect("the echo did not go out");
                received.expect("the echo did not arrive");
            })
        });
    }

    // The same 64 KiB, cut up as a peer chooses to cut it. A cost that climbs
    // with the number of pieces is a cost the peer sets.
    let mut group = Group::new("websocket fragmented messages");
    const MESSAGE: usize = 64 * 1024;

    for fragments in [1usize, 8, 64, 512] {
        let name = format!("64 KiB in {}", support::Figure::many(fragments, "fragment"));

        if !group.wants(&name) {
            continue;
        }

        let wire = fragmented(MESSAGE, fragments);
        let (mut peer, server_io) = tokio::io::duplex(8 << 20);
        let mut server = WebSocketConnection::new(server_io, Role::Origin, id(), Limits::default());

        group.throughput(&name, MESSAGE, || {
            runtime.block_on(async {
                let writing = async { peer.write_all(black_box(&wire)).await.expect("the message did not reach the server") };
                let (_, received) = tokio::join!(writing, server.receive_message());
                received.expect("the message did not arrive");
            })
        });
    }

    group.growth("64 KiB, over the fragment count", &[1, 8, 64, 512], |fragments| {
        let (peer, server_io) = tokio::io::duplex(8 << 20);
        (fragmented(MESSAGE, fragments), peer, WebSocketConnection::new(server_io, Role::Origin, id(), Limits::default()))
    }, |(wire, peer, server)| {
        runtime.block_on(async {
            let writing = async { peer.write_all(black_box(wire)).await.expect("the message did not reach the server") };
            let (_, received) = tokio::join!(writing, server.receive_message());
            received.expect("the message did not arrive");
        })
    });
}

/// A masked binary message of this many octets, cut into this many frames.
///
/// Written as octets rather than sent through a connection, since what is
/// being varied is exactly what a sending connection would decide for itself.
fn fragmented(octets: usize, fragments: usize) -> Vec<u8> {
    let payload = Payload::of(octets);
    let each = octets.div_ceil(fragments.max(1));

    let mut wire = Vec::with_capacity(octets + fragments * 16);

    for (index, chunk) in payload.chunks(each.max(1)).enumerate() {
        let last = index + 1 == payload.chunks(each.max(1)).count();

        let mut frame = Frame::new(if index == 0 { Opcode::Binary } else { Opcode::Continuation }, Bytes::copy_from_slice(chunk));
        frame.fin = last;
        frame.mask = Some(MASK);

        wire.extend_from_slice(&frame.encode());
    }

    wire
}

fn main() {
    frames();
    masking();
    handshake();
    messages();
}
