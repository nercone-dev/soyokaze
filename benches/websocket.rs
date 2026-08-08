//! WebSocket framing, masking, and the handshake that opens one.
//!
//! Framing and masking are measured on their own; the message cycle drives a
//! real pair of [`WebSocketConnection`]s over an in-memory transport, so what
//! it covers is a message crossing both of them, masked one way and unmasked
//! the other, exactly as a client and a server do it.
//!
//! ```bash
//! cargo bench --bench websocket
//! cargo bench --bench websocket -- masking
//! ```

mod support;

use std::hint::black_box;

use bytes::{Bytes, BytesMut};

use soyokaze::models::{ConnectionID, Limits, Role, Version};
use soyokaze::websocket::{Frame, FrameHead, Handshake, Opcode, Upgrade, WebSocketConnection};

use support::{Fixtures, Group, Payload};

/// The key an example handshake carries, from RFC 6455.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// The masking key every masked case is measured with.
const MASK: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

fn id() -> ConnectionID {
    ConnectionID(Bytes::from_static(b"bench"))
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

    let mut group = Group::new("websocket frame heads");
    for (name, octets) in [("a 7-bit length", 125usize), ("a 16-bit length", 65_535), ("a 64-bit length", 1 << 20)] {
        let mut frame = Frame::new(Opcode::Binary, Payload::of(octets));
        frame.mask = Some(MASK);

        let encoded = frame.encode();
        group.time(&format!("FrameHead::decode ({name})"), || FrameHead::decode(black_box(&encoded)));
    }

    group.time("FrameHead::decode (nothing there yet)", || FrameHead::decode(black_box(&[0x82])));
    group.time("Opcode::from_code", || Opcode::from_code(black_box(0x02)));
}

fn masking() {
    let mut group = Group::new("websocket masking");

    for (name, octets) in Fixtures::SIZES {
        let mut payload = Payload::of(*octets).to_vec();
        group.throughput(name, *octets, || Frame::apply_mask(black_box(MASK), &mut payload));
    }

    for (name, octets) in [("7 B, a tail only", 7usize), ("9 B, one word and a tail", 9)] {
        let mut payload = Payload::of(octets).to_vec();
        group.throughput(name, octets, || Frame::apply_mask(black_box(MASK), &mut payload));
    }
}

fn handshake() {
    let mut group = Group::new("websocket handshake");
    group.time("Upgrade::accept_key", || Upgrade::accept_key(black_box(KEY)));
    group.time("Upgrade::request", || Upgrade::request(black_box("www.example.com"), "/socket", KEY, Version::V1_1));
    group.time("Upgrade::response", || Upgrade::response(black_box(KEY), Version::V1_1));

    let request = Upgrade::request("www.example.com", "/socket", KEY, Version::V1_1);
    group.time("Upgrade::verify_request", || Upgrade::verify_request(black_box(&request)));
    group.time("Handshake::requested (an upgrade)", || Handshake::requested(black_box(&request)));

    let response = Upgrade::response(KEY, Version::V1_1);
    group.time("Upgrade::verify_response", || Upgrade::verify_response(black_box(&response), KEY));

    let plain = soyokaze::Message::request(soyokaze::Method::GET, "/index.html", Version::V1_1);
    group.time("Handshake::requested (a plain request)", || Handshake::requested(black_box(&plain)));
}

/// One message from a client to a server and back, over an in-memory
/// transport.
///
/// Both ends are real connections driven from one task, so a round covers
/// masking on the way out, unmasking on the way in, and everything the
/// connection does around both.
fn messages() {
    let mut group = Group::new("websocket message cycle");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("no runtime");

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
}

fn main() {
    frames();
    masking();
    handshake();
    messages();
}
