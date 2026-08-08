mod support;

use bytes::BytesMut;

use soyokaze::helpers::fields::HeaderField;
use soyokaze::helpers::{base64, sha1};
use soyokaze::models::{HeaderCase, Headers, Message, Method, StreamID, Version};
use soyokaze::protocol::common;
use soyokaze::protocol::h1;
use soyokaze::protocol::h2::{self, Frame, FrameHeader, FrameType};
use soyokaze::protocol::h3;
use soyokaze::protocol::quic;
use soyokaze::websocket;
use support::{opaque, Group};

fn request_headers() -> Headers {
    let mut headers = Headers::new();
    headers.append("host", "www.example.com");
    headers.append("accept", "*/*");
    headers.append("accept-encoding", "gzip, deflate, br");
    headers.append("cookie", "session=8f14e45fceea167a5a36dedd4bea2543; consent=1");
    headers.append("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) soyokaze/0.1");
    headers
}

fn http1() {
    let mut group = Group::new("http/1 start lines");
    group.bench("StartLine::parse (request)", || h1::StartLine::parse(opaque("GET /index.html HTTP/1.1")));
    group.bench("StartLine::parse (status)", || h1::StartLine::parse(opaque("HTTP/1.1 404 Not Found")));

    let request = Message::request(Method::GET, "/index.html", Version::V1_1);
    group.bench("StartLine::write (request)", || {
        let mut out = BytesMut::new();
        let _ = h1::StartLine::write(opaque(&request), &mut out);
        out
    });

    let mut group = Group::new("http/1 field lines");
    group.bench("Field::parse", || h1::Field::parse(opaque("Content-Type: text/html; charset=utf-8")));

    let headers = request_headers();
    let size = h1::Field::size(&headers) as usize;
    group.throughput("Field::write_all (5 fields)", size, || {
        let mut out = BytesMut::new();
        h1::Field::write_all(opaque(&headers), HeaderCase::Title, &mut out).unwrap();
        out
    });

    let lines: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{}: {value}", HeaderCase::Title.apply(name)))
        .collect();
    group.throughput("Field::parse_lines (5 fields)", size, || h1::Field::parse_lines(opaque(lines.clone())));

    let block: Vec<u8> = lines.iter().flat_map(|line| format!("{line}\r\n").into_bytes()).collect();
    group.throughput("Field::parse_block (5 fields)", size, || h1::Field::parse_block(opaque(&block), 100));

    let mut framed = block.clone();
    framed.extend_from_slice(b"\r\n");
    group.bench("Field::block_end (5 fields)", || h1::Field::block_end(opaque(&framed), &mut 0));

    let mut group = Group::new("http/1 message head");

    let request_line = b"GET /index.html HTTP/1.1";
    let head: usize = request_line.len() + 2 + block.len();
    group.throughput("parse request head (5 fields)", head, || {
        let message = h1::StartLine::parse_bytes(opaque(request_line.as_slice()));
        (message, h1::Field::parse_block(opaque(&block), 100))
    });

    let mut response = Message::response(200, Version::V1_1);
    response.headers = Some({
        let mut headers = Headers::new();
        headers.append("content-type", "text/html; charset=utf-8");
        headers.append("content-length", "42");
        headers.append("date", "Mon, 21 Oct 2013 20:13:21 GMT");
        headers.append("server", "Soyokaze");
        headers
    });

    let size = 15 + h1::Field::size(response.headers.as_ref().unwrap()) as usize;
    group.throughput("write response head (4 fields)", size, || {
        let mut out = BytesMut::with_capacity(256);
        let _ = h1::StartLine::write(opaque(&response), &mut out);
        out.extend_from_slice(b"\r\n");
        let _ = h1::Field::write_all(response.headers.as_ref().unwrap(), HeaderCase::Title, &mut out);
        out.extend_from_slice(b"\r\n");
        out
    });

    let mut group = Group::new("http/1 chunked coding");
    let chunk = vec![b'x'; 4096];
    group.throughput("Chunk::encode (4 KiB)", chunk.len(), || h1::Chunk::encode(opaque(&chunk)));

    let encoded = h1::Chunk::encode(&chunk);
    group.bench("Chunk::decode (4 KiB, no copy)", || h1::Chunk::decode(opaque(&encoded)));
    group.bench("Chunk::parse_size", || h1::Chunk::parse_size(opaque(b"1000;name=value\r\n")));
}

fn pseudo_headers() {
    let mut request = Message::request(Method::GET, "/index.html", Version::V2_0);
    request.headers = Some(request_headers());
    request.security.secure = true;

    let fields = common::Fields::of(&request).expect("the fixture request did not encode");
    let size: usize = fields.iter().map(|field| field.name.len() + field.value.len()).sum();

    let mut group = Group::new("pseudo-headers");
    group.throughput("common::fields (request)", size, || common::Fields::of(opaque(&request)));
    group.throughput("common::message (request)", size, || common::Fields::message(opaque(&fields), Version::V2_0));

    let response = vec![
        HeaderField::new(":status", "200"),
        HeaderField::new("content-type", "text/html; charset=utf-8"),
        HeaderField::new("content-length", "16384"),
    ];
    group.bench("common::message (response)", || common::Fields::message(opaque(&response), Version::V2_0));
}

fn http2() {
    let mut group = Group::new("http/2 frames");

    let data = Frame::Data { stream_id: StreamID(1), end_stream: false, data: vec![b'x'; 16_384].into() };
    group.throughput("encode DATA (16 KiB)", 16_384, || {
        let mut out = BytesMut::new();
        opaque(&data).encode_into(&mut out);
        out
    });

    let encoded = data.encode();
    let header = FrameHeader { length: 16_384, kind: FrameType::Data, flags: 0, stream_id: StreamID(1) };
    group.throughput("decode DATA (16 KiB)", 16_384, || {
        Frame::decode(header, opaque(&encoded[h2::FrameHeader::SIZE..]))
    });

    let payload = bytes::Bytes::copy_from_slice(&encoded[h2::FrameHeader::SIZE..]);
    group.throughput("decode DATA (16 KiB, shared)", 16_384, || Frame::decode_shared(header, opaque(&payload)));

    let settings = Frame::Settings { ack: false, params: vec![(1, 4096), (3, 100), (4, 65_535), (5, 16_384)] };
    let encoded = settings.encode();
    let header = FrameHeader { length: 24, kind: FrameType::Settings, flags: 0, stream_id: StreamID(0) };
    group.bench("decode SETTINGS (4 pairs)", || Frame::decode(header, opaque(&encoded[h2::FrameHeader::SIZE..])));

    let octets = [0u8, 0, 9, 0x01, 0x05, 0, 0, 0, 1];
    group.bench("FrameHeader::decode", || FrameHeader::decode(opaque(&octets)));
    group.bench("FrameHeader::encode", || opaque(&header).encode());
}

fn http3() {
    let mut group = Group::new("http/3 varints");
    for (name, value) in [("1 octet", 37u64), ("2 octets", 15_293), ("4 octets", 494_878_333), ("8 octets", quic::Varint::MAXIMUM)] {
        let mut out = BytesMut::with_capacity(16);
        group.bench(&format!("Varint::encode ({name})"), || {
            out.clear();
            quic::Varint::encode(&mut out, opaque(value));
        });

        let mut encoded = BytesMut::new();
        quic::Varint::encode(&mut encoded, value);
        group.bench(&format!("decode_varint ({name})"), || quic::Varint::decode(opaque(&encoded)));
    }

    let mut group = Group::new("http/3 frames");
    let data = h3::Frame::Data(vec![b'x'; 16_384].into());
    group.throughput("encode DATA (16 KiB)", 16_384, || opaque(&data).encode());

    let encoded = data.encode();
    group.throughput("Frame::parse DATA (16 KiB)", 16_384, || {
        let mut buffer = BytesMut::from(&encoded[..]);
        h3::Frame::parse(&mut buffer)
    });
}

fn websocket_frames() {
    let mut group = Group::new("websocket frames");

    for (name, length) in [("125 B", 125usize), ("64 KiB", 64 * 1024)] {
        let mut frame = websocket::Frame::new(websocket::Opcode::Binary, vec![b'x'; length]);
        frame.mask = Some([0xde, 0xad, 0xbe, 0xef]);

        group.throughput(&format!("encode masked ({name})"), length, || opaque(&frame).encode());

        let encoded = frame.encode();
        group.throughput(&format!("decode masked ({name})"), length, || websocket::Frame::decode(opaque(&encoded)));

        group.throughput(&format!("take masked ({name})"), length, || {
            let mut buffer = BytesMut::from(&encoded[..]);
            websocket::Frame::take(opaque(&mut buffer))
        });
    }

    let mut payload = vec![b'x'; 64 * 1024];
    group.throughput("apply_mask (64 KiB)", payload.len(), || {
        websocket::Frame::apply_mask([0xde, 0xad, 0xbe, 0xef], opaque(&mut payload));
    });
}

fn digests() {
    let mut group = Group::new("base64");
    for (name, length) in [("16 B", 16usize), ("1 KiB", 1024)] {
        let input = vec![0x5au8; length];
        group.throughput(&format!("encode ({name})"), length, || base64::encode(opaque(&input)));

        let encoded = base64::encode(&input);
        group.throughput(&format!("decode ({name})"), length, || base64::decode(opaque(&encoded)));
    }

    let mut group = Group::new("sha1");
    for (name, length) in [("60 B", 60usize), ("1 KiB", 1024), ("64 KiB", 64 * 1024)] {
        let input = vec![0x5au8; length];
        group.throughput(name, length, || sha1::sha1(opaque(&input)));
    }

    let mut group = Group::new("websocket handshake");
    group.bench("Upgrade::accept_key", || websocket::Upgrade::accept_key(opaque("dGhlIHNhbXBsZSBub25jZQ==")));
}

fn main() {
    http1();
    pseudo_headers();
    http2();
    http3();
    websocket_frames();
    digests();
}
