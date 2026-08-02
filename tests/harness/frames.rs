use bytes::BytesMut;

use soyokaze::protocol::{h2, h3};
use soyokaze::websocket;

pub fn check(data: &[u8]) {
    http2(data);
    http3(data);
    varints(data);
    websocket(data);
}

pub fn http2(data: &[u8]) {
    let Some(head) = data.get(..h2::FRAME_HEADER_SIZE) else {
        return;
    };

    let Ok(octets) = <[u8; h2::FRAME_HEADER_SIZE]>::try_from(head) else {
        return;
    };

    let (_, header) = h2::FrameHeader::decode(&octets);
    let Some(header) = header else {
        return;
    };

    let payload = &data[h2::FRAME_HEADER_SIZE..];
    if payload.len() > h2::MAXIMUM_FRAME_SIZE as usize {
        return;
    }

    let header = h2::FrameHeader { length: payload.len() as u32, ..header };
    let Ok(frame) = h2::Frame::decode(header, payload) else {
        return;
    };

    let encoded = frame.encode();
    assert_eq!(
        encoded.len(),
        h2::FRAME_HEADER_SIZE + frame.payload().len(),
        "a re-encoded frame disagreed with its own payload length",
    );

    let Ok(octets) = <[u8; h2::FRAME_HEADER_SIZE]>::try_from(&encoded[..h2::FRAME_HEADER_SIZE]) else {
        panic!("a re-encoded frame had no frame header");
    };

    let (_, header) = h2::FrameHeader::decode(&octets);
    let header = header.expect("a re-encoded frame named a frame type that does not exist");

    let again = h2::Frame::decode(header, &encoded[h2::FRAME_HEADER_SIZE..]);
    assert_eq!(again.ok(), Some(frame), "an HTTP/2 frame did not survive re-encoding");
}

pub fn http3(data: &[u8]) {
    let mut buffer = BytesMut::from(data);

    while let Ok(Some(frame)) = h3::parse_frame(&mut buffer) {
        let encoded = frame.encode();

        let mut written = BytesMut::from(&encoded[..]);
        let again = h3::parse_frame(&mut written);

        assert_eq!(again.ok().flatten(), Some(frame), "an HTTP/3 frame did not survive re-encoding");
        assert!(written.is_empty(), "re-parsing a frame left octets behind");
    }
}

pub fn varints(data: &[u8]) {
    let (consumed, value) = h3::decode_varint(data);
    if consumed == 0 {
        return;
    }

    assert!(consumed <= data.len(), "the varint decoder ran past the end of the input");
    assert!(value <= h3::MAXIMUM_VARINT, "the varint decoder returned a value no varint can hold");

    let mut out = BytesMut::new();
    h3::encode_varint(&mut out, value);

    assert_eq!(out.len(), h3::varint_len(value), "varint_len disagreed with encode_varint");
    assert_eq!(h3::decode_varint(&out), (out.len(), value), "varint {value} did not survive re-encoding");
}

pub fn websocket(data: &[u8]) {
    let Ok(Some((consumed, frame))) = websocket::Frame::decode(data) else {
        return;
    };

    assert!(consumed <= data.len(), "the frame decoder ran past the end of the input");

    let encoded = frame.encode();
    let again = websocket::Frame::decode(&encoded);

    assert_eq!(
        again.ok().flatten(),
        Some((encoded.len(), frame)),
        "a WebSocket frame did not survive re-encoding",
    );
}
