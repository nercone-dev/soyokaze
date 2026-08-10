//! The codecs and primitives every version shares.
//!
//! Nothing here touches a connection: these are the pieces a message is taken
//! apart into and put back together from, measured on their own so that a
//! change in one of them is visible before it is buried in a whole exchange.
//!
//! ```bash
//! cargo bench --bench helpers
//! cargo bench --bench helpers -- hpack qpack
//! ```

mod support;

use std::hint::black_box;

use soyokaze::helpers::fields::{Integer, StringLiteral};
use soyokaze::helpers::hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder};
use soyokaze::helpers::qpack::{self, Decoder as QpackDecoder, DecoderInstruction, Encoder as QpackEncoder, EncoderInstruction};
use soyokaze::helpers::text::{Text, INLINE};
use soyokaze::helpers::compression::Compression;
use soyokaze::helpers::{base64, huffman, scan, sha1};

use support::{Fixtures, Group, Payload, Section};

fn huffman_coding() {
    let mut group = Group::new("huffman::encode");
    for (name, input) in Fixtures::STRINGS {
        group.throughput(name, input.len(), || huffman::encode(black_box(input)));
    }

    let mut group = Group::new("huffman::encoded_len");
    for (name, input) in Fixtures::STRINGS {
        group.throughput(name, input.len(), || huffman::encoded_len(black_box(input)));
    }

    let mut group = Group::new("huffman::decode");
    for (name, input) in Fixtures::STRINGS {
        let encoded = huffman::encode(input);
        group.throughput(name, input.len(), || huffman::decode(black_box(&encoded)));
    }

    let mut group = Group::new("huffman round trip");
    for (name, input) in Fixtures::STRINGS {
        group.throughput(name, input.len(), || huffman::decode(&huffman::encode(black_box(input))));
    }

    let mut group = Group::new("huffman::decode (refused)");
    group.time("all one-bits (64 B)", || huffman::decode(black_box(&[0xffu8; 64])));
    group.time("padding longer than seven bits", || huffman::decode(black_box(&[0x3f, 0xff, 0xff, 0xff])));
}

/// The content codings, over a body that compresses like text and one that
/// does not, so that both the work and the ratio are visible.
///
/// The ceiling is set past every fixture, so what is measured is the codec
/// rather than the bound.
fn content_codings() {
    const ROOMY: u64 = 1 << 24;

    let bodies: &[(&str, Vec<u8>)] = &[
        ("compressible (64 KiB)", vec![b'a'; 64 * 1024]),
        ("mixed (64 KiB)", Payload::of(64 * 1024).to_vec()),
        ("compressible (1 MiB)", vec![b'a'; 1 << 20]),
    ];

    for coding in Compression::CODINGS {
        let mut group = Group::new(format!("compression::encode ({coding})"));
        for (name, body) in bodies {
            group.throughput(name, body.len(), || coding.encode(black_box(body)));
        }

        let mut group = Group::new(format!("compression::decode ({coding})"));
        for (name, body) in bodies {
            let encoded = coding.encode(body).expect("the fixture did not encode");
            group.throughput(name, body.len(), || coding.decode(black_box(&encoded), ROOMY));
        }
    }

    let mut group = Group::new("compression negotiation");
    group.time("accepted (four codings)", || Compression::accepted(black_box(["zstd;q=0.1, br, gzip, deflate"]).into_iter()));
    group.time("applied (one coding)", || Compression::applied(black_box(["gzip"]).into_iter()));
    group.time("parse a token", || Compression::parse(black_box("deflate")));
}

fn field_primitives() {
    let mut group = Group::new("fields::Integer");
    group.time("encode (fits the prefix)", || {
        let mut out = Vec::new();
        Integer::encode(&mut out, black_box(10), 5, 0);
        out
    });
    group.time("encode (one continuation)", || {
        let mut out = Vec::new();
        Integer::encode(&mut out, black_box(1337), 5, 0);
        out
    });
    group.time("encode (the largest there is)", || {
        let mut out = Vec::new();
        Integer::encode(&mut out, black_box(u64::MAX), 5, 0);
        out
    });
    group.time("decode (fits the prefix)", || Integer::decode(black_box(&[10]), 5));
    group.time("decode (one continuation)", || Integer::decode(black_box(&[31, 154, 10]), 5));

    let mut group = Group::new("fields::StringLiteral");
    for (name, value) in Fixtures::STRINGS {
        for (coding, huffman) in [("plain", false), ("huffman", true)] {
            group.throughput(&format!("encode {coding} ({name})"), value.len(), || {
                let mut out = Vec::new();
                StringLiteral::encode(&mut out, black_box(value), 7, 0x00, huffman);
                out
            });

            let mut encoded = Vec::new();
            StringLiteral::encode(&mut encoded, value, 7, 0x00, huffman);
            group.throughput(&format!("decode {coding} ({name})"), value.len(), || StringLiteral::decode(black_box(&encoded), 7));
        }
    }
}

fn hpack() {
    let sections = Section::both();

    let mut group = Group::new("hpack::Encoder::encode");
    for section in &sections {
        group.throughput(&format!("{} (cold table)", section.name), section.octets(), || HpackEncoder::new().encode(black_box(&section.fields)));
    }
    for section in &sections {
        let mut encoder = HpackEncoder::new();
        let _ = encoder.encode(&section.fields);

        group.throughput(&format!("{} (warm table)", section.name), section.octets(), || encoder.encode(black_box(&section.fields)));
    }

    let mut group = Group::new("hpack::Decoder::decode");
    for section in &sections {
        let block = HpackEncoder::new().encode(&section.fields);
        group.throughput(&format!("{} (cold table)", section.name), block.len(), || HpackDecoder::new().decode(black_box(&block)));
    }
    for section in &sections {
        let mut encoder = HpackEncoder::new();
        let first = encoder.encode(&section.fields);
        let block = encoder.encode(&section.fields);

        let mut decoder = HpackDecoder::new();
        let _ = decoder.decode(&first);

        group.throughput(&format!("{} (warm table)", section.name), block.len(), || decoder.decode(black_box(&block)));
    }

    let mut group = Group::new("hpack::Decoder::decode (refused)");
    group.time("an index naming nothing", || HpackDecoder::new().decode(black_box(&[0xbe])));
    group.time("a literal cut short", || HpackDecoder::new().decode(black_box(&[0x40, 0x05, b'a'])));
    group.time("an update past the ceiling", || HpackDecoder::new().decode(black_box(&[0x3f, 0xe1, 0xff, 0xff, 0x07])));
}

fn ready() -> QpackEncoder {
    let mut encoder = QpackEncoder::new();
    encoder.set_max_capacity(QpackDecoder::DEFAULT_MAX_CAPACITY);
    encoder
}

fn warmed(fields: &[soyokaze::helpers::fields::HeaderField]) -> (QpackEncoder, QpackDecoder) {
    let mut encoder = ready();
    let mut decoder = QpackDecoder::new();

    let block = encoder.encode(0, fields);
    let stream = encoder.take_encoder_stream();
    decoder.on_encoder_stream(&stream).expect("the encoder stream was refused");
    encoder.on_decoder_stream(&decoder.take_decoder_stream()).expect("the decoder stream was refused");

    if let Ok((_, Some(acknowledgment))) = decoder.decode(0, &block) {
        encoder.on_decoder_instruction(acknowledgment);
    }

    (encoder, decoder)
}

fn qpack() {
    let sections = Section::both();

    let mut group = Group::new("qpack::Encoder::encode");
    for section in &sections {
        group.throughput(&format!("{} (cold table)", section.name), section.octets(), || ready().encode(0, black_box(&section.fields)));
    }
    for section in &sections {
        let (mut encoder, _) = warmed(&section.fields);

        group.throughput(&format!("{} (warm table)", section.name), section.octets(), || {
            let encoded = encoder.encode(4, black_box(&section.fields));
            encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 4 });
            encoded
        });
    }

    let mut group = Group::new("qpack::Decoder::decode");
    for section in &sections {
        let block = ready().encode(0, &section.fields);
        group.throughput(&format!("{} (static only)", section.name), block.len(), || QpackDecoder::new().decode(0, black_box(&block)));
    }
    for section in &sections {
        let (mut encoder, mut decoder) = warmed(&section.fields);
        let block = encoder.encode(4, &section.fields);

        group.throughput(&format!("{} (warm table)", section.name), block.len(), || decoder.decode(8, black_box(&block)));
    }

    let mut group = Group::new("qpack instructions");
    let insert = EncoderInstruction::InsertWithNameReference { from_static: true, name_index: 17, value: b"www.example.com".to_vec() };
    let encoded = insert.encode();
    group.time("InsertWithNameReference::encode", || black_box(&insert).encode());
    group.time("InsertWithNameReference::decode", || EncoderInstruction::decode(black_box(&encoded)));

    let acknowledgment = DecoderInstruction::SectionAcknowledgment { stream_id: 4 };
    let encoded = acknowledgment.encode();
    group.time("SectionAcknowledgment::encode", || black_box(&acknowledgment).encode());
    group.time("SectionAcknowledgment::decode", || DecoderInstruction::decode(black_box(&encoded)));

    let capacity = QpackDecoder::DEFAULT_MAX_CAPACITY;
    group.time("Prefix::encode_insert_count", || qpack::Prefix::encode_insert_count(black_box(64), capacity));
    group.time("Prefix::decode_insert_count", || qpack::Prefix::decode_insert_count(black_box(65), 64, capacity));

    let mut group = Group::new("qpack::Decoder::decode (refused)");
    group.time("blocked on an insert never made", || QpackDecoder::new().decode(0, black_box(&[0xff, 0xff, 0xff, 0x00])));
    group.time("a prefix cut short", || QpackDecoder::new().decode(0, black_box(&[0x00])));
}

fn digests() {
    let mut group = Group::new("base64");
    for (name, octets) in Fixtures::SIZES {
        let input = vec![0x5au8; *octets];
        group.throughput(&format!("encode ({name})"), *octets, || base64::encode(black_box(&input)));

        let encoded = base64::encode(&input);
        group.throughput(&format!("decode ({name})"), *octets, || base64::decode(black_box(&encoded)));
    }

    let mut group = Group::new("sha1");
    for (name, octets) in Fixtures::SIZES {
        let input = vec![0x5au8; *octets];
        group.throughput(name, *octets, || sha1::sha1(black_box(&input)));
    }
    group.throughput("60 B (a websocket key)", 60, || sha1::sha1(black_box(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
}

fn text() {
    let mut group = Group::new("helpers::text::Text");
    for (name, length) in [("inline (8 B)", 8usize), ("at the boundary (30 B)", INLINE), ("just past it (31 B)", INLINE + 1), ("heap (256 B)", 256)] {
        let source = "Content-Type".repeat(length / 12 + 1)[..length].to_owned();

        group.time(&format!("from_str, {name}"), || Text::from_str(black_box(&source)));
        group.time(&format!("from_ascii_lowercase, {name}"), || Text::from_ascii_lowercase(black_box(source.as_bytes())));

        let text = Text::from_str(&source);
        group.time(&format!("clone, {name}"), || black_box(&text).clone());

        group.time(&format!("make_ascii_lowercase, {name}"), || {
            let mut held = Text::from_str(black_box(&source));
            held.make_ascii_lowercase();
            held
        });
    }
}

fn scanning() {
    let mut group = Group::new("helpers::scan");
    for (name, octets) in [("16 B", 16usize), ("64 B", 64), ("1 KiB", 1024)] {
        let value = vec![b'x'; octets];
        group.throughput(&format!("classify_field_value ({name})"), octets, || scan::classify_field_value(black_box(&value)));
        group.throughput(&format!("is_field_value ({name})"), octets, || scan::is_field_value(black_box(&value)));

        let haystack = vec![b'x'; octets];
        group.throughput(&format!("find, absent ({name})"), octets, || scan::find(black_box(&haystack), b':'));

        let mut present = haystack.clone();
        present[octets / 2] = b':';
        group.throughput(&format!("find, halfway ({name})"), octets / 2, || scan::find(black_box(&present), b':'));

        let mut destination = vec![0u8; octets];
        group.throughput(&format!("copy ({name})"), octets, || scan::copy(black_box(&mut destination), &haystack));
    }

    let mut table = [0u8; 256];
    for (value, slot) in table.iter_mut().enumerate() {
        *slot = (value as u8).is_ascii_lowercase() as u8;
    }

    let name = vec![b'a'; 32];
    group.throughput("all_in_class (32 B)", name.len(), || scan::all_in_class(black_box(&name), &table, 1));
}

fn main() {
    huffman_coding();
    content_codings();
    field_primitives();
    hpack();
    qpack();
    digests();
    text();
    scanning();
}
