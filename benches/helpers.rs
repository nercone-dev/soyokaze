//! The codecs and primitives every version shares.
//!
//! Nothing here touches a connection: these are the pieces a message is taken
//! apart into and put back together from, measured on their own so that a
//! change in one of them is visible before it is buried in a whole exchange.
//!
//! Each codec is looked at four ways, because each answers a different
//! question about it:
//!
//! - **timed**, over the strings and bodies a real message carries;
//! - **as a throughput**, so a codec that is fast because its input was short
//!   is told apart from one that is fast per octet;
//! - **as a curve**, so that a cost that stops being bounded shows up as a
//!   slope rather than as one slow row at the end of a sweep;
//! - **on malformed input**, since a parser that is quick to accept and slow
//!   to refuse is a parser an attacker chooses the input for.
//!
//! ```bash
//! cargo bench --bench helpers
//! cargo bench --bench helpers -- hpack qpack
//! ```

mod support;

use std::hint::black_box;
use std::sync::Mutex;

use soyokaze::helpers::compression::{Coding, Compression};
use soyokaze::helpers::fields::{HeaderField, Integer, StringLiteral};
use soyokaze::helpers::hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder};
use soyokaze::helpers::qpack::{self, Decoder as QpackDecoder, DecoderInstruction, Encoder as QpackEncoder, EncoderInstruction};
use soyokaze::helpers::sync::{Lock, Timeout};
use soyokaze::helpers::text::{Text, INLINE};
use soyokaze::helpers::{base64, huffman, scan, sha1};

use support::{Fixtures, Group, Payload, Section};

/// The strings a growth curve over a length is taken over.
///
/// Field text rather than one repeated octet: the Huffman table is keyed by
/// how common a character is, so a curve over `aaaa...` measures the one code
/// it happens to land on rather than the spread a header value really carries.
fn ascii(octets: usize) -> Vec<u8> {
    let alphabet = b"/assets-0123456789abcdefghijklmnopqrstuvwxyz.";

    (0..octets).map(|at| alphabet[at % alphabet.len()]).collect()
}

fn huffman_coding() {
    let mut group = Group::new("huffman::encode");
    for (name, input) in Fixtures::STRINGS {
        group.throughput(name, input.len(), || huffman::encode(black_box(input)));
    }
    group.growth("over the length encoded", Fixtures::LENGTHS, ascii, |input| huffman::encode(black_box(input)));

    let mut group = Group::new("huffman::encoded_len");
    for (name, input) in Fixtures::STRINGS {
        group.throughput(name, input.len(), || huffman::encoded_len(black_box(input)));
    }

    let mut group = Group::new("huffman::decode");
    for (name, input) in Fixtures::STRINGS {
        let encoded = huffman::encode(input);
        group.throughput(name, input.len(), || huffman::decode(black_box(&encoded)));
    }
    group.growth("over the length decoded", Fixtures::LENGTHS, |octets| huffman::encode(&ascii(octets)), |input| huffman::decode(black_box(input)));

    let mut group = Group::new("huffman round trip");
    for (name, input) in Fixtures::STRINGS {
        group.throughput(name, input.len(), || huffman::decode(&huffman::encode(black_box(input))));
    }

    // What an attacker picks the input for. A refusal that walks the whole
    // input before answering costs what the input is long, so these are read
    // against the accepting cases above rather than on their own.
    let mut group = Group::new("huffman::decode (refused)");
    group.time("all one-bits (64 B)", || huffman::decode(black_box(&[0xffu8; 64])));
    group.time("padding longer than seven bits", || huffman::decode(black_box(&[0x3f, 0xff, 0xff, 0xff])));
    group.growth("all one-bits, over the length", Fixtures::LENGTHS, |octets| vec![0xffu8; octets], |input| huffman::decode(black_box(input)));
}

/// The content codings, over the three shapes a body comes in.
///
/// The ceiling is set past every fixture, so what is measured is the codec
/// rather than the bound. The ratio each coding reaches is written out beside
/// the timings, since a coding that is fast and a coding that is worth using
/// are not the same question and the second one is free to answer here.
fn content_codings() {
    const ROOMY: u64 = 1 << 24;
    const BODY: usize = 64 * 1024;

    let shapes = Payload::shapes(BODY);

    if Group::new("compression ratios").wanted() {
        println!("\ncompression ratios");
        println!("------------------");

        for coding in Compression::CODINGS {
            let ratios: Vec<String> = shapes
                .iter()
                .map(|(name, body)| {
                    let encoded = coding.encode(body).expect("the fixture did not encode");
                    format!("{name} {:.1} %", encoded.len() as f64 / body.len() as f64 * 100.0)
                })
                .collect();

            println!("  {coding:<12}{}", ratios.join("   "));
        }
    }

    for coding in Compression::CODINGS {
        let mut group = Group::new(format!("compression::encode ({coding})"));
        for (name, body) in &shapes {
            group.throughput(&format!("{name} (64 KiB)"), body.len(), || coding.encode(black_box(body)));
        }
        group.growth("over the length encoded", Fixtures::LENGTHS, Payload::text, |body| coding.encode(black_box(body)));

        let mut group = Group::new(format!("compression::decode ({coding})"));
        for (name, body) in &shapes {
            let encoded = coding.encode(body).expect("the fixture did not encode");
            group.throughput(&format!("{name} (64 KiB)"), body.len(), || coding.decode(black_box(&encoded), ROOMY));
        }
        group.growth(
            "over the length decoded",
            Fixtures::LENGTHS,
            |octets| coding.encode(&Payload::text(octets)).expect("the fixture did not encode"),
            |encoded| coding.decode(black_box(encoded), ROOMY),
        );
    }

    let mut group = Group::new("compression negotiation");
    group.time("accepted (four codings)", || Compression::accepted(black_box(["zstd;q=0.1, br, gzip, deflate"]).into_iter()));
    group.time("accepted (none acceptable)", || Compression::accepted(black_box(["identity;q=1.0, *;q=0"]).into_iter()));
    group.time("applied (one coding)", || Compression::applied(black_box(["gzip"]).into_iter()));
    group.time("encoded (one coding)", || Compression::encoded(black_box(["gzip"]).into_iter()));
    group.time("parse a token", || Compression::parse(black_box("deflate")));
    group.time("Coding::parse (with a quality)", || Coding::parse(black_box("br;q=0.8")));
    group.time("Coding::list (four codings)", || Coding::list(black_box("zstd;q=0.1, br, gzip, deflate")).count());
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
    group.time("decode (past what fits)", || Integer::decode(black_box(&[31, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127]), 5));
    group.time("decode (cut short)", || Integer::decode(black_box(&[31, 154]), 5));

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

    let mut group = Group::new("fields::HeaderField");
    let field = HeaderField::new("content-type", "text/html; charset=utf-8");
    group.time("new", || HeaderField::new(black_box("content-type"), "text/html; charset=utf-8"));
    group.time("size", || black_box(&field).size());
    group.time("sensitive (a name that is not)", || black_box(&field).sensitive());
    group.time("sensitive (a name that is)", || HeaderField::new("cookie", "a=1").sensitive());
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
    group.growth("over the field count (warm table)", Fixtures::COUNTS, warm_hpack, |(encoder, fields)| encoder.encode(black_box(fields)));

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
    group.time("a name that is not a name", || HpackDecoder::new().decode(black_box(&[0x40, 0x03, b'A', b':', b'b', 0x01, b'v'])));
}

/// An encoder with this many fields already in its table, and the fields to
/// encode again.
fn warm_hpack(fields: usize) -> (HpackEncoder, Vec<HeaderField>) {
    let held: Vec<HeaderField> = (0..fields).map(|index| HeaderField::new(Section::field(index), "8f14e45fceea167a5a36dedd4bea2543")).collect();

    let mut encoder = HpackEncoder::new();
    let _ = encoder.encode(&held);

    (encoder, held)
}

fn ready() -> QpackEncoder {
    let mut encoder = QpackEncoder::new();
    encoder.set_max_capacity(QpackDecoder::DEFAULT_MAX_CAPACITY);
    encoder
}

/// How much of an encoder stream is handed over at once.
///
/// A decoder refuses a single buffered instruction past a ceiling, and a
/// section of a few thousand fields writes more insertions than that ceiling
/// holds — so the stream is delivered the way a connection delivers it, in
/// pieces the decoder consumes as they arrive, rather than in one blob no real
/// peer would send.
const STREAM_CHUNK: usize = 4096;

fn warmed(fields: &[HeaderField]) -> (QpackEncoder, QpackDecoder) {
    let mut encoder = ready();
    let mut decoder = QpackDecoder::new();

    let block = encoder.encode(0, fields);
    let stream = encoder.take_encoder_stream();

    for chunk in stream.chunks(STREAM_CHUNK) {
        decoder.on_encoder_stream(chunk).expect("the encoder stream was refused");
    }

    for chunk in decoder.take_decoder_stream().chunks(STREAM_CHUNK) {
        encoder.on_decoder_stream(chunk).expect("the decoder stream was refused");
    }

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
    group.growth(
        "over the field count (warm table)",
        Fixtures::COUNTS,
        |fields| {
            let held: Vec<HeaderField> = (0..fields).map(|index| HeaderField::new(Section::field(index), "8f14e45fceea167a5a36dedd4bea2543")).collect();
            let (encoder, _) = warmed(&held);
            (encoder, held)
        },
        |(encoder, fields)| {
            let encoded = encoder.encode(4, black_box(fields));
            encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 4 });
            encoded
        },
    );

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

    group.growth("encode, over the length", Fixtures::LENGTHS, |octets| vec![0x5au8; octets], |input| base64::encode(black_box(input)));
    group.growth("decode, over the length", Fixtures::LENGTHS, |octets| base64::encode(&vec![0x5au8; octets]), |input| base64::decode(black_box(input)));
    group.time("decode (an octet that is not base64)", || base64::decode(black_box("dGhlIHNhbX!sZSBub25jZQ==")));

    let mut group = Group::new("sha1");
    for (name, octets) in Fixtures::SIZES {
        let input = vec![0x5au8; *octets];
        group.throughput(name, *octets, || sha1::sha1(black_box(&input)));
    }
    group.throughput("60 B (a websocket key)", 60, || sha1::sha1(black_box(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
    group.growth("over the length", Fixtures::LENGTHS, |octets| vec![0x5au8; octets], |input| sha1::sha1(black_box(input)));
}

fn text() {
    let mut group = Group::new("helpers::text::Text");
    for (name, length) in [("inline (8 B)", 8usize), ("at the boundary (30 B)", INLINE), ("just past it (31 B)", INLINE + 1), ("heap (256 B)", 256)] {
        let source = "Content-Type".repeat(length / 12 + 1)[..length].to_owned();

        group.time(&format!("from_str, {name}"), || Text::from_str(black_box(&source)));
        group.time(&format!("from_ascii_lowercase, {name}"), || Text::from_ascii_lowercase(black_box(source.as_bytes())));

        let text = Text::from_str(&source);
        group.time(&format!("clone, {name}"), || black_box(&text).clone());
        group.time(&format!("as_str, {name}"), || black_box(&text).as_str().len());

        group.time(&format!("make_ascii_lowercase, {name}"), || {
            let mut held = Text::from_str(black_box(&source));
            held.make_ascii_lowercase();
            held
        });
    }

    let inline = Text::from_str("content-type");
    let heap = Text::from_str(&"content-type".repeat(8));
    group.time("compare, inline against inline", || black_box(&inline) == black_box(&inline));
    group.time("compare, heap against heap", || black_box(&heap) == black_box(&heap));

    group.growth("from_str, over the length", Fixtures::LENGTHS, |octets| "c".repeat(octets), |source| Text::from_str(black_box(source)));
}

fn scanning() {
    let mut group = Group::new("helpers::scan");
    for (name, octets) in [("16 B", 16usize), ("64 B", 64), ("1 KiB", 1024)] {
        let value = vec![b'x'; octets];
        group.throughput(&format!("classify_field_value ({name})"), octets, || scan::classify_field_value(black_box(&value)));
        group.throughput(&format!("is_field_value ({name})"), octets, || scan::is_field_value(black_box(&value)));
        group.throughput(&format!("all_visible ({name})"), octets, || scan::all_visible(black_box(&value)));

        let haystack = vec![b'x'; octets];
        group.throughput(&format!("find, absent ({name})"), octets, || scan::find(black_box(&haystack), b':'));

        let mut present = haystack.clone();
        present[octets / 2] = b':';
        group.throughput(&format!("find, halfway ({name})"), octets / 2, || scan::find(black_box(&present), b':'));

        let mut destination = vec![0u8; octets];
        group.throughput(&format!("copy ({name})"), octets, || scan::copy(black_box(&mut destination), &haystack));
    }

    let mut lowercase = [0u8; 256];
    for (value, slot) in lowercase.iter_mut().enumerate() {
        *slot = (value as u8).is_ascii_lowercase() as u8;
    }

    let name = vec![b'a'; 32];
    group.throughput("all_in_class (32 B)", name.len(), || scan::all_in_class(black_box(&name), &lowercase, 1));

    // Every one of these walks its input, so all four should read as linear.
    // One that does not is either doing less work than it looks or more.
    let mut group = Group::new("helpers::scan growth");
    group.growth("find, absent", Fixtures::LENGTHS, |octets| vec![b'x'; octets], |haystack| scan::find(black_box(haystack), b':'));
    group.growth("find, at the very end", Fixtures::LENGTHS, |octets| {
        let mut haystack = vec![b'x'; octets];
        *haystack.last_mut().expect("an empty haystack") = b':';
        haystack
    }, |haystack| scan::find(black_box(haystack), b':'));
    group.growth("classify_field_value", Fixtures::LENGTHS, |octets| vec![b'x'; octets], |value| scan::classify_field_value(black_box(value)));
    group.growth("copy", Fixtures::LENGTHS, |octets| (vec![0u8; octets], vec![b'x'; octets]), |(destination, source)| scan::copy(black_box(destination), source));
}

/// The locking and deadline helpers every connection reaches for.
///
/// Uncontended here, which is the cost a connection actually pays when nothing
/// else is running; what the same calls cost when every worker makes them at
/// once is in `--bench concurrency`.
fn synchronizing() {
    let mut group = Group::new("helpers::sync");

    group.time("Timeout::armed (a deadline)", || Timeout::armed(black_box(30.0)));
    group.time("Timeout::armed (no deadline)", || Timeout::armed(black_box(0.0)));
    group.time("Timeout::duration (a deadline)", || Timeout::duration(black_box(30.0)));
    group.time("Timeout::duration (no deadline)", || Timeout::duration(black_box(0.0)));

    let mutex = Mutex::new(0u64);
    group.time("Lock::on (uncontended)", || {
        let mut held = Lock::on(black_box(&mutex));
        *held += 1;
    });
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
    synchronizing();
}
