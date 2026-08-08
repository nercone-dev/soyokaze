mod support;

use soyokaze::helpers::fields::HeaderField;
use soyokaze::helpers::qpack::{self, Decoder, DecoderInstruction, Encoder, EncoderInstruction};
use support::{opaque, Group};

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField::new(name, value)
}

fn request() -> Vec<HeaderField> {
    vec![
        field(":method", "GET"),
        field(":scheme", "https"),
        field(":authority", "www.example.com"),
        field(":path", "/assets/app.7f3c9a2b.module.js"),
        field("accept", "*/*"),
        field("accept-encoding", "gzip, deflate, br"),
        field("cookie", "session=8f14e45fceea167a5a36dedd4bea2543; consent=1; locale=en-GB"),
        field("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) soyokaze/0.1 like Gecko"),
    ]
}

fn response() -> Vec<HeaderField> {
    vec![
        field(":status", "200"),
        field("content-type", "text/html; charset=utf-8"),
        field("content-length", "16384"),
        field("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        field("server", "Soyokaze"),
        field("strict-transport-security", "max-age=31536000; includeSubDomains"),
        field("vary", "accept-encoding"),
    ]
}

fn octets(fields: &[HeaderField]) -> usize {
    fields.iter().map(|field| field.name.len() + field.value.len()).sum()
}

fn ready() -> Encoder {
    let mut encoder = Encoder::new();
    encoder.set_max_capacity(qpack::Decoder::DEFAULT_MAX_CAPACITY);
    encoder
}

fn warmed(fields: &[HeaderField]) -> (Encoder, Decoder) {
    let mut encoder = ready();
    let mut decoder = Decoder::new();

    let block = encoder.encode(0, fields);
    let stream = encoder.take_encoder_stream();
    decoder.on_encoder_stream(&stream).expect("the encoder stream was refused");
    let answers = decoder.take_decoder_stream();
    encoder.on_decoder_stream(&answers).expect("the decoder stream was refused");

    if let Ok((_, Some(acknowledgment))) = decoder.decode(0, &block) {
        encoder.on_decoder_instruction(acknowledgment);
    }

    (encoder, decoder)
}

fn main() {
    let sections: [(&str, Vec<HeaderField>); 2] = [("request (8 fields)", request()), ("response (7 fields)", response())];

    let mut group = Group::new("qpack::Encoder::encode (cold table)");
    for (name, fields) in &sections {
        group.throughput(name, octets(fields), || ready().encode(0, opaque(fields)));
    }

    let mut group = Group::new("qpack::Encoder::encode + acknowledge (warm table)");
    for (name, fields) in &sections {
        let (mut encoder, _) = warmed(fields);
        group.throughput(name, octets(fields), || {
            let encoded = encoder.encode(4, opaque(fields));
            encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 4 });
            encoded
        });
    }

    let mut group = Group::new("qpack::Decoder::decode (static only)");
    for (name, fields) in &sections {
        let block = ready().encode(0, fields);
        group.throughput(name, block.len(), || Decoder::new().decode(0, opaque(&block)));
    }

    let mut group = Group::new("qpack::Decoder::decode (warm table)");
    for (name, fields) in &sections {
        let (mut encoder, mut decoder) = warmed(fields);
        let block = encoder.encode(4, fields);

        group.throughput(name, block.len(), || decoder.decode(8, opaque(&block)));
    }

    let mut group = Group::new("qpack instructions");
    let insert = EncoderInstruction::InsertWithNameReference {
        from_static: true,
        name_index: 17,
        value: b"www.example.com".to_vec(),
    };
    let encoded = insert.encode();
    group.bench("InsertWithNameReference::encode", || opaque(&insert).encode());
    group.bench("InsertWithNameReference::decode", || EncoderInstruction::decode(opaque(&encoded)));

    let acknowledgment = DecoderInstruction::SectionAcknowledgment { stream_id: 4 };
    let encoded = acknowledgment.encode();
    group.bench("SectionAcknowledgment::decode", || DecoderInstruction::decode(opaque(&encoded)));

    let mut group = Group::new("qpack insert counts");
    let capacity = qpack::Decoder::DEFAULT_MAX_CAPACITY;
    group.bench("encode_insert_count", || qpack::Prefix::encode_insert_count(opaque(64), capacity));
    group.bench("decode_insert_count", || qpack::Prefix::decode_insert_count(opaque(65), 64, capacity));

    let mut group = Group::new("qpack::Decoder::decode (rejected)");
    group.bench("blocked on a missing insert", || Decoder::new().decode(0, opaque(&[0xff, 0xff, 0xff, 0x00])));
    group.bench("truncated prefix", || Decoder::new().decode(0, opaque(&[0x00])));
}
