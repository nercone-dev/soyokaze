mod support;

use soyokaze::helpers::fields::{self, HeaderField};
use soyokaze::helpers::hpack::{Decoder, Encoder};
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
        field("accept-language", "en-GB,en;q=0.9"),
        field("cache-control", "no-cache"),
        field("cookie", "session=8f14e45fceea167a5a36dedd4bea2543; consent=1; locale=en-GB; theme=dark"),
        field("referer", "https://www.example.com/index.html"),
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
        field("cache-control", "max-age=0, private, must-revalidate"),
        field("strict-transport-security", "max-age=31536000; includeSubDomains"),
        field("vary", "accept-encoding"),
    ]
}

fn octets(fields: &[HeaderField]) -> usize {
    fields.iter().map(|field| field.name.len() + field.value.len()).sum()
}

fn main() {
    let sections: [(&str, Vec<HeaderField>); 2] = [("request (11 fields)", request()), ("response (8 fields)", response())];

    let mut group = Group::new("hpack::Encoder::encode (cold table)");
    for (name, fields) in &sections {
        group.throughput(name, octets(fields), || Encoder::new().encode(opaque(fields)));
    }

    let mut group = Group::new("hpack::Encoder::encode (warm table)");
    for (name, fields) in &sections {
        let mut encoder = Encoder::new();
        let _ = encoder.encode(fields);
        group.throughput(name, octets(fields), || encoder.encode(opaque(fields)));
    }

    let mut group = Group::new("hpack::Decoder::decode (cold table)");
    for (name, fields) in &sections {
        let block = Encoder::new().encode(fields);
        group.throughput(name, block.len(), || Decoder::new().decode(opaque(&block)));
    }

    let mut group = Group::new("hpack::Decoder::decode (warm table)");
    for (name, fields) in &sections {
        let mut encoder = Encoder::new();
        let first = encoder.encode(fields);
        let block = encoder.encode(fields);

        let mut decoder = Decoder::new();
        let _ = decoder.decode(&first);

        group.throughput(name, block.len(), || decoder.decode(opaque(&block)));
    }

    let mut group = Group::new("fields primitives");
    group.bench("Integer::encode (fits the prefix)", || {
        let mut out = Vec::new();
        fields::Integer::encode(&mut out, opaque(10), 5, 0);
        out
    });
    group.bench("Integer::encode (continuation)", || {
        let mut out = Vec::new();
        fields::Integer::encode(&mut out, opaque(1337), 5, 0);
        out
    });
    group.bench("Integer::decode (fits the prefix)", || fields::Integer::decode(opaque(&[10]), 5));
    group.bench("Integer::decode (continuation)", || fields::Integer::decode(opaque(&[31, 154, 10]), 5));

    let value = b"www.example.com";
    group.throughput("StringLiteral::encode (huffman)", value.len(), || {
        let mut out = Vec::new();
        fields::StringLiteral::encode(&mut out, opaque(value), 7, 0x00, true);
        out
    });

    let mut encoded = Vec::new();
    fields::StringLiteral::encode(&mut encoded, value, 7, 0x00, true);
    group.throughput("StringLiteral::decode (huffman)", value.len(), || fields::StringLiteral::decode(opaque(&encoded), 7));

    let mut group = Group::new("hpack::Decoder::decode (rejected)");
    group.bench("index that names nothing", || Decoder::new().decode(opaque(&[0xbe])));
    group.bench("truncated literal", || Decoder::new().decode(opaque(&[0x40, 0x05, b'a'])));
}
