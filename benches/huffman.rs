mod support;

use soyokaze::helpers::huffman;
use support::{opaque, Group};

const CASES: &[(&str, &[u8])] = &[
    ("short value (15 B)", b"www.example.com"),
    ("path (32 B)", b"/assets/app.7f3c9a2b.module.js"),
    ("date (29 B)", b"Mon, 21 Oct 2013 20:13:21 GMT"),
    ("user-agent (72 B)", b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) soyokaze/0.1 like Gecko"),
    ("cookie (256 B)", &[b'a'; 256]),
    ("incompressible (64 B)", &[0xc0; 64]),
];

fn main() {
    let mut group = Group::new("huffman::encode");
    for (name, input) in CASES {
        group.throughput(name, input.len(), || huffman::encode(opaque(input)));
    }

    let mut group = Group::new("huffman::encoded_len");
    for (name, input) in CASES {
        group.throughput(name, input.len(), || huffman::encoded_len(opaque(input)));
    }

    let mut group = Group::new("huffman::decode");
    for (name, input) in CASES {
        let encoded = huffman::encode(input);
        group.throughput(name, input.len(), || huffman::decode(opaque(&encoded)));
    }

    let mut group = Group::new("huffman::decode (rejected)");
    group.throughput("all one-bits (64 B)", 64, || huffman::decode(opaque(&[0xffu8; 64])));

    let mut group = Group::new("huffman round trip");
    for (name, input) in CASES {
        group.throughput(name, input.len(), || huffman::decode(&huffman::encode(opaque(input))));
    }
}
