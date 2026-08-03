use soyokaze::helpers::fields::{HeaderField, Integer, StringLiteral};
use soyokaze::helpers::hpack::{Decoder, Encoder};

use super::input::Input;

pub fn check(data: &[u8]) {
    block(data);
    integers(data);
    strings(data);

    let mut input = Input::new(data);
    roundtrip(&input.sections(4, 12, 48));
}

pub fn block(data: &[u8]) {
    let mut decoder = Decoder::new();
    let Ok(fields) = decoder.decode(data) else {
        return;
    };

    let decoded: usize = fields.iter().map(HeaderField::size).sum();
    assert!(
        decoded <= Decoder::DEFAULT_MAX_DECODED_SIZE,
        "the decoder returned {decoded} octets past its own ceiling",
    );

    assert!(
        decoder.dynamic_table().size() <= decoder.dynamic_table().capacity(),
        "the dynamic table grew past its maximum size",
    );
}

pub fn integers(data: &[u8]) {
    for prefix_bits in 1..=8u8 {
        let Ok((consumed, value)) = Integer::decode(data, prefix_bits) else {
            continue;
        };

        assert!(consumed <= data.len(), "the integer decoder ran past the end of the input");

        let mut out = Vec::new();
        Integer::encode(&mut out, value, prefix_bits, 0);

        let again = Integer::decode(&out, prefix_bits);
        assert_eq!(again, Ok((out.len(), value)), "integer {value} did not survive prefix {prefix_bits}");
    }
}

pub fn strings(data: &[u8]) {
    let Ok((consumed, value)) = StringLiteral::decode(data, 7) else {
        return;
    };

    assert!(consumed <= data.len(), "the string decoder ran past the end of the input");

    for huffman in [false, true] {
        let mut out = Vec::new();
        StringLiteral::encode(&mut out, &value, 7, 0x00, huffman);

        let again = StringLiteral::decode(&out, 7);
        assert_eq!(again, Ok((out.len(), value.clone())), "a string did not survive huffman={huffman}");
    }
}

pub fn roundtrip(sections: &[Vec<HeaderField>]) {
    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();

    for fields in sections {
        let block = encoder.encode(fields);

        let decoded = match decoder.decode(&block) {
            Ok(decoded) => decoded,
            Err(err) => panic!("a block this encoder produced did not decode: {err}"),
        };

        assert_eq!(&decoded, fields, "a field section changed in transit");
        assert_eq!(
            encoder.dynamic_table().len(),
            decoder.dynamic_table().len(),
            "the two dynamic tables drifted apart",
        );
    }
}
