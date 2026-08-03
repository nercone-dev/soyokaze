use soyokaze::helpers::fields::{Error, HeaderField, Integer, StringLiteral};

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField::new(name, value)
}

#[test]
fn encodes_the_specification_integers() {
    let mut out = Vec::new();
    Integer::encode(&mut out, 10, 5, 0);
    assert_eq!(out, [10]);

    let mut out = Vec::new();
    Integer::encode(&mut out, 1337, 5, 0);
    assert_eq!(out, [31, 154, 10]);

    let mut out = Vec::new();
    Integer::encode(&mut out, 42, 8, 0);
    assert_eq!(out, [42]);
}

#[test]
fn decodes_the_specification_integers() {
    assert_eq!(Integer::decode(&[10], 5), Ok((1, 10)));
    assert_eq!(Integer::decode(&[31, 154, 10], 5), Ok((3, 1337)));
    assert_eq!(Integer::decode(&[42], 8), Ok((1, 42)));
}

#[test]
fn keeps_the_flag_bits_above_the_prefix() {
    let mut out = Vec::new();
    Integer::encode(&mut out, 2, 6, 0x40);
    assert_eq!(out, [0x42]);
    assert_eq!(Integer::decode(&out, 6), Ok((1, 2)));
}

#[test]
fn round_trips_integers_at_every_prefix() {
    let values = [0, 1, 2, 14, 15, 16, 30, 31, 32, 127, 128, 255, 256, 16_383, 1 << 32, u64::MAX];

    for prefix_bits in 1..=8u8 {
        for value in values {
            let mut out = Vec::new();
            Integer::encode(&mut out, value, prefix_bits, 0);
            assert_eq!(Integer::decode(&out, prefix_bits), Ok((out.len(), value)), "{value} at {prefix_bits}");
        }
    }
}

#[test]
fn reports_a_truncated_integer() {
    assert_eq!(Integer::decode(&[], 5), Err(Error::Incomplete));
    assert_eq!(Integer::decode(&[31, 154], 5), Err(Error::Incomplete));
}

#[test]
fn refuses_an_integer_that_does_not_fit() {
    let overflowing = [0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f];
    assert_eq!(Integer::decode(&overflowing, 8), Err(Error::IntegerOverflow));
}

#[test]
fn round_trips_strings_both_ways() {
    for value in [&b""[..], b"a", b"custom-key", b"www.example.com", &[0xff, 0x00, 0x80]] {
        for huffman in [false, true] {
            let mut out = Vec::new();
            StringLiteral::encode(&mut out, value, 7, 0x00, huffman);

            assert_eq!(out.first().is_some_and(|first| first & 0x80 != 0), huffman);
            assert_eq!(StringLiteral::decode(&out, 7), Ok((out.len(), value.to_vec())));
        }
    }
}

#[test]
fn moves_the_huffman_mark_with_the_prefix() {
    for prefix_bits in [3, 4, 5, 6, 7u8] {
        for huffman in [false, true] {
            let mut out = Vec::new();
            StringLiteral::encode(&mut out, b"www.example.com", prefix_bits, 0x00, huffman);

            assert_eq!(out.first().is_some_and(|first| first & 1 << prefix_bits != 0), huffman);
            assert_eq!(StringLiteral::decode(&out, prefix_bits), Ok((out.len(), b"www.example.com".to_vec())));
        }
    }
}

#[test]
fn reports_a_string_that_ends_early() {
    assert_eq!(StringLiteral::decode(&[0x05, b'a', b'b'], 7), Err(Error::Incomplete));
    assert_eq!(StringLiteral::decode(&[], 7), Err(Error::Incomplete));
}

#[test]
fn refuses_a_string_whose_length_cannot_be_addressed() {
    let huge = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
    assert!(matches!(StringLiteral::decode(&huge, 7), Err(Error::Incomplete | Error::IntegerOverflow)));
}

#[test]
fn prefers_huffman_only_when_it_helps() {
    assert!(StringLiteral::prefers_huffman(b"www.example.com"));
    assert!(!StringLiteral::prefers_huffman(&[0xc0; 8]));
}

#[test]
fn every_sensitive_name_is_recognised() {
    for name in HeaderField::SENSITIVE {
        assert!(field(name, "value").sensitive(), "{name} should be treated as sensitive");
    }

    assert!(!field("accept", "value").sensitive());
}

#[test]
fn a_field_costs_its_octets_plus_the_overhead() {
    assert_eq!(field("name", "value").size(), 4 + 5 + HeaderField::OVERHEAD);
    assert_eq!(field("", "").size(), HeaderField::OVERHEAD);
}

#[test]
fn errors_describe_themselves() {
    assert_eq!(Error::IntegerOverflow.to_string(), "integer representation overflowed");
    assert_eq!(Error::Incomplete.to_string(), "representation ends before the input does");
}
