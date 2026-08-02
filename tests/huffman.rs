use soyokaze::helpers::huffman::{self, Branch, DecodeError, DecodeTable, EOS};

const VECTORS: &[(&str, &[u8])] = &[
    ("www.example.com", &[0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]),
    ("no-cache", &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]),
    ("custom-key", &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]),
    ("custom-value", &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf]),
    ("302", &[0x64, 0x02]),
    ("private", &[0xae, 0xc3, 0x77, 0x1a, 0x4b]),
    ("Mon, 21 Oct 2013 20:13:21 GMT", &[
        0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81,
        0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff,
    ]),
    ("https://www.example.com", &[
        0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae,
        0x43, 0xd3,
    ]),
];

#[test]
fn matches_the_specification_vectors() {
    for (text, encoded) in VECTORS {
        assert_eq!(&huffman::encode(text.as_bytes())[..], *encoded, "encoding {text:?}");
        assert_eq!(huffman::decode(encoded).as_deref(), Ok(text.as_bytes()), "decoding {text:?}");
    }
}

#[test]
fn encodes_an_empty_string_to_nothing() {
    assert!(huffman::encode(b"").is_empty());
    assert_eq!(huffman::decode(b"").as_deref(), Ok(&b""[..]));
    assert_eq!(huffman::encoded_len(b""), 0);
}

#[test]
fn round_trips_every_octet() {
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(huffman::decode(&huffman::encode(&all)).as_deref(), Ok(&all[..]));
}

#[test]
fn encoded_len_agrees_with_encode() {
    for length in 0..64 {
        let input: Vec<u8> = (0..length).map(|index: u8| index.wrapping_mul(37)).collect();
        assert_eq!(huffman::encoded_len(&input), huffman::encode(&input).len(), "length {length}");
    }
}

#[test]
fn shortens_text_and_lengthens_random_octets() {
    let text = b"https://www.example.com/index.html";
    assert!(huffman::encode(text).len() < text.len());

    let high = [0xc0u8; 16];
    assert!(huffman::encode(&high).len() > high.len());
}

#[test]
#[allow(clippy::unusual_byte_groupings)]
fn rejects_padding_that_is_not_all_ones() {
    assert_eq!(huffman::decode(&[0b00011_000]), Err(DecodeError::InvalidPadding));
}

#[test]
fn rejects_padding_longer_than_seven_bits() {
    let mut encoded = huffman::encode(b"a").to_vec();
    encoded.push(0xff);

    assert_eq!(huffman::decode(&encoded), Err(DecodeError::InvalidPadding));
}

#[test]
fn rejects_an_encoded_end_of_string_symbol() {
    assert_eq!(huffman::decode(&[0xff, 0xff, 0xff, 0xff]), Err(DecodeError::InvalidPadding));
}

#[test]
fn never_panics_on_arbitrary_octets() {
    for first in 0..=255u8 {
        for second in 0..=255u8 {
            let _ = huffman::decode(&[first, second]);
        }
    }
}

#[test]
fn the_decode_table_covers_every_symbol() {
    let table = DecodeTable::new(huffman::table());

    for (value, symbol) in huffman::table().iter().enumerate() {
        let mut node = 0;
        let mut reached = None;

        for depth in (0..symbol.length).rev() {
            let bit = symbol.code >> depth & 1 == 1;
            match table.step(node, bit) {
                Some(Branch::Node(next)) => node = next,
                Some(Branch::Symbol(symbol)) => {
                    reached = Some(symbol);
                    break;
                }
                None => break,
            }
        }

        assert_eq!(reached, Some(value as u16), "symbol {value} is not reachable in the decode table");
    }
}

#[test]
fn stepping_off_the_decode_table_yields_nothing() {
    let table = huffman::decode_table();
    assert_eq!(table.step(usize::MAX, true), None);
    assert_eq!(table.step(table.branches.len(), false), None);
}

#[test]
fn the_end_of_string_symbol_is_the_last_entry() {
    assert_eq!(huffman::table().len(), EOS as usize + 1);
    assert_eq!(huffman::table()[EOS as usize].length, 30);
}

#[test]
fn errors_describe_themselves() {
    assert_eq!(DecodeError::InvalidPadding.to_string(), "huffman padding is not all one-bits");
    assert_eq!(DecodeError::UnknownSymbol.to_string(), "huffman code does not map to a known symbol");
}
