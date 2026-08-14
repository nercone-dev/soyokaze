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

/// The code words, ordered as a canonical code numbers them: by length, and
/// within one length by value.
fn ordered() -> Vec<(usize, huffman::Symbol)> {
    let mut ordered: Vec<(usize, huffman::Symbol)> = huffman::table().iter().copied().enumerate().collect();
    ordered.sort_by_key(|(_, symbol)| (symbol.length, symbol.code));
    ordered
}

#[test]
fn the_code_is_complete_and_canonical() {
    // RFC 7541 Appendix B gives one code word per octet and one for the
    // end-of-string symbol. The canonical decoder reads a code word by its
    // numeric value alone, which is only sound if the code has the two
    // properties the appendix's table happens to have.
    let ordered = ordered();

    // Complete: the code words divide the space exactly, so every bit string
    // spells one of them and no bit string spells none.
    let kraft: f64 = ordered.iter().map(|(_, symbol)| 0.5f64.powi(symbol.length as i32)).sum();
    assert!((kraft - 1.0).abs() < 1e-12, "the code words cover {kraft} of the code space rather than all of it");

    // Canonical: each code word is the one before it plus one, shifted along
    // as the length grows.
    let mut expected = 0u32;
    let mut previous = 0u8;

    for (value, symbol) in &ordered {
        expected <<= symbol.length - previous;
        assert_eq!(symbol.code, expected, "the code word for symbol {value} is not the canonical one");
        expected += 1;
        previous = symbol.length;
    }
}

#[test]
fn the_canonical_tables_spell_out_every_code_word() {
    // Every code word, left-aligned in a window and padded with one-bits,
    // reads back as the symbol it stands for and the length it was written at.
    for (value, symbol) in huffman::table().iter().copied().enumerate() {
        let window = (symbol.code as u64) << (64 - symbol.length) | u64::MAX >> symbol.length;

        assert_eq!(
            huffman::CANONICAL.symbol(window),
            (value as u16, symbol.length as u32),
            "symbol {value} does not read back out of its own code word"
        );
    }
}

#[test]
fn the_fast_table_answers_exactly_the_short_code_words() {
    for index in 0..huffman::Canonical::FAST_SIZE {
        let window = (index as u64) << (64 - huffman::Canonical::FAST_BITS);
        let entry = huffman::CANONICAL.fast[index];

        let short = huffman::table()
            .iter()
            .enumerate()
            .find(|(_, symbol)| {
                symbol.length as usize <= huffman::Canonical::FAST_BITS
                    && (window >> (64 - symbol.length)) as u32 == symbol.code
            });

        match short {
            Some((value, symbol)) => assert_eq!(entry, (value as u16) << 8 | symbol.length as u16, "prefix {index:#04x} names the wrong symbol"),
            None => assert_eq!(entry, 0, "prefix {index:#04x} names a symbol no short code word covers"),
        }
    }
}

#[test]
fn the_pair_table_answers_what_the_symbols_do() {
    // One entry stands for as many whole code words as its bits spell, so it
    // must say exactly what reading those code words one at a time would.
    for index in 0..huffman::Canonical::PAIR_SIZE {
        let mut window = (index as u64) << (64 - huffman::Canonical::PAIR_BITS);
        let mut used = 0usize;
        let mut symbols = Vec::new();

        while symbols.len() < huffman::Canonical::PAIR_MOST {
            let (symbol, length) = huffman::CANONICAL.symbol(window | u64::MAX >> (huffman::Canonical::PAIR_BITS - used));

            if used + length as usize > huffman::Canonical::PAIR_BITS {
                break;
            }

            symbols.push(symbol as u8);
            used += length as usize;
            window <<= length;
        }

        let entry = huffman::CANONICAL.pairs[index];
        assert_eq!(entry as u8 as usize, if symbols.is_empty() { 0 } else { used }, "prefix {index:#05x} takes the wrong number of bits");
        assert_eq!((entry >> 8) as u8 as usize, symbols.len(), "prefix {index:#05x} answers the wrong number of symbols");

        for (offset, symbol) in symbols.iter().enumerate() {
            assert_eq!((entry >> (16 + 8 * offset)) as u8, *symbol, "prefix {index:#05x} answers the wrong symbol {offset}");
        }
    }
}

#[test]
fn decoding_follows_the_padding_rules_over_every_short_input() {
    // RFC 7541 §5.2: an encoding is a sequence of code words padded to the
    // octet with the most significant bits of the end-of-string code, which
    // are one-bits; padding of eight bits or more, padding that is not all
    // ones, and the end-of-string code itself are all refused. The expected
    // answer is worked out here from the code table rather than from what the
    // decoder does.
    let lengths: Vec<u8> = huffman::table().iter().map(|symbol| symbol.length).collect();

    for width in 0..=2usize {
        for value in 0..1u32 << (8 * width) {
            let input: Vec<u8> = (0..width).map(|octet| (value >> (8 * octet)) as u8).collect();

            let bits: Vec<bool> = input.iter().flat_map(|octet| (0..8).map(move |bit| octet >> (7 - bit) & 1 == 1)).collect();
            let mut at = 0;
            let mut expected: Option<Vec<u8>> = Some(Vec::new());

            while at < bits.len() {
                let mut code = 0u32;
                let mut length = 0u8;
                let mut found = None;

                while at + (length as usize) < bits.len() && found.is_none() && length < 30 {
                    code = code << 1 | bits[at + length as usize] as u32;
                    length += 1;
                    found = lengths.iter().position(|held| *held == length).map(|_| ()).and_then(|_| {
                        huffman::table().iter().position(|symbol| symbol.length == length && symbol.code == code)
                    });
                }

                match found {
                    Some(symbol) if symbol == EOS as usize => {
                        expected = None;
                        break;
                    }
                    Some(symbol) => {
                        expected.as_mut().expect("still decoding").push(symbol as u8);
                        at += length as usize;
                    }
                    None => {
                        // What is left spells no whole code word, so it can only
                        // be padding: fewer than eight bits, all ones.
                        let rest = &bits[at..];
                        if rest.len() >= 8 || rest.iter().any(|bit| !*bit) {
                            expected = None;
                        }
                        at = bits.len();
                    }
                }
            }

            let mut decoded = Vec::new();
            let answered = huffman::decode_into(&input, &mut decoded).map(|_| decoded);

            match expected {
                Some(expected) => assert_eq!(answered, Ok(expected), "{input:02x?} should have decoded"),
                None => assert!(answered.is_err(), "{input:02x?} should have been refused, and decoded to {answered:02x?}"),
            }
        }
    }
}
