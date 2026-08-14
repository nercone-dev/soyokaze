use soyokaze::helpers::fields::{Entry, Error, HeaderField, Integer, Mark, StaticIndex, StringLiteral};
use soyokaze::helpers::{hpack, qpack};

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
    // Recognised by length and first octet rather than by walking the list, so
    // the two are checked against each other over names near the list as well
    // as the list itself.
    let corpus: Vec<String> = HeaderField::SENSITIVE
        .iter()
        .flat_map(|name| {
            let name = name.to_string();
            [name.clone(), name[..name.len() - 1].to_string(), format!("{name}x"), format!("x{}", &name[1..])]
        })
        .chain(["".into(), "accept".into(), "cookies".into(), "content-type".into()])
        .collect();

    for name in &corpus {
        assert_eq!(
            field(name, "value").sensitive(),
            HeaderField::SENSITIVE.contains(&name.as_str()),
            "{name:?} is not classified as the list says"
        );
    }
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

// ---------------------------------------------------------------- conformance

#[test]
fn a_field_name_is_a_non_empty_token() {
    for name in ["content-length", "x-custom", "a!#$%&'*+-.^_`|~9"] {
        assert!(HeaderField::is_name(name), "{name:?} is a token");
    }

    for name in ["", "bad name", "a:b", "a\r\nb", "a\0b", "a(b", "a@b", "a\u{7f}b"] {
        assert!(!HeaderField::is_name(name), "RFC 9110 5.6.2: {name:?} is not a token, so it is not a field name");
    }

    assert!(HeaderField::is_lowercase_name("x-custom"));
    assert!(!HeaderField::is_lowercase_name("X-Custom"), "RFC 9113 8.2.1 and RFC 9114 4.2 want a lowercase name");
}

#[test]
fn a_field_value_carries_no_control_octet_and_no_surrounding_space() {
    for value in ["", "plain", "a\tb", "a b", "caf\u{e9}"] {
        assert!(HeaderField::is_value(value), "{value:?} is a field value");
    }

    for value in ["a\r\nb", "a\rb", "a\nb", "a\0b", "a\u{7f}b", " leading", "trailing ", "\ttab", "tab\t"] {
        assert!(!HeaderField::is_value(value), "RFC 9110 5.5: {value:?} is not a field value");
    }
}

#[test]
fn a_string_literal_leaves_room_for_its_huffman_mark() {
    let max = StringLiteral::MAX_PREFIX_BITS;
    assert_eq!(max, 7, "the mark sits just above the prefix, so eight bits would push it out of the octet");

    for prefix_bits in [0u8, 1, 7] {
        assert_eq!(StringLiteral::huffman_mark(prefix_bits), 1 << prefix_bits);
    }

    for prefix_bits in [8u8, 63, 200, 255] {
        assert_eq!(
            StringLiteral::huffman_mark(prefix_bits),
            1 << max,
            "a prefix wider than {max} is read as {max} rather than shifting the mark out of the octet"
        );
    }
}

#[test]
fn a_prefix_no_representation_uses_never_takes_the_process_with_it() {
    let mut out = Vec::new();
    StringLiteral::encode(&mut out, b"hello", 8, 0x00, true);
    assert!(!out.is_empty(), "an over-wide prefix must be read as the widest one, not overflow a shift");

    let mut scratch = Vec::new();
    for prefix_bits in [8u8, 64, 255] {
        let _ = StringLiteral::decode_into_ascii(&out, prefix_bits, &mut scratch);
        let _ = StringLiteral::decode_into_ascii(&[0x05, b'a'], prefix_bits, &mut scratch);
    }
}

#[test]
fn the_token_table_marks_lowercase_tokens() {
    // RFC 9110 §5.6.2 gives the token characters; RFC 9113 §8.2.1 and RFC 9114
    // §4.2 add that a field name carries no uppercase letter. The table holds
    // both answers, and the second must be exactly the first without A-Z.
    for value in 0..=255u8 {
        let token = value.is_ascii_alphanumeric()
            || matches!(value, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~');

        let marks = HeaderField::TOKENS[value as usize];
        assert_eq!(marks & HeaderField::TOKEN != 0, token, "{value:#04x} is marked wrongly as a token");
        assert_eq!(
            marks & HeaderField::LOWERCASE != 0,
            token && !value.is_ascii_uppercase(),
            "{value:#04x} is marked wrongly as a lowercase token"
        );
    }
}

#[test]
fn a_lowercase_name_is_a_token_carrying_no_capital() {
    for value in 0..=255u8 {
        let token = HeaderField::TOKENS[value as usize] & HeaderField::TOKEN != 0;

        for length in 1..=20usize {
            for at in 0..length {
                let mut name = vec![b'a'; length];
                name[at] = value;
                let name = String::from_utf8_lossy(&name).into_owned();

                assert_eq!(HeaderField::is_name(&name), token, "{name:?} is not classified as a token");
                assert_eq!(
                    HeaderField::is_lowercase_name(&name),
                    token && !value.is_ascii_uppercase(),
                    "{name:?} is not classified as a lowercase token"
                );
            }
        }
    }

    assert!(!HeaderField::is_name(""), "an empty name is not a token");
    assert!(!HeaderField::is_lowercase_name(""), "an empty name is not a lowercase token");
}

#[test]
fn a_mark_stands_for_exactly_its_name() {
    let names = [
        "", "a", "b", "te", "host", "accept", "accept-encoding", "content-type", "content-length",
        "strict-transport-security", "x-a-rather-long-header-field-name-indeed", "ab", "ba", "abc", "acb",
    ];

    for left in names {
        assert_eq!(Mark::of(left), Mark::of(left), "the same name marks differently twice");

        for right in names {
            if left != right {
                assert_ne!(Mark::of(left), Mark::of(right), "{left:?} and {right:?} share a mark");
            }
        }
    }
}

#[test]
fn an_entry_confirms_a_mark_against_the_name_itself() {
    let entry = Entry::of(field("content-type", "text/html"));

    assert!(entry.named(Mark::of("content-type"), &field("content-type", "text/plain")));
    assert!(entry.valued(&field("anything", "text/html")));
    assert!(!entry.valued(&field("content-type", "text/plain")));

    // A mark that matched but a name that did not must not be taken for a hit,
    // whatever the mark says.
    assert!(!entry.named(Mark::of("content-type"), &field("content-length", "10")));
}

#[test]
fn the_static_index_finds_every_entry_it_was_built_from() {
    for (entries, base) in [(hpack::StaticTable::entries().as_slice(), 1usize), (qpack::StaticTable::entries().as_slice(), 0)] {
        let index = StaticIndex::new(entries, base);

        for (offset, entry) in entries.iter().enumerate() {
            let (named, exact) = index.lookup(&entry.name, &entry.value);

            let first = entries.iter().position(|other| other.name == entry.name).expect("the name is in the table");
            assert_eq!(named, Some(base + first), "{:?} does not resolve to its lowest index", entry.name);
            assert_eq!(exact, Some(base + offset), "{:?}: {:?} does not resolve to its own index", entry.name, entry.value);
        }

        assert_eq!(index.lookup("x-not-in-any-static-table", "?"), (None, None));
    }
}
