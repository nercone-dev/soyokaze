use soyokaze::helpers::hpack::{
    self, Decoder, DynamicTable, Encoder, Error, HeaderField, DEFAULT_DYNAMIC_TABLE_SIZE,
};

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField::new(name, value)
}

#[test]
fn encodes_the_specification_integers() {
    let mut out = Vec::new();
    hpack::encode_integer(&mut out, 10, 5, 0);
    assert_eq!(out, [10]);

    let mut out = Vec::new();
    hpack::encode_integer(&mut out, 1337, 5, 0);
    assert_eq!(out, [31, 154, 10]);

    let mut out = Vec::new();
    hpack::encode_integer(&mut out, 42, 8, 0);
    assert_eq!(out, [42]);
}

#[test]
fn decodes_the_specification_integers() {
    assert_eq!(hpack::decode_integer(&[10], 5), Ok((1, 10)));
    assert_eq!(hpack::decode_integer(&[31, 154, 10], 5), Ok((3, 1337)));
    assert_eq!(hpack::decode_integer(&[42], 8), Ok((1, 42)));
}

#[test]
fn keeps_the_flag_bits_above_the_prefix() {
    let mut out = Vec::new();
    hpack::encode_integer(&mut out, 2, 6, 0x40);
    assert_eq!(out, [0x42]);
    assert_eq!(hpack::decode_integer(&out, 6), Ok((1, 2)));
}

#[test]
fn round_trips_integers_at_every_prefix() {
    let values = [0, 1, 2, 14, 15, 16, 30, 31, 32, 127, 128, 255, 256, 16_383, 1 << 32, u64::MAX];

    for prefix_bits in 1..=8u8 {
        for value in values {
            let mut out = Vec::new();
            hpack::encode_integer(&mut out, value, prefix_bits, 0);
            assert_eq!(hpack::decode_integer(&out, prefix_bits), Ok((out.len(), value)), "{value} at {prefix_bits}");
        }
    }
}

#[test]
fn reports_a_truncated_integer() {
    assert_eq!(hpack::decode_integer(&[], 5), Err(Error::Incomplete));
    assert_eq!(hpack::decode_integer(&[31, 154], 5), Err(Error::Incomplete));
}

#[test]
fn refuses_an_integer_that_does_not_fit() {
    let overflowing = [0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f];
    assert_eq!(hpack::decode_integer(&overflowing, 8), Err(Error::IntegerOverflow));
}

#[test]
fn round_trips_strings_both_ways() {
    for value in [&b""[..], b"a", b"custom-key", b"www.example.com", &[0xff, 0x00, 0x80]] {
        for huffman in [false, true] {
            let mut out = Vec::new();
            hpack::encode_string(&mut out, value, huffman);

            assert_eq!(out.first().is_some_and(|first| first & 0x80 != 0), huffman);
            assert_eq!(hpack::decode_string(&out), Ok((out.len(), value.to_vec())));
        }
    }
}

#[test]
fn reports_a_string_that_ends_early() {
    assert_eq!(hpack::decode_string(&[0x05, b'a', b'b']), Err(Error::Incomplete));
    assert_eq!(hpack::decode_string(&[]), Err(Error::Incomplete));
}

#[test]
fn refuses_a_string_whose_length_cannot_be_addressed() {
    let huge = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
    assert!(matches!(hpack::decode_string(&huge), Err(Error::Incomplete | Error::IntegerOverflow)));
}

#[test]
fn prefers_huffman_only_when_it_helps() {
    assert!(hpack::preferred_huffman(b"www.example.com"));
    assert!(!hpack::preferred_huffman(&[0xc0; 8]));
}

#[test]
fn resolves_the_static_table() {
    let table = DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE);

    assert_eq!(table.resolve(1), Ok(&field(":authority", "")));
    assert_eq!(table.resolve(2), Ok(&field(":method", "GET")));
    assert_eq!(table.resolve(61), Ok(&field("www-authenticate", "")));
}

#[test]
fn refuses_index_zero_and_anything_past_the_end() {
    let table = DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE);

    assert_eq!(table.resolve(0), Err(Error::IndexOutOfRange(0)));
    assert_eq!(table.resolve(62), Err(Error::IndexOutOfRange(62)));
    assert_eq!(table.resolve(usize::MAX), Err(Error::IndexOutOfRange(usize::MAX)));
}

#[test]
fn indexes_the_dynamic_table_from_the_newest_entry() {
    let mut table = DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE);

    table.insert(field("first", "1"));
    table.insert(field("second", "2"));

    assert_eq!(table.resolve(62), Ok(&field("second", "2")));
    assert_eq!(table.resolve(63), Ok(&field("first", "1")));
    assert_eq!(table.len(), 2);
}

#[test]
fn evicts_the_oldest_entries_to_make_room() {
    let mut table = DynamicTable::new(2 * (HeaderField::OVERHEAD + 5));

    table.insert(field("aaaa", "a"));
    table.insert(field("bbbb", "b"));
    assert_eq!(table.len(), 2);

    table.insert(field("cccc", "c"));
    assert_eq!(table.len(), 2);
    assert_eq!(table.resolve(62), Ok(&field("cccc", "c")));
    assert_eq!(table.resolve(63), Ok(&field("bbbb", "b")));
}

#[test]
fn drops_an_entry_larger_than_the_whole_table() {
    let mut table = DynamicTable::new(HeaderField::OVERHEAD + 4);

    table.insert(field("aa", "a"));
    table.insert(field("a-very-long-name-indeed", "and a very long value"));

    assert!(table.is_empty(), "an oversized entry must clear the table and not be stored");
    assert_eq!(table.size(), 0);
}

#[test]
fn resizing_evicts_down_to_the_new_maximum() {
    let mut table = DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE);

    for index in 0..8 {
        table.insert(field(&format!("name-{index}"), "value"));
    }

    table.resize(HeaderField::OVERHEAD + 11);
    assert_eq!(table.len(), 1);
    assert!(table.size() <= table.max_size());

    table.resize(0);
    assert!(table.is_empty());
}

#[test]
fn finds_a_full_match_before_a_name_only_match() {
    let table = DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE);

    assert_eq!(table.find(&field(":method", "GET")), Some((2, true)));
    assert_eq!(table.find(&field(":method", "PATCH")), Some((2, false)));
    assert_eq!(table.find(&field("x-nothing", "here")), None);
}

#[test]
fn decodes_the_specification_request_sequence() {
    let mut decoder = Decoder::new();

    let first = decoder.decode(&[0x82, 0x86, 0x84, 0x41, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm']);
    assert_eq!(
        first,
        Ok(vec![
            field(":method", "GET"),
            field(":scheme", "http"),
            field(":path", "/"),
            field(":authority", "www.example.com"),
        ]),
    );
    assert_eq!(decoder.dynamic_table().size(), 57);

    let second = decoder.decode(&[0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, b'n', b'o', b'-', b'c', b'a', b'c', b'h', b'e']);
    assert_eq!(
        second,
        Ok(vec![
            field(":method", "GET"),
            field(":scheme", "http"),
            field(":path", "/"),
            field(":authority", "www.example.com"),
            field("cache-control", "no-cache"),
        ]),
    );
    assert_eq!(decoder.dynamic_table().size(), 110);
}

#[test]
fn round_trips_a_request() {
    let fields = vec![
        field(":method", "GET"),
        field(":scheme", "https"),
        field(":authority", "example.test"),
        field(":path", "/index.html"),
        field("accept", "*/*"),
        field("user-agent", "soyokaze/0.1"),
    ];

    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();

    let first = encoder.encode(&fields);
    assert_eq!(decoder.decode(&first), Ok(fields.clone()));

    let second = encoder.encode(&fields);
    assert!(second.len() < first.len(), "the dynamic table did not shorten the second block");
    assert_eq!(decoder.decode(&second), Ok(fields));
}

#[test]
fn never_indexes_a_sensitive_field() {
    let secret = field("authorization", "Bearer opensesame");

    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();

    let block = encoder.encode(std::slice::from_ref(&secret));
    assert_eq!(decoder.decode(&block), Ok(vec![secret.clone()]));

    assert!(encoder.dynamic_table().is_empty(), "a sensitive field was stored by the encoder");
    assert!(decoder.dynamic_table().is_empty(), "a sensitive field was stored by the decoder");

    assert_eq!(block[0] & 0xf0, 0x10);
}

#[test]
fn every_sensitive_name_is_recognised() {
    for name in hpack::SENSITIVE_NAMES {
        assert!(field(name, "value").sensitive(), "{name} should be treated as sensitive");
    }

    assert!(!field("accept", "value").sensitive());
}

#[test]
fn a_size_update_leads_the_next_block() {
    let mut encoder = Encoder::new();
    encoder.set_dynamic_table_size(256);

    let block = encoder.encode(&[field("x-a", "1")]);
    assert_eq!(block[0] & 0xe0, 0x20, "the block does not open with a dynamic table size update");

    let mut decoder = Decoder::new();
    assert_eq!(decoder.decode(&block), Ok(vec![field("x-a", "1")]));
    assert_eq!(decoder.dynamic_table().max_size(), 256);

    let next = encoder.encode(&[field("x-b", "2")]);
    assert_ne!(next[0] & 0xe0, 0x20);
}

#[test]
fn refuses_a_size_update_above_the_negotiated_maximum() {
    let mut decoder = Decoder::new();
    decoder.set_dynamic_table_size(512);

    let mut block = Vec::new();
    hpack::encode_integer(&mut block, 4096, 5, 0x20);

    assert_eq!(decoder.decode(&block), Err(Error::InvalidDynamicTableSizeUpdate));
}

#[test]
fn refuses_an_index_that_names_nothing() {
    let mut decoder = Decoder::new();

    assert_eq!(decoder.decode(&[0x80]), Err(Error::IndexOutOfRange(0)));
    assert_eq!(decoder.decode(&[0xbe]), Err(Error::IndexOutOfRange(62)));
}

#[test]
fn refuses_a_block_that_ends_mid_representation() {
    let mut decoder = Decoder::new();

    assert_eq!(decoder.decode(&[0x40, 0x05, b'a']), Err(Error::Incomplete));
}

#[test]
fn stops_once_the_decoded_list_grows_too_large() {
    let mut decoder = Decoder::new();
    decoder.set_max_decoded_size(128);

    let mut encoder = Encoder::new();
    let fields: Vec<HeaderField> = (0..8).map(|index| field(&format!("x-name-{index}"), "value")).collect();
    let block = encoder.encode(&fields);

    assert_eq!(decoder.decode(&block), Err(Error::DecodedSizeExceeded));
}

#[test]
fn a_huffman_fault_inside_a_block_surfaces_as_a_huffman_error() {
    let mut decoder = Decoder::new();

    let block = [0x00, 0x01, b'a', 0x85, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(matches!(decoder.decode(&block), Err(Error::Huffman(_))));
}

#[test]
fn decoding_arbitrary_octets_never_panics() {
    for first in 0..=255u8 {
        let mut decoder = Decoder::new();
        let _ = decoder.decode(&[first, 0x00, 0x7f, 0xff, first]);
    }
}

#[test]
fn errors_describe_themselves() {
    assert_eq!(Error::IndexOutOfRange(9).to_string(), "index 9 is out of range");
    assert_eq!(Error::IntegerOverflow.to_string(), "integer representation overflowed");
    assert_eq!(Error::Incomplete.to_string(), "representation ends before the block does");
}
