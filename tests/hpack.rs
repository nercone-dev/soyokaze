use soyokaze::helpers::fields::{HeaderField, Integer};
use soyokaze::helpers::hpack::{Decoder, DynamicTable, Encoder, Error};

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField::new(name, value)
}

fn literal_with_indexing(name: &str, value: &str) -> Vec<u8> {
    let mut block = vec![0x40, name.len() as u8];
    block.extend_from_slice(name.as_bytes());
    block.push(value.len() as u8);
    block.extend_from_slice(value.as_bytes());
    block
}

#[test]
fn resolves_the_static_table() {
    let decoder = Decoder::new();

    assert_eq!(decoder.resolve(1), Ok(&field(":authority", "")));
    assert_eq!(decoder.resolve(2), Ok(&field(":method", "GET")));
    assert_eq!(decoder.resolve(61), Ok(&field("www-authenticate", "")));
}

#[test]
fn refuses_index_zero_and_anything_past_the_end() {
    let decoder = Decoder::new();

    assert_eq!(decoder.resolve(0), Err(Error::IndexOutOfRange(0)));
    assert_eq!(decoder.resolve(62), Err(Error::IndexOutOfRange(62)));
    assert_eq!(decoder.resolve(u64::MAX), Err(Error::IndexOutOfRange(u64::MAX)));
}

#[test]
fn indexes_the_dynamic_table_from_the_newest_entry() {
    let mut decoder = Decoder::new();

    decoder.decode(&literal_with_indexing("first", "1")).expect("the literal did not decode");
    decoder.decode(&literal_with_indexing("second", "2")).expect("the literal did not decode");

    assert_eq!(decoder.resolve(62), Ok(&field("second", "2")));
    assert_eq!(decoder.resolve(63), Ok(&field("first", "1")));
    assert_eq!(decoder.dynamic_table().len(), 2);
}

#[test]
fn evicts_the_oldest_entries_to_make_room() {
    let mut table = DynamicTable::new(2 * (HeaderField::OVERHEAD + 5));

    table.insert(field("aaaa", "a"));
    table.insert(field("bbbb", "b"));
    assert_eq!(table.len(), 2);

    table.insert(field("cccc", "c"));
    assert_eq!(table.len(), 2);
    assert_eq!(table.get(0), Some(&field("cccc", "c")));
    assert_eq!(table.get(1), Some(&field("bbbb", "b")));
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
    let mut table = DynamicTable::new(DynamicTable::DEFAULT_CAPACITY);

    for index in 0..8 {
        table.insert(field(&format!("name-{index}"), "value"));
    }

    table.set_capacity(HeaderField::OVERHEAD + 11);
    assert_eq!(table.len(), 1);
    assert!(table.size() <= table.capacity());

    table.set_capacity(0);
    assert!(table.is_empty());
}

#[test]
fn finds_a_full_match_before_a_name_only_match() {
    let table = DynamicTable::new(DynamicTable::DEFAULT_CAPACITY);

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
fn a_size_update_leads_the_next_block() {
    let mut encoder = Encoder::new();
    encoder.set_max_capacity(256);

    let block = encoder.encode(&[field("x-a", "1")]);
    assert_eq!(block[0] & 0xe0, 0x20, "the block does not open with a dynamic table size update");

    let mut decoder = Decoder::new();
    assert_eq!(decoder.decode(&block), Ok(vec![field("x-a", "1")]));
    assert_eq!(decoder.dynamic_table().capacity(), 256);

    let next = encoder.encode(&[field("x-b", "2")]);
    assert_ne!(next[0] & 0xe0, 0x20);
}

#[test]
fn the_capacity_limit_caps_what_the_peer_permits() {
    let mut encoder = Encoder::new();
    encoder.set_capacity_limit(128);
    encoder.set_max_capacity(4096);

    assert_eq!(encoder.dynamic_table().capacity(), 128);

    let block = encoder.encode(&[field("x-a", "1")]);
    assert_eq!(block[0] & 0xe0, 0x20, "the block does not open with a dynamic table size update");

    let mut decoder = Decoder::new();
    assert_eq!(decoder.decode(&block), Ok(vec![field("x-a", "1")]));
    assert_eq!(decoder.dynamic_table().capacity(), 128);
}

#[test]
fn refuses_a_size_update_above_the_negotiated_maximum() {
    let mut decoder = Decoder::new();
    decoder.set_max_capacity(512);

    let mut block = Vec::new();
    Integer::encode(&mut block, 4096, 5, 0x20);

    assert_eq!(decoder.decode(&block), Err(Error::InvalidCapacityUpdate));
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
