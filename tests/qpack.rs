use soyokaze::helpers::hpack::HeaderField;
use soyokaze::helpers::qpack::{
    self, Decoder, DecoderInstruction, DynamicTable, Encoder, EncoderInstruction, Error,
    ADVERTISED_TABLE_CAPACITY,
};
use soyokaze::models::Limits;

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField::new(name, value)
}

fn paired() -> (Encoder, Decoder) {
    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();

    encoder.set_max_capacity(ADVERTISED_TABLE_CAPACITY);
    let update = encoder.set_capacity(ADVERTISED_TABLE_CAPACITY).expect("the table was not sized");
    decoder.on_encoder_instruction(update).expect("the decoder refused the capacity update");

    (encoder, decoder)
}

fn exchange(encoder: &mut Encoder, decoder: &mut Decoder, instructions: Vec<EncoderInstruction>) {
    for instruction in instructions {
        match decoder.on_encoder_instruction(instruction) {
            Ok(Some(acknowledgment)) => encoder.on_decoder_instruction(acknowledgment),
            Ok(None) => {}
            Err(err) => panic!("the decoder rejected an encoder instruction: {err}"),
        }
    }
}

#[test]
fn the_static_table_has_the_specified_shape() {
    let table = qpack::static_table();

    assert_eq!(table.len(), 99);
    assert_eq!(table[0], field(":authority", ""));
    assert_eq!(table[17], field(":method", "GET"));
    assert_eq!(table[25], field(":status", "200"));
    assert_eq!(table[98], field("x-frame-options", "sameorigin"));
}

#[test]
fn finds_a_full_static_match_before_a_name_only_one() {
    assert_eq!(qpack::find_static(&field(":method", "GET")), Some((17, true)));
    assert_eq!(qpack::find_static(&field(":method", "BREW")), Some((15, false)));
    assert_eq!(qpack::find_static(&field("x-nothing", "here")), None);
}

#[test]
fn absolute_indices_count_up_from_the_first_insert() {
    let mut table = DynamicTable::new(ADVERTISED_TABLE_CAPACITY);

    assert_eq!(table.insert(field("first", "1")), 0);
    assert_eq!(table.insert(field("second", "2")), 1);

    assert_eq!(table.get(0), Some(&field("first", "1")));
    assert_eq!(table.get(1), Some(&field("second", "2")));
    assert_eq!(table.get(2), None);
    assert_eq!(table.inserted_count(), 2);
}

#[test]
fn relative_and_post_base_indices_resolve_around_the_base() {
    let mut table = DynamicTable::new(ADVERTISED_TABLE_CAPACITY);
    for index in 0..4 {
        table.insert(field(&format!("name-{index}"), "value"));
    }

    assert_eq!(table.relative(0), Some(3));
    assert_eq!(table.relative(3), Some(0));
    assert_eq!(table.relative(4), None);

    assert_eq!(table.indexed(4, 0), Some(3));
    assert_eq!(table.indexed(4, 4), None);
    assert_eq!(table.post_base(2, 1), Some(3));
    assert_eq!(table.post_base(u64::MAX, 1), None);
}

#[test]
fn eviction_leaves_the_absolute_indices_alone() {
    let mut table = DynamicTable::new(2 * (HeaderField::OVERHEAD + 5));

    table.insert(field("aaaa", "a"));
    table.insert(field("bbbb", "b"));
    table.insert(field("cccc", "c"));

    assert_eq!(table.len(), 2);
    assert_eq!(table.inserted_count(), 3);
    assert_eq!(table.get(0), None, "the evicted entry is still reachable");
    assert_eq!(table.get(2), Some(&field("cccc", "c")));
}

#[test]
fn an_entry_larger_than_the_capacity_does_not_fit() {
    let table = DynamicTable::new(64);

    assert!(table.fits(&field("ab", "cd")));
    assert!(!table.fits(&field("a-rather-long-name", "and a rather long value")));
}

#[test]
fn setting_a_smaller_capacity_evicts() {
    let mut table = DynamicTable::new(ADVERTISED_TABLE_CAPACITY);
    for index in 0..8 {
        table.insert(field(&format!("name-{index}"), "value"));
    }

    table.set_capacity(0);
    assert!(table.is_empty());
    assert_eq!(table.size(), 0);
}

#[test]
fn a_section_that_needs_no_dynamic_entry_encodes_a_zero() {
    assert_eq!(qpack::encode_insert_count(0, ADVERTISED_TABLE_CAPACITY), 0);
    assert_eq!(qpack::decode_insert_count(0, 0, ADVERTISED_TABLE_CAPACITY), Ok(0));
}

#[test]
fn the_wrapped_insert_count_recovers_inside_its_window() {
    let capacity = ADVERTISED_TABLE_CAPACITY;
    let entries = qpack::max_entries(capacity);
    assert_eq!(entries, 128);

    for inserted in [1u64, 5, 127, 128, 129, 255, 256, 1_000] {
        let floor = (inserted + entries).saturating_sub(2 * entries);

        for required in (floor + 1)..=inserted {
            let encoded = qpack::encode_insert_count(required, capacity);
            assert_eq!(
                qpack::decode_insert_count(encoded, inserted, capacity),
                Ok(required),
                "required {required} with {inserted} inserted",
            );
        }
    }
}

#[test]
fn refuses_an_insert_count_no_encoder_could_have_sent() {
    let capacity = ADVERTISED_TABLE_CAPACITY;
    let full_range = 2 * qpack::max_entries(capacity);

    assert_eq!(qpack::decode_insert_count(full_range + 1, 0, capacity), Err(Error::InvalidInsertCount));
    assert_eq!(qpack::decode_insert_count(1, 0, capacity), Err(Error::InvalidInsertCount));
}

#[test]
fn encoder_instructions_round_trip() {
    let instructions = [
        EncoderInstruction::SetDynamicTableCapacity { capacity: 0 },
        EncoderInstruction::SetDynamicTableCapacity { capacity: 4096 },
        EncoderInstruction::InsertWithNameReference { from_static: true, name_index: 17, value: b"GET".to_vec() },
        EncoderInstruction::InsertWithNameReference { from_static: false, name_index: 0, value: Vec::new() },
        EncoderInstruction::InsertWithLiteralName { name: b"x-soyokaze".to_vec(), value: b"1".to_vec() },
        EncoderInstruction::Duplicate { index: 0 },
        EncoderInstruction::Duplicate { index: 1_000_000 },
    ];

    for instruction in instructions {
        let encoded = instruction.encode();
        assert_eq!(EncoderInstruction::decode(&encoded), Ok((encoded.len(), instruction)));
    }
}

#[test]
fn decoder_instructions_round_trip() {
    let instructions = [
        DecoderInstruction::SectionAcknowledgment { stream_id: 0 },
        DecoderInstruction::SectionAcknowledgment { stream_id: 1 << 40 },
        DecoderInstruction::StreamCancellation { stream_id: 4 },
        DecoderInstruction::InsertCountIncrement { increment: 1 },
        DecoderInstruction::InsertCountIncrement { increment: 63 },
    ];

    for instruction in instructions {
        let encoded = instruction.encode();
        assert_eq!(DecoderInstruction::decode(&encoded), Ok((encoded.len(), instruction)));
    }
}

#[test]
fn instructions_report_a_truncated_encoding() {
    assert_eq!(EncoderInstruction::decode(&[]), Err(Error::Incomplete));
    assert_eq!(DecoderInstruction::decode(&[]), Err(Error::Incomplete));

    assert_eq!(EncoderInstruction::decode(&[0x42, b'a', b'b', 0x05, b'x']), Err(Error::Incomplete));
}

#[test]
fn a_capacity_above_the_maximum_is_refused() {
    let mut decoder = Decoder::new();
    decoder.set_max_capacity(512);

    let too_large = EncoderInstruction::SetDynamicTableCapacity { capacity: 4096 };
    assert_eq!(decoder.on_encoder_instruction(too_large), Err(Error::InvalidCapacityUpdate));

    let allowed = EncoderInstruction::SetDynamicTableCapacity { capacity: 512 };
    assert_eq!(decoder.on_encoder_instruction(allowed), Ok(None));
}

#[test]
fn an_insert_naming_a_missing_entry_is_refused() {
    let mut decoder = Decoder::new();

    let from_static = EncoderInstruction::InsertWithNameReference { from_static: true, name_index: 99, value: Vec::new() };
    assert_eq!(decoder.on_encoder_instruction(from_static), Err(Error::IndexOutOfRange(99)));

    let from_dynamic = EncoderInstruction::InsertWithNameReference { from_static: false, name_index: 0, value: Vec::new() };
    assert_eq!(decoder.on_encoder_instruction(from_dynamic), Err(Error::IndexOutOfRange(0)));

    assert_eq!(decoder.on_encoder_instruction(EncoderInstruction::Duplicate { index: 0 }), Err(Error::IndexOutOfRange(0)));
}

#[test]
fn an_entry_larger_than_the_table_is_refused() {
    let mut decoder = Decoder::new();
    decoder.set_max_capacity(64);
    let _ = decoder.on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity { capacity: 64 });

    let oversized = EncoderInstruction::InsertWithLiteralName {
        name: vec![b'a'; 64],
        value: vec![b'b'; 64],
    };

    assert_eq!(decoder.on_encoder_instruction(oversized), Err(Error::EntryTooLarge));
}

#[test]
fn an_insert_raises_the_decoders_insert_count() {
    let mut decoder = Decoder::new();

    let insert = EncoderInstruction::InsertWithLiteralName { name: b"x-a".to_vec(), value: b"1".to_vec() };
    assert_eq!(
        decoder.on_encoder_instruction(insert),
        Ok(Some(DecoderInstruction::InsertCountIncrement { increment: 1 })),
    );

    assert_eq!(decoder.dynamic_table().inserted_count(), 1);
}

#[test]
fn round_trips_a_request_over_the_static_table() {
    let fields = vec![
        field(":method", "GET"),
        field(":scheme", "https"),
        field(":path", "/"),
        field(":authority", "example.test"),
    ];

    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();

    let (block, instructions) = encoder.encode(0, &fields);
    exchange(&mut encoder, &mut decoder, instructions);

    assert_eq!(decoder.decode(0, &block), Ok((fields, None)));
}

#[test]
fn a_fresh_encoder_holds_no_dynamic_table() {
    let encoder = Encoder::new();

    assert_eq!(encoder.dynamic_table().capacity(), 0, "RFC 9204 §3.2.3 starts the table at zero");
    assert_eq!(encoder.max_capacity(), 0, "RFC 9204 §5 defaults the peer's allowance to zero");
}

#[test]
fn nothing_is_inserted_before_the_peer_permits_a_table() {
    let fields = vec![field(":method", "GET"), field("x-request-id", "0123456789abcdef")];

    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();

    let (block, instructions) = encoder.encode(0, &fields);
    assert!(instructions.is_empty(), "the encoder inserted before the peer allowed a dynamic table");
    assert!(encoder.dynamic_table().is_empty());
    assert_eq!(encoder.dynamic_table().inserted_count(), 0);

    assert_eq!(decoder.decode(0, &block), Ok((fields, None)), "the section must stand on its own");
}

#[test]
fn a_peer_that_permits_nothing_keeps_the_table_shut() {
    let mut encoder = Encoder::new();
    encoder.set_max_capacity(0);

    assert_eq!(encoder.set_capacity(4096), None, "a capacity no peer permits must not be announced");
    assert_eq!(encoder.dynamic_table().capacity(), 0);

    let (_, instructions) = encoder.encode(0, &[field("x-custom", "value")]);
    assert!(instructions.is_empty(), "the encoder inserted into a table the peer refused");
}

#[test]
fn the_capacity_update_precedes_the_first_insert() {
    let mut encoder = Encoder::new();
    encoder.set_max_capacity(512);

    assert_eq!(
        encoder.set_capacity(4096),
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity: 512 }),
        "the capacity must be clamped to what the peer permits",
    );
    assert_eq!(encoder.set_capacity(512), None, "an unchanged capacity says nothing");

    let (_, instructions) = encoder.encode(0, &[field("x-custom", "value")]);
    assert!(!instructions.is_empty(), "the encoder ignored the table the peer permitted");
}

#[test]
fn the_dynamic_table_shortens_a_repeated_section() {
    let fields = vec![
        field(":method", "GET"),
        field(":authority", "example.test"),
        field("user-agent", "soyokaze/0.1"),
        field("x-request-id", "01234567-89ab-cdef-0123-456789abcdef"),
    ];

    let (mut encoder, mut decoder) = paired();

    let (first, instructions) = encoder.encode(0, &fields);
    assert!(!instructions.is_empty(), "nothing was inserted into the dynamic table");
    exchange(&mut encoder, &mut decoder, instructions);

    let (decoded, acknowledgment) = decoder.decode(0, &first).expect("the first section did not decode");
    assert_eq!(decoded, fields);
    assert_eq!(acknowledgment, None, "a section over the static table needs no acknowledgement");

    let (second, instructions) = encoder.encode(4, &fields);
    assert!(instructions.is_empty(), "the encoder inserted the same fields twice");
    assert!(second.len() < first.len(), "the dynamic table did not shorten the second section");

    let (decoded, acknowledgment) = decoder.decode(4, &second).expect("the second section did not decode");
    assert_eq!(decoded, fields);
    assert_eq!(
        acknowledgment,
        Some(DecoderInstruction::SectionAcknowledgment { stream_id: 4 }),
        "a section that used the dynamic table must be acknowledged",
    );
}

#[test]
fn a_section_that_outruns_the_inserts_blocks() {
    let fields = vec![field("x-custom", "value")];

    let (mut encoder, mut decoder) = paired();

    let (_, instructions) = encoder.encode(0, &fields);
    assert_eq!(instructions.len(), 1);
    encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment: 1 });

    let (block, _) = encoder.encode(4, &fields);
    assert_eq!(decoder.decode(4, &block), Err(Error::Blocked));
}

#[test]
fn never_indexes_a_sensitive_field() {
    let secret = field("authorization", "Bearer opensesame");

    let (mut encoder, mut decoder) = paired();

    let (block, instructions) = encoder.encode(0, std::slice::from_ref(&secret));
    assert!(instructions.is_empty(), "a sensitive field was inserted into the dynamic table");
    exchange(&mut encoder, &mut decoder, instructions);

    assert_eq!(decoder.decode(0, &block), Ok((vec![secret], None)));
    assert!(encoder.dynamic_table().is_empty());
}

#[test]
fn trailers_and_empty_sections_survive() {
    let (mut encoder, mut decoder) = paired();

    let (block, instructions) = encoder.encode(0, &[]);
    exchange(&mut encoder, &mut decoder, instructions);
    assert_eq!(decoder.decode(0, &block), Ok((Vec::new(), None)));

    let trailers = vec![field("x-checksum", "deadbeef")];
    let (block, instructions) = encoder.encode(4, &trailers);
    exchange(&mut encoder, &mut decoder, instructions);
    assert_eq!(decoder.decode(4, &block), Ok((trailers, None)));
}

#[test]
fn stops_once_the_decoded_section_grows_too_large() {
    let fields: Vec<HeaderField> = (0..8).map(|index| field(&format!("x-name-{index}"), "value")).collect();

    let (mut encoder, mut decoder) = paired();
    decoder.set_max_decoded_size(128);

    let (block, instructions) = encoder.encode(0, &fields);
    exchange(&mut encoder, &mut decoder, instructions);

    assert_eq!(decoder.decode(0, &block), Err(Error::DecodedSizeExceeded));
}

#[test]
fn refuses_a_section_that_ends_early() {
    let mut decoder = Decoder::new();

    assert_eq!(decoder.decode(0, &[]), Err(Error::Incomplete));
    assert_eq!(decoder.decode(0, &[0x00]), Err(Error::Incomplete));
}

#[test]
fn refuses_a_section_naming_an_entry_that_does_not_exist() {
    let mut decoder = Decoder::new();

    let block = [0x00, 0x00, 0xff, 0x24];
    assert!(matches!(decoder.decode(0, &block), Err(Error::IndexOutOfRange(_))));
}

#[test]
fn decoding_arbitrary_octets_never_panics() {
    for first in 0..=255u8 {
        let mut decoder = Decoder::new();
        let _ = decoder.decode(0, &[0x00, 0x00, first, 0x7f, 0xff, first]);
    }
}

#[test]
fn a_stream_cancellation_drops_the_pending_section() {
    let fields = vec![field("x-custom", "value")];

    let (mut encoder, mut decoder) = paired();

    let (_, instructions) = encoder.encode(0, &fields);
    exchange(&mut encoder, &mut decoder, instructions);

    let (_, _) = encoder.encode(4, &fields);
    encoder.on_decoder_instruction(DecoderInstruction::StreamCancellation { stream_id: 4 });

    let known = encoder.known_received_count();
    encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 4 });
    assert_eq!(encoder.known_received_count(), known);
}

#[test]
fn errors_describe_themselves() {
    assert_eq!(Error::Blocked.to_string(), "decoding is blocked on a pending dynamic table insertion");
    assert_eq!(Error::IndexOutOfRange(3).to_string(), "absolute index 3 is out of range");
    assert_eq!(Error::EntryTooLarge.to_string(), "entry is larger than the dynamic table capacity");
}

#[test]
fn a_decoder_that_never_acknowledges_cannot_grow_the_section_queue() {
    let (mut encoder, mut decoder) = paired();
    let fields = vec![field("x-request", "one")];

    let (_, instructions) = encoder.encode(0, &fields);
    exchange(&mut encoder, &mut decoder, instructions);
    encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 });

    let ceiling = Limits::default().max_outstanding_sections as usize;

    for stream in 1..(ceiling as u64 * 4) {
        let (_, instructions) = encoder.encode(stream * 4, &fields);
        exchange(&mut encoder, &mut decoder, instructions);
    }

    assert!(
        encoder.outstanding() <= ceiling,
        "a silent decoder grew the queue to {} sections",
        encoder.outstanding()
    );
}

#[test]
fn sections_beyond_the_queue_still_decode() {
    let (mut encoder, mut decoder) = paired();
    let fields = vec![field("x-request", "one"), field(":method", "GET")];

    let (_, instructions) = encoder.encode(0, &fields);
    exchange(&mut encoder, &mut decoder, instructions);
    encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 });

    let mut block = Vec::new();
    for stream in 1..(Limits::default().max_outstanding_sections as u64 + 8) {
        let (encoded, instructions) = encoder.encode(stream * 4, &fields);
        exchange(&mut encoder, &mut decoder, instructions);
        block = encoded;
    }

    let (decoded, _) = decoder.decode(4, &block).expect("a section encoded past the queue did not decode");
    assert_eq!(decoded, fields, "the fields survive the fallback to literal representations");
}

#[test]
fn a_cancelled_stream_releases_its_sections() {
    let (mut encoder, mut decoder) = paired();
    let fields = vec![field("x-request", "one")];

    let (_, instructions) = encoder.encode(0, &fields);
    exchange(&mut encoder, &mut decoder, instructions);
    encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 });

    encoder.encode(4, &fields);
    assert_eq!(encoder.outstanding(), 1, "a section referencing the table waits to be acknowledged");

    encoder.cancel(4);
    assert_eq!(encoder.outstanding(), 0, "a stream that is gone leaves no section behind");
}
