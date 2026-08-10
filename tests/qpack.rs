use soyokaze::helpers::fields::HeaderField;
use soyokaze::helpers::qpack::{self, Decoder, DecoderInstruction, DynamicTable, Encoder, EncoderInstruction, Error};

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField::new(name, value)
}

fn paired() -> (Encoder, Decoder) {
    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();

    let update = encoder.set_max_capacity(Decoder::DEFAULT_MAX_CAPACITY).expect("the table was not sized");
    decoder.on_encoder_instruction(update).expect("the decoder refused the capacity update");

    (encoder, decoder)
}

fn section(encoder: &mut Encoder, stream_id: u64, fields: &[HeaderField]) -> (Vec<u8>, Vec<u8>) {
    let block = encoder.encode(stream_id, fields);
    (block, encoder.take_encoder_stream())
}

fn exchange(encoder: &mut Encoder, decoder: &mut Decoder, stream: &[u8]) {
    decoder.on_encoder_stream(stream).expect("the decoder rejected the encoder stream");
    let answers = decoder.take_decoder_stream();
    encoder.on_decoder_stream(&answers).expect("the encoder rejected the decoder stream");
}

#[test]
fn the_static_table_has_the_specified_shape() {
    let table = qpack::StaticTable::entries();

    assert_eq!(table.len(), 99);
    assert_eq!(table[0], field(":authority", ""));
    assert_eq!(table[17], field(":method", "GET"));
    assert_eq!(table[25], field(":status", "200"));
    assert_eq!(table[98], field("x-frame-options", "sameorigin"));
}

#[test]
fn finds_a_full_static_match_before_a_name_only_one() {
    assert_eq!(qpack::StaticTable::find(&field(":method", "GET")), Some((17, true)));
    assert_eq!(qpack::StaticTable::find(&field(":method", "BREW")), Some((15, false)));
    assert_eq!(qpack::StaticTable::find(&field("x-nothing", "here")), None);
}

#[test]
fn absolute_indices_count_up_from_the_first_insert() {
    let mut table = DynamicTable::new(Decoder::DEFAULT_MAX_CAPACITY);

    assert_eq!(table.insert(field("first", "1")), 0);
    assert_eq!(table.insert(field("second", "2")), 1);

    assert_eq!(table.get(0), Some(&field("first", "1")));
    assert_eq!(table.get(1), Some(&field("second", "2")));
    assert_eq!(table.get(2), None);
    assert_eq!(table.inserted_count(), 2);
}

#[test]
fn relative_and_post_base_indices_resolve_around_the_base() {
    let mut table = DynamicTable::new(Decoder::DEFAULT_MAX_CAPACITY);
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
    let mut table = DynamicTable::new(Decoder::DEFAULT_MAX_CAPACITY);
    for index in 0..8 {
        table.insert(field(&format!("name-{index}"), "value"));
    }

    table.set_capacity(0);
    assert!(table.is_empty());
    assert_eq!(table.size(), 0);
}

#[test]
fn a_section_that_needs_no_dynamic_entry_encodes_a_zero() {
    assert_eq!(qpack::Prefix::encode_insert_count(0, Decoder::DEFAULT_MAX_CAPACITY), 0);
    assert_eq!(qpack::Prefix::decode_insert_count(0, 0, Decoder::DEFAULT_MAX_CAPACITY), Ok(0));
}

#[test]
fn the_wrapped_insert_count_recovers_inside_its_window() {
    let capacity = Decoder::DEFAULT_MAX_CAPACITY;
    let entries = qpack::Prefix::max_entries(capacity);
    assert_eq!(entries, 128);

    for inserted in [1u64, 5, 127, 128, 129, 255, 256, 1_000] {
        let floor = (inserted + entries).saturating_sub(2 * entries);

        for required in (floor + 1)..=inserted {
            let encoded = qpack::Prefix::encode_insert_count(required, capacity);
            assert_eq!(
                qpack::Prefix::decode_insert_count(encoded, inserted, capacity),
                Ok(required),
                "required {required} with {inserted} inserted",
            );
        }
    }
}

#[test]
fn refuses_an_insert_count_no_encoder_could_have_sent() {
    let capacity = Decoder::DEFAULT_MAX_CAPACITY;
    let full_range = 2 * qpack::Prefix::max_entries(capacity);

    assert_eq!(qpack::Prefix::decode_insert_count(full_range + 1, 0, capacity), Err(Error::InvalidInsertCount));
    assert_eq!(qpack::Prefix::decode_insert_count(1, 0, capacity), Err(Error::InvalidInsertCount));
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

    let (block, stream) = section(&mut encoder, 0, &fields);
    exchange(&mut encoder, &mut decoder, &stream);

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

    let (block, stream) = section(&mut encoder, 0, &fields);
    assert!(stream.is_empty(), "the encoder inserted before the peer allowed a dynamic table");
    assert!(encoder.dynamic_table().is_empty());
    assert_eq!(encoder.dynamic_table().inserted_count(), 0);

    assert_eq!(decoder.decode(0, &block), Ok((fields, None)), "the section must stand on its own");
}

#[test]
fn a_peer_that_permits_nothing_keeps_the_table_shut() {
    let mut encoder = Encoder::new();

    assert_eq!(encoder.set_max_capacity(0), None, "a capacity no peer permits must not be announced");
    assert_eq!(encoder.dynamic_table().capacity(), 0);

    let (_, stream) = section(&mut encoder, 0, &[field("x-custom", "value")]);
    assert!(stream.is_empty(), "the encoder inserted into a table the peer refused");
}

#[test]
fn the_capacity_update_precedes_the_first_insert() {
    let mut encoder = Encoder::new();

    assert_eq!(
        encoder.set_max_capacity(512),
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity: 512 }),
        "the capacity must be clamped to what the peer permits",
    );
    assert_eq!(encoder.set_max_capacity(512), None, "an unchanged capacity says nothing");

    let (_, stream) = section(&mut encoder, 0, &[field("x-custom", "value")]);
    assert!(!stream.is_empty(), "the encoder ignored the table the peer permitted");
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

    let (first, stream) = section(&mut encoder, 0, &fields);
    assert!(!stream.is_empty(), "nothing was inserted into the dynamic table");
    exchange(&mut encoder, &mut decoder, &stream);

    let (decoded, acknowledgment) = decoder.decode(0, &first).expect("the first section did not decode");
    assert_eq!(decoded, fields);
    assert_eq!(acknowledgment, None, "a section over the static table needs no acknowledgement");

    let (second, stream) = section(&mut encoder, 4, &fields);
    assert!(stream.is_empty(), "the encoder inserted the same fields twice");
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

    let _ = section(&mut encoder, 0, &fields);
    assert_eq!(encoder.dynamic_table().inserted_count(), 1);
    encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment: 1 });

    let (block, _) = section(&mut encoder, 4, &fields);
    assert_eq!(decoder.decode(4, &block), Err(Error::Blocked));
}

#[test]
fn never_indexes_a_sensitive_field() {
    let secret = field("authorization", "Bearer opensesame");

    let (mut encoder, mut decoder) = paired();

    let (block, stream) = section(&mut encoder, 0, std::slice::from_ref(&secret));
    assert!(stream.is_empty(), "a sensitive field was inserted into the dynamic table");
    exchange(&mut encoder, &mut decoder, &stream);

    assert_eq!(decoder.decode(0, &block), Ok((vec![secret], None)));
    assert!(encoder.dynamic_table().is_empty());
}

#[test]
fn trailers_and_empty_sections_survive() {
    let (mut encoder, mut decoder) = paired();

    let (block, stream) = section(&mut encoder, 0, &[]);
    exchange(&mut encoder, &mut decoder, &stream);
    assert_eq!(decoder.decode(0, &block), Ok((Vec::new(), None)));

    let trailers = vec![field("x-checksum", "deadbeef")];
    let (block, stream) = section(&mut encoder, 4, &trailers);
    exchange(&mut encoder, &mut decoder, &stream);
    assert_eq!(decoder.decode(4, &block), Ok((trailers, None)));
}

#[test]
fn stops_once_the_decoded_section_grows_too_large() {
    let fields: Vec<HeaderField> = (0..8).map(|index| field(&format!("x-name-{index}"), "value")).collect();

    let (mut encoder, mut decoder) = paired();
    decoder.set_max_decoded_size(128);

    let (block, stream) = section(&mut encoder, 0, &fields);
    exchange(&mut encoder, &mut decoder, &stream);

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

    let (_, stream) = section(&mut encoder, 0, &fields);
    exchange(&mut encoder, &mut decoder, &stream);

    let _ = section(&mut encoder, 4, &fields);
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

    let (_, stream) = section(&mut encoder, 0, &fields);
    exchange(&mut encoder, &mut decoder, &stream);
    encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 });

    let ceiling = Encoder::DEFAULT_MAX_OUTSTANDING_SECTIONS;

    for stream_id in 1..(ceiling as u64 * 4) {
        let (_, stream) = section(&mut encoder, stream_id * 4, &fields);
        exchange(&mut encoder, &mut decoder, &stream);
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

    let (_, stream) = section(&mut encoder, 0, &fields);
    exchange(&mut encoder, &mut decoder, &stream);
    encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 });

    let mut block = Vec::new();
    for stream_id in 1..(Encoder::DEFAULT_MAX_OUTSTANDING_SECTIONS as u64 + 8) {
        let (encoded, stream) = section(&mut encoder, stream_id * 4, &fields);
        exchange(&mut encoder, &mut decoder, &stream);
        block = encoded;
    }

    let (decoded, _) = decoder.decode(4, &block).expect("a section encoded past the queue did not decode");
    assert_eq!(decoded, fields, "the fields survive the fallback to literal representations");
}

#[test]
fn a_cancelled_stream_releases_its_sections() {
    let (mut encoder, mut decoder) = paired();
    let fields = vec![field("x-request", "one")];

    let (_, stream) = section(&mut encoder, 0, &fields);
    exchange(&mut encoder, &mut decoder, &stream);
    encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 });

    encoder.encode(4, &fields);
    assert_eq!(encoder.outstanding(), 1, "a section referencing the table waits to be acknowledged");

    encoder.cancel(4);
    assert_eq!(encoder.outstanding(), 0, "a stream that is gone leaves no section behind");
}

#[test]
fn a_blocked_stream_is_registered_until_its_insertions_arrive() {
    let fields = vec![field("x-custom", "value")];

    let (mut encoder, mut decoder) = paired();

    let (_, stream) = section(&mut encoder, 0, &fields);
    encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment: 1 });
    let (block, _) = section(&mut encoder, 4, &fields);

    assert_eq!(decoder.decode(4, &block), Err(Error::Blocked));
    assert_eq!(decoder.blocked(), 1);
    assert!(decoder.unblocked().is_empty(), "nothing arrived, so nothing is unblocked");

    decoder.on_encoder_stream(&stream).expect("the instructions did not apply");

    assert_eq!(decoder.unblocked(), vec![4]);
    let (decoded, acknowledgment) = decoder.decode(4, &block).expect("the unblocked section did not decode");
    assert_eq!(decoded, fields);
    assert_eq!(acknowledgment, Some(DecoderInstruction::SectionAcknowledgment { stream_id: 4 }));
    assert_eq!(decoder.blocked(), 0, "a decoded section leaves the blocked set");
}

#[test]
fn refuses_more_blocked_streams_than_were_advertised() {
    let fields = vec![field("x-custom", "value")];

    let (mut encoder, mut decoder) = paired();
    decoder.set_max_blocked_streams(2);

    let _ = section(&mut encoder, 0, &fields);
    encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment: 1 });

    let (block, _) = section(&mut encoder, 4, &fields);
    assert_eq!(decoder.decode(4, &block), Err(Error::Blocked));
    assert_eq!(decoder.decode(8, &block), Err(Error::Blocked));

    assert_eq!(decoder.decode(4, &block), Err(Error::Blocked), "a stream already blocked takes no new slot");
    assert_eq!(decoder.decode(12, &block), Err(Error::TooManyBlockedStreams));

    decoder.cancel(4);
    assert_eq!(decoder.decode(12, &block), Err(Error::Blocked), "a cancelled stream frees its slot");
}

#[test]
fn a_partial_instruction_waits_for_the_rest_of_the_stream() {
    let mut decoder = Decoder::new();

    let mut stream = Vec::new();
    EncoderInstruction::SetDynamicTableCapacity { capacity: 128 }.encode_into(&mut stream);
    EncoderInstruction::InsertWithLiteralName { name: b"x-custom".to_vec(), value: b"value".to_vec() }.encode_into(&mut stream);

    let (head, tail) = stream.split_at(stream.len() - 4);
    decoder.on_encoder_stream(head).expect("a partial instruction is not an error");
    assert_eq!(decoder.dynamic_table().len(), 0, "a partial insert must not apply");

    decoder.on_encoder_stream(tail).expect("the completed instruction did not apply");
    assert_eq!(decoder.dynamic_table().len(), 1);

    let answer = decoder.take_decoder_stream();
    assert_eq!(DecoderInstruction::decode(&answer), Ok((answer.len(), DecoderInstruction::InsertCountIncrement { increment: 1 })));
    assert!(decoder.take_decoder_stream().is_empty(), "taking the stream drains it");
}

#[test]
fn refuses_an_instruction_that_grows_past_its_ceiling() {
    let mut decoder = Decoder::new();
    decoder.set_max_instruction_size(4);

    let mut stream = Vec::new();
    EncoderInstruction::InsertWithLiteralName { name: b"x-very-long-name".to_vec(), value: b"value".to_vec() }.encode_into(&mut stream);

    assert_eq!(decoder.on_encoder_stream(&stream[..3]), Ok(()));
    assert_eq!(decoder.on_encoder_stream(&stream[3..]), Err(Error::InstructionTooLarge));

    let mut encoder = Encoder::new();
    encoder.set_max_instruction_size(0);
    assert_eq!(encoder.on_decoder_stream(&[0x80]), Err(Error::InstructionTooLarge));
}

#[test]
fn acknowledgements_on_the_decoder_stream_free_the_encoder() {
    let fields = vec![field("x-custom", "value")];

    let (mut encoder, _) = paired();

    let _ = section(&mut encoder, 0, &fields);
    encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment: 1 });

    let _ = section(&mut encoder, 4, &fields);
    assert_eq!(encoder.outstanding(), 1);

    let mut stream = Vec::new();
    DecoderInstruction::SectionAcknowledgment { stream_id: 4 }.encode_into(&mut stream);
    encoder.on_decoder_stream(&stream).expect("the acknowledgement did not apply");

    assert_eq!(encoder.outstanding(), 0);
    assert_eq!(encoder.known_received_count(), 1);
}

#[test]
fn queued_instructions_ride_the_encoder_stream() {
    let mut encoder = Encoder::new();

    let update = encoder.set_max_capacity(4096).expect("the table was not sized");
    encoder.queue(&[update]);

    let stream = encoder.take_encoder_stream();
    assert_eq!(EncoderInstruction::decode(&stream), Ok((stream.len(), EncoderInstruction::SetDynamicTableCapacity { capacity: 4096 })));
    assert!(encoder.take_encoder_stream().is_empty(), "taking the stream drains it");
}

#[test]
fn the_capacity_limit_caps_what_the_peer_permits() {
    let mut encoder = Encoder::new();
    encoder.set_capacity_limit(128);

    assert_eq!(
        encoder.set_max_capacity(4096),
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity: 128 }),
        "the capacity must be clamped to the encoder's own limit",
    );

    assert_eq!(
        encoder.set_capacity_limit(64),
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity: 64 }),
        "shrinking the limit must be announced",
    );
    assert_eq!(encoder.set_capacity_limit(4096), None, "raising the limit grows nothing on its own");
    assert_eq!(encoder.dynamic_table().capacity(), 64);
}

/// The side-channel buffers are the encoder's and the decoder's own.
///
/// RFC 9204 §4.2 gives each end an encoder stream and a decoder stream, and
/// what is queued for them is state of the codec, not of whoever drives it. A
/// caller sends the octets and hands the buffer back; it never reaches into the
/// codec to do that itself.
#[test]
fn the_encoder_stream_can_be_read_without_draining_it() {
    let mut encoder = Encoder::new();
    let update = encoder.set_max_capacity(4096).expect("the table was not sized");
    encoder.queue(&[update]);

    let queued = encoder.encoder_stream().to_vec();
    assert!(!queued.is_empty(), "a queued instruction must reach the stream");
    assert_eq!(encoder.encoder_stream(), queued, "reading the stream must not drain it");
    assert_eq!(encoder.take_encoder_stream(), queued, "taking it must yield what was read");
    assert!(encoder.encoder_stream().is_empty(), "taking the stream drains it");
}

#[test]
fn the_decoder_stream_can_be_read_without_draining_it() {
    let mut decoder = Decoder::new();
    decoder.queue(&[DecoderInstruction::SectionAcknowledgment { stream_id: 0 }]);

    let queued = decoder.decoder_stream().to_vec();
    assert!(!queued.is_empty(), "a queued instruction must reach the stream");
    assert_eq!(decoder.decoder_stream(), queued, "reading the stream must not drain it");
    assert_eq!(decoder.take_decoder_stream(), queued, "taking it must yield what was read");
    assert!(decoder.decoder_stream().is_empty(), "taking the stream drains it");
}

#[test]
fn a_reclaimed_encoder_buffer_is_reused_and_keeps_what_was_queued_meanwhile() {
    let mut encoder = Encoder::new();
    let update = encoder.set_max_capacity(4096).expect("the table was not sized");
    encoder.queue(&[update]);

    let taken = encoder.take_encoder_stream();
    assert!(taken.capacity() > 0, "the taken buffer must carry its allocation");

    // Something queued while the caller held the buffer must survive the reclaim.
    encoder.queue(&[EncoderInstruction::Duplicate { index: 0 }]);
    let meanwhile = encoder.encoder_stream().to_vec();
    assert!(!meanwhile.is_empty(), "the second instruction must reach the stream");

    encoder.reclaim_encoder_stream(taken);

    assert_eq!(encoder.encoder_stream(), meanwhile, "a reclaim must not drop what was queued");
}

#[test]
fn a_reclaimed_buffer_that_outgrew_the_idle_capacity_is_given_up() {
    let mut encoder = Encoder::new();
    encoder.set_idle_capacity(1024);

    let grown = Vec::with_capacity(64 * 1024);
    encoder.reclaim_encoder_stream(grown);

    assert!(
        encoder.take_encoder_stream().capacity() <= 1024,
        "a buffer past the idle capacity must not stay attached to an idle encoder",
    );

    let mut decoder = Decoder::new();
    decoder.set_idle_capacity(1024);
    decoder.reclaim_decoder_stream(Vec::with_capacity(64 * 1024));

    assert!(decoder.take_decoder_stream().capacity() <= 1024, "the decoder must give the memory back too");
}

/// The codecs stand alone, so their ceilings are their own.
#[test]
fn a_codec_carries_no_setting_that_is_not_qpack() {
    let mut encoder = Encoder::new();
    encoder.set_idle_capacity(2048);
    encoder.set_max_outstanding_sections(4);
    encoder.set_max_instruction_size(999);

    // Nothing above is an HTTP/3 or QUIC setting, and the encoder needs none.
    let update = encoder.set_max_capacity(4096).expect("the table was not sized");
    encoder.queue(&[update]);
    assert!(!encoder.encoder_stream().is_empty());
}

#[test]
fn an_unacknowledged_entry_is_not_inserted_again() {
    let fields = vec![field("x-custom", "value")];
    let (mut encoder, mut decoder) = paired();

    let (first, stream) = section(&mut encoder, 0, &fields);
    assert_eq!(encoder.dynamic_table().inserted_count(), 1);

    let (second, _) = section(&mut encoder, 4, &fields);
    assert_eq!(encoder.dynamic_table().inserted_count(), 1, "an exact copy already in the table must not be inserted again");

    decoder.on_encoder_stream(&stream).expect("the instructions did not apply");
    let (decoded, _) = decoder.decode(0, &first).expect("the first section did not decode");
    assert_eq!(decoded, fields);
    let (decoded, _) = decoder.decode(4, &second).expect("the second section did not decode");
    assert_eq!(decoded, fields);
}

// ---------------------------------------------------------------- conformance

#[test]
fn a_table_will_not_evict_an_entry_a_section_still_names() {
    let mut table = DynamicTable::new(2 * (HeaderField::OVERHEAD + 2));
    table.insert(field("a", "1"));
    table.insert(field("b", "2"));

    assert_eq!(table.oldest(), 0, "the oldest entry is the one the next eviction would take");

    assert!(table.admits(&field("c", "3"), u64::MAX), "with nothing in flight the table may make room as it likes");
    assert!(
        !table.admits(&field("c", "3"), 0),
        "RFC 9204 2.1.1.1: an entry a field block still names may not be evicted to make room"
    );
    assert!(table.admits(&field("c", "3"), 1), "an entry nothing names any longer may be");
}

#[test]
fn an_encoder_never_evicts_what_its_unacknowledged_sections_name() {
    // Room for two entries and no more, so every insertion past the second
    // has to evict one.
    let capacity = 2 * (HeaderField::OVERHEAD + 8);

    let mut encoder = Encoder::new();
    encoder.set_max_capacity(capacity);
    encoder.set_capacity_limit(capacity);

    let mut decoder = Decoder::new();
    decoder.set_max_capacity(capacity);

    // A first section fills the table.
    let first = encoder.encode(0, &[field("aaaa", "1111"), field("bbbb", "2222")]);
    decoder.on_encoder_stream(&encoder.take_encoder_stream()).expect("the encoder stream was refused");

    // Tell the encoder the insertions arrived, so it may reference them, but
    // never acknowledge the section itself.
    encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment: 2 });
    let referencing = encoder.encode(4, &[field("aaaa", "1111"), field("bbbb", "2222")]);

    let before = encoder.dynamic_table().inserted_count();

    // Now encode a section of fresh fields on another stream. Making room for
    // them would mean evicting what stream 4 still names.
    let _ = encoder.encode(8, &[field("cccc", "3333"), field("dddd", "4444")]);

    assert_eq!(
        encoder.dynamic_table().inserted_count(),
        before,
        "nothing may be inserted while doing so would evict an entry an unacknowledged section names"
    );

    // The peer can still read the section that is in flight.
    decoder.on_encoder_stream(&encoder.take_encoder_stream()).expect("the encoder stream was refused");
    let (fields, _) = decoder.decode(4, &referencing).expect("a section the encoder promised became unreadable");
    assert_eq!(fields, vec![field("aaaa", "1111"), field("bbbb", "2222")]);

    let (fields, _) = decoder.decode(0, &first).expect("the first section became unreadable");
    assert_eq!(fields, vec![field("aaaa", "1111"), field("bbbb", "2222")]);
}

#[test]
fn acknowledging_a_section_frees_what_it_named() {
    let capacity = 2 * (HeaderField::OVERHEAD + 8);

    let mut encoder = Encoder::new();
    encoder.set_max_capacity(capacity);
    encoder.set_capacity_limit(capacity);

    let _ = encoder.encode(0, &[field("aaaa", "1111"), field("bbbb", "2222")]);
    encoder.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment: 2 });
    let _ = encoder.encode(4, &[field("aaaa", "1111"), field("bbbb", "2222")]);

    assert_eq!(encoder.outstanding(), 1, "the section on stream 4 names dynamic entries and is not acknowledged");
    encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 4 });
    assert_eq!(encoder.outstanding(), 0);

    let before = encoder.dynamic_table().inserted_count();
    let _ = encoder.encode(8, &[field("cccc", "3333"), field("dddd", "4444")]);

    assert!(
        encoder.dynamic_table().inserted_count() > before,
        "once nothing names them, the table is free to evict and insert again"
    );
}
