use soyokaze::helpers::fields::HeaderField;
use soyokaze::helpers::qpack::{self, Decoder, DecoderInstruction, Encoder, EncoderInstruction};

use super::input::Input;

pub fn check(data: &[u8]) {
    block(data);
    encoder_instruction(data);
    decoder_instruction(data);
    insert_count(data);

    let mut input = Input::new(data);
    session(&input.sections(4, 12, 48));
}

pub fn block(data: &[u8]) {
    let mut decoder = Decoder::new();
    let _ = decoder.decode(0, data);

    assert!(
        decoder.dynamic_table().size() <= decoder.dynamic_table().capacity(),
        "the dynamic table grew past its capacity",
    );
}

pub fn encoder_instruction(data: &[u8]) {
    let Ok((consumed, instruction)) = EncoderInstruction::decode(data) else {
        return;
    };

    assert!(consumed <= data.len(), "an encoder instruction ran past the end of the input");

    let encoded = instruction.encode();
    let again = EncoderInstruction::decode(&encoded);
    assert_eq!(again, Ok((encoded.len(), instruction)), "an encoder instruction did not survive re-encoding");
}

pub fn decoder_instruction(data: &[u8]) {
    let Ok((consumed, instruction)) = DecoderInstruction::decode(data) else {
        return;
    };

    assert!(consumed <= data.len(), "a decoder instruction ran past the end of the input");

    let encoded = instruction.encode();
    let again = DecoderInstruction::decode(&encoded);
    assert_eq!(again, Ok((encoded.len(), instruction)), "a decoder instruction did not survive re-encoding");
}

pub fn insert_count(data: &[u8]) {
    let mut input = Input::new(data);

    let capacity = qpack::Decoder::DEFAULT_MAX_CAPACITY;
    let entries = qpack::Prefix::max_entries(capacity);
    let full_range = 2 * entries;

    let inserted = (input.byte() as u64) << 8 | input.byte() as u64;

    let floor = (inserted + entries).saturating_sub(full_range);
    let span = inserted - floor.min(inserted);

    let required = if span == 0 { 0 } else { floor + 1 + input.byte() as u64 % span };

    let encoded = qpack::Prefix::encode_insert_count(required, capacity);
    assert!(encoded <= full_range, "an encoded insert count no decoder would accept");

    let decoded = qpack::Prefix::decode_insert_count(encoded, inserted, capacity);
    assert_eq!(decoded, Ok(required), "required insert count {required} did not survive with {inserted} inserted");
}

pub fn session(sections: &[Vec<HeaderField>]) {
    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();

    if let Some(update) = encoder.set_max_capacity(qpack::Decoder::DEFAULT_MAX_CAPACITY) {
        decoder.on_encoder_instruction(update).expect("the decoder refused the capacity update");
    }

    for (index, fields) in sections.iter().enumerate() {
        let stream_id = index as u64;
        let (block, instructions) = encoder.encode(stream_id, fields);

        for instruction in instructions {
            let bytes = instruction.encode();
            let (consumed, delivered) = match EncoderInstruction::decode(&bytes) {
                Ok(decoded) => decoded,
                Err(err) => panic!("an instruction this encoder produced did not decode: {err}"),
            };

            assert_eq!(consumed, bytes.len(), "an instruction decoded to the wrong length");
            assert_eq!(delivered, instruction, "an instruction changed in transit");

            match decoder.on_encoder_instruction(delivered) {
                Ok(Some(acknowledgment)) => encoder.on_decoder_instruction(acknowledgment),
                Ok(None) => {}
                Err(err) => panic!("the decoder rejected an instruction this encoder produced: {err}"),
            }
        }

        let (decoded, acknowledgment) = match decoder.decode(stream_id, &block) {
            Ok(decoded) => decoded,
            Err(err) => panic!("a section this encoder produced did not decode: {err}"),
        };

        assert_eq!(&decoded, fields, "a field section changed in transit");

        if let Some(acknowledgment) = acknowledgment {
            encoder.on_decoder_instruction(acknowledgment);
        }

        assert_eq!(
            encoder.dynamic_table().inserted_count(),
            decoder.dynamic_table().inserted_count(),
            "the two dynamic tables drifted apart",
        );
    }
}
