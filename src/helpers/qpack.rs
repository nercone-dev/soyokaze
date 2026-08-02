use std::collections::VecDeque;
use std::fmt;
use std::sync::OnceLock;

use crate::helpers::hpack::{self, HeaderField};
use crate::helpers::huffman;
use crate::helpers::text::Text;
use crate::models::Limits;

pub const DEFAULT_MAX_TABLE_CAPACITY: usize = 0;

pub const ADVERTISED_TABLE_CAPACITY: usize = 4096;

pub fn static_table() -> &'static [HeaderField; 99] {
    static STATIC_TABLE: OnceLock<[HeaderField; 99]> = OnceLock::new();
    STATIC_TABLE.get_or_init(|| {
        [
            (":authority", ""),                                                     // 0
            (":path", "/"),                                                         // 1
            ("age", "0"),                                                           // 2
            ("content-disposition", ""),                                            // 3
            ("content-length", "0"),                                                // 4
            ("cookie", ""),                                                         // 5
            ("date", ""),                                                           // 6
            ("etag", ""),                                                           // 7
            ("if-modified-since", ""),                                              // 8
            ("if-none-match", ""),                                                  // 9
            ("last-modified", ""),                                                  // 10
            ("link", ""),                                                           // 11
            ("location", ""),                                                       // 12
            ("referer", ""),                                                        // 13
            ("set-cookie", ""),                                                     // 14
            (":method", "CONNECT"),                                                 // 15
            (":method", "DELETE"),                                                  // 16
            (":method", "GET"),                                                     // 17
            (":method", "HEAD"),                                                    // 18
            (":method", "OPTIONS"),                                                 // 19
            (":method", "POST"),                                                    // 20
            (":method", "PUT"),                                                     // 21
            (":scheme", "http"),                                                    // 22
            (":scheme", "https"),                                                   // 23
            (":status", "103"),                                                     // 24
            (":status", "200"),                                                     // 25
            (":status", "304"),                                                     // 26
            (":status", "404"),                                                     // 27
            (":status", "503"),                                                     // 28
            ("accept", "*/*"),                                                      // 29
            ("accept", "application/dns-message"),                                  // 30
            ("accept-encoding", "gzip, deflate, br"),                               // 31
            ("accept-ranges", "bytes"),                                             // 32
            ("access-control-allow-headers", "cache-control"),                      // 33
            ("access-control-allow-headers", "content-type"),                       // 34
            ("access-control-allow-origin", "*"),                                   // 35
            ("cache-control", "max-age=0"),                                         // 36
            ("cache-control", "max-age=2592000"),                                   // 37
            ("cache-control", "max-age=604800"),                                    // 38
            ("cache-control", "no-cache"),                                          // 39
            ("cache-control", "no-store"),                                          // 40
            ("cache-control", "public, max-age=31536000"),                          // 41
            ("content-encoding", "br"),                                             // 42
            ("content-encoding", "gzip"),                                           // 43
            ("content-type", "application/dns-message"),                            // 44
            ("content-type", "application/javascript"),                             // 45
            ("content-type", "application/json"),                                   // 46
            ("content-type", "application/x-www-form-urlencoded"),                  // 47
            ("content-type", "image/gif"),                                          // 48
            ("content-type", "image/jpeg"),                                         // 49
            ("content-type", "image/png"),                                          // 50
            ("content-type", "text/css"),                                           // 51
            ("content-type", "text/html; charset=utf-8"),                           // 52
            ("content-type", "text/plain"),                                         // 53
            ("content-type", "text/plain;charset=utf-8"),                           // 54
            ("range", "bytes=0-"),                                                  // 55
            ("strict-transport-security", "max-age=31536000"),                      // 56
            ("strict-transport-security", "max-age=31536000; includesubdomains"),   // 57
            ("strict-transport-security", "max-age=31536000; includesubdomains; preload"), // 58
            ("vary", "accept-encoding"),                                            // 59
            ("vary", "origin"),                                                     // 60
            ("x-content-type-options", "nosniff"),                                  // 61
            ("x-xss-protection", "1; mode=block"),                                  // 62
            (":status", "100"),                                                     // 63
            (":status", "204"),                                                     // 64
            (":status", "206"),                                                     // 65
            (":status", "302"),                                                     // 66
            (":status", "400"),                                                     // 67
            (":status", "403"),                                                     // 68
            (":status", "421"),                                                     // 69
            (":status", "425"),                                                     // 70
            (":status", "500"),                                                     // 71
            ("accept-language", ""),                                                // 72
            ("access-control-allow-credentials", "FALSE"),                          // 73
            ("access-control-allow-credentials", "TRUE"),                           // 74
            ("access-control-allow-headers", "*"),                                  // 75
            ("access-control-allow-methods", "get"),                                // 76
            ("access-control-allow-methods", "get, post, options"),                 // 77
            ("access-control-allow-methods", "options"),                            // 78
            ("access-control-expose-headers", "content-length"),                    // 79
            ("access-control-request-headers", "content-type"),                     // 80
            ("access-control-request-method", "get"),                               // 81
            ("access-control-request-method", "post"),                              // 82
            ("alt-svc", "clear"),                                                   // 83
            ("authorization", ""),                                                  // 84
            ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"), // 85
            ("early-data", "1"),                                                    // 86
            ("expect-ct", ""),                                                      // 87
            ("forwarded", ""),                                                      // 88
            ("if-range", ""),                                                       // 89
            ("origin", ""),                                                         // 90
            ("purpose", "prefetch"),                                                // 91
            ("server", ""),                                                         // 92
            ("timing-allow-origin", "*"),                                           // 93
            ("upgrade-insecure-requests", "1"),                                     // 94
            ("user-agent", ""),                                                     // 95
            ("x-forwarded-for", ""),                                                // 96
            ("x-frame-options", "deny"),                                            // 97
            ("x-frame-options", "sameorigin"),                                      // 98
        ]
        .map(|(name, value)| HeaderField::new(name, value))
    })
}

pub fn static_index() -> &'static hpack::StaticIndex {
    static INDEX: OnceLock<hpack::StaticIndex> = OnceLock::new();
    INDEX.get_or_init(|| hpack::StaticIndex::new(static_table(), 0))
}

pub fn find_static(field: &HeaderField) -> Option<(u64, bool)> {
    let (named, exact) = static_index().lookup(&field.name, &field.value);

    match (exact, named) {
        (Some(index), _) => Some((index as u64, true)),
        (None, Some(index)) => Some((index as u64, false)),
        (None, None) => None,
    }
}

pub fn max_entries(max_capacity: usize) -> u64 {
    (max_capacity / HeaderField::OVERHEAD) as u64
}

pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    size: usize,
    capacity: usize,
    inserted_count: u64,
}

impl DynamicTable {
    pub fn new(capacity: usize) -> Self {
        Self { entries: VecDeque::new(), size: 0, capacity, inserted_count: 0 }
    }

    pub fn insert(&mut self, field: HeaderField) -> u64 {
        let size = field.size();

        while self.size + size > self.capacity {
            match self.entries.pop_back() {
                Some(evicted) => self.size -= evicted.size(),
                None => break,
            }
        }

        self.size += size;
        self.entries.push_front(field);
        self.inserted_count += 1;

        self.inserted_count - 1
    }

    pub fn fits(&self, field: &HeaderField) -> bool {
        field.size() <= self.capacity
    }

    pub fn get(&self, absolute_index: u64) -> Option<&HeaderField> {
        let offset = self.inserted_count.checked_sub(absolute_index + 1)?;
        self.entries.get(offset as usize)
    }

    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;

        while self.size > self.capacity {
            match self.entries.pop_back() {
                Some(evicted) => self.size -= evicted.size(),
                None => break,
            }
        }
    }

    pub fn relative(&self, index: u64) -> Option<u64> {
        self.inserted_count.checked_sub(index + 1)
    }

    pub fn indexed(&self, base: u64, index: u64) -> Option<u64> {
        base.checked_sub(index + 1)
    }

    pub fn post_base(&self, base: u64, index: u64) -> Option<u64> {
        base.checked_add(index)
    }

    pub fn find(&self, field: &HeaderField) -> Option<(u64, bool)> {
        let mut name_only = None;

        for (offset, entry) in self.entries.iter().enumerate() {
            if entry.name != field.name {
                continue;
            }

            let Some(absolute) = self.inserted_count.checked_sub(offset as u64 + 1) else {
                break;
            };

            if entry.value == field.value {
                return Some((absolute, true));
            }

            name_only.get_or_insert(absolute);
        }

        name_only.map(|absolute| (absolute, false))
    }

    pub fn inserted_count(&self) -> u64 {
        self.inserted_count
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    IndexOutOfRange(u64),
    IntegerOverflow,
    InvalidCapacityUpdate,
    InvalidInsertCount,
    InvalidBase,
    EntryTooLarge,
    Incomplete,
    Blocked,
    Huffman(huffman::DecodeError),
    DecodedSizeExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfRange(index) => write!(f, "absolute index {index} is out of range"),
            Self::IntegerOverflow => write!(f, "integer representation overflowed"),
            Self::InvalidCapacityUpdate => write!(f, "dynamic table capacity update exceeds the negotiated limit"),
            Self::InvalidInsertCount => write!(f, "required insert count could not have been produced by an encoder"),
            Self::InvalidBase => write!(f, "delta base places the base below zero"),
            Self::EntryTooLarge => write!(f, "entry is larger than the dynamic table capacity"),
            Self::DecodedSizeExceeded => write!(f, "decoded header list exceeds the permitted size"),
            Self::Incomplete => write!(f, "representation ends before the block does"),
            Self::Blocked => write!(f, "decoding is blocked on a pending dynamic table insertion"),
            Self::Huffman(err) => write!(f, "huffman error: {err}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<huffman::DecodeError> for Error {
    fn from(err: huffman::DecodeError) -> Self {
        Self::Huffman(err)
    }
}

impl From<hpack::Error> for Error {
    fn from(err: hpack::Error) -> Self {
        match err {
            hpack::Error::IndexOutOfRange(index) => Self::IndexOutOfRange(index as u64),
            hpack::Error::IntegerOverflow => Self::IntegerOverflow,
            hpack::Error::InvalidDynamicTableSizeUpdate => Self::InvalidCapacityUpdate,
            hpack::Error::Incomplete => Self::Incomplete,
            hpack::Error::Huffman(err) => Self::Huffman(err),
            hpack::Error::DecodedSizeExceeded => Self::DecodedSizeExceeded,
        }
    }
}

pub fn encode_string(out: &mut Vec<u8>, value: &[u8], prefix_bits: u8, flags: u8) {
    let huffman = 1 << prefix_bits;
    let encoded = huffman::encoded_len(value);

    if encoded < value.len() {
        hpack::encode_integer(out, encoded as u64, prefix_bits, flags | huffman);
        huffman::encode_sized(value, encoded, out);
    } else {
        hpack::encode_integer(out, value.len() as u64, prefix_bits, flags);
        out.extend_from_slice(value);
    }
}

pub fn decode_string(input: &[u8], prefix_bits: u8) -> Result<(usize, Vec<u8>), Error> {
    let mut value = Vec::new();
    let consumed = decode_string_into(input, prefix_bits, &mut value)?;
    Ok((consumed, value))
}

pub fn decode_string_into(input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<usize, Error> {
    decode_string_into_ascii(input, prefix_bits, scratch).map(|(consumed, _)| consumed)
}

pub fn decode_string_into_ascii(input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<(usize, bool), Error> {
    let huffman = input.first().ok_or(Error::Incomplete)? & 1 << prefix_bits != 0;
    let (prefix, length) = hpack::decode_integer(input, prefix_bits)?;

    let length = length as usize;
    let end = prefix.checked_add(length).ok_or(Error::Incomplete)?;
    let octets = input.get(prefix..end).ok_or(Error::Incomplete)?;

    scratch.clear();
    let ascii = if huffman {
        huffman::decode_into_ascii(octets, scratch)?
    } else {
        scratch.extend_from_slice(octets);
        octets.is_ascii()
    };

    Ok((end, ascii))
}

pub fn decode_field(input: &[u8], prefix_bits: u8) -> Result<(usize, Text), Error> {
    let mut scratch = Vec::new();
    decode_field_into(input, prefix_bits, &mut scratch)
}

pub fn decode_field_into(input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<(usize, Text), Error> {
    let (consumed, ascii) = decode_string_into_ascii(input, prefix_bits, scratch)?;
    Ok((consumed, hpack::decoded_text(scratch, ascii)))
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncoderInstruction {
    SetDynamicTableCapacity { capacity: usize },
    InsertWithNameReference { from_static: bool, name_index: u64, value: Vec<u8> },
    InsertWithLiteralName { name: Vec<u8>, value: Vec<u8> },
    Duplicate { index: u64 },
}

impl EncoderInstruction {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::SetDynamicTableCapacity { capacity } => {
                hpack::encode_integer(out, *capacity as u64, 5, 0x20);
            }

            Self::InsertWithNameReference { from_static, name_index, value } => {
                hpack::encode_integer(out, *name_index, 6, 0x80 | u8::from(*from_static) << 6);
                encode_string(out, value, 7, 0x00);
            }

            Self::InsertWithLiteralName { name, value } => {
                encode_string(out, name, 5, 0x40);
                encode_string(out, value, 7, 0x00);
            }

            Self::Duplicate { index } => hpack::encode_integer(out, *index, 5, 0x00),
        }
    }

    pub fn decode(input: &[u8]) -> Result<(usize, Self), Error> {
        let first = *input.first().ok_or(Error::Incomplete)?;

        if first & 0x80 != 0 {
            let (mut consumed, name_index) = hpack::decode_integer(input, 6)?;
            let (taken, value) = decode_string(&input[consumed..], 7)?;
            consumed += taken;

            return Ok((consumed, Self::InsertWithNameReference {
                from_static: first & 0x40 != 0,
                name_index,
                value,
            }));
        }

        if first & 0x40 != 0 {
            let (mut consumed, name) = decode_string(input, 5)?;
            let (taken, value) = decode_string(&input[consumed..], 7)?;
            consumed += taken;

            return Ok((consumed, Self::InsertWithLiteralName { name, value }));
        }

        if first & 0x20 != 0 {
            let (consumed, capacity) = hpack::decode_integer(input, 5)?;
            return Ok((consumed, Self::SetDynamicTableCapacity { capacity: capacity as usize }));
        }

        let (consumed, index) = hpack::decode_integer(input, 5)?;
        Ok((consumed, Self::Duplicate { index }))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecoderInstruction {
    SectionAcknowledgment { stream_id: u64 },
    StreamCancellation { stream_id: u64 },
    InsertCountIncrement { increment: u64 },
}

impl DecoderInstruction {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::SectionAcknowledgment { stream_id } => hpack::encode_integer(out, *stream_id, 7, 0x80),
            Self::StreamCancellation { stream_id } => hpack::encode_integer(out, *stream_id, 6, 0x40),
            Self::InsertCountIncrement { increment } => hpack::encode_integer(out, *increment, 6, 0x00),
        }
    }

    pub fn decode(input: &[u8]) -> Result<(usize, Self), Error> {
        let first = *input.first().ok_or(Error::Incomplete)?;

        if first & 0x80 != 0 {
            let (consumed, stream_id) = hpack::decode_integer(input, 7)?;
            return Ok((consumed, Self::SectionAcknowledgment { stream_id }));
        }

        if first & 0x40 != 0 {
            let (consumed, stream_id) = hpack::decode_integer(input, 6)?;
            return Ok((consumed, Self::StreamCancellation { stream_id }));
        }

        let (consumed, increment) = hpack::decode_integer(input, 6)?;
        Ok((consumed, Self::InsertCountIncrement { increment }))
    }
}

pub fn relative(base: u64, absolute: u64) -> u64 {
    base.saturating_sub(absolute).saturating_sub(1)
}

pub fn encode_insert_count(required: u64, max_capacity: usize) -> u64 {
    let full_range = 2 * max_entries(max_capacity);
    if required == 0 || full_range == 0 {
        return 0;
    }

    required % full_range + 1
}

pub fn decode_insert_count(encoded: u64, inserted: u64, max_capacity: usize) -> Result<u64, Error> {
    if encoded == 0 {
        return Ok(0);
    }

    let full_range = 2 * max_entries(max_capacity);
    if full_range == 0 || encoded > full_range {
        return Err(Error::InvalidInsertCount);
    }

    let max_value = inserted.saturating_add(max_entries(max_capacity));
    let max_wrapped = max_value / full_range * full_range;

    let mut required = max_wrapped.saturating_add(encoded).saturating_sub(1);
    if required > max_value {
        if required <= full_range {
            return Err(Error::InvalidInsertCount);
        }
        required -= full_range;
    }

    if required == 0 {
        return Err(Error::InvalidInsertCount);
    }

    Ok(required)
}

pub struct Encoder {
    dynamic_table: DynamicTable,
    known_received_count: u64,
    max_capacity: usize,
    max_outstanding_sections: usize,
    sections: VecDeque<(u64, u64)>,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(0),
            known_received_count: 0,
            max_capacity: DEFAULT_MAX_TABLE_CAPACITY,
            max_outstanding_sections: Limits::default().max_outstanding_sections as usize,
            sections: VecDeque::new(),
        }
    }

    pub fn set_max_outstanding_sections(&mut self, max_sections: usize) {
        self.max_outstanding_sections = max_sections;
    }

    pub fn encode(&mut self, stream_id: u64, headers: &[HeaderField]) -> (Vec<u8>, Vec<EncoderInstruction>) {
        let mut instructions = Vec::new();
        let mut representations = Vec::new();
        let mut required = 0;

        let tracked = self.sections.len() < self.max_outstanding_sections;

        for field in headers {
            let matched = match tracked {
                true => self.reference(field),
                false => find_static(field).map(|(index, value)| (true, index, value)),
            };

            let indexed = matched.is_some_and(|(_, _, value)| value)
                || self.dynamic_table.find(field).is_some_and(|(_, value)| value);

            if tracked
                && !indexed
                && !field.sensitive()
                && let Some(instruction) = self.insert(field, matched)
            {
                instructions.push(instruction);
            }

            if let Some((false, absolute, _)) = matched {
                required = required.max(absolute.saturating_add(1));
            }

            representations.push((field, matched));
        }

        let mut out = Vec::with_capacity(representations.len() * 8 + 16);
        hpack::encode_integer(&mut out, encode_insert_count(required, self.max_capacity), 8, 0x00);
        hpack::encode_integer(&mut out, 0, 7, 0x00);

        for (field, matched) in representations {
            self.encode_field(&mut out, field, matched, required);
        }

        if required > 0 {
            self.sections.push_back((stream_id, required));
        }

        (out, instructions)
    }

    pub fn reference(&self, field: &HeaderField) -> Option<(bool, u64, bool)> {
        let in_static = find_static(field);
        if let Some((index, true)) = in_static {
            return Some((true, index, true));
        }

        let in_dynamic = self
            .dynamic_table
            .find(field)
            .filter(|(absolute, _)| *absolute < self.known_received_count);
        if let Some((absolute, true)) = in_dynamic {
            return Some((false, absolute, true));
        }

        in_static
            .map(|(index, _)| (true, index, false))
            .or(in_dynamic.map(|(absolute, _)| (false, absolute, false)))
    }

    pub fn insert(&mut self, field: &HeaderField, matched: Option<(bool, u64, bool)>) -> Option<EncoderInstruction> {
        if !self.dynamic_table.fits(field) {
            return None;
        }

        let instruction = match matched {
            Some((from_static, index, _)) => EncoderInstruction::InsertWithNameReference {
                from_static,
                name_index: if from_static {
                    index
                } else {
                    self.dynamic_table.inserted_count().saturating_sub(index).saturating_sub(1)
                },
                value: field.value.as_bytes().to_vec(),
            },
            None => EncoderInstruction::InsertWithLiteralName {
                name: field.name.as_bytes().to_vec(),
                value: field.value.as_bytes().to_vec(),
            },
        };

        self.dynamic_table.insert(field.clone());
        Some(instruction)
    }

    pub fn encode_field(&self, out: &mut Vec<u8>, field: &HeaderField, matched: Option<(bool, u64, bool)>, base: u64) {
        let never = u8::from(field.sensitive());

        match matched {
            Some((true, index, true)) => hpack::encode_integer(out, index, 6, 0xc0),
            Some((false, absolute, true)) => {
                hpack::encode_integer(out, relative(base, absolute), 6, 0x80);
            }

            Some((true, index, false)) => {
                hpack::encode_integer(out, index, 4, 0x50 | never << 5);
                encode_string(out, field.value.as_bytes(), 7, 0x00);
            }
            Some((false, absolute, false)) => {
                hpack::encode_integer(out, relative(base, absolute), 4, 0x40 | never << 5);
                encode_string(out, field.value.as_bytes(), 7, 0x00);
            }

            None => {
                encode_string(out, field.name.as_bytes(), 3, 0x20 | never << 4);
                encode_string(out, field.value.as_bytes(), 7, 0x00);
            }
        }
    }

    pub fn on_decoder_instruction(&mut self, instruction: DecoderInstruction) {
        match instruction {
            DecoderInstruction::SectionAcknowledgment { stream_id } => {
                if let Some(offset) = self.sections.iter().position(|(id, _)| *id == stream_id)
                    && let Some((_, required)) = self.sections.remove(offset)
                {
                    self.known_received_count = self.known_received_count.max(required);
                }
            }

            DecoderInstruction::InsertCountIncrement { increment } => {
                self.known_received_count = self.known_received_count.saturating_add(increment);
            }

            DecoderInstruction::StreamCancellation { stream_id } => self.cancel(stream_id),
        }
    }

    pub fn cancel(&mut self, stream_id: u64) {
        self.sections.retain(|(id, _)| *id != stream_id);
    }

    pub fn outstanding(&self) -> usize {
        self.sections.len()
    }

    pub fn set_capacity(&mut self, capacity: usize) -> Option<EncoderInstruction> {
        let capacity = capacity.min(self.max_capacity);
        if capacity == self.dynamic_table.capacity() {
            return None;
        }

        self.dynamic_table.set_capacity(capacity);
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity })
    }

    pub fn set_max_capacity(&mut self, max_capacity: usize) {
        self.max_capacity = max_capacity;
        if self.dynamic_table.capacity() > max_capacity {
            self.dynamic_table.set_capacity(max_capacity);
        }
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn known_received_count(&self) -> u64 {
        self.known_received_count
    }

    pub fn dynamic_table(&self) -> &DynamicTable {
        &self.dynamic_table
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Decoder {
    dynamic_table: DynamicTable,
    max_capacity: usize,
    max_decoded_size: usize,
    scratch: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(ADVERTISED_TABLE_CAPACITY),
            max_capacity: ADVERTISED_TABLE_CAPACITY,
            max_decoded_size: hpack::DEFAULT_MAX_DECODED_SIZE,
            scratch: Vec::new(),
        }
    }

    pub fn set_max_decoded_size(&mut self, max_size: usize) {
        self.max_decoded_size = max_size;
    }

    pub fn on_encoder_instruction(&mut self, instruction: EncoderInstruction) -> Result<Option<DecoderInstruction>, Error> {
        let field = match instruction {
            EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                if capacity > self.max_capacity {
                    return Err(Error::InvalidCapacityUpdate);
                }

                self.dynamic_table.set_capacity(capacity);
                return Ok(None);
            }

            EncoderInstruction::InsertWithNameReference { from_static, name_index, value } => {
                let name = if from_static {
                    static_table()
                        .get(name_index as usize)
                        .ok_or(Error::IndexOutOfRange(name_index))?
                        .name
                        .clone()
                } else {
                    let absolute = self.dynamic_table.relative(name_index).ok_or(Error::IndexOutOfRange(name_index))?;
                    self.dynamic_table.get(absolute).ok_or(Error::IndexOutOfRange(absolute))?.name.clone()
                };

                HeaderField::new(name, Text::from_utf8_lossy(&value))
            }

            EncoderInstruction::InsertWithLiteralName { name, value } => {
                HeaderField::new(Text::from_utf8_lossy(&name), Text::from_utf8_lossy(&value))
            }

            EncoderInstruction::Duplicate { index } => {
                let absolute = self.dynamic_table.relative(index).ok_or(Error::IndexOutOfRange(index))?;
                self.dynamic_table.get(absolute).ok_or(Error::IndexOutOfRange(absolute))?.clone()
            }
        };

        if !self.dynamic_table.fits(&field) {
            return Err(Error::EntryTooLarge);
        }

        self.dynamic_table.insert(field);
        Ok(Some(DecoderInstruction::InsertCountIncrement { increment: 1 }))
    }

    pub fn decode(&mut self, stream_id: u64, block: &[u8]) -> Result<(Vec<HeaderField>, Option<DecoderInstruction>), Error> {
        let mut scratch = std::mem::take(&mut self.scratch);
        let decoded = self.decode_into(stream_id, block, &mut scratch);
        self.scratch = scratch;
        decoded
    }

    pub fn decode_into(&mut self, stream_id: u64, block: &[u8], scratch: &mut Vec<u8>) -> Result<(Vec<HeaderField>, Option<DecoderInstruction>), Error> {
        let (mut consumed, encoded) = hpack::decode_integer(block, 8)?;
        let required = decode_insert_count(encoded, self.dynamic_table.inserted_count(), self.max_capacity)?;

        if required > self.dynamic_table.inserted_count() {
            return Err(Error::Blocked);
        }

        let negative = block.get(consumed).ok_or(Error::Incomplete)? & 0x80 != 0;
        let (taken, delta) = hpack::decode_integer(&block[consumed..], 7)?;
        consumed += taken;

        let base = if negative {
            required.checked_sub(delta.checked_add(1).ok_or(Error::InvalidBase)?).ok_or(Error::InvalidBase)?
        } else {
            required.checked_add(delta).ok_or(Error::IntegerOverflow)?
        };

        let mut headers = Vec::new();
        let mut decoded_size = 0usize;
        let mut rest = &block[consumed..];

        while let Some(first) = rest.first() {
            let (consumed, field) = match first {
                _ if first & 0x80 != 0 => {
                    let (consumed, index) = hpack::decode_integer(rest, 6)?;
                    (consumed, self.resolve(first & 0x40 != 0, base, index)?)
                }

                _ if first & 0x40 != 0 => {
                    let (mut consumed, index) = hpack::decode_integer(rest, 4)?;
                    let name = self.resolve_name(first & 0x10 != 0, base, index)?;

                    let (taken, value) = decode_field_into(&rest[consumed..], 7, scratch)?;
                    consumed += taken;

                    (consumed, HeaderField::new(name, value))
                }

                _ if first & 0x20 != 0 => {
                    let (mut consumed, name) = decode_field_into(rest, 3, scratch)?;
                    let (taken, value) = decode_field_into(&rest[consumed..], 7, scratch)?;
                    consumed += taken;

                    (consumed, HeaderField::new(name, value))
                }

                _ if first & 0x10 != 0 => {
                    let (consumed, index) = hpack::decode_integer(rest, 4)?;
                    let absolute = self.dynamic_table.post_base(base, index).ok_or(Error::IndexOutOfRange(index))?;

                    (consumed, self.dynamic_table.get(absolute).ok_or(Error::IndexOutOfRange(absolute))?.clone())
                }

                _ => {
                    let (mut consumed, index) = hpack::decode_integer(rest, 3)?;
                    let absolute = self.dynamic_table.post_base(base, index).ok_or(Error::IndexOutOfRange(index))?;
                    let name = self.dynamic_table.get(absolute).ok_or(Error::IndexOutOfRange(absolute))?.name.clone();

                    let (taken, value) = decode_field_into(&rest[consumed..], 7, scratch)?;
                    consumed += taken;

                    (consumed, HeaderField::new(name, value))
                }
            };

            decoded_size += field.size();
            if decoded_size > self.max_decoded_size {
                return Err(Error::DecodedSizeExceeded);
            }

            if headers.is_empty() {
                headers.reserve(block.len().min(64));
            }

            headers.push(field);
            rest = &rest[consumed..];
        }

        let acknowledgment = (required > 0).then_some(DecoderInstruction::SectionAcknowledgment { stream_id });

        Ok((headers, acknowledgment))
    }

    pub fn resolve(&self, from_static: bool, base: u64, index: u64) -> Result<HeaderField, Error> {
        if from_static {
            return static_table().get(index as usize).cloned().ok_or(Error::IndexOutOfRange(index));
        }

        let absolute = self.dynamic_table.indexed(base, index).ok_or(Error::IndexOutOfRange(index))?;
        self.dynamic_table.get(absolute).cloned().ok_or(Error::IndexOutOfRange(absolute))
    }

    pub fn resolve_name(&self, from_static: bool, base: u64, index: u64) -> Result<Text, Error> {
        if from_static {
            let field = static_table().get(index as usize).ok_or(Error::IndexOutOfRange(index))?;
            return Ok(field.name.clone());
        }

        let absolute = self.dynamic_table.indexed(base, index).ok_or(Error::IndexOutOfRange(index))?;
        let field = self.dynamic_table.get(absolute).ok_or(Error::IndexOutOfRange(absolute))?;
        Ok(field.name.clone())
    }

    pub fn set_max_capacity(&mut self, max_capacity: usize) {
        self.max_capacity = max_capacity;
        if self.dynamic_table.capacity() > max_capacity {
            self.dynamic_table.set_capacity(max_capacity);
        }
    }

    pub fn dynamic_table(&self) -> &DynamicTable {
        &self.dynamic_table
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
