use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::OnceLock;

use crate::helpers::huffman;
use crate::helpers::text::Text;

pub const DEFAULT_DYNAMIC_TABLE_SIZE: usize = 4096;
pub const DEFAULT_MAX_DECODED_SIZE: usize = 64 * 1024;

pub const SENSITIVE_NAMES: &[&str] = &["authorization", "proxy-authorization", "cookie", "set-cookie"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: Text,
    pub value: Text,
}

impl HeaderField {
    pub const OVERHEAD: usize = 32;

    pub fn new(name: impl Into<Text>, value: impl Into<Text>) -> Self {
        Self { name: name.into(), value: value.into() }
    }

    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + Self::OVERHEAD
    }

    pub fn sensitive(&self) -> bool {
        matches!(self.name.len(), 6 | 10 | 13 | 19) && SENSITIVE_NAMES.contains(&self.name.as_str())
    }
}

pub fn static_table() -> &'static [HeaderField; 61] {
    static STATIC_TABLE: OnceLock<[HeaderField; 61]> = OnceLock::new();
    STATIC_TABLE.get_or_init(|| {
        [
            (":authority", ""),                  // 1
            (":method", "GET"),                  // 2
            (":method", "POST"),                 // 3
            (":path", "/"),                      // 4
            (":path", "/index.html"),            // 5
            (":scheme", "http"),                 // 6
            (":scheme", "https"),                // 7
            (":status", "200"),                  // 8
            (":status", "204"),                  // 9
            (":status", "206"),                  // 10
            (":status", "304"),                  // 11
            (":status", "400"),                  // 12
            (":status", "404"),                  // 13
            (":status", "500"),                  // 14
            ("accept-charset", ""),              // 15
            ("accept-encoding", "gzip, deflate"), // 16
            ("accept-language", ""),             // 17
            ("accept-ranges", ""),               // 18
            ("accept", ""),                      // 19
            ("access-control-allow-origin", ""), // 20
            ("age", ""),                         // 21
            ("allow", ""),                       // 22
            ("authorization", ""),               // 23
            ("cache-control", ""),               // 24
            ("content-disposition", ""),         // 25
            ("content-encoding", ""),            // 26
            ("content-language", ""),            // 27
            ("content-length", ""),              // 28
            ("content-location", ""),            // 29
            ("content-range", ""),               // 30
            ("content-type", ""),                // 31
            ("cookie", ""),                      // 32
            ("date", ""),                        // 33
            ("etag", ""),                        // 34
            ("expect", ""),                      // 35
            ("expires", ""),                     // 36
            ("from", ""),                        // 37
            ("host", ""),                        // 38
            ("if-match", ""),                    // 39
            ("if-modified-since", ""),           // 40
            ("if-none-match", ""),               // 41
            ("if-range", ""),                    // 42
            ("if-unmodified-since", ""),         // 43
            ("last-modified", ""),               // 44
            ("link", ""),                        // 45
            ("location", ""),                    // 46
            ("max-forwards", ""),                // 47
            ("proxy-authenticate", ""),          // 48
            ("proxy-authorization", ""),         // 49
            ("range", ""),                       // 50
            ("referer", ""),                     // 51
            ("refresh", ""),                     // 52
            ("retry-after", ""),                 // 53
            ("server", ""),                      // 54
            ("set-cookie", ""),                  // 55
            ("strict-transport-security", ""),   // 56
            ("transfer-encoding", ""),           // 57
            ("user-agent", ""),                  // 58
            ("vary", ""),                        // 59
            ("via", ""),                         // 60
            ("www-authenticate", ""),            // 61
        ]
        .map(|(name, value)| HeaderField::new(name, value))
    })
}

#[derive(Default)]
pub struct FieldHasher(u64);

impl Hasher for FieldHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut hash = if self.0 == 0 { 0xcbf2_9ce4_8422_2325 } else { self.0 };

        for byte in bytes {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }

        self.0 = hash;
    }
}

pub type FieldMap<K, V> = HashMap<K, V, BuildHasherDefault<FieldHasher>>;

pub struct NameEntry {
    pub first: usize,
    pub values: Vec<(&'static str, usize)>,
}

pub struct StaticIndex {
    by_name: FieldMap<&'static str, NameEntry>,
}

impl StaticIndex {
    pub fn new(entries: &'static [HeaderField], base: usize) -> Self {
        let mut by_name: FieldMap<&'static str, NameEntry> = FieldMap::default();

        for (offset, entry) in entries.iter().enumerate() {
            let index = base + offset;

            by_name
                .entry(entry.name.as_str())
                .or_insert_with(|| NameEntry { first: index, values: Vec::new() })
                .values
                .push((entry.value.as_str(), index));
        }

        Self { by_name }
    }

    pub fn lookup(&self, name: &str, value: &str) -> (Option<usize>, Option<usize>) {
        let Some(entry) = self.by_name.get(name) else {
            return (None, None);
        };

        let exact = entry.values.iter().find(|(candidate, _)| *candidate == value).map(|(_, index)| *index);
        (Some(entry.first), exact)
    }
}

pub fn static_index() -> &'static StaticIndex {
    static INDEX: OnceLock<StaticIndex> = OnceLock::new();
    INDEX.get_or_init(|| StaticIndex::new(static_table(), 1))
}

pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        Self { entries: VecDeque::new(), size: 0, max_size }
    }

    pub fn insert(&mut self, field: HeaderField) {
        let size = field.size();

        while self.size + size > self.max_size {
            match self.entries.pop_back() {
                Some(evicted) => self.size -= evicted.size(),
                None => return,
            }
        }

        self.size += size;
        self.entries.push_front(field);
    }

    pub fn get(&self, index: usize) -> Option<&HeaderField> {
        self.entries.get(index)
    }

    pub fn resize(&mut self, max_size: usize) {
        self.max_size = max_size;

        while self.size > self.max_size {
            match self.entries.pop_back() {
                Some(evicted) => self.size -= evicted.size(),
                None => break,
            }
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn resolve(&self, index: usize) -> Result<&HeaderField, Error> {
        if index == 0 {
            return Err(Error::IndexOutOfRange(index));
        }

        let table = static_table();

        if (1..=table.len()).contains(&index) {
            return Ok(&table[index - 1]);
        }

        self.get(index - table.len() - 1).ok_or(Error::IndexOutOfRange(index))
    }

    pub fn find(&self, field: &HeaderField) -> Option<(usize, bool)> {
        let (named, exact) = static_index().lookup(&field.name, &field.value);
        if let Some(index) = exact {
            return Some((index, true));
        }

        let base = static_table().len() + 1;
        let mut name_only = named;

        for (offset, entry) in self.entries.iter().enumerate() {
            if entry.name != field.name {
                continue;
            }

            if entry.value == field.value {
                return Some((base + offset, true));
            }

            name_only.get_or_insert(base + offset);
        }

        name_only.map(|index| (index, false))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    IndexOutOfRange(usize),
    IntegerOverflow,
    InvalidDynamicTableSizeUpdate,
    Incomplete,
    Huffman(huffman::DecodeError),
    DecodedSizeExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfRange(index) => write!(f, "index {index} is out of range"),
            Self::IntegerOverflow => write!(f, "integer representation overflowed"),
            Self::InvalidDynamicTableSizeUpdate => write!(f, "dynamic table size update exceeds the negotiated limit"),
            Self::Incomplete => write!(f, "representation ends before the block does"),
            Self::Huffman(err) => write!(f, "huffman error: {err}"),
            Self::DecodedSizeExceeded => write!(f, "decoded header list exceeds the permitted size"),
        }
    }
}

impl std::error::Error for Error {}

impl From<huffman::DecodeError> for Error {
    fn from(err: huffman::DecodeError) -> Self {
        Self::Huffman(err)
    }
}

pub fn prefix_limit(prefix_bits: u8) -> u64 {
    (1u64 << prefix_bits.min(63)) - 1
}

pub fn encode_integer(out: &mut Vec<u8>, value: u64, prefix_bits: u8, flags: u8) {
    let limit = prefix_limit(prefix_bits);

    if value < limit {
        out.push(flags | value as u8);
        return;
    }

    out.push(flags | limit as u8);

    let mut rest = value - limit;
    while rest >= 128 {
        out.push((rest % 128) as u8 | 0x80);
        rest /= 128;
    }
    out.push(rest as u8);
}

pub fn decode_integer(input: &[u8], prefix_bits: u8) -> Result<(usize, u64), Error> {
    let limit = prefix_limit(prefix_bits);

    let first = *input.first().ok_or(Error::Incomplete)?;
    let mut value = first as u64 & limit;
    if value < limit {
        return Ok((1, value));
    }

    let mut consumed = 1;
    let mut shift = 0;
    loop {
        let octet = *input.get(consumed).ok_or(Error::Incomplete)?;
        consumed += 1;

        value = (octet as u64 & 0x7f)
            .checked_shl(shift)
            .and_then(|part| value.checked_add(part))
            .ok_or(Error::IntegerOverflow)?;

        if octet & 0x80 == 0 {
            return Ok((consumed, value));
        }

        shift += 7;
        if shift >= 64 {
            return Err(Error::IntegerOverflow);
        }
    }
}

pub fn encode_string(out: &mut Vec<u8>, value: &[u8], huffman: bool) {
    if huffman {
        let encoded = huffman::encoded_len(value);
        encode_integer(out, encoded as u64, 7, 0x80);
        huffman::encode_sized(value, encoded, out);
    } else {
        encode_integer(out, value.len() as u64, 7, 0x00);
        out.extend_from_slice(value);
    }
}

pub fn encode_value(out: &mut Vec<u8>, value: &[u8]) {
    let encoded = huffman::encoded_len(value);

    if encoded < value.len() {
        encode_integer(out, encoded as u64, 7, 0x80);
        huffman::encode_sized(value, encoded, out);
    } else {
        encode_integer(out, value.len() as u64, 7, 0x00);
        out.extend_from_slice(value);
    }
}

pub fn decode_string(input: &[u8]) -> Result<(usize, Vec<u8>), Error> {
    let mut value = Vec::new();
    let consumed = decode_string_into(input, &mut value)?;
    Ok((consumed, value))
}

pub fn decode_string_into(input: &[u8], scratch: &mut Vec<u8>) -> Result<usize, Error> {
    decode_string_into_ascii(input, scratch).map(|(consumed, _)| consumed)
}

pub fn decode_string_into_ascii(input: &[u8], scratch: &mut Vec<u8>) -> Result<(usize, bool), Error> {
    let huffman = input.first().ok_or(Error::Incomplete)? & 0x80 != 0;
    let (prefix, length) = decode_integer(input, 7)?;

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

#[inline]
pub fn decoded_text(octets: &[u8], ascii: bool) -> Text {
    match ascii {
        true => Text::from_verified_ascii(octets),
        false => Text::from_utf8_lossy(octets),
    }
}

pub fn into_string(octets: Vec<u8>) -> String {
    match String::from_utf8(octets) {
        Ok(text) => text,
        Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
    }
}

pub struct Encoder {
    dynamic_table: DynamicTable,
    pending_size_update: Option<usize>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { dynamic_table: DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE), pending_size_update: None }
    }

    pub fn encode(&mut self, headers: &[HeaderField]) -> Vec<u8> {
        let mut out = Vec::with_capacity(headers.len() * 8 + 16);
        self.encode_into(&mut out, headers);
        out
    }

    pub fn encode_into(&mut self, out: &mut Vec<u8>, headers: &[HeaderField]) {
        out.reserve(headers.len() * 8 + 16);

        if let Some(max_size) = self.pending_size_update.take() {
            encode_integer(out, max_size as u64, 5, 0x20);
        }

        for field in headers {
            self.encode_field(out, field);
        }
    }

    pub fn encode_field(&mut self, out: &mut Vec<u8>, field: &HeaderField) {
        let found = self.dynamic_table.find(field);
        if let Some((index, true)) = found {
            encode_integer(out, index as u64, 7, 0x80);
            return;
        }

        let index = found.map_or(0, |(index, _)| index as u64);
        let sensitive = field.sensitive();

        if sensitive {
            encode_integer(out, index, 4, 0x10);
        } else {
            encode_integer(out, index, 6, 0x40);
        }

        if index == 0 {
            encode_value(out, field.name.as_bytes());
        }
        encode_value(out, field.value.as_bytes());

        if !sensitive {
            self.dynamic_table.insert(field.clone());
        }
    }

    pub fn set_dynamic_table_size(&mut self, max_size: usize) {
        self.dynamic_table.resize(max_size);
        self.pending_size_update = Some(max_size);
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

pub fn preferred_huffman(value: &[u8]) -> bool {
    huffman::encoded_len(value) < value.len()
}

pub struct Decoder {
    dynamic_table: DynamicTable,
    max_dynamic_table_size: usize,
    max_decoded_size: usize,
    scratch: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE),
            max_dynamic_table_size: DEFAULT_DYNAMIC_TABLE_SIZE,
            max_decoded_size: DEFAULT_MAX_DECODED_SIZE,
            scratch: Vec::new(),
        }
    }

    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, Error> {
        let mut headers = Vec::new();
        let mut decoded_size = 0usize;
        let mut rest = block;

        while let Some(first) = rest.first() {
            let (consumed, field) = match first {
                _ if first & 0x80 != 0 => {
                    let (consumed, index) = decode_integer(rest, 7)?;
                    let index = index as usize;
                    if index == 0 {
                        return Err(Error::IndexOutOfRange(index));
                    }

                    (consumed, Some(self.dynamic_table.resolve(index)?.clone()))
                }

                _ if first & 0x40 != 0 => {
                    let (consumed, field) = self.decode_literal(rest, 6)?;
                    self.dynamic_table.insert(field.clone());
                    (consumed, Some(field))
                }

                _ if first & 0x20 != 0 => {
                    let (consumed, max_size) = decode_integer(rest, 5)?;
                    if max_size as usize > self.max_dynamic_table_size {
                        return Err(Error::InvalidDynamicTableSizeUpdate);
                    }

                    self.dynamic_table.resize(max_size as usize);
                    (consumed, None)
                }

                _ => {
                    let (consumed, field) = self.decode_literal(rest, 4)?;
                    (consumed, Some(field))
                }
            };

            if let Some(field) = field {
                decoded_size += field.size();
                if decoded_size > self.max_decoded_size {
                    return Err(Error::DecodedSizeExceeded);
                }

                if headers.is_empty() {
                    headers.reserve(block.len().min(64));
                }

                headers.push(field);
            }

            rest = &rest[consumed..];
        }

        Ok(headers)
    }

    pub fn set_max_decoded_size(&mut self, max_size: usize) {
        self.max_decoded_size = max_size;
    }

    pub fn decode_literal(&mut self, input: &[u8], prefix_bits: u8) -> Result<(usize, HeaderField), Error> {
        let (mut consumed, index) = decode_integer(input, prefix_bits)?;

        let mut scratch = std::mem::take(&mut self.scratch);

        let name = if index == 0 {
            match decode_string_into_ascii(&input[consumed..], &mut scratch) {
                Ok((taken, ascii)) => {
                    consumed += taken;
                    decoded_text(&scratch, ascii)
                }
                Err(error) => {
                    self.scratch = scratch;
                    return Err(error);
                }
            }
        } else {
            match self.dynamic_table.resolve(index as usize) {
                Ok(field) => field.name.clone(),
                Err(error) => {
                    self.scratch = scratch;
                    return Err(error);
                }
            }
        };

        let (taken, ascii) = match decode_string_into_ascii(&input[consumed..], &mut scratch) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.scratch = scratch;
                return Err(error);
            }
        };
        consumed += taken;

        let field = HeaderField { name, value: decoded_text(&scratch, ascii) };
        self.scratch = scratch;

        Ok((consumed, field))
    }

    pub fn set_dynamic_table_size(&mut self, max_size: usize) {
        self.max_dynamic_table_size = max_size;
        if self.dynamic_table.max_size() > max_size {
            self.dynamic_table.resize(max_size);
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
