//! HPACK, the field compression format HTTP/2 uses.
//!
//! A field is sent either as an index into a table both ends agree on, or as a
//! literal that may then be added to that table. The static table is fixed and
//! shared; the dynamic table is built up over the connection from the fields
//! that have gone past, and each direction has its own pair — the sender's
//! [`Encoder`] and the receiver's [`Decoder`] — whose contents must stay in
//! step. That is why a field block that will not decode is fatal to the whole
//! connection rather than to one stream: once the tables diverge, nothing that
//! follows can be read.
//!
//! [`SENSITIVE_NAMES`] are never inserted into the dynamic table, since a
//! secret whose length can be inferred from compressed output is a secret that
//! leaks. QPACK reuses [`HeaderField`], [`encode_integer`] and
//! [`decode_integer`] from here, which is why they are not private to this
//! module.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::OnceLock;

use crate::helpers::huffman;
use crate::helpers::text::Text;

/// The dynamic table size both ends assume before any setting says otherwise.
pub const DEFAULT_DYNAMIC_TABLE_SIZE: usize = 4096;
/// The decoded field list size a [`Decoder`] accepts until told otherwise.
pub const DEFAULT_MAX_DECODED_SIZE: usize = 64 * 1024;

/// Fields never placed in the dynamic table, because compressing a secret
/// against attacker-chosen text leaks it.
pub const SENSITIVE_NAMES: &[&str] = &["authorization", "proxy-authorization", "cookie", "set-cookie"];

/// One field: a name and a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    /// The field name, lowercase.
    pub name: Text,
    /// The field value.
    pub value: Text,
}

impl HeaderField {
    /// The per-entry overhead charged against a dynamic table's size.
    ///
    /// A fixed allowance for the bookkeeping an entry costs, so that a table
    /// full of empty fields still has a bounded entry count.
    pub const OVERHEAD: usize = 32;

    /// A field with this name and value.
    pub fn new(name: impl Into<Text>, value: impl Into<Text>) -> Self {
        Self { name: name.into(), value: value.into() }
    }

    /// What this field costs against a dynamic table's size.
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + Self::OVERHEAD
    }

    /// Whether the field is one of [`SENSITIVE_NAMES`], and so must never be
    /// indexed.
    pub fn sensitive(&self) -> bool {
        matches!(self.name.len(), 6 | 10 | 13 | 19) && SENSITIVE_NAMES.contains(&self.name.as_str())
    }
}

/// The static table, indexed from 1.
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

/// An FNV-1a hasher for the short keys a field index is built on.
///
/// Field names are a handful of octets, where a hash tuned for long inputs
/// costs more than the lookup saves.
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

/// A map keyed by field name, hashed with [`FieldHasher`].
pub type FieldMap<K, V> = HashMap<K, V, BuildHasherDefault<FieldHasher>>;

/// Every static table entry that shares one name.
pub struct NameEntry {
    /// The lowest index carrying this name, for a name-only reference.
    pub first: usize,
    /// Each value stored under this name, with its index.
    pub values: Vec<(&'static str, usize)>,
}

/// A reverse index over a static table: field to index.
///
/// Both HPACK and QPACK need to ask "is this field already in the static
/// table", and a linear scan of sixty or a hundred entries per field is the
/// bulk of encoding a small request. QPACK builds one of these over its own
/// table, which is why this is not specific to HPACK's.
pub struct StaticIndex {
    by_name: FieldMap<&'static str, NameEntry>,
}

impl StaticIndex {
    /// Indexes `entries`, numbering the first one `base`.
    ///
    /// HPACK numbers its static table from 1 and QPACK from 0, which is the
    /// only difference between the two.
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

    /// Looks a field up.
    ///
    /// Returns the lowest index carrying the name, and the index carrying both
    /// name and value if there is one.
    pub fn lookup(&self, name: &str, value: &str) -> (Option<usize>, Option<usize>) {
        let Some(entry) = self.by_name.get(name) else {
            return (None, None);
        };

        let exact = entry.values.iter().find(|(candidate, _)| *candidate == value).map(|(_, index)| *index);
        (Some(entry.first), exact)
    }
}

/// The reverse index over the HPACK static table, built on first use.
pub fn static_index() -> &'static StaticIndex {
    static INDEX: OnceLock<StaticIndex> = OnceLock::new();
    INDEX.get_or_init(|| StaticIndex::new(static_table(), 1))
}

/// The table of fields built up over one direction of a connection.
///
/// Entries are indexed from the most recent, so an index means something
/// different once anything is inserted. Insertion evicts from the far end
/// until the new entry fits.
pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    /// An empty table holding at most `max_size` octets.
    pub fn new(max_size: usize) -> Self {
        Self { entries: VecDeque::new(), size: 0, max_size }
    }

    /// Inserts a field at the front, evicting from the back to make room.
    ///
    /// A field larger than the whole table empties it and is then dropped,
    /// which is what the format requires rather than an error.
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

    /// The entry `index` places back from the most recent insertion.
    pub fn get(&self, index: usize) -> Option<&HeaderField> {
        self.entries.get(index)
    }

    /// Changes the size ceiling, evicting until the table is under it.
    pub fn resize(&mut self, max_size: usize) {
        self.max_size = max_size;

        while self.size > self.max_size {
            match self.entries.pop_back() {
                Some(evicted) => self.size -= evicted.size(),
                None => break,
            }
        }
    }

    /// How many octets the entries account for, [`HeaderField::OVERHEAD`] included.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The current size ceiling.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// How many entries the table holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolves a wire index across the static and dynamic tables.
    ///
    /// Indices from 1 address the static table, and continue past its end into
    /// the dynamic one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] for zero, which addresses nothing,
    /// and for anything past the end of the dynamic table.
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

    /// Finds the best index for a field, across both tables.
    ///
    /// The flag says whether the value matched too; `false` means the index
    /// names the field name only, and the value has to be sent as a literal.
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

/// Why a field block would not decode.
///
/// Every one of these is fatal to the connection: the tables have diverged, so
/// nothing that follows can be read either.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// An index addresses no entry in either table.
    IndexOutOfRange(usize),
    /// An integer would not fit in 64 bits.
    IntegerOverflow,
    /// A size update asks for more than the negotiated ceiling.
    InvalidDynamicTableSizeUpdate,
    /// A representation runs past the end of the block.
    Incomplete,
    /// A Huffman string would not decode.
    Huffman(huffman::DecodeError),
    /// The decoded fields exceed what the decoder was told to accept.
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

/// The largest value a prefix of `prefix_bits` can hold on its own.
///
/// A value at or above this is written as the limit followed by continuation
/// octets.
pub fn prefix_limit(prefix_bits: u8) -> u64 {
    (1u64 << prefix_bits.min(63)) - 1
}

/// Writes an integer in the prefixed encoding both HPACK and QPACK use.
///
/// The low `prefix_bits` of the first octet carry the value, and the bits
/// above them carry `flags`, which is what tells the two ends apart which
/// representation this is. Values too large for the prefix continue over
/// further octets, seven bits at a time.
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

/// Reads a prefixed integer, returning how many octets it took and its value.
///
/// # Errors
///
/// Returns [`Error::Incomplete`] when the continuation runs off the end of the
/// input, and [`Error::IntegerOverflow`] when the value will not fit in 64
/// bits — which is how an encoding that continues forever is stopped.
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

/// Writes a length-prefixed string, Huffman coded or not as asked.
///
/// Use [`encode_value`] to have the shorter of the two chosen for you.
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

/// Writes a length-prefixed string, Huffman coding it only when that is shorter.
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

/// Reads a length-prefixed string, returning how many octets it took.
///
/// # Errors
///
/// As [`decode_string_into_ascii`].
pub fn decode_string(input: &[u8]) -> Result<(usize, Vec<u8>), Error> {
    let mut value = Vec::new();
    let consumed = decode_string_into(input, &mut value)?;
    Ok((consumed, value))
}

/// [`decode_string`], decoding into a buffer the caller reuses.
///
/// # Errors
///
/// As [`decode_string_into_ascii`].
pub fn decode_string_into(input: &[u8], scratch: &mut Vec<u8>) -> Result<usize, Error> {
    decode_string_into_ascii(input, scratch).map(|(consumed, _)| consumed)
}

/// [`decode_string_into`], also reporting whether the result is ASCII.
///
/// `scratch` is cleared first and holds the decoded octets on success.
///
/// # Errors
///
/// Returns [`Error::Incomplete`] when the string runs past the end of the
/// input, and [`Error::Huffman`] when a Huffman coded string will not decode.
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

/// Builds a [`Text`] from decoded octets, skipping validation when the decoder
/// already established they are ASCII.
#[inline]
pub fn decoded_text(octets: &[u8], ascii: bool) -> Text {
    match ascii {
        true => Text::from_verified_ascii(octets),
        false => Text::from_utf8_lossy(octets),
    }
}

/// Turns octets into a `String`, replacing anything that is not valid UTF-8.
pub fn into_string(octets: Vec<u8>) -> String {
    match String::from_utf8(octets) {
        Ok(text) => text,
        Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
    }
}

/// The sending half of one direction of an HTTP/2 connection.
///
/// Holds the dynamic table as the sender believes it to be. Every block it
/// produces must reach the peer's [`Decoder`] in order and be decoded, or the
/// two tables part ways.
pub struct Encoder {
    dynamic_table: DynamicTable,
    pending_size_update: Option<usize>,
}

impl Encoder {
    /// An encoder with an empty table of [`DEFAULT_DYNAMIC_TABLE_SIZE`].
    pub fn new() -> Self {
        Self { dynamic_table: DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE), pending_size_update: None }
    }

    /// Encodes one field block.
    pub fn encode(&mut self, headers: &[HeaderField]) -> Vec<u8> {
        let mut out = Vec::with_capacity(headers.len() * 8 + 16);
        self.encode_into(&mut out, headers);
        out
    }

    /// [`Encoder::encode`], appending to a buffer the caller reuses.
    ///
    /// Any pending size update is emitted first, since the format requires it
    /// to lead the block.
    pub fn encode_into(&mut self, out: &mut Vec<u8>, headers: &[HeaderField]) {
        out.reserve(headers.len() * 8 + 16);

        if let Some(max_size) = self.pending_size_update.take() {
            encode_integer(out, max_size as u64, 5, 0x20);
        }

        for field in headers {
            self.encode_field(out, field);
        }
    }

    /// Encodes one field, and inserts it into the table unless it is sensitive.
    ///
    /// A field already in a table is sent as a bare index. Otherwise it goes
    /// out as a literal, against a name index where one exists. Sensitive
    /// fields use the never-indexed form, which also asks intermediaries not
    /// to index them.
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

    /// Resizes the table and arranges for the next block to announce it.
    ///
    /// Called when the peer's `SETTINGS_HEADER_TABLE_SIZE` arrives.
    pub fn set_dynamic_table_size(&mut self, max_size: usize) {
        self.dynamic_table.resize(max_size);
        self.pending_size_update = Some(max_size);
    }

    /// The table as the encoder believes the peer's decoder holds it.
    pub fn dynamic_table(&self) -> &DynamicTable {
        &self.dynamic_table
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether Huffman coding this value would make it shorter.
pub fn preferred_huffman(value: &[u8]) -> bool {
    huffman::encoded_len(value) < value.len()
}

/// The receiving half of one direction of an HTTP/2 connection.
///
/// Holds the dynamic table as the receiver has rebuilt it. Blocks have to be
/// fed in the order they arrived, since each one may change the table the next
/// one is read against.
pub struct Decoder {
    dynamic_table: DynamicTable,
    max_dynamic_table_size: usize,
    max_decoded_size: usize,
    scratch: Vec<u8>,
}

impl Decoder {
    /// A decoder with an empty table of [`DEFAULT_DYNAMIC_TABLE_SIZE`],
    /// accepting up to [`DEFAULT_MAX_DECODED_SIZE`] of decoded fields.
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(DEFAULT_DYNAMIC_TABLE_SIZE),
            max_dynamic_table_size: DEFAULT_DYNAMIC_TABLE_SIZE,
            max_decoded_size: DEFAULT_MAX_DECODED_SIZE,
            scratch: Vec::new(),
        }
    }

    /// Decodes one field block, updating the table as it goes.
    ///
    /// # Errors
    ///
    /// Any [`Error`]; all of them are fatal to the connection, because the
    /// table is left in a state the peer does not share.
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

    /// Bounds the decoded size of one field block.
    ///
    /// This is what stops a small block of indexed references from expanding
    /// into an unbounded field list.
    pub fn set_max_decoded_size(&mut self, max_size: usize) {
        self.max_decoded_size = max_size;
    }

    /// Decodes one literal representation, whose name may itself be an index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] when a name index addresses nothing,
    /// and whatever [`decode_string_into_ascii`] rejects the strings with.
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

    /// Sets the ceiling this end advertised, which is the largest size the
    /// peer may then update the table to.
    pub fn set_dynamic_table_size(&mut self, max_size: usize) {
        self.max_dynamic_table_size = max_size;
        if self.dynamic_table.max_size() > max_size {
            self.dynamic_table.resize(max_size);
        }
    }

    /// The table as rebuilt from the blocks decoded so far.
    pub fn dynamic_table(&self) -> &DynamicTable {
        &self.dynamic_table
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
