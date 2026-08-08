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
//! The vocabulary and wire primitives — [`HeaderField`], [`fields::Integer`],
//! [`fields::StringLiteral`], [`fields::StaticIndex`] — are shared with QPACK
//! and live in [`fields`].
//!
//! [`fields`]: crate::helpers::fields

use std::collections::VecDeque;
use std::fmt;
use std::sync::OnceLock;

use crate::helpers::fields::{self, HeaderField, Integer, StaticIndex, StringLiteral};
use crate::helpers::huffman;

/// The static table, and the reverse index over it.
pub struct StaticTable;

impl StaticTable {
    /// The entries, indexed from 1.
    pub fn entries() -> &'static [HeaderField; 61] {
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

    /// The reverse index over the HPACK static table, built on first use.
    pub fn index() -> &'static StaticIndex {
        static INDEX: OnceLock<StaticIndex> = OnceLock::new();
        INDEX.get_or_init(|| StaticIndex::new(StaticTable::entries(), 1))
    }

    /// Finds a field in the static table.
    ///
    /// The flag says whether the value matched too; `false` means the index
    /// names the field name only.
    pub fn find(field: &HeaderField) -> Option<(usize, bool)> {
        let (named, exact) = StaticTable::index().lookup(&field.name, &field.value);

        match (exact, named) {
            (Some(index), _) => Some((index, true)),
            (None, Some(index)) => Some((index, false)),
            (None, None) => None,
        }
    }
}


/// The table of fields built up over one direction of a connection.
///
/// Entries are indexed from the most recent, so an index means something
/// different once anything is inserted. Insertion evicts from the far end
/// until the new entry fits.
pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    size: usize,
    capacity: usize,
}

impl DynamicTable {
    /// The capacity both ends assume before any setting says otherwise.
    pub const DEFAULT_CAPACITY: usize = 4096;

    /// An empty table holding at most `capacity` octets.
    pub fn new(capacity: usize) -> Self {
        Self { entries: VecDeque::new(), size: 0, capacity }
    }

    /// Inserts a field at the front, evicting from the back to make room.
    ///
    /// A field larger than the whole table empties it and is then dropped,
    /// which is what the format requires rather than an error.
    pub fn insert(&mut self, field: HeaderField) {
        let size = field.size();

        while self.size + size > self.capacity {
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

    /// Changes the capacity, evicting until the table is under it.
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;

        while self.size > self.capacity {
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

    /// The current capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many entries the table holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Finds the best offset for a field in the dynamic table.
    ///
    /// The flag says whether the value matched too. Offsets count from the
    /// most recent insertion, which is how the wire indexes the table once
    /// the static entries are stepped over.
    pub fn find(&self, field: &HeaderField) -> Option<(usize, bool)> {
        let mut name_only = None;

        for (offset, entry) in self.entries.iter().enumerate() {
            if entry.name != field.name {
                continue;
            }

            if entry.value == field.value {
                return Some((offset, true));
            }

            name_only.get_or_insert(offset);
        }

        name_only.map(|offset| (offset, false))
    }
}

/// Why a field block would not decode.
///
/// Every one of these is fatal to the connection: the tables have diverged, so
/// nothing that follows can be read either.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// An index addresses no entry in either table.
    IndexOutOfRange(u64),
    /// An integer would not fit in 64 bits.
    IntegerOverflow,
    /// A capacity update asks for more than the negotiated ceiling.
    InvalidCapacityUpdate,
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
            Self::InvalidCapacityUpdate => write!(f, "dynamic table capacity update exceeds the negotiated limit"),
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

impl From<fields::Error> for Error {
    fn from(err: fields::Error) -> Self {
        match err {
            fields::Error::IntegerOverflow => Self::IntegerOverflow,
            fields::Error::Incomplete => Self::Incomplete,
            fields::Error::Huffman(err) => Self::Huffman(err),
        }
    }
}

/// The sending half of one direction of a connection.
///
/// Holds the dynamic table as the sender believes it to be. Every block it
/// produces must reach the peer's [`Decoder`] in order and be decoded, or the
/// two tables part ways.
pub struct Encoder {
    dynamic_table: DynamicTable,
    max_capacity: usize,
    capacity_limit: usize,
    pending_size_update: Option<usize>,
}

impl Encoder {
    /// The capacity this encoder is willing to keep, whatever the peer permits.
    pub const DEFAULT_CAPACITY_LIMIT: usize = 4096;

    /// An encoder with an empty table of [`DynamicTable::DEFAULT_CAPACITY`].
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(DynamicTable::DEFAULT_CAPACITY),
            max_capacity: DynamicTable::DEFAULT_CAPACITY,
            capacity_limit: Self::DEFAULT_CAPACITY_LIMIT,
            pending_size_update: None,
        }
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

        if let Some(capacity) = self.pending_size_update.take() {
            Integer::encode(out, capacity as u64, 5, 0x20);
        }

        for field in headers {
            self.encode_field(out, field);
        }
    }

    /// Picks the reference to use for a field.
    ///
    /// Returns the best index across both tables and whether the value
    /// matched as well as the name; `false` means the index names the field
    /// name only, and the value has to be sent as a literal.
    pub fn reference(&self, field: &HeaderField) -> Option<(usize, bool)> {
        let in_static = StaticTable::find(field);
        if let Some((index, true)) = in_static {
            return Some((index, true));
        }

        let base = StaticTable::entries().len() + 1;
        let in_dynamic = self.dynamic_table.find(field).map(|(offset, exact)| (base + offset, exact));
        if let Some((index, true)) = in_dynamic {
            return Some((index, true));
        }

        in_static.or(in_dynamic)
    }

    /// Encodes one field, and inserts it into the table unless it is sensitive.
    ///
    /// A field already in a table is sent as a bare index. Otherwise it goes
    /// out as a literal, against a name index where one exists. Sensitive
    /// fields use the never-indexed form, which also asks intermediaries not
    /// to index them.
    pub fn encode_field(&mut self, out: &mut Vec<u8>, field: &HeaderField) {
        let found = self.reference(field);
        if let Some((index, true)) = found {
            Integer::encode(out, index as u64, 7, 0x80);
            return;
        }

        let index = found.map_or(0, |(index, _)| index as u64);
        let sensitive = field.sensitive();

        if sensitive {
            Integer::encode(out, index, 4, 0x10);
        } else {
            Integer::encode(out, index, 6, 0x40);
        }

        if index == 0 {
            StringLiteral::encode_shorter(out, field.name.as_bytes(), 7, 0x00);
        }
        StringLiteral::encode_shorter(out, field.value.as_bytes(), 7, 0x00);

        if !sensitive {
            self.dynamic_table.insert(field.clone());
        }
    }

    /// Sets the ceiling the peer advertised, and arranges for the next block
    /// to announce the capacity chosen under it.
    ///
    /// Called when the peer's `SETTINGS_HEADER_TABLE_SIZE` arrives. The
    /// capacity actually used is the smaller of what the peer permits and
    /// [`Encoder::capacity_limit`].
    pub fn set_max_capacity(&mut self, max_capacity: usize) {
        self.max_capacity = max_capacity;

        let capacity = max_capacity.min(self.capacity_limit);
        self.dynamic_table.set_capacity(capacity);
        self.pending_size_update = Some(capacity);
    }

    /// Bounds the capacity this encoder keeps, whatever the peer permits.
    pub fn set_capacity_limit(&mut self, capacity_limit: usize) {
        self.capacity_limit = capacity_limit;
        if self.dynamic_table.capacity() > capacity_limit {
            self.dynamic_table.set_capacity(capacity_limit);
            self.pending_size_update = Some(capacity_limit);
        }
    }

    /// The capacity this encoder is willing to keep.
    pub fn capacity_limit(&self) -> usize {
        self.capacity_limit
    }

    /// The ceiling the peer advertised.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
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

/// The receiving half of one direction of a connection.
///
/// Holds the dynamic table as the receiver has rebuilt it. Blocks have to be
/// fed in the order they arrived, since each one may change the table the next
/// one is read against.
pub struct Decoder {
    dynamic_table: DynamicTable,
    max_capacity: usize,
    max_decoded_size: usize,
    scratch: Vec<u8>,
}

impl Decoder {
    /// The decoded field list size a decoder accepts until told otherwise.
    pub const DEFAULT_MAX_DECODED_SIZE: usize = 64 * 1024;

    /// A decoder with an empty table of [`DynamicTable::DEFAULT_CAPACITY`],
    /// accepting up to [`Decoder::DEFAULT_MAX_DECODED_SIZE`] of decoded fields.
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(DynamicTable::DEFAULT_CAPACITY),
            max_capacity: DynamicTable::DEFAULT_CAPACITY,
            max_decoded_size: Self::DEFAULT_MAX_DECODED_SIZE,
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
        let mut scratch = std::mem::take(&mut self.scratch);
        let decoded = self.decode_into(block, &mut scratch);
        self.scratch = scratch;
        decoded
    }

    /// [`Decoder::decode`], decoding through a buffer the caller reuses.
    ///
    /// # Errors
    ///
    /// As [`Decoder::decode`].
    pub fn decode_into(&mut self, block: &[u8], scratch: &mut Vec<u8>) -> Result<Vec<HeaderField>, Error> {
        let mut headers = Vec::new();
        let mut decoded_size = 0usize;
        let mut rest = block;

        while let Some(first) = rest.first() {
            let (consumed, field) = match first {
                _ if first & 0x80 != 0 => {
                    let (consumed, index) = Integer::decode(rest, 7)?;
                    (consumed, Some(self.resolve(index)?.clone()))
                }

                _ if first & 0x40 != 0 => {
                    let (consumed, field) = self.decode_literal(rest, 6, scratch)?;
                    self.dynamic_table.insert(field.clone());
                    (consumed, Some(field))
                }

                _ if first & 0x20 != 0 => {
                    let (consumed, capacity) = Integer::decode(rest, 5)?;
                    if capacity as usize > self.max_capacity {
                        return Err(Error::InvalidCapacityUpdate);
                    }

                    self.dynamic_table.set_capacity(capacity as usize);
                    (consumed, None)
                }

                _ => {
                    let (consumed, field) = self.decode_literal(rest, 4, scratch)?;
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

    /// Resolves a wire index across the static and dynamic tables.
    ///
    /// Indices from 1 address the static table, and continue past its end into
    /// the dynamic one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] for zero, which addresses nothing,
    /// and for anything past the end of the dynamic table.
    pub fn resolve(&self, index: u64) -> Result<&HeaderField, Error> {
        if index == 0 {
            return Err(Error::IndexOutOfRange(index));
        }

        let table = StaticTable::entries();

        if index <= table.len() as u64 {
            return Ok(&table[index as usize - 1]);
        }

        usize::try_from(index - table.len() as u64 - 1)
            .ok()
            .and_then(|offset| self.dynamic_table.get(offset))
            .ok_or(Error::IndexOutOfRange(index))
    }

    /// Decodes one literal representation, whose name may itself be an index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] when a name index addresses nothing,
    /// and otherwise as [`Integer::decode`] and
    /// [`StringLiteral::decode_into_ascii`].
    pub fn decode_literal(&self, input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<(usize, HeaderField), Error> {
        let (mut consumed, index) = Integer::decode(input, prefix_bits)?;

        let name = if index == 0 {
            let (taken, ascii) = StringLiteral::decode_into_ascii(&input[consumed..], 7, scratch)?;
            consumed += taken;
            StringLiteral::text(scratch, ascii)
        } else {
            self.resolve(index)?.name.clone()
        };

        let (taken, ascii) = StringLiteral::decode_into_ascii(&input[consumed..], 7, scratch)?;
        consumed += taken;

        Ok((consumed, HeaderField { name, value: StringLiteral::text(scratch, ascii) }))
    }

    /// Sets the ceiling this end advertised, which is the largest capacity the
    /// peer may then update the table to.
    pub fn set_max_capacity(&mut self, max_capacity: usize) {
        self.max_capacity = max_capacity;
        if self.dynamic_table.capacity() > max_capacity {
            self.dynamic_table.set_capacity(max_capacity);
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
