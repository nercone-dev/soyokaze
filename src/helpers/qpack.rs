//! QPACK, the field compression format HTTP/3 uses.
//!
//! QPACK is HPACK adapted to a transport that may deliver streams out of
//! order. HPACK can index the previous block because TCP guarantees the peer
//! read it; QUIC gives no such promise, so QPACK splits the work in two:
//!
//! - Table updates travel on their own unidirectional encoder stream, as
//!   [`EncoderInstruction`]s, and are acknowledged on a decoder stream as
//!   [`DecoderInstruction`]s.
//! - Field blocks on request streams reference the table by *absolute* index
//!   and declare, up front, how many insertions the decoder must have seen to
//!   read them.
//!
//! When a block arrives before the insertions it depends on, the decoder is
//! *blocked*: it reports [`Error::Blocked`] and the caller holds the block
//! until the encoder stream catches up. Bound that wait, since a peer that
//! never sends the insertions would otherwise pin the stream open forever.
//!
//! This [`Encoder`] only references dynamic entries it knows the peer has
//! acknowledged, so the blocks it produces never block the peer's decoder.
//!
//! The vocabulary and wire primitives — [`HeaderField`], [`fields::Integer`],
//! [`fields::StringLiteral`], [`fields::StaticIndex`] — are shared with HPACK
//! and live in [`fields`].
//!
//! [`fields`]: crate::helpers::fields

use std::collections::VecDeque;
use std::fmt;
use std::sync::OnceLock;

use bytes::BytesMut;

use crate::helpers::fields::{self, HeaderField, Integer, StaticIndex, StringLiteral};
use crate::helpers::huffman;
use crate::helpers::text::Text;

/// The static table, and the reverse index over it.
///
/// The mirror of [`crate::helpers::hpack::StaticTable`], differing only in
/// that QPACK indexes from 0 where HPACK indexes from 1.
pub struct StaticTable;

impl StaticTable {
    /// The static table, indexed from 0.
    pub fn entries() -> &'static [HeaderField; 99] {
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

    /// The reverse index over the QPACK static table, built on first use.
    pub fn index() -> &'static StaticIndex {
        static INDEX: OnceLock<StaticIndex> = OnceLock::new();
        INDEX.get_or_init(|| StaticIndex::new(StaticTable::entries(), 0))
    }

    /// Finds a field in the static table.
    ///
    /// The flag says whether the value matched too; `false` means the index names
    /// the field name only.
    pub fn find(field: &HeaderField) -> Option<(u64, bool)> {
        let (named, exact) = StaticTable::index().lookup(&field.name, &field.value);

        match (exact, named) {
            (Some(index), _) => Some((index as u64, true)),
            (None, Some(index)) => Some((index as u64, false)),
            (None, None) => None,
        }
    }
}





/// The table of fields built up over one direction of a connection.
///
/// Unlike the HPACK table this counts insertions for their whole life, so an
/// entry keeps one absolute index no matter what is inserted after it. That is
/// what lets a field block name an entry without knowing how far the table has
/// moved on by the time it is read.
pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    size: usize,
    capacity: usize,
    inserted_count: u64,
}

impl DynamicTable {
    /// The capacity assumed before the peer's settings arrive.
    ///
    /// Zero, so that nothing is inserted until the peer has said how much table
    /// it is willing to keep.
    pub const DEFAULT_CAPACITY: usize = 0;

    /// An empty table holding at most `capacity` octets.
    pub fn new(capacity: usize) -> Self {
        Self { entries: VecDeque::new(), size: 0, capacity, inserted_count: 0 }
    }

    /// Inserts a field, evicting from the back to make room, and returns its
    /// absolute index.
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

    /// Whether a field could ever fit in the table as it is sized now.
    pub fn fits(&self, field: &HeaderField) -> bool {
        field.size() <= self.capacity
    }

    /// The entry at an absolute index, or `None` when it has been evicted or
    /// was never inserted.
    pub fn get(&self, absolute_index: u64) -> Option<&HeaderField> {
        let offset = self.inserted_count.checked_sub(absolute_index + 1)?;
        self.entries.get(offset as usize)
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

    /// The absolute index for one counted back from the most recent insertion.
    ///
    /// This is how the encoder stream names entries, since it is read in the
    /// order it was written.
    pub fn relative(&self, index: u64) -> Option<u64> {
        self.inserted_count.checked_sub(index + 1)
    }

    /// The absolute index for one counted back from `base`.
    ///
    /// This is how a field block names entries that were already in the table
    /// when the block was written.
    pub fn indexed(&self, base: u64, index: u64) -> Option<u64> {
        base.checked_sub(index + 1).filter(|absolute| *absolute < self.inserted_count)
    }

    /// The absolute index for one counted forward from `base`.
    ///
    /// This is how a field block names entries inserted while the block itself
    /// was being written.
    pub fn post_base(&self, base: u64, index: u64) -> Option<u64> {
        base.checked_add(index).filter(|absolute| *absolute < self.inserted_count)
    }

    /// Finds the best absolute index for a field in the dynamic table.
    ///
    /// The flag says whether the value matched too.
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

    /// How many entries have ever been inserted, evictions included.
    ///
    /// Absolute indices are numbered against this, so it never decreases.
    pub fn inserted_count(&self) -> u64 {
        self.inserted_count
    }

    /// How many octets the entries account for, [`HeaderField::OVERHEAD`] included.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The current capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many entries the table holds right now.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Why a field block or an instruction would not decode.
///
/// Only [`Error::Blocked`] is recoverable: it means the block arrived ahead of
/// the insertions it depends on and should be tried again once the encoder
/// stream has caught up. The rest are fatal to the connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// An absolute index addresses no entry.
    IndexOutOfRange(u64),
    /// An integer would not fit in 64 bits.
    IntegerOverflow,
    /// A capacity update asks for more than was advertised.
    InvalidCapacityUpdate,
    /// The required insert count could not have come from a working encoder.
    InvalidInsertCount,
    /// The delta base places the base below zero.
    InvalidBase,
    /// An entry is larger than the whole dynamic table.
    EntryTooLarge,
    /// A single buffered instruction grew past the permitted size.
    InstructionTooLarge,
    /// More streams are blocked than this end said it would support.
    TooManyBlockedStreams,
    /// A representation runs past the end of the block.
    Incomplete,
    /// The block depends on insertions that have not arrived yet.
    ///
    /// Hold the block and decode it again once more of the encoder stream has
    /// been fed in. Not an error the connection should be torn down over.
    Blocked,
    /// A Huffman string would not decode.
    Huffman(huffman::DecodeError),
    /// The decoded fields exceed what the decoder was told to accept.
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
            Self::InstructionTooLarge => write!(f, "a single instruction exceeds the permitted size"),
            Self::TooManyBlockedStreams => write!(f, "more streams are blocked than were advertised"),
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

impl From<fields::Error> for Error {
    fn from(err: fields::Error) -> Self {
        match err {
            fields::Error::IntegerOverflow => Self::IntegerOverflow,
            fields::Error::Incomplete => Self::Incomplete,
            fields::Error::Huffman(err) => Self::Huffman(err),
        }
    }
}

/// An instruction the encoder sends on its unidirectional stream.
///
/// These are what change the decoder's dynamic table. They travel apart from
/// the field blocks that reference them, which is the whole point: a block can
/// go out without waiting for the table update it depends on to be read.
#[derive(Debug, PartialEq, Eq)]
pub enum EncoderInstruction {
    /// Resize the dynamic table, within what the decoder advertised.
    SetDynamicTableCapacity {
        /// The new capacity in octets.
        capacity: usize,
    },
    /// Insert a field whose name is taken from an existing entry.
    InsertWithNameReference {
        /// Whether `name_index` addresses the static table.
        from_static: bool,
        /// The entry the name comes from; relative to the most recent
        /// insertion when it addresses the dynamic table.
        name_index: u64,
        /// The value, spelled out.
        value: Vec<u8>,
    },
    /// Insert a field, spelling out both name and value.
    InsertWithLiteralName {
        /// The field name.
        name: Vec<u8>,
        /// The field value.
        value: Vec<u8>,
    },
    /// Re-insert an existing entry, so it survives eviction of the original.
    Duplicate {
        /// The entry to copy, counted back from the most recent insertion.
        index: u64,
    },
}

impl EncoderInstruction {
    /// Encodes the instruction.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// [`EncoderInstruction::encode`], appending to a buffer the caller owns.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::SetDynamicTableCapacity { capacity } => {
                Integer::encode(out, *capacity as u64, 5, 0x20);
            }

            Self::InsertWithNameReference { from_static, name_index, value } => {
                Integer::encode(out, *name_index, 6, 0x80 | u8::from(*from_static) << 6);
                StringLiteral::encode_shorter(out, value, 7, 0x00);
            }

            Self::InsertWithLiteralName { name, value } => {
                StringLiteral::encode_shorter(out, name, 5, 0x40);
                StringLiteral::encode_shorter(out, value, 7, 0x00);
            }

            Self::Duplicate { index } => Integer::encode(out, *index, 5, 0x00),
        }
    }

    /// Reads one instruction, returning how many octets it took.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incomplete`] when the instruction is not all there
    /// yet, which is the signal to wait for more of the stream rather than to
    /// fail the connection.
    pub fn decode(input: &[u8]) -> Result<(usize, Self), Error> {
        let first = *input.first().ok_or(Error::Incomplete)?;

        if first & 0x80 != 0 {
            let (mut consumed, name_index) = Integer::decode(input, 6)?;
            let (taken, value) = StringLiteral::decode(&input[consumed..], 7)?;
            consumed += taken;

            return Ok((consumed, Self::InsertWithNameReference {
                from_static: first & 0x40 != 0,
                name_index,
                value,
            }));
        }

        if first & 0x40 != 0 {
            let (mut consumed, name) = StringLiteral::decode(input, 5)?;
            let (taken, value) = StringLiteral::decode(&input[consumed..], 7)?;
            consumed += taken;

            return Ok((consumed, Self::InsertWithLiteralName { name, value }));
        }

        if first & 0x20 != 0 {
            let (consumed, capacity) = Integer::decode(input, 5)?;
            return Ok((consumed, Self::SetDynamicTableCapacity { capacity: capacity as usize }));
        }

        let (consumed, index) = Integer::decode(input, 5)?;
        Ok((consumed, Self::Duplicate { index }))
    }
}

/// An instruction the decoder sends back on its unidirectional stream.
///
/// These tell the encoder what the decoder has actually taken in, which is
/// what lets the encoder know which entries are safe to reference without
/// blocking the peer.
#[derive(Debug, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// A field section on this stream was decoded.
    SectionAcknowledgment {
        /// The stream the section arrived on.
        stream_id: u64,
    },
    /// This stream was abandoned, so its sections will never be acknowledged.
    StreamCancellation {
        /// The stream that was abandoned.
        stream_id: u64,
    },
    /// This many further insertions have been taken in.
    InsertCountIncrement {
        /// How many entries were added since the last report.
        increment: u64,
    },
}

impl DecoderInstruction {
    /// Encodes the instruction.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// [`DecoderInstruction::encode`], appending to a buffer the caller owns.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::SectionAcknowledgment { stream_id } => Integer::encode(out, *stream_id, 7, 0x80),
            Self::StreamCancellation { stream_id } => Integer::encode(out, *stream_id, 6, 0x40),
            Self::InsertCountIncrement { increment } => Integer::encode(out, *increment, 6, 0x00),
        }
    }

    /// Reads one instruction, returning how many octets it took.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incomplete`] when the instruction is not all there
    /// yet, which is the signal to wait for more of the stream.
    pub fn decode(input: &[u8]) -> Result<(usize, Self), Error> {
        let first = *input.first().ok_or(Error::Incomplete)?;

        if first & 0x80 != 0 {
            let (consumed, stream_id) = Integer::decode(input, 7)?;
            return Ok((consumed, Self::SectionAcknowledgment { stream_id }));
        }

        if first & 0x40 != 0 {
            let (consumed, stream_id) = Integer::decode(input, 6)?;
            return Ok((consumed, Self::StreamCancellation { stream_id }));
        }

        let (consumed, increment) = Integer::decode(input, 6)?;
        Ok((consumed, Self::InsertCountIncrement { increment }))
    }
}




/// The prefix a field section opens with: the Required Insert Count and the
/// Base the block's indices are read against.
pub struct Prefix;

impl Prefix {
    /// The most entries a table of this capacity could ever hold.
    ///
    /// Each entry costs at least [`HeaderField::OVERHEAD`], so this is a ceiling
    /// whatever the fields are. It sets the modulus the required insert count is
    /// encoded against.
    pub fn max_entries(max_capacity: usize) -> u64 {
        (max_capacity / HeaderField::OVERHEAD) as u64
    }

    /// The index a field block uses to name an absolute entry, counted back from `base`.
    pub fn relative(base: u64, absolute: u64) -> u64 {
        base.saturating_sub(absolute).saturating_sub(1)
    }

    /// Encodes the required insert count that leads a field block.
    ///
    /// The count is sent modulo twice [`Prefix::max_entries`] rather than in full, because
    /// the full value grows without bound over a long connection while the window
    /// of counts a decoder could plausibly be at does not. Zero means the block
    /// references no dynamic entry and so can never block.
    pub fn encode_insert_count(required: u64, max_capacity: usize) -> u64 {
        let full_range = 2 * Prefix::max_entries(max_capacity);
        if required == 0 || full_range == 0 {
            return 0;
        }

        required % full_range + 1
    }

    /// Recovers the required insert count from its wrapped form.
    ///
    /// `inserted` is how many entries this decoder has taken in, which is what
    /// pins the wrapped value to the one window it could have come from.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInsertCount`] when the value could not have been
    /// produced by a working encoder — either it is outside the window, or the
    /// table has no capacity for a dynamic reference at all.
    pub fn decode_insert_count(encoded: u64, inserted: u64, max_capacity: usize) -> Result<u64, Error> {
        if encoded == 0 {
            return Ok(0);
        }

        let full_range = 2 * Prefix::max_entries(max_capacity);
        if full_range == 0 || encoded > full_range {
            return Err(Error::InvalidInsertCount);
        }

        let max_value = inserted.saturating_add(Prefix::max_entries(max_capacity));
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
}

/// The sending half of one direction of a connection.
///
/// The encoder only references dynamic entries the peer has acknowledged, so
/// the blocks it produces never leave the peer's decoder blocked. It tracks
/// the sections it is still waiting on, and once
/// [`Encoder::set_max_outstanding_sections`] of them are outstanding it stops
/// using the dynamic table at all rather than letting that list grow.
pub struct Encoder {
    dynamic_table: DynamicTable,
    known_received_count: u64,
    max_capacity: usize,
    capacity_limit: usize,
    max_outstanding_sections: usize,
    max_instruction_size: usize,
    sections: VecDeque<(u64, u64)>,
    idle_capacity: usize,
    stream_out: Vec<u8>,
    stream_recv: BytesMut,
}

impl Encoder {
    /// The capacity this encoder is willing to keep, whatever the peer permits.
    pub const DEFAULT_CAPACITY_LIMIT: usize = 4096;

    /// The unacknowledged sections an encoder tracks until told otherwise.
    pub const DEFAULT_MAX_OUTSTANDING_SECTIONS: usize = 512;

    /// The size a single buffered instruction may grow to until told otherwise.
    pub const DEFAULT_MAX_INSTRUCTION_SIZE: usize = 64 * 1024;

    /// The size the encoder stream buffer may keep while idle until told
    /// otherwise.
    pub const DEFAULT_IDLE_CAPACITY: usize = 64 * 1024;

    /// An encoder with an empty table, which stays empty until the peer's
    /// settings raise [`DynamicTable::DEFAULT_CAPACITY`].
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(0),
            known_received_count: 0,
            max_capacity: DynamicTable::DEFAULT_CAPACITY,
            capacity_limit: Self::DEFAULT_CAPACITY_LIMIT,
            max_outstanding_sections: Self::DEFAULT_MAX_OUTSTANDING_SECTIONS,
            idle_capacity: Self::DEFAULT_IDLE_CAPACITY,
            max_instruction_size: Self::DEFAULT_MAX_INSTRUCTION_SIZE,
            sections: VecDeque::new(),
            stream_out: Vec::new(),
            stream_recv: BytesMut::new(),
        }
    }

    /// Bounds how many unacknowledged sections the encoder will track.
    pub fn set_max_outstanding_sections(&mut self, max_sections: usize) {
        self.max_outstanding_sections = max_sections;
    }

    /// Bounds how large a single instruction on the peer's decoder stream may
    /// grow before it is refused.
    pub fn set_max_instruction_size(&mut self, max_size: usize) {
        self.max_instruction_size = max_size;
    }

    /// Queues instructions for this end's encoder stream.
    ///
    /// The octets accumulate on the encoder stream until
    /// [`Encoder::take_encoder_stream`] takes them for sending.
    pub fn queue(&mut self, instructions: &[EncoderInstruction]) {
        for instruction in instructions {
            instruction.encode_into(&mut self.stream_out);
        }
    }

    /// Takes in octets from the peer's decoder stream.
    ///
    /// Partial instructions are buffered until the rest arrives.
    /// Acknowledgements here are what free the encoder to reference more of
    /// its table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InstructionTooLarge`] when a single instruction grows
    /// past [`Encoder::set_max_instruction_size`], and any other [`Error`]
    /// when one will not decode.
    pub fn on_decoder_stream(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.stream_recv.extend_from_slice(bytes);

        if self.stream_recv.len() > self.max_instruction_size {
            return Err(Error::InstructionTooLarge);
        }

        loop {
            match DecoderInstruction::decode(&self.stream_recv) {
                Ok((consumed, instruction)) => {
                    let _ = self.stream_recv.split_to(consumed);
                    self.on_decoder_instruction(instruction);
                }
                Err(Error::Incomplete) => break,
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    /// Bounds how large the encoder stream buffer stays while idle.
    pub fn set_idle_capacity(&mut self, idle_capacity: usize) {
        self.idle_capacity = idle_capacity;
    }

    /// The octets queued for this end's encoder stream.
    ///
    /// Empty when there is nothing to send, which is what a caller polling for
    /// work should test rather than taking the buffer to find out.
    pub fn encoder_stream(&self) -> &[u8] {
        &self.stream_out
    }

    /// Takes the octets queued for this end's encoder stream.
    ///
    /// The buffer goes with them; hand it back to
    /// [`Encoder::reclaim_encoder_stream`] once it has been written out to
    /// have the encoder reuse the allocation.
    pub fn take_encoder_stream(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stream_out)
    }

    /// Takes a buffer back from [`Encoder::take_encoder_stream`] to be reused.
    ///
    /// It is emptied, and given up rather than kept once it has grown past
    /// [`Encoder::set_idle_capacity`], so a burst of instructions does not
    /// leave its memory attached to an idle encoder. Anything queued while the
    /// caller held it is kept, in order.
    pub fn reclaim_encoder_stream(&mut self, mut buffer: Vec<u8>) {
        buffer.clear();

        if buffer.capacity() > self.idle_capacity {
            buffer.shrink_to(self.idle_capacity / 2);
        }

        buffer.extend_from_slice(&self.stream_out);
        self.stream_out = buffer;
    }

    /// Encodes a field block for `stream_id`.
    ///
    /// Returns the block and the instructions that must go out on the encoder
    /// stream for the peer to be able to read it. The instructions do not have
    /// to arrive first — the block carries the insert count it needs, and the
    /// peer will hold it until they do.
    pub fn encode(&mut self, stream_id: u64, headers: &[HeaderField]) -> (Vec<u8>, Vec<EncoderInstruction>) {
        let mut out = Vec::with_capacity(headers.len() * 8 + 16);
        let instructions = self.encode_into(&mut out, stream_id, headers);
        (out, instructions)
    }

    /// [`Encoder::encode`], appending the block to a buffer the caller reuses.
    pub fn encode_into(&mut self, out: &mut Vec<u8>, stream_id: u64, headers: &[HeaderField]) -> Vec<EncoderInstruction> {
        let mut instructions = Vec::new();
        let mut representations = Vec::new();
        let mut required = 0;

        let tracked = self.sections.len() < self.max_outstanding_sections;

        for field in headers {
            let matched = match tracked {
                true => self.reference(field),
                false => StaticTable::find(field).map(|(index, value)| (true, index, value)),
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

        out.reserve(representations.len() * 8 + 16);
        Integer::encode(out, Prefix::encode_insert_count(required, self.max_capacity), 8, 0x00);
        Integer::encode(out, 0, 7, 0x00);

        for (field, matched) in representations {
            self.encode_field(out, field, matched, required);
        }

        if required > 0 {
            self.sections.push_back((stream_id, required));
        }

        instructions
    }

    /// Picks the reference to use for a field.
    ///
    /// Returns whether the entry is in the static table, its index, and
    /// whether the value matched as well as the name. Dynamic entries the peer
    /// has not acknowledged are passed over, so a block never blocks the peer.
    pub fn reference(&self, field: &HeaderField) -> Option<(bool, u64, bool)> {
        let in_static = StaticTable::find(field);
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

    /// Adds a field to the table and returns the instruction that tells the
    /// peer to do the same.
    ///
    /// `None` when the field could never fit in the table as it is sized now.
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

    /// Writes one field representation against `base`.
    ///
    /// Sensitive fields go out in the never-indexed form, which asks
    /// intermediaries not to index them either.
    pub fn encode_field(&self, out: &mut Vec<u8>, field: &HeaderField, matched: Option<(bool, u64, bool)>, base: u64) {
        let never = u8::from(field.sensitive());

        match matched {
            Some((true, index, true)) => Integer::encode(out, index, 6, 0xc0),
            Some((false, absolute, true)) => {
                Integer::encode(out, Prefix::relative(base, absolute), 6, 0x80);
            }

            Some((true, index, false)) => {
                Integer::encode(out, index, 4, 0x50 | never << 5);
                StringLiteral::encode_shorter(out, field.value.as_bytes(), 7, 0x00);
            }
            Some((false, absolute, false)) => {
                Integer::encode(out, Prefix::relative(base, absolute), 4, 0x40 | never << 5);
                StringLiteral::encode_shorter(out, field.value.as_bytes(), 7, 0x00);
            }

            None => {
                StringLiteral::encode_shorter(out, field.name.as_bytes(), 3, 0x20 | never << 4);
                StringLiteral::encode_shorter(out, field.value.as_bytes(), 7, 0x00);
            }
        }
    }

    /// Takes in one instruction from the peer's decoder stream.
    ///
    /// Acknowledgements are what raise the known received count, and so what
    /// makes further entries safe to reference.
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

    /// Forgets the sections on a stream that will never be acknowledged.
    pub fn cancel(&mut self, stream_id: u64) {
        self.sections.retain(|(id, _)| *id != stream_id);
    }

    /// How many sections are still waiting to be acknowledged.
    pub fn outstanding(&self) -> usize {
        self.sections.len()
    }

    /// Sets the ceiling the peer advertised, and resizes the table under it.
    ///
    /// The capacity actually used is the smaller of what the peer permits and
    /// [`Encoder::capacity_limit`]. Returns the instruction announcing the new
    /// capacity, or `None` when it did not change, so nothing needs saying.
    pub fn set_max_capacity(&mut self, max_capacity: usize) -> Option<EncoderInstruction> {
        self.max_capacity = max_capacity;

        let capacity = max_capacity.min(self.capacity_limit);
        if capacity == self.dynamic_table.capacity() {
            return None;
        }

        self.dynamic_table.set_capacity(capacity);
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity })
    }

    /// Bounds the capacity this encoder keeps, whatever the peer permits.
    pub fn set_capacity_limit(&mut self, capacity_limit: usize) -> Option<EncoderInstruction> {
        self.capacity_limit = capacity_limit;

        let capacity = self.max_capacity.min(capacity_limit);
        if capacity >= self.dynamic_table.capacity() {
            return None;
        }

        self.dynamic_table.set_capacity(capacity);
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity })
    }

    /// The capacity this encoder is willing to keep.
    pub fn capacity_limit(&self) -> usize {
        self.capacity_limit
    }

    /// The ceiling the peer advertised.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// How many insertions the peer is known to have taken in.
    ///
    /// Entries at or above this are not referenced, since doing so would block
    /// the peer's decoder.
    pub fn known_received_count(&self) -> u64 {
        self.known_received_count
    }

    /// The table as the encoder holds it.
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
/// Field blocks arrive on request streams and table updates on the encoder
/// stream, in no particular order relative to one another. A block that
/// arrives early yields [`Error::Blocked`] and should be decoded again once
/// more of the encoder stream has been fed in through
/// [`Decoder::on_encoder_instruction`].
pub struct Decoder {
    dynamic_table: DynamicTable,
    max_capacity: usize,
    max_decoded_size: usize,
    max_instruction_size: usize,
    max_blocked_streams: usize,
    blocked: fields::FieldMap<u64, u64>,
    scratch: Vec<u8>,
    idle_capacity: usize,
    stream_out: Vec<u8>,
    stream_recv: BytesMut,
}

impl Decoder {
    /// The dynamic table capacity a decoder advertises and is willing to hold.
    pub const DEFAULT_MAX_CAPACITY: usize = 4096;

    /// The decoded field list size a decoder accepts until told otherwise.
    pub const DEFAULT_MAX_DECODED_SIZE: usize = 64 * 1024;

    /// The size a single buffered instruction may grow to until told otherwise.
    pub const DEFAULT_MAX_INSTRUCTION_SIZE: usize = 64 * 1024;

    /// The blocked streams a decoder advertises and holds itself to until told
    /// otherwise.
    pub const DEFAULT_MAX_BLOCKED_STREAMS: usize = 16;

    /// The size the decoder stream buffer may keep while idle until told
    /// otherwise.
    pub const DEFAULT_IDLE_CAPACITY: usize = 64 * 1024;

    /// A decoder holding up to [`Decoder::DEFAULT_MAX_CAPACITY`], accepting up
    /// to [`Decoder::DEFAULT_MAX_DECODED_SIZE`] of decoded fields.
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(Self::DEFAULT_MAX_CAPACITY),
            max_capacity: Self::DEFAULT_MAX_CAPACITY,
            max_decoded_size: Self::DEFAULT_MAX_DECODED_SIZE,
            max_instruction_size: Self::DEFAULT_MAX_INSTRUCTION_SIZE,
            max_blocked_streams: Self::DEFAULT_MAX_BLOCKED_STREAMS,
            blocked: fields::FieldMap::default(),
            scratch: Vec::new(),
            idle_capacity: Self::DEFAULT_IDLE_CAPACITY,
            stream_out: Vec::new(),
            stream_recv: BytesMut::new(),
        }
    }

    /// Bounds the decoded size of one field block.
    pub fn set_max_decoded_size(&mut self, max_size: usize) {
        self.max_decoded_size = max_size;
    }

    /// Bounds how large a single instruction on the peer's encoder stream may
    /// grow before it is refused.
    pub fn set_max_instruction_size(&mut self, max_size: usize) {
        self.max_instruction_size = max_size;
    }

    /// Bounds how many streams may be blocked at once, which is what
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` promises the peer.
    pub fn set_max_blocked_streams(&mut self, max_streams: usize) {
        self.max_blocked_streams = max_streams;
    }

    /// Queues instructions for this end's decoder stream.
    ///
    /// The octets accumulate on the decoder stream until
    /// [`Decoder::take_decoder_stream`] takes them for sending.
    pub fn queue(&mut self, instructions: &[DecoderInstruction]) {
        for instruction in instructions {
            instruction.encode_into(&mut self.stream_out);
        }
    }

    /// Takes in octets from the peer's encoder stream.
    ///
    /// Partial instructions are buffered until the rest arrives. Each complete
    /// instruction is applied to the table, and whatever answer it calls for
    /// is queued on the decoder stream. An insertion may unblock streams;
    /// ask [`Decoder::unblocked`] afterwards and decode their held blocks
    /// again.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InstructionTooLarge`] when a single instruction grows
    /// past [`Decoder::set_max_instruction_size`], and otherwise as
    /// [`Decoder::on_encoder_instruction`].
    pub fn on_encoder_stream(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.stream_recv.extend_from_slice(bytes);

        if self.stream_recv.len() > self.max_instruction_size {
            return Err(Error::InstructionTooLarge);
        }

        loop {
            match EncoderInstruction::decode(&self.stream_recv) {
                Ok((consumed, instruction)) => {
                    let _ = self.stream_recv.split_to(consumed);
                    if let Some(answer) = self.on_encoder_instruction(instruction)? {
                        answer.encode_into(&mut self.stream_out);
                    }
                }
                Err(Error::Incomplete) => break,
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    /// Bounds how large the decoder stream buffer stays while idle.
    pub fn set_idle_capacity(&mut self, idle_capacity: usize) {
        self.idle_capacity = idle_capacity;
    }

    /// The octets queued for this end's decoder stream.
    ///
    /// Empty when there is nothing to send, which is what a caller polling for
    /// work should test rather than taking the buffer to find out.
    pub fn decoder_stream(&self) -> &[u8] {
        &self.stream_out
    }

    /// Takes the octets queued for this end's decoder stream.
    ///
    /// The buffer goes with them; hand it back to
    /// [`Decoder::reclaim_decoder_stream`] once it has been written out to
    /// have the decoder reuse the allocation.
    pub fn take_decoder_stream(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stream_out)
    }

    /// Takes a buffer back from [`Decoder::take_decoder_stream`] to be reused.
    ///
    /// It is emptied, and given up rather than kept once it has grown past
    /// [`Decoder::set_idle_capacity`], so a burst of instructions does not
    /// leave its memory attached to an idle decoder. Anything queued while the
    /// caller held it is kept, in order.
    pub fn reclaim_decoder_stream(&mut self, mut buffer: Vec<u8>) {
        buffer.clear();

        if buffer.capacity() > self.idle_capacity {
            buffer.shrink_to(self.idle_capacity / 2);
        }

        buffer.extend_from_slice(&self.stream_out);
        self.stream_out = buffer;
    }

    /// The streams whose held blocks have stopped being blocked.
    ///
    /// A stream leaves the blocked set once its block is decoded again or the
    /// stream is cancelled, not here, so asking twice reports the same streams.
    pub fn unblocked(&self) -> Vec<u64> {
        let inserted = self.dynamic_table.inserted_count();
        self.blocked.iter().filter(|(_, required)| **required <= inserted).map(|(stream_id, _)| *stream_id).collect()
    }

    /// Forgets the blocked state of a stream that was reset or abandoned.
    pub fn cancel(&mut self, stream_id: u64) {
        self.blocked.remove(&stream_id);
    }

    /// How many streams are blocked right now.
    pub fn blocked(&self) -> usize {
        self.blocked.len()
    }

    /// Applies one instruction from the peer's encoder stream.
    ///
    /// Returns the instruction to send back, if the peer should be told. An
    /// insertion unblocks any block that was waiting on it, so the caller
    /// should retry blocked streams afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCapacityUpdate`] when the peer asks for more
    /// table than was advertised, [`Error::IndexOutOfRange`] when a name
    /// reference addresses nothing, and [`Error::EntryTooLarge`] when an entry
    /// could not fit in the table at all.
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
                    StaticTable::entries()
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

    /// Decodes a field block that arrived on `stream_id`.
    ///
    /// Returns the fields and the acknowledgement to send back, if one is
    /// owed. A block that referenced no dynamic entry needs no acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Blocked`] when the block depends on insertions that
    /// have not arrived — hold it and try again rather than failing the
    /// connection. Every other [`Error`] is fatal.
    pub fn decode(&mut self, stream_id: u64, block: &[u8]) -> Result<(Vec<HeaderField>, Option<DecoderInstruction>), Error> {
        let mut scratch = std::mem::take(&mut self.scratch);
        let decoded = self.decode_into(stream_id, block, &mut scratch);
        self.scratch = scratch;
        decoded
    }

    /// [`Decoder::decode`], decoding through a buffer the caller reuses.
    ///
    /// # Errors
    ///
    /// As [`Decoder::decode`].
    pub fn decode_into(&mut self, stream_id: u64, block: &[u8], scratch: &mut Vec<u8>) -> Result<(Vec<HeaderField>, Option<DecoderInstruction>), Error> {
        let (mut consumed, encoded) = Integer::decode(block, 8)?;
        let required = Prefix::decode_insert_count(encoded, self.dynamic_table.inserted_count(), self.max_capacity)?;

        if required > self.dynamic_table.inserted_count() {
            if !self.blocked.contains_key(&stream_id) && self.blocked.len() >= self.max_blocked_streams {
                return Err(Error::TooManyBlockedStreams);
            }

            self.blocked.insert(stream_id, required);
            return Err(Error::Blocked);
        }

        self.blocked.remove(&stream_id);

        let negative = block.get(consumed).ok_or(Error::Incomplete)? & 0x80 != 0;
        let (taken, delta) = Integer::decode(&block[consumed..], 7)?;
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
                    let (consumed, index) = Integer::decode(rest, 6)?;
                    (consumed, self.resolve(first & 0x40 != 0, base, index)?)
                }

                _ if first & 0x40 != 0 => {
                    let (mut consumed, index) = Integer::decode(rest, 4)?;
                    let name = self.resolve_name(first & 0x10 != 0, base, index)?;

                    let (taken, value) = StringLiteral::decode_text_into(&rest[consumed..], 7, scratch)?;
                    consumed += taken;

                    (consumed, HeaderField::new(name, value))
                }

                _ if first & 0x20 != 0 => {
                    let (mut consumed, name) = StringLiteral::decode_text_into(rest, 3, scratch)?;
                    let (taken, value) = StringLiteral::decode_text_into(&rest[consumed..], 7, scratch)?;
                    consumed += taken;

                    (consumed, HeaderField::new(name, value))
                }

                _ if first & 0x10 != 0 => {
                    let (consumed, index) = Integer::decode(rest, 4)?;
                    let absolute = self.dynamic_table.post_base(base, index).ok_or(Error::IndexOutOfRange(index))?;

                    (consumed, self.dynamic_table.get(absolute).ok_or(Error::IndexOutOfRange(absolute))?.clone())
                }

                _ => {
                    let (mut consumed, index) = Integer::decode(rest, 3)?;
                    let absolute = self.dynamic_table.post_base(base, index).ok_or(Error::IndexOutOfRange(index))?;
                    let name = self.dynamic_table.get(absolute).ok_or(Error::IndexOutOfRange(absolute))?.name.clone();

                    let (taken, value) = StringLiteral::decode_text_into(&rest[consumed..], 7, scratch)?;
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

    /// Resolves a field reference from a field block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] when the index addresses no entry.
    pub fn resolve(&self, from_static: bool, base: u64, index: u64) -> Result<HeaderField, Error> {
        if from_static {
            return StaticTable::entries().get(index as usize).cloned().ok_or(Error::IndexOutOfRange(index));
        }

        let absolute = self.dynamic_table.indexed(base, index).ok_or(Error::IndexOutOfRange(index))?;
        self.dynamic_table.get(absolute).cloned().ok_or(Error::IndexOutOfRange(absolute))
    }

    /// [`Decoder::resolve`] for a reference that names only the field name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] when the index addresses no entry.
    pub fn resolve_name(&self, from_static: bool, base: u64, index: u64) -> Result<Text, Error> {
        if from_static {
            let field = StaticTable::entries().get(index as usize).ok_or(Error::IndexOutOfRange(index))?;
            return Ok(field.name.clone());
        }

        let absolute = self.dynamic_table.indexed(base, index).ok_or(Error::IndexOutOfRange(index))?;
        let field = self.dynamic_table.get(absolute).ok_or(Error::IndexOutOfRange(absolute))?;
        Ok(field.name.clone())
    }

    /// Sets the ceiling this end advertises, above which the peer may not size
    /// the table.
    pub fn set_max_capacity(&mut self, max_capacity: usize) {
        self.max_capacity = max_capacity;
        if self.dynamic_table.capacity() > max_capacity {
            self.dynamic_table.set_capacity(max_capacity);
        }
    }

    /// The table as rebuilt from the encoder stream so far.
    pub fn dynamic_table(&self) -> &DynamicTable {
        &self.dynamic_table
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
