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
//! until the encoder stream catches up. [`Limits::qpack_block_timeout`] bounds
//! that wait, since a peer that never sends the insertions would otherwise pin
//! the stream open forever.
//!
//! This [`Encoder`] only references dynamic entries it knows the peer has
//! acknowledged, so the blocks it produces never block the peer's decoder.
//!
//! Integer and Huffman string coding are shared with [`hpack`] rather than
//! reimplemented, as are [`HeaderField`] and the static table index.

use std::collections::VecDeque;
use std::fmt;
use std::sync::OnceLock;

use crate::api::common::Limits;
use crate::helpers::hpack::{self, HeaderField};
use crate::helpers::huffman;
use crate::helpers::text::Text;

/// The dynamic table capacity assumed before the peer's settings arrive.
///
/// Zero, so that nothing is inserted until the peer has said how much table it
/// is willing to keep.
pub const DEFAULT_MAX_TABLE_CAPACITY: usize = 0;

/// The dynamic table capacity this end advertises and is willing to hold.
pub const ADVERTISED_TABLE_CAPACITY: usize = 4096;

/// The static table, indexed from 0.
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

/// The reverse index over the QPACK static table, built on first use.
pub fn static_index() -> &'static hpack::StaticIndex {
    static INDEX: OnceLock<hpack::StaticIndex> = OnceLock::new();
    INDEX.get_or_init(|| hpack::StaticIndex::new(static_table(), 0))
}

/// Finds a field in the static table.
///
/// The flag says whether the value matched too; `false` means the index names
/// the field name only.
pub fn find_static(field: &HeaderField) -> Option<(u64, bool)> {
    let (named, exact) = static_index().lookup(&field.name, &field.value);

    match (exact, named) {
        (Some(index), _) => Some((index as u64, true)),
        (None, Some(index)) => Some((index as u64, false)),
        (None, None) => None,
    }
}

/// The most entries a table of this capacity could ever hold.
///
/// Each entry costs at least [`HeaderField::OVERHEAD`], so this is a ceiling
/// whatever the fields are. It sets the modulus the required insert count is
/// encoded against.
pub fn max_entries(max_capacity: usize) -> u64 {
    (max_capacity / HeaderField::OVERHEAD) as u64
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
        base.checked_sub(index + 1)
    }

    /// The absolute index for one counted forward from `base`.
    ///
    /// This is how a field block names entries inserted while the block itself
    /// was being written.
    pub fn post_base(&self, base: u64, index: u64) -> Option<u64> {
        base.checked_add(index)
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

/// Writes a length-prefixed string, Huffman coding it only when that is shorter.
///
/// Unlike HPACK the prefix width varies by representation, so the bit that
/// marks Huffman coding sits at `prefix_bits` rather than always at the top.
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

/// Reads a length-prefixed string, returning how many octets it took.
///
/// # Errors
///
/// As [`decode_string_into_ascii`].
pub fn decode_string(input: &[u8], prefix_bits: u8) -> Result<(usize, Vec<u8>), Error> {
    let mut value = Vec::new();
    let consumed = decode_string_into(input, prefix_bits, &mut value)?;
    Ok((consumed, value))
}

/// [`decode_string`], decoding into a buffer the caller reuses.
///
/// # Errors
///
/// As [`decode_string_into_ascii`].
pub fn decode_string_into(input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<usize, Error> {
    decode_string_into_ascii(input, prefix_bits, scratch).map(|(consumed, _)| consumed)
}

/// [`decode_string_into`], also reporting whether the result is ASCII.
///
/// `scratch` is cleared first and holds the decoded octets on success.
///
/// # Errors
///
/// Returns [`Error::Incomplete`] when the string runs past the end of the
/// input, and [`Error::Huffman`] when a Huffman coded string will not decode.
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

/// Reads a length-prefixed string straight into a [`Text`].
///
/// # Errors
///
/// As [`decode_string_into_ascii`].
pub fn decode_field(input: &[u8], prefix_bits: u8) -> Result<(usize, Text), Error> {
    let mut scratch = Vec::new();
    decode_field_into(input, prefix_bits, &mut scratch)
}

/// [`decode_field`], decoding through a buffer the caller reuses.
///
/// # Errors
///
/// As [`decode_string_into_ascii`].
pub fn decode_field_into(input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<(usize, Text), Error> {
    let (consumed, ascii) = decode_string_into_ascii(input, prefix_bits, scratch)?;
    Ok((consumed, hpack::decoded_text(scratch, ascii)))
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
            Self::SectionAcknowledgment { stream_id } => hpack::encode_integer(out, *stream_id, 7, 0x80),
            Self::StreamCancellation { stream_id } => hpack::encode_integer(out, *stream_id, 6, 0x40),
            Self::InsertCountIncrement { increment } => hpack::encode_integer(out, *increment, 6, 0x00),
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

/// The index a field block uses to name an absolute entry, counted back from `base`.
pub fn relative(base: u64, absolute: u64) -> u64 {
    base.saturating_sub(absolute).saturating_sub(1)
}

/// Encodes the required insert count that leads a field block.
///
/// The count is sent modulo twice [`max_entries`] rather than in full, because
/// the full value grows without bound over a long connection while the window
/// of counts a decoder could plausibly be at does not. Zero means the block
/// references no dynamic entry and so can never block.
pub fn encode_insert_count(required: u64, max_capacity: usize) -> u64 {
    let full_range = 2 * max_entries(max_capacity);
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

/// The sending half of one direction of an HTTP/3 connection.
///
/// The encoder only references dynamic entries the peer has acknowledged, so
/// the blocks it produces never leave the peer's decoder blocked. It tracks
/// the sections it is still waiting on, and once
/// [`Limits::max_outstanding_sections`] of them are outstanding it stops using
/// the dynamic table at all rather than letting that list grow.
pub struct Encoder {
    dynamic_table: DynamicTable,
    known_received_count: u64,
    max_capacity: usize,
    max_outstanding_sections: usize,
    sections: VecDeque<(u64, u64)>,
}

impl Encoder {
    /// An encoder with an empty table, which stays empty until the peer's
    /// settings raise [`DEFAULT_MAX_TABLE_CAPACITY`].
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(0),
            known_received_count: 0,
            max_capacity: DEFAULT_MAX_TABLE_CAPACITY,
            max_outstanding_sections: Limits::default().max_outstanding_sections as usize,
            sections: VecDeque::new(),
        }
    }

    /// Bounds how many unacknowledged sections the encoder will track.
    pub fn set_max_outstanding_sections(&mut self, max_sections: usize) {
        self.max_outstanding_sections = max_sections;
    }

    /// Encodes a field block for `stream_id`.
    ///
    /// Returns the block and the instructions that must go out on the encoder
    /// stream for the peer to be able to read it. The instructions do not have
    /// to arrive first — the block carries the insert count it needs, and the
    /// peer will hold it until they do.
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

    /// Picks the reference to use for a field.
    ///
    /// Returns whether the entry is in the static table, its index, and
    /// whether the value matched as well as the name. Dynamic entries the peer
    /// has not acknowledged are passed over, so a block never blocks the peer.
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

    /// Resizes the table, and returns the instruction announcing it.
    ///
    /// The request is clamped to what the peer advertised. `None` when the
    /// capacity is already what was asked for, so nothing needs saying.
    pub fn set_capacity(&mut self, capacity: usize) -> Option<EncoderInstruction> {
        let capacity = capacity.min(self.max_capacity);
        if capacity == self.dynamic_table.capacity() {
            return None;
        }

        self.dynamic_table.set_capacity(capacity);
        Some(EncoderInstruction::SetDynamicTableCapacity { capacity })
    }

    /// Sets the ceiling the peer advertised, above which the table may not be sized.
    pub fn set_max_capacity(&mut self, max_capacity: usize) {
        self.max_capacity = max_capacity;
        if self.dynamic_table.capacity() > max_capacity {
            self.dynamic_table.set_capacity(max_capacity);
        }
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

/// The receiving half of one direction of an HTTP/3 connection.
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
    scratch: Vec<u8>,
}

impl Decoder {
    /// A decoder holding up to [`ADVERTISED_TABLE_CAPACITY`], accepting up to
    /// [`hpack::DEFAULT_MAX_DECODED_SIZE`] of decoded fields.
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(ADVERTISED_TABLE_CAPACITY),
            max_capacity: ADVERTISED_TABLE_CAPACITY,
            max_decoded_size: hpack::DEFAULT_MAX_DECODED_SIZE,
            scratch: Vec::new(),
        }
    }

    /// Bounds the decoded size of one field block.
    pub fn set_max_decoded_size(&mut self, max_size: usize) {
        self.max_decoded_size = max_size;
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

    /// Resolves a field reference from a field block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] when the index addresses no entry.
    pub fn resolve(&self, from_static: bool, base: u64, index: u64) -> Result<HeaderField, Error> {
        if from_static {
            return static_table().get(index as usize).cloned().ok_or(Error::IndexOutOfRange(index));
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
            let field = static_table().get(index as usize).ok_or(Error::IndexOutOfRange(index))?;
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
