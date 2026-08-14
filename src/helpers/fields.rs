//! The field vocabulary and wire primitives HPACK and QPACK share.
//!
//! Both compression formats are built out of the same pieces: a
//! [`HeaderField`] naming one field, the prefixed [`Integer`] and
//! [`StringLiteral`] representations of RFC 7541 §5, and a [`StaticIndex`]
//! answering "is this field already in the static table". [`hpack`] and
//! [`qpack`] each bring their own tables and instructions on top; what is
//! here is only what the two would otherwise duplicate.
//!
//! [`hpack`]: crate::helpers::hpack
//! [`qpack`]: crate::helpers::qpack

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};

use crate::helpers::huffman;
use crate::helpers::scan;
use crate::helpers::text::Text;

/// One field: a name and a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    /// The field name, lowercase.
    pub name: Text,
    /// The field value.
    pub value: Text,
}

impl HeaderField {
    /// Fields never placed in the dynamic table, because compressing a secret
    /// against attacker-chosen text leaks it.
    pub const SENSITIVE: &'static [&'static str] = &["authorization", "proxy-authorization", "cookie", "set-cookie"];

    /// The per-entry overhead charged against a dynamic table's size.
    ///
    /// A fixed allowance for the bookkeeping an entry costs, so that a table
    /// full of empty fields still has a bounded entry count.
    pub const OVERHEAD: usize = 32;

    /// The fewest fields a section is given room for before it is decoded.
    pub const SECTION_FLOOR: usize = 8;

    /// The room left beyond what the last section carried.
    ///
    /// A decoded section rarely stays as it arrived: an HTTP/2 or HTTP/3
    /// request gains the `Host` its `:authority` folds into. Leaving a slot
    /// spare is what keeps that from reallocating a list that was otherwise
    /// sized exactly.
    pub const SECTION_SPARE: usize = 1;

    /// The most fields a section is given room for before it is decoded.
    ///
    /// A section carrying more still decodes; what the ceiling bounds is the
    /// room a decoder goes on holding afterwards, so that one outsized section
    /// does not leave every later one sized for it.
    pub const SECTION_CEILING: usize = 128;

    /// A field with this name and value.
    pub fn new(name: impl Into<Text>, value: impl Into<Text>) -> Self {
        Self { name: name.into(), value: value.into() }
    }

    /// How many fields to make room for, given what the last section carried.
    ///
    /// Field sections on one connection are near enough alike that the last
    /// one is the best guess available for the next, and a guess is worth
    /// having: a list grown from empty reallocates several times on its way to
    /// an ordinary request's length. The block's own size says little, since
    /// compressing against a warm table is exactly what makes a long section
    /// short on the wire.
    ///
    /// A decoder asks this of its first field rather than before it, so a
    /// block refused before any field decodes never allocates at all.
    pub fn section_hint(previous: usize) -> usize {
        previous.saturating_add(Self::SECTION_SPARE).clamp(Self::SECTION_FLOOR, Self::SECTION_CEILING)
    }

    /// What this field costs against a dynamic table's size.
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + Self::OVERHEAD
    }

    /// Whether the field is one of [`HeaderField::SENSITIVE`], and so must never be
    /// indexed.
    pub fn sensitive(&self) -> bool {
        let name = self.name.as_str();
        let Some(first) = name.as_bytes().first() else {
            return false;
        };

        match (name.len(), first) {
            (6, b'c') => name == "cookie",
            (10, b's') => name == "set-cookie",
            (13, b'a') => name == "authorization",
            (19, b'p') => name == "proxy-authorization",
            _ => false,
        }
    }

    /// [`HeaderField::TOKENS`]: the octet may appear in a token, and so in a
    /// field name.
    pub const TOKEN: u8 = 1 << 0;
    /// [`HeaderField::TOKENS`]: the octet may appear in a token and is not an
    /// uppercase letter, which is what the binary versions require of a name.
    pub const LOWERCASE: u8 = 1 << 1;

    /// Which octets may appear in a field name.
    ///
    /// `token` of RFC 9110 §5.6.2, which is the same set every version admits.
    /// This is the field vocabulary's own table; [`h1::Octets::TABLE`] is the
    /// HTTP/1 line scanner's, which carries the classes a start line needs as
    /// well.
    ///
    /// [`h1::Octets::TABLE`]: crate::protocol::h1::Octets::TABLE
    pub const TOKENS: &'static [u8; 256] = &{
        let mut octets = [0u8; 256];
        let mut value = 0usize;

        while value < 256 {
            let byte = value as u8;

            let token = byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                );

            octets[value] = token as u8 | ((token && !byte.is_ascii_uppercase()) as u8) << 1;
            value += 1;
        }

        octets
    };

    /// Whether a field name may be sent or accepted.
    ///
    /// A name is a non-empty token. RFC 9113 §8.2.1 and RFC 9114 §4.2 add that
    /// it must be lowercase, which [`HeaderField::is_lowercase_name`] asks;
    /// this is the part every version shares.
    #[inline]
    pub fn is_name(name: &str) -> bool {
        !name.is_empty() && scan::all_in_class(name.as_bytes(), Self::TOKENS, Self::TOKEN)
    }

    /// [`HeaderField::is_name`], and lowercase as the binary versions require.
    ///
    /// One pass rather than two: [`HeaderField::LOWERCASE`] marks exactly the
    /// octets that are both, so the table answers the whole question.
    #[inline]
    pub fn is_lowercase_name(name: &str) -> bool {
        !name.is_empty() && scan::all_in_class(name.as_bytes(), Self::TOKENS, Self::LOWERCASE)
    }

    /// Whether a field value may be sent or accepted.
    ///
    /// `field-value` of RFC 9110 §5.5: no control octet other than a tab, and
    /// no leading or trailing whitespace, which a receiver would strip and so
    /// could read two ways.
    #[inline]
    pub fn is_value(value: &str) -> bool {
        let octets = value.as_bytes();

        if matches!(octets.first(), Some(b' ' | b'\t')) || matches!(octets.last(), Some(b' ' | b'\t')) {
            return false;
        }

        scan::is_field_value(octets)
    }
}

/// An FNV-1a hasher for the short keys a field index is built on.
///
/// Field names are a handful of octets, where a hash tuned for long inputs
/// costs more than the lookup saves.
#[derive(Default)]
pub struct FieldHasher(u64);

impl FieldHasher {
    /// What an empty hash starts from.
    pub const SEED: u64 = 0xcbf2_9ce4_8422_2325;
    /// The odd multiplier each word is mixed with.
    pub const FACTOR: u64 = 0x9e37_79b9_7f4a_7c15;

    /// Mixes one word in.
    #[inline]
    pub fn mix(hash: u64, word: u64) -> u64 {
        (hash.rotate_left(5) ^ word).wrapping_mul(Self::FACTOR)
    }

    /// The eight octets at `offset`, as a word.
    ///
    /// # Panics
    ///
    /// Panics when fewer than eight octets remain at `offset`.
    #[inline]
    pub fn word(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("eight octets are eight octets"))
    }

    /// Fewer than eight octets, gathered into a word.
    ///
    /// The pieces are read at fixed widths and may overlap, so nothing here
    /// reaches for a copy driven by a length only known at run time — which is
    /// a call out to the C library, and costs more than the whole hash. Two
    /// runs of the same length still differ whenever their octets do, which is
    /// all a hash asks.
    ///
    /// # Panics
    ///
    /// Panics when eight octets or more are given.
    #[inline]
    pub fn short(bytes: &[u8]) -> u64 {
        match bytes.len() {
            0 => 0,
            len @ 1..=3 => bytes[0] as u64 | (bytes[len / 2] as u64) << 8 | (bytes[len - 1] as u64) << 16,
            len => {
                let head = u32::from_le_bytes(bytes[..4].try_into().expect("four octets are four octets")) as u64;
                let tail = u32::from_le_bytes(bytes[len - 4..].try_into().expect("four octets are four octets")) as u64;
                head | tail << 32
            }
        }
    }
}

impl Hasher for FieldHasher {
    fn finish(&self) -> u64 {
        // The bucket a map picks comes off the low bits and the tag off the
        // high ones, so the last word's own bits are spread across both before
        // either is read.
        let hash = self.0;
        hash ^ hash >> 32
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut hash = match self.0 {
            0 => Self::SEED,
            held => held,
        };

        // Eight octets at a time: a field name is a handful of them, and a
        // multiply per octet costs more than the whole lookup it leads to. The
        // last word is read to end on the final octet rather than to begin
        // after the one before, so it overlaps rather than needing a tail of
        // its own.
        if bytes.len() >= size_of::<u64>() {
            let mut offset = 0;

            while offset + size_of::<u64>() <= bytes.len() {
                hash = Self::mix(hash, Self::word(bytes, offset));
                offset += size_of::<u64>();
            }

            if offset < bytes.len() {
                hash = Self::mix(hash, Self::word(bytes, bytes.len() - size_of::<u64>()));
            }
        } else {
            hash = Self::mix(hash, Self::short(bytes));
        }

        self.0 = Self::mix(hash, bytes.len() as u64);
    }
}

/// A map keyed by field name, hashed with [`FieldHasher`].
pub type FieldMap<K, V> = HashMap<K, V, BuildHasherDefault<FieldHasher>>;

/// A hasher for keys that are hashes already.
///
/// A [`Mark`] is a [`FieldHasher`] digest, so putting it through a second
/// round would mix bits that are spread as well as they are going to get. This
/// hands the word straight back, which is what a map keyed by a mark wants —
/// the same reason [`StreamHasher`] exists for a stream identifier.
///
/// [`StreamHasher`]: crate::protocol::common::StreamHasher
#[derive(Default)]
pub struct MarkHasher(u64);

impl Hasher for MarkHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0 = bytes.iter().fold(self.0, |hash, octet| FieldHasher::mix(hash, *octet as u64));
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

/// A map keyed by a [`Mark`], which is hashed already.
pub type MarkMap<V> = HashMap<Mark, V, BuildHasherDefault<MarkHasher>>;

/// A cheap stand-in for a field name, so a table can be searched without
/// comparing the names themselves.
///
/// A dynamic table is searched from one end to the other for every field
/// encoded, which is where most of the comparing on a connection happens. Two
/// marks that differ stand for two names that differ, so a mismatch settles an
/// entry in one word comparison; two that agree are still confirmed against
/// the names, since a mark is a hash and hashes collide.
///
/// Only the name is marked. A value is only ever compared once the name has
/// matched, which is rare enough that hashing every value to save those
/// comparisons costs more than it saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mark(pub u64);

impl Mark {
    /// The mark of a name.
    #[inline]
    pub fn of(name: &str) -> Self {
        let mut hasher = FieldHasher::default();
        hasher.write(name.as_bytes());
        Self(hasher.finish())
    }
}

/// One entry of a dynamic table: the field, and the [`Mark`] it is searched by.
///
/// HPACK and QPACK number their tables differently but hold them the same way,
/// so both keep their entries as these.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The field itself.
    pub field: HeaderField,
    /// What the field's name is searched by.
    pub mark: Mark,
}

impl Entry {
    /// An entry holding `field`.
    pub fn of(field: HeaderField) -> Self {
        Self { mark: Mark::of(&field.name), field }
    }

    /// What the field costs against a table's size.
    pub fn size(&self) -> usize {
        self.field.size()
    }

    /// Whether this entry's name is the marked field's.
    #[inline]
    pub fn named(&self, mark: Mark, field: &HeaderField) -> bool {
        self.mark == mark && self.field.name == field.name
    }

    /// Whether this entry's value is the field's.
    #[inline]
    pub fn valued(&self, field: &HeaderField) -> bool {
        self.field.value == field.value
    }
}

/// Every static table entry that shares one name.
pub struct NameEntry {
    /// The name itself, which confirms a [`Mark`] that matched.
    pub name: &'static str,
    /// The lowest index carrying this name, for a name-only reference.
    pub first: usize,
    /// Each value stored under this name, with its index.
    pub values: Vec<(&'static str, usize)>,
}

/// A reverse index over a static table: field to index.
///
/// Both HPACK and QPACK need to ask "is this field already in the static
/// table", and a linear scan of sixty or a hundred entries per field is the
/// bulk of encoding a small request.
pub struct StaticIndex {
    by_name: MarkMap<NameEntry>,
}

impl StaticIndex {
    /// Indexes `entries`, numbering the first one `base`.
    ///
    /// HPACK numbers its static table from 1 and QPACK from 0, which is the
    /// only difference between the two.
    pub fn new(entries: &'static [HeaderField], base: usize) -> Self {
        let mut by_name: MarkMap<NameEntry> = MarkMap::default();

        for (offset, entry) in entries.iter().enumerate() {
            let index = base + offset;
            let name = entry.name.as_str();

            by_name
                .entry(Mark::of(name))
                .or_insert_with(|| NameEntry { name, first: index, values: Vec::new() })
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
        // Keyed by the mark rather than by the name, so a name that is not in
        // the table — which is most of what a connection sends — is turned
        // away on a word comparison, and one that is costs only the single
        // comparison that confirms the mark.
        let Some(entry) = self.by_name.get(&Mark::of(name)).filter(|entry| scan::same(entry.name.as_bytes(), name.as_bytes())) else {
            return (None, None);
        };

        let exact = entry.values.iter().find(|(candidate, _)| scan::same(candidate.as_bytes(), value.as_bytes())).map(|(_, index)| *index);
        (Some(entry.first), exact)
    }
}

/// Why a wire primitive would not decode.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// An integer would not fit in 64 bits.
    IntegerOverflow,
    /// A representation runs past the end of the input.
    Incomplete,
    /// A Huffman string would not decode.
    Huffman(huffman::DecodeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegerOverflow => write!(f, "integer representation overflowed"),
            Self::Incomplete => write!(f, "representation ends before the input does"),
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

/// The prefixed integer representation both HPACK and QPACK are built out of.
pub struct Integer;

impl Integer {
    /// The largest value a prefix of `prefix_bits` can hold on its own.
    ///
    /// A value at or above this is written as the limit followed by
    /// continuation octets.
    pub fn limit(prefix_bits: u8) -> u64 {
        (1u64 << prefix_bits.min(63)) - 1
    }

    /// Writes an integer.
    ///
    /// The low `prefix_bits` of the first octet carry the value, and the bits
    /// above them carry `flags`, which is what tells the two ends apart which
    /// representation this is. Values too large for the prefix continue over
    /// further octets, seven bits at a time.
    pub fn encode(out: &mut Vec<u8>, value: u64, prefix_bits: u8, flags: u8) {
        let limit = Self::limit(prefix_bits);

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

    /// Reads an integer, returning how many octets it took and its value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incomplete`] when the continuation runs off the end of
    /// the input, and [`Error::IntegerOverflow`] when the value will not fit in
    /// 64 bits — which is how an encoding that continues forever is stopped.
    pub fn decode(input: &[u8], prefix_bits: u8) -> Result<(usize, u64), Error> {
        let limit = Self::limit(prefix_bits);

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
}

/// The length-prefixed string representation both HPACK and QPACK are built out
/// of.
///
/// The length is an [`Integer`] and the bit just above its prefix marks Huffman
/// coding. HPACK always writes that length in a seven-bit prefix, so the mark
/// always lands at `0x80`; QPACK varies the prefix by representation, so the
/// mark moves with it. `prefix_bits` is what covers both, and is always 7 for
/// HPACK.
pub struct StringLiteral;

impl StringLiteral {
    /// The widest prefix a string literal can be written with.
    ///
    /// The bit just above the prefix carries the Huffman mark, so an eight-bit
    /// prefix would leave no room for it. Both formats stay at or under this;
    /// a wider `prefix_bits` is read as this one rather than shifting the mark
    /// out of the octet.
    pub const MAX_PREFIX_BITS: u8 = 7;

    /// The mark that says a string is Huffman coded, for a prefix of
    /// `prefix_bits`.
    ///
    /// Held to [`StringLiteral::MAX_PREFIX_BITS`], so this is always a bit of
    /// the octet rather than an overflowing shift.
    #[inline]
    pub fn huffman_mark(prefix_bits: u8) -> u8 {
        1u8 << prefix_bits.min(Self::MAX_PREFIX_BITS)
    }

    /// Writes a string, Huffman coded or not as asked.
    ///
    /// Use [`StringLiteral::encode_shorter`] to have the shorter of the two
    /// chosen for you.
    pub fn encode(out: &mut Vec<u8>, value: &[u8], prefix_bits: u8, flags: u8, huffman: bool) {
        let prefix_bits = prefix_bits.min(Self::MAX_PREFIX_BITS);

        if huffman {
            let encoded = huffman::encoded_len(value);
            Integer::encode(out, encoded as u64, prefix_bits, flags | Self::huffman_mark(prefix_bits));
            huffman::encode_sized(value, encoded, out);
        } else {
            Integer::encode(out, value.len() as u64, prefix_bits, flags);
            out.extend_from_slice(value);
        }
    }

    /// [`StringLiteral::encode`], Huffman coding only when that is shorter.
    ///
    /// The coded length is measured once and reused, rather than asked for
    /// again through [`StringLiteral::prefers_huffman`], since this is on the
    /// path every field goes down.
    pub fn encode_shorter(out: &mut Vec<u8>, value: &[u8], prefix_bits: u8, flags: u8) {
        let prefix_bits = prefix_bits.min(Self::MAX_PREFIX_BITS);
        let encoded = huffman::encoded_len(value);

        if encoded < value.len() {
            Integer::encode(out, encoded as u64, prefix_bits, flags | Self::huffman_mark(prefix_bits));
            huffman::encode_sized(value, encoded, out);
        } else {
            Integer::encode(out, value.len() as u64, prefix_bits, flags);
            out.extend_from_slice(value);
        }
    }

    /// Whether Huffman coding this value would make it shorter.
    pub fn prefers_huffman(value: &[u8]) -> bool {
        huffman::encoded_len(value) < value.len()
    }

    /// Reads a string, returning how many octets it took.
    ///
    /// # Errors
    ///
    /// As [`StringLiteral::decode_into_ascii`].
    pub fn decode(input: &[u8], prefix_bits: u8) -> Result<(usize, Vec<u8>), Error> {
        let mut value = Vec::new();
        let consumed = Self::decode_into(input, prefix_bits, &mut value)?;
        Ok((consumed, value))
    }

    /// [`StringLiteral::decode`], decoding into a buffer the caller reuses.
    ///
    /// # Errors
    ///
    /// As [`StringLiteral::decode_into_ascii`].
    pub fn decode_into(input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<usize, Error> {
        Self::decode_into_ascii(input, prefix_bits, scratch).map(|(consumed, _)| consumed)
    }

    /// [`StringLiteral::decode_into`], also reporting whether the result is
    /// ASCII.
    ///
    /// `scratch` is cleared first and holds the decoded octets on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incomplete`] when the string runs past the end of the
    /// input, [`Error::Huffman`] when a Huffman coded string will not decode,
    /// and otherwise as [`Integer::decode`].
    pub fn decode_into_ascii(input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<(usize, bool), Error> {
        let prefix_bits = prefix_bits.min(Self::MAX_PREFIX_BITS);
        let huffman = input.first().ok_or(Error::Incomplete)? & Self::huffman_mark(prefix_bits) != 0;
        let (prefix, length) = Integer::decode(input, prefix_bits)?;

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

    /// Reads a string straight into a [`Text`].
    ///
    /// # Errors
    ///
    /// As [`StringLiteral::decode_into_ascii`].
    pub fn decode_text(input: &[u8], prefix_bits: u8) -> Result<(usize, Text), Error> {
        let mut scratch = Vec::new();
        Self::decode_text_into(input, prefix_bits, &mut scratch)
    }

    /// [`StringLiteral::decode_text`], decoding through a buffer the caller
    /// reuses.
    ///
    /// # Errors
    ///
    /// As [`StringLiteral::decode_into_ascii`].
    pub fn decode_text_into(input: &[u8], prefix_bits: u8, scratch: &mut Vec<u8>) -> Result<(usize, Text), Error> {
        let (consumed, ascii) = Self::decode_into_ascii(input, prefix_bits, scratch)?;
        Ok((consumed, Self::text(scratch, ascii)))
    }

    /// Builds a [`Text`] from decoded octets, skipping validation when the
    /// decoder already established they are ASCII.
    ///
    /// `ascii` comes from [`StringLiteral::decode_into_ascii`], which classifies
    /// the octets as it decodes them, so a caller passing what that returned is
    /// always right about them.
    #[inline]
    pub fn text(octets: &[u8], ascii: bool) -> Text {
        match ascii {
            // SAFETY: `ascii` says the decoder saw no octet at or above 0x80.
            true => unsafe { Text::from_verified_ascii(octets) },
            false => Text::from_utf8_lossy(octets),
        }
    }
}
