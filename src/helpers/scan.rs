//! Word-at-a-time scanning over the octets of a message.
//!
//! Parsing HTTP/1.x means walking bytes looking for delimiters and rejecting
//! forbidden octets, which is most of the work in a small request. The
//! routines here do that eight octets at a time using the usual SWAR
//! bit-twiddling, and fall back to a byte loop for the tail.
//!
//! Everything here works on raw octets and makes no assumption about encoding.

/// How many octets one machine word holds.
pub const LANES: usize = size_of::<u64>();
/// The low bit of every lane.
pub const LOW: u64 = 0x0101_0101_0101_0101;
/// The high bit of every lane.
pub const HIGH: u64 = 0x8080_8080_8080_8080;

/// Marks the high bit of each lane of `word` that holds zero.
///
/// Non-zero exactly when some lane is zero, which is how a search for one
/// octet is done: exclusive-or the word against a broadcast of the needle and
/// ask whether any lane went to zero.
#[inline]
pub fn holds_zero(word: u64) -> u64 {
    word.wrapping_sub(LOW) & !word & HIGH
}

/// Reads the eight octets at `offset` as a little-endian word.
///
/// # Panics
///
/// Panics when fewer than [`LANES`] octets remain at `offset`.
#[inline]
pub fn word_at(haystack: &[u8], offset: usize) -> u64 {
    let mut octets = [0u8; LANES];
    octets.copy_from_slice(&haystack[offset..offset + LANES]);
    u64::from_le_bytes(octets)
}

/// The offset of the first `needle` in `haystack`, if it is there.
#[inline]
pub fn find(haystack: &[u8], needle: u8) -> Option<usize> {
    let broadcast = LOW.wrapping_mul(needle as u64);
    let mut offset = 0;

    while offset + LANES <= haystack.len() {
        let marked = holds_zero(word_at(haystack, offset) ^ broadcast);

        if marked != 0 {
            return Some(offset + (marked.trailing_zeros() / 8) as usize);
        }

        offset += LANES;
    }

    haystack[offset..].iter().position(|octet| *octet == needle).map(|index| offset + index)
}

/// Copies `source` to the front of `destination`.
///
/// Short copies — which is most of them, since field names and values usually
/// are — are done as a pair of overlapping fixed-width copies rather than a
/// length-driven loop.
///
/// # Panics
///
/// Debug builds assert that `destination` is long enough; release builds
/// panic on the slice bounds instead.
#[inline]
pub fn copy(destination: &mut [u8], source: &[u8]) {
    let len = source.len();
    debug_assert!(destination.len() >= len, "the destination is too short for the source");

    if len > 32 {
        destination[..len].copy_from_slice(source);
        return;
    }

    if len >= 16 {
        destination[..16].copy_from_slice(&source[..16]);
        destination[len - 16..len].copy_from_slice(&source[len - 16..]);
    } else if len >= 8 {
        destination[..8].copy_from_slice(&source[..8]);
        destination[len - 8..len].copy_from_slice(&source[len - 8..]);
    } else if len >= 4 {
        destination[..4].copy_from_slice(&source[..4]);
        destination[len - 4..len].copy_from_slice(&source[len - 4..]);
    } else if len >= 2 {
        destination[..2].copy_from_slice(&source[..2]);
        destination[len - 2..len].copy_from_slice(&source[len - 2..]);
    } else if len == 1 {
        destination[0] = source[0];
    }
}

/// Whether `left` and `right` hold the same octets.
///
/// Short runs — which field names and tokens are — are settled by a pair of
/// overlapping fixed-width comparisons rather than by a length-driven loop,
/// which is a call out to the C library and costs more than the answer it
/// gives. Longer ones are left to that loop, which is what it is good at.
///
/// The counterpart of [`copy`], and split at the same widths.
#[inline]
pub fn same(left: &[u8], right: &[u8]) -> bool {
    let len = left.len();

    if len != right.len() {
        return false;
    }

    if len > 32 {
        return left == right;
    }

    let wide = |octets: &[u8], at: usize| u128::from_ne_bytes(octets[at..at + 16].try_into().expect("sixteen octets are sixteen octets"));
    let word = |octets: &[u8], at: usize| u64::from_ne_bytes(octets[at..at + 8].try_into().expect("eight octets are eight octets"));
    let half = |octets: &[u8], at: usize| u32::from_ne_bytes(octets[at..at + 4].try_into().expect("four octets are four octets"));
    let pair = |octets: &[u8], at: usize| u16::from_ne_bytes(octets[at..at + 2].try_into().expect("two octets are two octets"));

    if len >= 16 {
        return (wide(left, 0) ^ wide(right, 0)) | (wide(left, len - 16) ^ wide(right, len - 16)) == 0;
    }

    if len >= 8 {
        return (word(left, 0) ^ word(right, 0)) | (word(left, len - 8) ^ word(right, len - 8)) == 0;
    }

    if len >= 4 {
        return (half(left, 0) ^ half(right, 0)) | (half(left, len - 4) ^ half(right, len - 4)) == 0;
    }

    if len >= 2 {
        return (pair(left, 0) ^ pair(right, 0)) | (pair(left, len - 2) ^ pair(right, len - 2)) == 0;
    }

    len == 0 || left[0] == right[0]
}

/// [`classify_field_value`]: the value carries a control octet, and so is not
/// a valid field value.
pub const VALUE_CONTROL: u8 = 1 << 0;
/// [`classify_field_value`]: the value carries an octet at or above `0x80`.
///
/// Such a value is legal but not ASCII, so it has to go through UTF-8
/// validation rather than being taken as ASCII outright.
pub const VALUE_OBS_TEXT: u8 = 1 << 1;

/// Marks the high bit of each lane of `word` that holds less than `bound`.
///
/// # Panics
///
/// Debug builds assert `bound <= 0x80`; above that the subtraction borrows
/// across lane boundaries and the answer is meaningless.
#[inline]
pub fn holds_less(word: u64, bound: u64) -> u64 {
    debug_assert!(bound <= 0x80, "a bound above 0x80 can borrow out of its byte");

    let lowered = (word | HIGH).wrapping_sub(LOW.wrapping_mul(bound));
    !lowered & !word & HIGH
}

/// Marks the high bit of each lane of `word` that holds zero.
///
/// Unlike [`holds_zero`] this is exact rather than approximate, so it can be
/// used where the marks themselves are combined with other masks.
#[inline]
pub fn marks_zero(word: u64) -> u64 {
    !((word & !HIGH).wrapping_add(!HIGH) | word) & HIGH
}

/// Classifies a field value in one pass.
///
/// Returns the or of [`VALUE_CONTROL`] and [`VALUE_OBS_TEXT`]. A horizontal
/// tab is permitted and does not count as a control octet; every other octet
/// below `0x20`, and `0x7f`, does.
#[inline]
pub fn classify_field_value(text: &[u8]) -> u8 {
    let mut control = 0u64;
    let mut obs_text = 0u64;
    let mut offset = 0;

    let classify = |word: u64, control: &mut u64, obs_text: &mut u64| {
        let tab = marks_zero(word ^ LOW.wrapping_mul(b'\t' as u64));
        let del = marks_zero(word ^ LOW.wrapping_mul(0x7f));

        *control |= (holds_less(word, 0x20) & !tab) | del;
        *obs_text |= word & HIGH;
    };

    while offset + LANES <= text.len() {
        classify(word_at(text, offset), &mut control, &mut obs_text);
        offset += LANES;
    }

    if offset < text.len() && text.len() >= LANES {
        classify(word_at(text, text.len() - LANES), &mut control, &mut obs_text);
        offset = text.len();
    }

    let (control, obs_text) = text[offset..].iter().fold((control != 0, obs_text != 0), |(control, obs_text), octet| {
        (
            control || (*octet < 0x20 && *octet != b'\t') || *octet == 0x7f,
            obs_text || *octet >= 0x80,
        )
    });

    (control as u8) | (obs_text as u8) << 1
}

/// Whether `text` may be sent as a field value.
///
/// Octets at or above `0x80` are allowed; control octets other than tab are not.
#[inline]
pub fn is_field_value(text: &[u8]) -> bool {
    classify_field_value(text) & VALUE_CONTROL == 0
}

/// Whether every octet of `text` is visible: above `SP` and not `DEL`.
///
/// `VCHAR` and `obs-text` together, which is the set a request target and an
/// authority are held to. A contiguous range rather than a scattered set, so
/// the bit-twiddling above answers it and no table is reached for.
///
/// An empty `text` is vacuously all of anything, and answers `true`.
#[inline]
pub fn all_visible(text: &[u8]) -> bool {
    let mut marked = 0u64;
    let mut offset = 0;

    let classify = |word: u64| holds_less(word, 0x21) | marks_zero(word ^ LOW.wrapping_mul(0x7f));

    while offset + LANES <= text.len() {
        marked |= classify(word_at(text, offset));
        offset += LANES;
    }

    if offset < text.len() && text.len() >= LANES {
        marked |= classify(word_at(text, text.len() - LANES));
        offset = text.len();
    }

    marked == 0 && text[offset..].iter().all(|octet| *octet > 0x20 && *octet != 0x7f)
}

/// Whether every octet of `text` is one `table` marks with `mask`.
///
/// The classes a scattered set of octets forms — a token, say — are not
/// something the bit-twiddling above can express, so this stays a table
/// lookup. What it does do is take [`LANES`] octets at a time and combine the
/// answers rather than branch on each one, which lets the loads run ahead of
/// each other instead of the loop stalling on every octet.
///
/// An empty `text` is vacuously all of anything, and answers `true`.
#[inline]
pub fn all_in_class(text: &[u8], table: &[u8; 256], mask: u8) -> bool {
    let mut held = mask;
    let mut chunks = text.chunks_exact(LANES);

    for chunk in &mut chunks {
        held &= table[chunk[0] as usize]
            & table[chunk[1] as usize]
            & table[chunk[2] as usize]
            & table[chunk[3] as usize]
            & table[chunk[4] as usize]
            & table[chunk[5] as usize]
            & table[chunk[6] as usize]
            & table[chunk[7] as usize];
    }

    for octet in chunks.remainder() {
        held &= table[*octet as usize];
    }

    held & mask != 0
}
