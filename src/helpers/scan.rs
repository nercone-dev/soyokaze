pub const LANES: usize = size_of::<u64>();
pub const LOW: u64 = 0x0101_0101_0101_0101;
pub const HIGH: u64 = 0x8080_8080_8080_8080;

#[inline]
pub fn holds_zero(word: u64) -> u64 {
    word.wrapping_sub(LOW) & !word & HIGH
}

#[inline]
pub fn word_at(haystack: &[u8], offset: usize) -> u64 {
    let mut octets = [0u8; LANES];
    octets.copy_from_slice(&haystack[offset..offset + LANES]);
    u64::from_le_bytes(octets)
}

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

pub const VALUE_CONTROL: u8 = 1 << 0;
pub const VALUE_OBS_TEXT: u8 = 1 << 1;

#[inline]
pub fn holds_less(word: u64, bound: u64) -> u64 {
    debug_assert!(bound <= 0x80, "a bound above 0x80 can borrow out of its byte");

    let lowered = (word | HIGH).wrapping_sub(LOW.wrapping_mul(bound));
    !lowered & !word & HIGH
}

#[inline]
pub fn marks_zero(word: u64) -> u64 {
    !((word & !HIGH).wrapping_add(!HIGH) | word) & HIGH
}

#[inline]
pub fn classify_field_value(text: &[u8]) -> u8 {
    let mut control = 0u64;
    let mut obs_text = 0u64;
    let mut offset = 0;

    while offset + LANES <= text.len() {
        let word = word_at(text, offset);

        let tab = marks_zero(word ^ LOW.wrapping_mul(b'\t' as u64));
        let del = marks_zero(word ^ LOW.wrapping_mul(0x7f));

        control |= (holds_less(word, 0x20) & !tab) | del;
        obs_text |= word & HIGH;

        offset += LANES;
    }

    let (control, obs_text) = text[offset..].iter().fold((control != 0, obs_text != 0), |(control, obs_text), octet| {
        (
            control || (*octet < 0x20 && *octet != b'\t') || *octet == 0x7f,
            obs_text || *octet >= 0x80,
        )
    });

    (control as u8) | (obs_text as u8) << 1
}

#[inline]
pub fn is_field_value(text: &[u8]) -> bool {
    classify_field_value(text) & VALUE_CONTROL == 0
}
