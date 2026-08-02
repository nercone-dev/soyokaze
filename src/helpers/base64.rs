use std::fmt;

pub const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub const PAD: u8 = b'=';

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength(usize),
    InvalidSymbol(u8),
    InvalidPadding,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(length) => write!(f, "length {length} is not a multiple of four"),
            Self::InvalidSymbol(symbol) => write!(f, "symbol {symbol:#04x} is not in the base64 alphabet"),
            Self::InvalidPadding => write!(f, "padding is misplaced or carries non-zero bits"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub const INVALID: u8 = 0xff;

pub static VALUES: [u8; 256] = {
    let mut values = [INVALID; 256];
    let mut index = 0;

    while index < 64 {
        values[ALPHABET[index] as usize] = index as u8;
        index += 1;
    }

    values
};

pub fn symbol(value: u8) -> u8 {
    ALPHABET[value as usize & 0x3f]
}

pub fn value(symbol: u8) -> Option<u8> {
    match VALUES[symbol as usize] {
        INVALID => None,
        value => Some(value),
    }
}

pub fn encoded_len(input: &[u8]) -> usize {
    input.len().div_ceil(3) * 4
}

pub fn encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(encoded_len(input));

    let mut groups = input.chunks_exact(3);
    for group in &mut groups {
        let packed = (group[0] as u32) << 16 | (group[1] as u32) << 8 | group[2] as u32;

        out.extend_from_slice(&[
            symbol((packed >> 18) as u8),
            symbol((packed >> 12) as u8),
            symbol((packed >> 6) as u8),
            symbol(packed as u8),
        ]);
    }

    let rest = groups.remainder();
    if !rest.is_empty() {
        let packed = (rest[0] as u32) << 16 | (*rest.get(1).unwrap_or(&0) as u32) << 8;

        out.extend_from_slice(&[
            symbol((packed >> 18) as u8),
            symbol((packed >> 12) as u8),
            if rest.len() > 1 { symbol((packed >> 6) as u8) } else { PAD },
            PAD,
        ]);
    }

    String::from_utf8(out).unwrap_or_default()
}

pub fn sextets(group: &[u8]) -> Result<u32, DecodeError> {
    let mut packed = 0u32;

    for symbol in group {
        match VALUES[*symbol as usize] {
            INVALID => return Err(DecodeError::InvalidSymbol(*symbol)),
            value => packed = packed << 6 | value as u32,
        }
    }

    Ok(packed)
}

pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    let input = input.as_bytes();
    if !input.len().is_multiple_of(4) {
        return Err(DecodeError::InvalidLength(input.len()));
    }

    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let (body, last) = input.split_at(input.len() - 4);

    for group in body.chunks_exact(4) {
        if group.contains(&PAD) {
            return Err(DecodeError::InvalidPadding);
        }

        let packed = sextets(group)?;
        out.extend_from_slice(&[(packed >> 16) as u8, (packed >> 8) as u8, packed as u8]);
    }

    let padding = last.iter().filter(|symbol| **symbol == PAD).count();
    if padding > 2 || last[..4 - padding].contains(&PAD) {
        return Err(DecodeError::InvalidPadding);
    }

    let mut packed = sextets(&last[..4 - padding])?;
    packed <<= 6 * padding;

    if packed & ((1 << (8 * padding)) - 1) != 0 {
        return Err(DecodeError::InvalidPadding);
    }

    out.push((packed >> 16) as u8);
    if padding < 2 {
        out.push((packed >> 8) as u8);
    }
    if padding < 1 {
        out.push(packed as u8);
    }

    Ok(out)
}
