//! The Huffman code HPACK and QPACK share.
//!
//! The code is a fixed canonical one, tuned on a corpus of real field values,
//! so no table travels with the data. HTTP/2 and HTTP/3 both use it, which is
//! why it lives here rather than in either codec.
//!
//! Encoding is a table lookup per octet, packing codes into a bit accumulator.
//! Decoding walks a table-driven automaton four bits at a time, built once by
//! [`DecodeTable::new`] and shared from [`decode_table`].
//!
//! Padding must be the high bits of the end-of-string code — a decoder must
//! reject anything else, and reject the code itself appearing in full, since
//! both would let one string be written more than one way.

use std::fmt;
use std::sync::OnceLock;

use bytes::Bytes;

/// One code word: `length` bits, right-aligned in `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symbol {
    /// The code word, right-aligned.
    pub code: u32,
    /// How many bits of `code` are meaningful; never more than 30.
    pub length: u8,
}

impl Symbol {
    /// A code word of `length` bits.
    pub const fn new(code: u32, length: u8) -> Self {
        Self { code, length }
    }
}

/// The end-of-string symbol, which never appears in a well-formed encoding.
pub const EOS: u16 = 256;

/// The code word for each octet, and for [`EOS`] at the end.
pub static TABLE: [Symbol; 257] = [
    Symbol::new(0x1ff8, 13),     // 0
    Symbol::new(0x7fffd8, 23),   // 1
    Symbol::new(0xfffffe2, 28),  // 2
    Symbol::new(0xfffffe3, 28),  // 3
    Symbol::new(0xfffffe4, 28),  // 4
    Symbol::new(0xfffffe5, 28),  // 5
    Symbol::new(0xfffffe6, 28),  // 6
    Symbol::new(0xfffffe7, 28),  // 7
    Symbol::new(0xfffffe8, 28),  // 8
    Symbol::new(0xffffea, 24),   // 9
    Symbol::new(0x3ffffffc, 30), // 10
    Symbol::new(0xfffffe9, 28),  // 11
    Symbol::new(0xfffffea, 28),  // 12
    Symbol::new(0x3ffffffd, 30), // 13
    Symbol::new(0xfffffeb, 28),  // 14
    Symbol::new(0xfffffec, 28),  // 15
    Symbol::new(0xfffffed, 28),  // 16
    Symbol::new(0xfffffee, 28),  // 17
    Symbol::new(0xfffffef, 28),  // 18
    Symbol::new(0xffffff0, 28),  // 19
    Symbol::new(0xffffff1, 28),  // 20
    Symbol::new(0xffffff2, 28),  // 21
    Symbol::new(0x3ffffffe, 30), // 22
    Symbol::new(0xffffff3, 28),  // 23
    Symbol::new(0xffffff4, 28),  // 24
    Symbol::new(0xffffff5, 28),  // 25
    Symbol::new(0xffffff6, 28),  // 26
    Symbol::new(0xffffff7, 28),  // 27
    Symbol::new(0xffffff8, 28),  // 28
    Symbol::new(0xffffff9, 28),  // 29
    Symbol::new(0xffffffa, 28),  // 30
    Symbol::new(0xffffffb, 28),  // 31
    Symbol::new(0x14, 6),        // 32 ' '
    Symbol::new(0x3f8, 10),      // 33 '!'
    Symbol::new(0x3f9, 10),      // 34 '"'
    Symbol::new(0xffa, 12),      // 35 '#'
    Symbol::new(0x1ff9, 13),     // 36 '$'
    Symbol::new(0x15, 6),        // 37 '%'
    Symbol::new(0xf8, 8),        // 38 '&'
    Symbol::new(0x7fa, 11),      // 39 '\''
    Symbol::new(0x3fa, 10),      // 40 '('
    Symbol::new(0x3fb, 10),      // 41 ')'
    Symbol::new(0xf9, 8),        // 42 '*'
    Symbol::new(0x7fb, 11),      // 43 '+'
    Symbol::new(0xfa, 8),        // 44 ','
    Symbol::new(0x16, 6),        // 45 '-'
    Symbol::new(0x17, 6),        // 46 '.'
    Symbol::new(0x18, 6),        // 47 '/'
    Symbol::new(0x0, 5),         // 48 '0'
    Symbol::new(0x1, 5),         // 49 '1'
    Symbol::new(0x2, 5),         // 50 '2'
    Symbol::new(0x19, 6),        // 51 '3'
    Symbol::new(0x1a, 6),        // 52 '4'
    Symbol::new(0x1b, 6),        // 53 '5'
    Symbol::new(0x1c, 6),        // 54 '6'
    Symbol::new(0x1d, 6),        // 55 '7'
    Symbol::new(0x1e, 6),        // 56 '8'
    Symbol::new(0x1f, 6),        // 57 '9'
    Symbol::new(0x5c, 7),        // 58 ':'
    Symbol::new(0xfb, 8),        // 59 ';'
    Symbol::new(0x7ffc, 15),     // 60 '<'
    Symbol::new(0x20, 6),        // 61 '='
    Symbol::new(0xffb, 12),      // 62 '>'
    Symbol::new(0x3fc, 10),      // 63 '?'
    Symbol::new(0x1ffa, 13),     // 64 '@'
    Symbol::new(0x21, 6),        // 65 'A'
    Symbol::new(0x5d, 7),        // 66 'B'
    Symbol::new(0x5e, 7),        // 67 'C'
    Symbol::new(0x5f, 7),        // 68 'D'
    Symbol::new(0x60, 7),        // 69 'E'
    Symbol::new(0x61, 7),        // 70 'F'
    Symbol::new(0x62, 7),        // 71 'G'
    Symbol::new(0x63, 7),        // 72 'H'
    Symbol::new(0x64, 7),        // 73 'I'
    Symbol::new(0x65, 7),        // 74 'J'
    Symbol::new(0x66, 7),        // 75 'K'
    Symbol::new(0x67, 7),        // 76 'L'
    Symbol::new(0x68, 7),        // 77 'M'
    Symbol::new(0x69, 7),        // 78 'N'
    Symbol::new(0x6a, 7),        // 79 'O'
    Symbol::new(0x6b, 7),        // 80 'P'
    Symbol::new(0x6c, 7),        // 81 'Q'
    Symbol::new(0x6d, 7),        // 82 'R'
    Symbol::new(0x6e, 7),        // 83 'S'
    Symbol::new(0x6f, 7),        // 84 'T'
    Symbol::new(0x70, 7),        // 85 'U'
    Symbol::new(0x71, 7),        // 86 'V'
    Symbol::new(0x72, 7),        // 87 'W'
    Symbol::new(0xfc, 8),        // 88 'X'
    Symbol::new(0x73, 7),        // 89 'Y'
    Symbol::new(0xfd, 8),        // 90 'Z'
    Symbol::new(0x1ffb, 13),     // 91 '['
    Symbol::new(0x7fff0, 19),    // 92 '\\'
    Symbol::new(0x1ffc, 13),     // 93 ']'
    Symbol::new(0x3ffc, 14),     // 94 '^'
    Symbol::new(0x22, 6),        // 95 '_'
    Symbol::new(0x7ffd, 15),     // 96 '`'
    Symbol::new(0x3, 5),         // 97 'a'
    Symbol::new(0x23, 6),        // 98 'b'
    Symbol::new(0x4, 5),         // 99 'c'
    Symbol::new(0x24, 6),        // 100 'd'
    Symbol::new(0x5, 5),         // 101 'e'
    Symbol::new(0x25, 6),        // 102 'f'
    Symbol::new(0x26, 6),        // 103 'g'
    Symbol::new(0x27, 6),        // 104 'h'
    Symbol::new(0x6, 5),         // 105 'i'
    Symbol::new(0x74, 7),        // 106 'j'
    Symbol::new(0x75, 7),        // 107 'k'
    Symbol::new(0x28, 6),        // 108 'l'
    Symbol::new(0x29, 6),        // 109 'm'
    Symbol::new(0x2a, 6),        // 110 'n'
    Symbol::new(0x7, 5),         // 111 'o'
    Symbol::new(0x2b, 6),        // 112 'p'
    Symbol::new(0x76, 7),        // 113 'q'
    Symbol::new(0x2c, 6),        // 114 'r'
    Symbol::new(0x8, 5),         // 115 's'
    Symbol::new(0x9, 5),         // 116 't'
    Symbol::new(0x2d, 6),        // 117 'u'
    Symbol::new(0x77, 7),        // 118 'v'
    Symbol::new(0x78, 7),        // 119 'w'
    Symbol::new(0x79, 7),        // 120 'x'
    Symbol::new(0x7a, 7),        // 121 'y'
    Symbol::new(0x7b, 7),        // 122 'z'
    Symbol::new(0x7ffe, 15),     // 123 '{'
    Symbol::new(0x7fc, 11),      // 124 '|'
    Symbol::new(0x3ffd, 14),     // 125 '}'
    Symbol::new(0x1ffd, 13),     // 126 '~'
    Symbol::new(0xffffffc, 28),  // 127
    Symbol::new(0xfffe6, 20),    // 128
    Symbol::new(0x3fffd2, 22),   // 129
    Symbol::new(0xfffe7, 20),    // 130
    Symbol::new(0xfffe8, 20),    // 131
    Symbol::new(0x3fffd3, 22),   // 132
    Symbol::new(0x3fffd4, 22),   // 133
    Symbol::new(0x3fffd5, 22),   // 134
    Symbol::new(0x7fffd9, 23),   // 135
    Symbol::new(0x3fffd6, 22),   // 136
    Symbol::new(0x7fffda, 23),   // 137
    Symbol::new(0x7fffdb, 23),   // 138
    Symbol::new(0x7fffdc, 23),   // 139
    Symbol::new(0x7fffdd, 23),   // 140
    Symbol::new(0x7fffde, 23),   // 141
    Symbol::new(0xffffeb, 24),   // 142
    Symbol::new(0x7fffdf, 23),   // 143
    Symbol::new(0xffffec, 24),   // 144
    Symbol::new(0xffffed, 24),   // 145
    Symbol::new(0x3fffd7, 22),   // 146
    Symbol::new(0x7fffe0, 23),   // 147
    Symbol::new(0xffffee, 24),   // 148
    Symbol::new(0x7fffe1, 23),   // 149
    Symbol::new(0x7fffe2, 23),   // 150
    Symbol::new(0x7fffe3, 23),   // 151
    Symbol::new(0x7fffe4, 23),   // 152
    Symbol::new(0x1fffdc, 21),   // 153
    Symbol::new(0x3fffd8, 22),   // 154
    Symbol::new(0x7fffe5, 23),   // 155
    Symbol::new(0x3fffd9, 22),   // 156
    Symbol::new(0x7fffe6, 23),   // 157
    Symbol::new(0x7fffe7, 23),   // 158
    Symbol::new(0xffffef, 24),   // 159
    Symbol::new(0x3fffda, 22),   // 160
    Symbol::new(0x1fffdd, 21),   // 161
    Symbol::new(0xfffe9, 20),    // 162
    Symbol::new(0x3fffdb, 22),   // 163
    Symbol::new(0x3fffdc, 22),   // 164
    Symbol::new(0x7fffe8, 23),   // 165
    Symbol::new(0x7fffe9, 23),   // 166
    Symbol::new(0x1fffde, 21),   // 167
    Symbol::new(0x7fffea, 23),   // 168
    Symbol::new(0x3fffdd, 22),   // 169
    Symbol::new(0x3fffde, 22),   // 170
    Symbol::new(0xfffff0, 24),   // 171
    Symbol::new(0x1fffdf, 21),   // 172
    Symbol::new(0x3fffdf, 22),   // 173
    Symbol::new(0x7fffeb, 23),   // 174
    Symbol::new(0x7fffec, 23),   // 175
    Symbol::new(0x1fffe0, 21),   // 176
    Symbol::new(0x1fffe1, 21),   // 177
    Symbol::new(0x3fffe0, 22),   // 178
    Symbol::new(0x1fffe2, 21),   // 179
    Symbol::new(0x7fffed, 23),   // 180
    Symbol::new(0x3fffe1, 22),   // 181
    Symbol::new(0x7fffee, 23),   // 182
    Symbol::new(0x7fffef, 23),   // 183
    Symbol::new(0xfffea, 20),    // 184
    Symbol::new(0x3fffe2, 22),   // 185
    Symbol::new(0x3fffe3, 22),   // 186
    Symbol::new(0x3fffe4, 22),   // 187
    Symbol::new(0x7ffff0, 23),   // 188
    Symbol::new(0x3fffe5, 22),   // 189
    Symbol::new(0x3fffe6, 22),   // 190
    Symbol::new(0x7ffff1, 23),   // 191
    Symbol::new(0x3ffffe0, 26),  // 192
    Symbol::new(0x3ffffe1, 26),  // 193
    Symbol::new(0xfffeb, 20),    // 194
    Symbol::new(0x7fff1, 19),    // 195
    Symbol::new(0x3fffe7, 22),   // 196
    Symbol::new(0x7ffff2, 23),   // 197
    Symbol::new(0x3fffe8, 22),   // 198
    Symbol::new(0x1ffffec, 25),  // 199
    Symbol::new(0x3ffffe2, 26),  // 200
    Symbol::new(0x3ffffe3, 26),  // 201
    Symbol::new(0x3ffffe4, 26),  // 202
    Symbol::new(0x7ffffde, 27),  // 203
    Symbol::new(0x7ffffdf, 27),  // 204
    Symbol::new(0x3ffffe5, 26),  // 205
    Symbol::new(0xfffff1, 24),   // 206
    Symbol::new(0x1ffffed, 25),  // 207
    Symbol::new(0x7fff2, 19),    // 208
    Symbol::new(0x1fffe3, 21),   // 209
    Symbol::new(0x3ffffe6, 26),  // 210
    Symbol::new(0x7ffffe0, 27),  // 211
    Symbol::new(0x7ffffe1, 27),  // 212
    Symbol::new(0x3ffffe7, 26),  // 213
    Symbol::new(0x7ffffe2, 27),  // 214
    Symbol::new(0xfffff2, 24),   // 215
    Symbol::new(0x1fffe4, 21),   // 216
    Symbol::new(0x1fffe5, 21),   // 217
    Symbol::new(0x3ffffe8, 26),  // 218
    Symbol::new(0x3ffffe9, 26),  // 219
    Symbol::new(0xffffffd, 28),  // 220
    Symbol::new(0x7ffffe3, 27),  // 221
    Symbol::new(0x7ffffe4, 27),  // 222
    Symbol::new(0x7ffffe5, 27),  // 223
    Symbol::new(0xfffec, 20),    // 224
    Symbol::new(0xfffff3, 24),   // 225
    Symbol::new(0xfffed, 20),    // 226
    Symbol::new(0x1fffe6, 21),   // 227
    Symbol::new(0x3fffe9, 22),   // 228
    Symbol::new(0x1fffe7, 21),   // 229
    Symbol::new(0x1fffe8, 21),   // 230
    Symbol::new(0x7ffff3, 23),   // 231
    Symbol::new(0x3fffea, 22),   // 232
    Symbol::new(0x3fffeb, 22),   // 233
    Symbol::new(0x1ffffee, 25),  // 234
    Symbol::new(0x1ffffef, 25),  // 235
    Symbol::new(0xfffff4, 24),   // 236
    Symbol::new(0xfffff5, 24),   // 237
    Symbol::new(0x3ffffea, 26),  // 238
    Symbol::new(0x7ffff4, 23),   // 239
    Symbol::new(0x3ffffeb, 26),  // 240
    Symbol::new(0x7ffffe6, 27),  // 241
    Symbol::new(0x3ffffec, 26),  // 242
    Symbol::new(0x3ffffed, 26),  // 243
    Symbol::new(0x7ffffe7, 27),  // 244
    Symbol::new(0x7ffffe8, 27),  // 245
    Symbol::new(0x7ffffe9, 27),  // 246
    Symbol::new(0x7ffffea, 27),  // 247
    Symbol::new(0x7ffffeb, 27),  // 248
    Symbol::new(0xffffffe, 28),  // 249
    Symbol::new(0x7ffffec, 27),  // 250
    Symbol::new(0x7ffffed, 27),  // 251
    Symbol::new(0x7ffffee, 27),  // 252
    Symbol::new(0x7ffffef, 27),  // 253
    Symbol::new(0x7fffff0, 27),  // 254
    Symbol::new(0x3ffffee, 26),  // 255
    Symbol::new(0x3fffffff, 30), // 256 EOS
];

/// The code table.
pub fn table() -> &'static [Symbol; 257] {
    &TABLE
}

/// The code length for each symbol, split out so [`encoded_len`] can size a
/// buffer without touching the code words.
pub static LENGTHS: [u8; 257] = {
    let mut lengths = [0u8; 257];
    let mut value = 0;

    while value < 257 {
        lengths[value] = TABLE[value].length;
        value += 1;
    }

    lengths
};

/// The code in its canonical form, which is what the decoder walks.
///
/// The code words are canonical: sorted by length, and within one length by
/// value. That lets a code word be recognised by the numeric value of the bits
/// alone rather than by following them one at a time — [`Canonical::fast`]
/// answers every short code word in one lookup, and the rest are found by
/// asking which length's range the bits fall in.
///
/// [`DecodeTable`] holds the same code as an automaton, which is how the
/// format is usually described and what [`decode_table`] exposes. The two
/// accept exactly the same encodings; this is the one [`decode_into_ascii`]
/// runs on.
pub struct Canonical {
    /// One entry per [`Canonical::FAST_BITS`]-bit prefix: the symbol in the
    /// high octet and the length of its code word in the low one, or zero when
    /// no code word that short begins with those bits.
    pub fast: [u16; Canonical::FAST_SIZE],
    /// The largest window each length covers, the code word left-aligned in a
    /// word. A length carrying no code word repeats the length below it, so it
    /// never matches.
    pub limit: [u64; Canonical::MAX_BITS + 1],
    /// The first code word of each length.
    pub base: [u32; Canonical::MAX_BITS + 1],
    /// Where the symbols of each length begin in [`Canonical::symbols`].
    pub offset: [u16; Canonical::MAX_BITS + 1],
    /// Every symbol, ordered by the length of its code word and then by its
    /// value, which is the order a canonical code numbers them in.
    pub symbols: [u16; 257],
    /// One entry per [`Canonical::PAIR_BITS`]-bit prefix, answering as many
    /// whole code words as those bits spell: how many bits they took in the
    /// low octet, how many symbols they were in the next, and the symbols
    /// themselves in the two above that. A zero entry means the code word at
    /// the front is longer than the prefix.
    pub pairs: [u32; Canonical::PAIR_SIZE],
}

impl Canonical {
    /// How many bits [`Canonical::fast`] is indexed by.
    ///
    /// Every code word of eight bits or fewer covers the alphanumerics and the
    /// punctuation a field value is mostly made of, so one lookup answers
    /// nearly every symbol and the table stays small enough to stay resident.
    pub const FAST_BITS: usize = 8;
    /// How many entries [`Canonical::fast`] holds.
    pub const FAST_SIZE: usize = 1 << Self::FAST_BITS;
    /// The longest code word there is, and so how many bits a window has to
    /// hold before one can be read out of it.
    pub const MAX_BITS: usize = 30;
    /// How many bits [`Canonical::pairs`] is indexed by.
    ///
    /// Wide enough for two of the short code words at once — the shortest is
    /// five bits — which is what halves the number of dependent lookups a
    /// string costs. Wider would answer more pairs and fewer singles, at a
    /// table that no longer stays in the first level of cache.
    pub const PAIR_BITS: usize = 12;
    /// How many entries [`Canonical::pairs`] holds.
    pub const PAIR_SIZE: usize = 1 << Self::PAIR_BITS;
    /// The most symbols one [`Canonical::pairs`] entry can answer.
    pub const PAIR_MOST: usize = Self::PAIR_BITS / 5;

    /// Builds the canonical form from a code table.
    pub const fn new(table: &[Symbol; 257]) -> Self {
        let mut count = [0u16; Self::MAX_BITS + 1];
        let mut value = 0;

        while value < 257 {
            count[table[value].length as usize] += 1;
            value += 1;
        }

        let mut base = [0u32; Self::MAX_BITS + 1];
        let mut offset = [0u16; Self::MAX_BITS + 1];
        let mut limit = [0u64; Self::MAX_BITS + 1];

        let mut code = 0u32;
        let mut index = 0u16;
        let mut length = 1;

        while length <= Self::MAX_BITS {
            code <<= 1;
            base[length] = code;
            offset[length] = index;
            limit[length] = match count[length] {
                0 => limit[length - 1],
                held => (((code + held as u32 - 1) as u64) << (64 - length)) | (u64::MAX >> length),
            };

            code += count[length] as u32;
            index += count[length];
            length += 1;
        }

        let mut symbols = [0u16; 257];
        let mut filled = [0u16; Self::MAX_BITS + 1];
        let mut value = 0;

        while value < 257 {
            let length = table[value].length as usize;
            symbols[(offset[length] + filled[length]) as usize] = value as u16;
            filled[length] += 1;
            value += 1;
        }

        let mut fast = [0u16; Self::FAST_SIZE];
        let mut value = 0;

        while value < 257 {
            let length = table[value].length as usize;

            if length <= Self::FAST_BITS {
                let first = (table[value].code as usize) << (Self::FAST_BITS - length);
                let spread = 1 << (Self::FAST_BITS - length);
                let mut slot = 0;

                while slot < spread {
                    fast[first + slot] = ((value as u16) << 8) | length as u16;
                    slot += 1;
                }
            }

            value += 1;
        }

        let mut pairs = [0u32; Self::PAIR_SIZE];
        let mut index = 0;

        while index < Self::PAIR_SIZE {
            let mut window = (index as u64) << (64 - Self::PAIR_BITS);
            let mut used = 0usize;
            let mut count = 0u32;
            let mut held = [0u32; 2];

            while (count as usize) < Self::PAIR_MOST {
                let entry = fast[(window >> (64 - Self::FAST_BITS)) as usize];

                let mut length = match entry & 0xff {
                    0 => Self::FAST_BITS + 1,
                    short => short as usize,
                };

                while length < Self::MAX_BITS && window > limit[length] {
                    length += 1;
                }

                // Only the leading `PAIR_BITS` of the window are the index's
                // own, so a code word running past them is one this entry
                // cannot answer.
                if used + length > Self::PAIR_BITS {
                    break;
                }

                let code = (window >> (64 - length)) as u32;
                held[count as usize] = symbols[offset[length] as usize + (code - base[length]) as usize] as u32;

                count += 1;
                used += length;
                window <<= length;
            }

            if count > 0 {
                pairs[index] = used as u32 | count << 8 | held[0] << 16 | held[1] << 24;
            }

            index += 1;
        }

        Self { fast, limit, base, offset, symbols, pairs }
    }

    /// The symbol the top bits of `window` spell, and how many bits it took,
    /// for a code word longer than [`Canonical::FAST_BITS`].
    ///
    /// The code is complete, so some length always matches and this always
    /// answers.
    #[inline]
    pub fn long(&self, window: u64) -> (u16, u32) {
        let mut length = Self::FAST_BITS + 1;

        while length < Self::MAX_BITS && window > self.limit[length] {
            length += 1;
        }

        let code = (window >> (64 - length)) as u32;
        let index = self.offset[length] as usize + (code - self.base[length]) as usize;

        (self.symbols[index], length as u32)
    }

    /// The symbol the top bits of `window` spell, and how many bits it took.
    ///
    /// `window` holds the bits left-aligned and must carry
    /// [`Canonical::MAX_BITS`] of them; a caller holding fewer pads with
    /// one-bits, which is what valid padding is, and then refuses a code word
    /// longer than what it really had.
    #[inline]
    pub fn symbol(&self, window: u64) -> (u16, u32) {
        let entry = self.fast[(window >> (64 - Self::FAST_BITS)) as usize];

        match entry & 0xff {
            0 => self.long(window),
            length => (entry >> 8, length as u32),
        }
    }
}

/// The canonical form of the code, built once at compile time.
pub static CANONICAL: Canonical = Canonical::new(&TABLE);

/// The octets of an encoding, read as the bits a code word is spelled in.
///
/// Code words do not fall on octet boundaries, so the octets are read into a
/// window holding the next bits left-aligned. Filling takes whole octets, so
/// the window may carry bits past what [`Bits::held`] counts; those are always
/// below the bits that count, and [`Bits::fill`] clears them before it reads
/// more in.
pub struct Bits<'a> {
    /// The octets not yet read into the window.
    pub input: &'a [u8],
    /// The next bits, left-aligned.
    pub window: u64,
    /// How many bits of [`Bits::window`] are meaningful.
    pub held: u32,
}

impl<'a> Bits<'a> {
    /// How many bits the window holds.
    pub const WIDTH: u32 = u64::BITS;

    /// A window over `input`, with nothing read in yet.
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, window: 0, held: 0 }
    }

    /// The mask of the bits that count, which is the top [`Bits::held`] of them.
    #[inline]
    pub fn mask(&self) -> u64 {
        !u64::MAX.checked_shr(self.held).unwrap_or(0)
    }

    /// Reads octets in until the window cannot hold another whole one.
    #[inline]
    pub fn fill(&mut self) {
        self.window &= self.mask();

        if self.input.len() >= size_of::<u64>() && self.held <= Self::WIDTH - 8 {
            let octets: [u8; 8] = self.input[..8].try_into().expect("eight octets are eight octets");
            let taken = ((Self::WIDTH - self.held) / 8) as usize;

            self.window |= u64::from_be_bytes(octets) >> self.held;
            self.held += (taken * 8) as u32;
            self.input = &self.input[taken..];

            return;
        }

        while self.held <= Self::WIDTH - 8 {
            let Some((octet, rest)) = self.input.split_first() else { return };

            self.window |= (*octet as u64) << (Self::WIDTH - 8 - self.held);
            self.held += 8;
            self.input = rest;
        }
    }

    /// Drops the `length` bits at the front.
    ///
    /// # Panics
    ///
    /// Debug builds assert that the window held them.
    #[inline]
    pub fn take(&mut self, length: u32) {
        debug_assert!(length <= self.held, "the window holds fewer bits than were taken");

        self.window <<= length;
        self.held -= length;
    }

    /// The window with everything past what it holds set to one, which is what
    /// valid padding is.
    #[inline]
    pub fn padded(&self) -> u64 {
        self.window | u64::MAX.checked_shr(self.held).unwrap_or(0)
    }

    /// Whether what is left is valid padding: fewer than eight bits, all ones.
    #[inline]
    pub fn is_padding(&self) -> bool {
        let mask = self.mask();
        self.held < 8 && self.window & mask == mask
    }
}

/// What following one bit out of a node reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// Another node, by index into [`DecodeTable::branches`].
    Node(usize),
    /// A complete symbol.
    Symbol(u16),
}

/// How many transitions one automaton row holds: one per four-bit input.
pub const NIBBLE: usize = 16;

/// [`Transition`]: a symbol was completed and should be emitted.
pub const EMIT: u8 = 1 << 0;
/// [`Transition`]: the bits do not spell a code word, so decoding fails.
pub const FAIL: u8 = 1 << 1;
/// [`Transition`]: the end-of-string code was met, which is not allowed on the wire.
pub const ENDED: u8 = 1 << 2;

/// One step of the decoding automaton, for one state and one four-bit input.
///
/// At most one symbol can be completed per nibble, because no code word is
/// shorter than five bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// The state to move to.
    pub next: u16,
    /// The symbol completed, meaningful only when [`EMIT`] is set.
    pub symbol: u8,
    /// The or of [`EMIT`], [`FAIL`] and [`ENDED`].
    pub flags: u8,
}

impl Transition {
    /// The transition for an input that cannot continue any code word.
    pub const STUCK: Self = Self { next: 0, symbol: 0, flags: FAIL };
}

/// The decoding automaton, built once and shared.
///
/// The bit-level tree in `branches` is what the code table spells out
/// directly; `rows` is that tree flattened into a table indexed by state and
/// nibble, which is what the decoder actually walks.
pub struct DecodeTable {
    /// The binary tree of the code, indexed by node, then by bit.
    pub branches: Vec<[Option<Branch>; 2]>,
    /// One row of [`NIBBLE`] transitions per state.
    pub rows: Vec<[Transition; NIBBLE]>,
    /// Whether each state may end an encoding.
    ///
    /// A state is accepting when it sits on the all-ones path from the root,
    /// which is what valid padding leaves behind.
    pub accepting: Vec<bool>,
}

impl DecodeTable {
    /// Builds the automaton from a code table.
    pub fn new(table: &[Symbol; 257]) -> Self {
        let mut branches = vec![[None, None]];

        for (value, symbol) in table.iter().enumerate() {
            let mut node = 0;
            for depth in (0..symbol.length).rev() {
                let bit = (symbol.code >> depth & 1) as usize;
                if depth == 0 {
                    branches[node][bit] = Some(Branch::Symbol(value as u16));
                } else {
                    node = match branches[node][bit] {
                        Some(Branch::Node(next)) => next,
                        _ => {
                            branches.push([None, None]);
                            let next = branches.len() - 1;
                            branches[node][bit] = Some(Branch::Node(next));
                            next
                        }
                    };
                }
            }
        }

        let (rows, accepting) = Self::compile(&branches);
        Self { branches, rows, accepting }
    }

    /// Flattens the bit tree into nibble-wide rows, and works out which states
    /// may end an encoding.
    ///
    /// Only states reachable from the root are given rows, so the table stays
    /// far smaller than the tree it came from.
    pub fn compile(branches: &[[Option<Branch>; 2]]) -> (Vec<[Transition; NIBBLE]>, Vec<bool>) {
        let mut state_of = vec![u16::MAX; branches.len()];
        let mut nodes = vec![0usize];
        state_of[0] = 0;

        let mut rows: Vec<[Transition; NIBBLE]> = Vec::new();
        let mut state = 0;

        while state < nodes.len() {
            let mut row = [Transition::STUCK; NIBBLE];

            for (nibble, slot) in row.iter_mut().enumerate() {
                let mut node = nodes[state];
                let mut symbol = 0u8;
                let mut flags = 0u8;

                for shift in (0..4).rev() {
                    match branches[node][nibble >> shift & 1] {
                        Some(Branch::Node(next)) => node = next,
                        Some(Branch::Symbol(EOS)) => {
                            flags |= ENDED;
                            break;
                        }
                        Some(Branch::Symbol(value)) => {
                            symbol = value as u8;
                            flags |= EMIT;
                            node = 0;
                        }
                        None => {
                            flags |= FAIL;
                            break;
                        }
                    }
                }

                if flags & (FAIL | ENDED) != 0 {
                    *slot = Transition { next: 0, symbol, flags };
                    continue;
                }

                if state_of[node] == u16::MAX {
                    state_of[node] = nodes.len() as u16;
                    nodes.push(node);
                }

                *slot = Transition { next: state_of[node], symbol, flags };
            }

            rows.push(row);
            state += 1;
        }

        let mut on_ones = vec![false; branches.len()];
        let mut node = 0usize;
        on_ones[0] = true;

        for _ in 0..7 {
            match branches[node][1] {
                Some(Branch::Node(next)) => {
                    node = next;
                    on_ones[node] = true;
                }
                _ => break,
            }
        }

        let accepting = nodes.iter().map(|node| on_ones[*node]).collect();
        (rows, accepting)
    }

    /// Follows one bit out of `node` in the bit tree.
    ///
    /// The decoder itself walks `rows` a nibble at a time; this is for
    /// inspecting the code directly.
    pub fn step(&self, node: usize, bit: bool) -> Option<Branch> {
        self.branches.get(node).and_then(|pair| pair[bit as usize])
    }
}

/// The shared decoding automaton, built on first use.
pub fn decode_table() -> &'static DecodeTable {
    static DECODE_TABLE: OnceLock<DecodeTable> = OnceLock::new();
    DECODE_TABLE.get_or_init(|| DecodeTable::new(table()))
}

/// Why a Huffman string would not decode.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The encoding does not end on the all-ones padding, or it spells out the
    /// end-of-string code in full.
    InvalidPadding,
    /// The bits do not spell a code word.
    UnknownSymbol,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPadding => write!(f, "huffman padding is not all one-bits"),
            Self::UnknownSymbol => write!(f, "huffman code does not map to a known symbol"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encodes octets, padding to a whole octet with one-bits.
pub fn encode(input: &[u8]) -> Bytes {
    let encoded = encoded_len(input);

    let mut out = Vec::with_capacity(encoded);
    encode_sized(input, encoded, &mut out);

    Bytes::from(out)
}

/// [`encode`], appending to a buffer the caller owns.
pub fn encode_into(input: &[u8], out: &mut Vec<u8>) {
    encode_sized(input, encoded_len(input), out)
}

/// [`encode_into`] for a caller that has already computed [`encoded_len`].
///
/// The length is only used to reserve; a wrong one costs a reallocation but
/// does not change the output.
pub fn encode_sized(input: &[u8], encoded: usize, out: &mut Vec<u8>) {
    let table = table();
    out.reserve(encoded);

    let mut pending: u64 = 0;
    let mut bits: u32 = 0;

    for byte in input {
        let symbol = table[*byte as usize];
        pending = pending << symbol.length | symbol.code as u64;
        bits += symbol.length as u32;

        if bits >= 32 {
            bits -= 32;
            out.extend_from_slice(&((pending >> bits) as u32).to_be_bytes());
        }
    }

    while bits >= 8 {
        bits -= 8;
        out.push((pending >> bits) as u8);
    }

    if bits > 0 {
        let padding = 8 - bits;
        out.push(((pending << padding) | ((1 << padding) - 1)) as u8);
    }
}

/// Decodes a Huffman string.
///
/// # Errors
///
/// Returns [`DecodeError::UnknownSymbol`] when the bits do not spell a code
/// word, and [`DecodeError::InvalidPadding`] when the encoding does not end on
/// the all-ones padding or spells out the end-of-string code.
pub fn decode(input: &[u8]) -> Result<Bytes, DecodeError> {
    let mut out = Vec::new();
    decode_into(input, &mut out)?;
    Ok(Bytes::from(out))
}

/// [`decode`], appending to a buffer the caller owns.
///
/// # Errors
///
/// As [`decode`]. The buffer may hold a partial result when this fails.
pub fn decode_into(input: &[u8], out: &mut Vec<u8>) -> Result<(), DecodeError> {
    decode_into_ascii(input, out).map(|_| ())
}

/// [`decode_into`], also reporting whether the result is ASCII.
///
/// Returns `true` when no decoded octet has its high bit set. Field values are
/// almost always ASCII, and knowing so lets the caller build a [`Text`]
/// without a second pass over the octets.
///
/// # Errors
///
/// As [`decode`]. The buffer may hold a partial result when this fails.
///
/// [`Text`]: crate::helpers::text::Text
pub fn decode_into_ascii(input: &[u8], out: &mut Vec<u8>) -> Result<bool, DecodeError> {
    let codes = &CANONICAL;
    let mut bits = Bits::new(input);

    // No code word is shorter than five bits, so this is what the input could
    // decode to at most, and every write below lands inside it.
    out.reserve(input.len() * 8 / 5 + Canonical::PAIR_MOST);

    let start = out.len();
    let capacity = out.capacity();
    let room = out.as_mut_ptr();
    let mut written = 0usize;
    let mut seen = 0u8;

    loop {
        bits.fill();

        while bits.held >= Canonical::MAX_BITS as u32 {
            let entry = codes.pairs[(bits.window >> (64 - Canonical::PAIR_BITS)) as usize];
            let length = entry as u8 as u32;

            if length == 0 {
                let (symbol, length) = codes.long(bits.window);

                if symbol == EOS {
                    // SAFETY: `written` octets were written into the room
                    // reserved above, so the partial result is initialised.
                    unsafe { out.set_len(start + written) };
                    return Err(DecodeError::InvalidPadding);
                }

                // SAFETY: as above, and `written` is below what was reserved.
                debug_assert!(start + written < capacity, "a decoded symbol would land past the room reserved for it");
                unsafe { room.add(start + written).write(symbol as u8) };
                written += 1;
                seen |= symbol as u8;
                bits.take(length);
                continue;
            }

            // Both symbols are written whether the entry answered one or two,
            // so that the count only moves the cursor and never a branch. The
            // room reserved above allows for the octet a single write leaves
            // behind.
            //
            // SAFETY: as above.
            debug_assert!(start + written + Canonical::PAIR_MOST <= capacity, "a decoded pair would land past the room reserved for it");
            unsafe { room.add(start + written).cast::<[u8; 2]>().write_unaligned(((entry >> 16) as u16).to_le_bytes()) };
            written += (entry >> 8) as u8 as usize;
            seen |= (entry >> 16) as u8 | (entry >> 24) as u8;
            bits.take(length);
        }

        if bits.input.is_empty() {
            break;
        }
    }

    // What is left is shorter than a code word can be read out of on its own,
    // so it is read against the padding and a code word is only taken when the
    // input really carried the whole of it. Padding is asked about first: no
    // code word is all one-bits over seven bits or fewer, so a window that is
    // already valid padding carries nothing more to read and is the ordinary
    // way out.
    while !bits.is_padding() {
        let (symbol, length) = codes.symbol(bits.padded());

        if length > bits.held {
            break;
        }

        if symbol == EOS {
            // SAFETY: as above.
            unsafe { out.set_len(start + written) };
            return Err(DecodeError::InvalidPadding);
        }

        // SAFETY: as above.
        debug_assert!(start + written < capacity, "a decoded symbol would land past the room reserved for it");
        unsafe { room.add(start + written).write(symbol as u8) };
        written += 1;
        seen |= symbol as u8;
        bits.take(length);
    }

    // SAFETY: as above.
    unsafe { out.set_len(start + written) };

    match bits.is_padding() {
        true => Ok(seen & 0x80 == 0),
        false => Err(DecodeError::InvalidPadding),
    }
}

/// How many octets [`encode`] will produce for this input, padding included.
///
/// The codecs call this before encoding to decide whether Huffman coding is
/// worth it at all: when it is no shorter than the input, the string is sent
/// as it stands.
pub fn encoded_len(input: &[u8]) -> usize {
    let bits: usize = input.iter().map(|byte| LENGTHS[*byte as usize] as usize).sum();
    bits.div_ceil(8)
}
