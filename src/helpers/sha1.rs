//! SHA-1.
//!
//! This exists for one reason: the WebSocket opening handshake derives
//! `Sec-WebSocket-Accept` by hashing the client's nonce together with a fixed
//! GUID. That derivation is not a security mechanism — it only proves the peer
//! read the request and is speaking WebSocket rather than something else — so
//! SHA-1 being broken as a collision-resistant hash does not matter here.
//!
//! Do not reach for this anywhere a hash is load-bearing.

/// The size of one compression block, in octets.
pub const BLOCK_SIZE: usize = 64;
/// The size of the digest, in octets.
pub const DIGEST_SIZE: usize = 20;

/// The five words the state starts at.
pub const INITIAL_STATE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// The round constant for each of the four twenty-round stages.
pub const CONSTANTS: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

/// An in-progress SHA-1 hash.
///
/// Feed it with [`Sha1::update`] as many times as needed, then consume it with
/// [`Sha1::finish`]. For a single buffer, [`sha1`] does both in one call.
pub struct Sha1 {
    state: [u32; 5],
    block: [u8; BLOCK_SIZE],
    filled: usize,
    length: u64,
}

impl Sha1 {
    /// A hash over nothing yet.
    pub fn new() -> Self {
        Self { state: INITIAL_STATE, block: [0; BLOCK_SIZE], filled: 0, length: 0 }
    }

    /// Feeds more octets in.
    pub fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64 * 8);

        let mut input = input;
        while !input.is_empty() {
            let taken = (BLOCK_SIZE - self.filled).min(input.len());
            self.block[self.filled..self.filled + taken].copy_from_slice(&input[..taken]);
            self.filled += taken;
            input = &input[taken..];

            if self.filled == BLOCK_SIZE {
                let block = self.block;
                self.compress(&block);
                self.filled = 0;
            }
        }
    }

    /// Mixes one full block into the state.
    ///
    /// [`Sha1::update`] calls this as blocks fill; it is rarely useful on its own.
    pub fn compress(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut words = [0u32; 80];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([block[index * 4], block[index * 4 + 1], block[index * 4 + 2], block[index * 4 + 3]]);
        }
        for index in 16..80 {
            words[index] = (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (round, word) in words.iter().enumerate() {
            let (mixed, constant) = match round {
                0..=19 => ((b & c) | (!b & d), CONSTANTS[0]),
                20..=39 => (b ^ c ^ d, CONSTANTS[1]),
                40..=59 => ((b & c) | (b & d) | (c & d), CONSTANTS[2]),
                _ => (b ^ c ^ d, CONSTANTS[3]),
            };

            let next = a
                .rotate_left(5)
                .wrapping_add(mixed)
                .wrapping_add(e)
                .wrapping_add(*word)
                .wrapping_add(constant);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    /// Pads the last block and returns the digest.
    pub fn finish(mut self) -> [u8; DIGEST_SIZE] {
        let length = self.length;

        let mut padding = Vec::with_capacity(BLOCK_SIZE * 2);
        padding.push(0x80);
        while (self.filled + padding.len()) % BLOCK_SIZE != BLOCK_SIZE - 8 {
            padding.push(0x00);
        }
        padding.extend_from_slice(&length.to_be_bytes());
        self.update(&padding);

        let mut digest = [0u8; DIGEST_SIZE];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

/// The SHA-1 digest of one buffer.
pub fn sha1(input: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hash = Sha1::new();
    hash.update(input);
    hash.finish()
}
