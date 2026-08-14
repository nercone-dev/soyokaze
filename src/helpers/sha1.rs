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

/// How many rounds one stage runs for.
pub const STAGE_ROUNDS: usize = 20;

/// How many rounds one block is compressed over.
pub const ROUNDS: usize = STAGE_ROUNDS * CONSTANTS.len();

/// How many words of the message schedule are kept at once.
///
/// The schedule is eighty words long, but each one is built from four of the
/// sixteen before it, so sixteen is all that has to be held: a word is written
/// over the one it will never be read beside again. The whole schedule would
/// be five times the size and would go out to memory and come back.
pub const SCHEDULE: usize = 16;

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
    ///
    /// Whole blocks are compressed where they lie: only a partial block at
    /// either end is ever copied into the one held here, so a long input is
    /// not written out a second time on its way through.
    pub fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64 * 8);

        let mut input = input;

        if self.filled > 0 {
            let taken = (BLOCK_SIZE - self.filled).min(input.len());
            self.block[self.filled..self.filled + taken].copy_from_slice(&input[..taken]);
            self.filled += taken;
            input = &input[taken..];

            if self.filled < BLOCK_SIZE {
                return;
            }

            let block = self.block;
            self.compress(&block);
            self.filled = 0;
        }

        let mut blocks = input.chunks_exact(BLOCK_SIZE);
        for block in &mut blocks {
            self.compress(block.try_into().expect("a block is a block"));
        }

        let rest = blocks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.filled = rest.len();
    }

    /// The message schedule word for `round`, extending the window in place
    /// once the block's own sixteen words have been used.
    #[inline]
    pub fn extend(words: &mut [u32; SCHEDULE], round: usize) -> u32 {
        if round < SCHEDULE {
            return words[round];
        }

        // The recurrence reaches three, eight, fourteen and sixteen words back,
        // which around a window of sixteen are these four slots.
        let slot = round % SCHEDULE;
        let extended = (words[(round + 13) % SCHEDULE] ^ words[(round + 8) % SCHEDULE] ^ words[(round + 2) % SCHEDULE] ^ words[slot]).rotate_left(1);

        words[slot] = extended;
        extended
    }

    /// The mix of three state words a stage calls for.
    #[inline]
    pub fn mixed(stage: usize, b: u32, c: u32, d: u32) -> u32 {
        match stage {
            0 => d ^ (b & (c ^ d)),
            2 => (b & c) | (d & (b | c)),
            _ => b ^ c ^ d,
        }
    }

    /// One round, given the word and constant it mixes in.
    #[inline]
    pub fn round(state: [u32; 5], stage: usize, word: u32) -> [u32; 5] {
        let [a, b, c, d, e] = state;

        let next = a
            .rotate_left(5)
            .wrapping_add(Self::mixed(stage, b, c, d))
            .wrapping_add(e)
            .wrapping_add(word)
            .wrapping_add(CONSTANTS[stage]);

        [next, a, b.rotate_left(30), c, d]
    }

    /// Mixes one full block into the state.
    ///
    /// [`Sha1::update`] calls this as blocks fill; it is rarely useful on its own.
    pub fn compress(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut words = [0u32; SCHEDULE];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_be_bytes([block[index * 4], block[index * 4 + 1], block[index * 4 + 2], block[index * 4 + 3]]);
        }

        let mut state = self.state;

        // One loop per stage, so the mix and the constant are settled for the
        // whole of it rather than chosen again on every round.
        for stage in 0..CONSTANTS.len() {
            for round in stage * STAGE_ROUNDS..(stage + 1) * STAGE_ROUNDS {
                state = Self::round(state, stage, Self::extend(&mut words, round));
            }
        }

        for (held, added) in self.state.iter_mut().zip(state) {
            *held = held.wrapping_add(added);
        }
    }

    /// Pads the last block and returns the digest.
    pub fn finish(mut self) -> [u8; DIGEST_SIZE] {
        let length = self.length;

        // At most one octet of mark, the zeroes up to the length, and the
        // length itself — which never passes two blocks, so it is written into
        // one buffer here rather than gathered on the heap.
        let mut padding = [0u8; BLOCK_SIZE * 2];
        padding[0] = 0x80;

        let zeroes = (BLOCK_SIZE + BLOCK_SIZE - 8 - (self.filled + 1) % BLOCK_SIZE) % BLOCK_SIZE;
        let end = 1 + zeroes;
        padding[end..end + 8].copy_from_slice(&length.to_be_bytes());
        self.update(&padding[..end + 8]);

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
