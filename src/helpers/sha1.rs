pub const BLOCK_SIZE: usize = 64;
pub const DIGEST_SIZE: usize = 20;

pub const INITIAL_STATE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

pub const CONSTANTS: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

pub struct Sha1 {
    state: [u32; 5],
    block: [u8; BLOCK_SIZE],
    filled: usize,
    length: u64,
}

impl Sha1 {
    pub fn new() -> Self {
        Self { state: INITIAL_STATE, block: [0; BLOCK_SIZE], filled: 0, length: 0 }
    }

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

    pub fn compress(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut words = [0u32; 80];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[index * 4],
                block[index * 4 + 1],
                block[index * 4 + 2],
                block[index * 4 + 3],
            ]);
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

pub fn sha1(input: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hash = Sha1::new();
    hash.update(input);
    hash.finish()
}
