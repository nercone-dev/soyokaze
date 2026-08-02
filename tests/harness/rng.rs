pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        self.0 = state;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 { 0 } else { (self.next_u64() % bound as u64) as usize }
    }

    pub fn bytes(&mut self, max: usize) -> Vec<u8> {
        let length = self.below(max) + 1;
        (0..length).map(|_| self.next_u64() as u8).collect()
    }

    pub fn biased(&mut self, max: usize, alphabet: &[u8]) -> Vec<u8> {
        let length = self.below(max) + 1;
        (0..length).map(|_| alphabet[self.below(alphabet.len())]).collect()
    }
}
