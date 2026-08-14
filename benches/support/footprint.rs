//! What a round costs the allocator, over enough rounds to average.

use crate::support::alloc::{Cost, Counter};

/// How many times a round reached for memory, and how much it asked for.
///
/// Counted rather than timed, so it is exact and needs none of the repetition
/// a timing does: two runs of the same code report the same number. That is
/// what makes it the measurement to reach for when a timing is too noisy to
/// settle an argument.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Footprint {
    /// What the counted rounds cost together.
    pub total: Cost,

    /// How many rounds were counted.
    pub rounds: u64,
}

impl Footprint {
    /// What share of the rounds runs uncounted first, so that the tables,
    /// buffers and caches a connection grows once and then reuses are left out
    /// of the steady-state cost.
    pub const WARMUP: u64 = 10;

    /// Counts what a body costs, over this many rounds.
    ///
    /// The body is given the round number, so a round can work on a fresh
    /// stream or a fresh key rather than measuring the same one over and over.
    pub fn measure<T>(rounds: u64, mut body: impl FnMut(u64) -> T) -> Self {
        let warmup = (rounds / Self::WARMUP).max(1);

        for round in 0..warmup {
            std::hint::black_box(body(round));
        }

        let mut total = Cost::default();
        for round in warmup..warmup + rounds {
            total.merge(&Counter::count(|| body(round)));
        }

        Self { total, rounds }
    }

    /// How many times one round reached for memory.
    pub fn calls(&self) -> f64 {
        self.total.calls as f64 / self.rounds.max(1) as f64
    }

    /// How many octets one round asked for.
    pub fn octets(&self) -> f64 {
        self.total.octets as f64 / self.rounds.max(1) as f64
    }

    /// How many octets one call asked for on average, which says whether a
    /// round's octets are one large request or many small ones.
    pub fn each(&self) -> f64 {
        match self.total.calls {
            0 => 0.0,
            calls => self.total.octets as f64 / calls as f64,
        }
    }
}
