//! Timing a body, and the statistics over what that gives.

use std::time::{Duration, Instant};

use crate::support::budget::Budget;

/// One timed batch: how many iterations ran, and how long they took together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// How many times the body ran.
    pub iterations: u32,

    /// How long those iterations took together.
    pub elapsed: Duration,
}

impl Sample {
    /// A batch of this many iterations, which took this long.
    pub fn new(iterations: u32, elapsed: Duration) -> Self {
        Self { iterations, elapsed }
    }

    /// Runs a body this many times and times it.
    pub fn take<T>(iterations: u32, body: &mut impl FnMut() -> T) -> Self {
        let started = Instant::now();

        for _ in 0..iterations {
            std::hint::black_box(body());
        }

        Self::new(iterations, started.elapsed())
    }

    /// How long one iteration took, in seconds.
    ///
    /// Seconds rather than a `Duration`, which holds whole nanoseconds and
    /// would round every reading faster than a few nanoseconds to the same
    /// number — and the readings here are routinely faster than that.
    pub fn each(&self) -> f64 {
        self.elapsed.as_secs_f64() / self.iterations.max(1) as f64
    }

    /// How many iterations ran per second.
    pub fn rate(&self) -> f64 {
        match self.elapsed.as_secs_f64() {
            seconds if seconds > 0.0 => self.iterations as f64 / seconds,
            _ => f64::INFINITY,
        }
    }
}

/// Every batch taken for one case, and the statistics over them.
///
/// A batch is the unit a statistic is over, not an iteration: an iteration is
/// usually far too short to time on its own, so what is compared is one
/// batch's per-iteration time against another's.
#[derive(Debug, Clone, Default)]
pub struct Samples {
    /// The batches, in the order they were taken.
    pub batches: Vec<Sample>,
}

impl Samples {
    /// Warms a body up, sizes a batch for it, then takes batches until the
    /// budget runs out.
    pub fn measure<T>(budget: Budget, mut body: impl FnMut() -> T) -> Self {
        Self::warm(budget, &mut body);

        let iterations = Self::calibrate(budget, &mut body);
        let deadline = Instant::now() + budget.measure;

        let mut batches = Vec::new();
        while batches.is_empty() || Instant::now() < deadline {
            batches.push(Sample::take(iterations, &mut body));
        }

        Self { batches }
    }

    /// Folds another set of batches into this one.
    ///
    /// What comes back is read exactly as one thread's readings are: the
    /// batches are per-iteration times whoever took them, so a median over
    /// several threads is what one iteration cost while they all ran.
    pub fn merge(&mut self, other: &Self) {
        self.batches.extend_from_slice(&other.batches);
    }

    /// Runs a body untimed for the budget's warm-up, so that caches, branch
    /// predictors and any lazily built table are where they will be when the
    /// timing starts.
    pub fn warm<T>(budget: Budget, body: &mut impl FnMut() -> T) {
        let deadline = Instant::now() + budget.warmup;

        while Instant::now() < deadline {
            std::hint::black_box(body());
        }
    }

    /// How many iterations a batch needs for the batch to outlast the budget's
    /// resolution, doubling until it does.
    pub fn calibrate<T>(budget: Budget, body: &mut impl FnMut() -> T) -> u32 {
        let mut iterations = 1u32;

        loop {
            if Sample::take(iterations, body).elapsed >= budget.resolution || iterations >= budget.ceiling {
                return iterations;
            }

            iterations = iterations.saturating_mul(2).min(budget.ceiling);
        }
    }

    /// Whether no batch was taken at all.
    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    /// How many iterations ran in total.
    pub fn iterations(&self) -> u64 {
        self.batches.iter().map(|batch| batch.iterations as u64).sum()
    }

    /// How long the batches took together.
    pub fn elapsed(&self) -> Duration {
        self.batches.iter().map(|batch| batch.elapsed).sum()
    }

    /// Each batch's per-iteration time in seconds, in ascending order.
    pub fn sorted(&self) -> Vec<f64> {
        let mut each: Vec<f64> = self.batches.iter().map(Sample::each).collect();
        each.sort_unstable_by(f64::total_cmp);
        each
    }

    /// The per-iteration time at this quantile, from `0.0` to `1.0`.
    pub fn quantile(&self, at: f64) -> f64 {
        let sorted = self.sorted();
        if sorted.is_empty() {
            return 0.0;
        }

        let index = (at.clamp(0.0, 1.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[index.min(sorted.len() - 1)]
    }

    /// The fastest batch's per-iteration time, which is the reading least
    /// disturbed by whatever else the machine was doing.
    pub fn best(&self) -> f64 {
        self.quantile(0.0)
    }

    /// The slowest batch's per-iteration time.
    pub fn worst(&self) -> f64 {
        self.quantile(1.0)
    }

    /// The middle batch's per-iteration time.
    pub fn median(&self) -> f64 {
        self.quantile(0.5)
    }

    /// The mean per-iteration time, weighted by how many iterations each batch
    /// held.
    pub fn mean(&self) -> f64 {
        match self.iterations() {
            0 => 0.0,
            iterations => self.elapsed().as_secs_f64() / iterations as f64,
        }
    }

    /// How far the batches' per-iteration times spread around their mean.
    pub fn deviation(&self) -> f64 {
        if self.batches.len() < 2 {
            return 0.0;
        }

        let each = self.sorted();
        let mean = each.iter().sum::<f64>() / each.len() as f64;
        let variance = each.iter().map(|value| (value - mean).powi(2)).sum::<f64>() / (each.len() - 1) as f64;

        variance.sqrt()
    }

    /// The deviation as a share of the median, which is what says whether two
    /// readings differ by more than the noise between them.
    pub fn noise(&self) -> f64 {
        match self.median() {
            median if median > 0.0 => self.deviation() / median,
            _ => 0.0,
        }
    }
}
