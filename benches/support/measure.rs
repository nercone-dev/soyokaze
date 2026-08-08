//! What a case measured, and what its numbers mean.

use crate::support::alloc::Counter;
use crate::support::budget::Budget;
use crate::support::figure::Figure;
use crate::support::load::driver::Run;
use crate::support::sample::Samples;

/// What a case measured.
///
/// Each variant carries exactly what its kind of measurement needs, and
/// answers [`Measure::columns`] with the columns that kind is read in, so a
/// report never has to know which kind it is looking at. A new kind of
/// measurement is a new variant and nothing else.
#[derive(Debug, Clone)]
pub enum Measure {
    /// How long one iteration takes.
    Time(Samples),

    /// How long one iteration takes, over a payload of this many octets.
    Throughput(Samples, usize),

    /// How many allocations one round makes, over this many rounds.
    Allocations {
        /// How many allocations the rounds made together.
        total: u64,
        /// How many rounds ran.
        rounds: u64,
    },

    /// What came of driving a server under load.
    Load(Run),
}

impl Measure {
    /// Times a body under a budget.
    pub fn time<T>(budget: Budget, body: impl FnMut() -> T) -> Self {
        Self::Time(Samples::measure(budget, body))
    }

    /// Times a body that works over this many octets.
    pub fn throughput<T>(budget: Budget, octets: usize, body: impl FnMut() -> T) -> Self {
        Self::Throughput(Samples::measure(budget, body), octets)
    }

    /// Counts the allocations a body makes, over this many rounds.
    ///
    /// The body is given the round number, so that a round can work on a fresh
    /// stream or a fresh key rather than measuring the same one over and over.
    /// A tenth of the rounds run before any is counted, which is what leaves
    /// out the tables, buffers and caches that are grown once and then reused.
    pub fn allocations<T>(rounds: u64, mut body: impl FnMut(u64) -> T) -> Self {
        let warmup = (rounds / 10).max(1);

        for round in 0..warmup {
            std::hint::black_box(body(round));
        }

        let total = (warmup..warmup + rounds).map(|round| Counter::count(|| body(round))).sum();

        Self::Allocations { total, rounds }
    }

    /// The batches this measurement was reduced from, if it was timed.
    pub fn samples(&self) -> Option<&Samples> {
        match self {
            Self::Time(samples) | Self::Throughput(samples, _) => Some(samples),
            Self::Allocations { .. } | Self::Load(_) => None,
        }
    }

    /// How long one iteration took in seconds, if this measurement is of a
    /// length of time.
    pub fn each(&self) -> Option<f64> {
        self.samples().map(Samples::median)
    }

    /// The columns this measurement is read in, named.
    pub fn columns(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::Time(samples) => vec![
                ("median", Figure::time(samples.median())),
                ("best", Figure::time(samples.best())),
                ("dev", Figure::share(samples.noise())),
                ("rate", Figure::rate(samples.median())),
            ],

            Self::Throughput(samples, octets) => vec![
                ("median", Figure::time(samples.median())),
                ("best", Figure::time(samples.best())),
                ("dev", Figure::share(samples.noise())),
                ("throughput", Figure::throughput(*octets, samples.median())),
            ],

            Self::Allocations { total, rounds } => vec![
                ("per round", format!("{:.2}", *total as f64 / (*rounds).max(1) as f64)),
                ("total", Figure::count(*total as f64)),
                ("rounds", Figure::count(*rounds as f64)),
            ],

            Self::Load(run) => vec![
                ("requests", Figure::per_second(run.rate())),
                ("body", Figure::octets(run.bandwidth())),
                ("p50", Figure::time(run.outcome.latency.quantile(0.50).as_secs_f64())),
                ("p99", Figure::time(run.outcome.latency.quantile(0.99).as_secs_f64())),
                ("worst", Figure::time(run.outcome.latency.worst.as_secs_f64())),
                ("failed", Figure::share(run.failures())),
            ],
        }
    }

    /// The one number a machine reading this measurement wants.
    pub fn value(&self) -> f64 {
        match self {
            Self::Time(samples) | Self::Throughput(samples, _) => samples.median(),
            Self::Allocations { total, rounds } => *total as f64 / (*rounds).max(1) as f64,
            Self::Load(run) => run.rate(),
        }
    }

    /// What [`Measure::value`] is measured in.
    pub fn dimension(&self) -> &'static str {
        match self {
            Self::Time(_) | Self::Throughput(..) => "seconds",
            Self::Allocations { .. } => "allocations",
            Self::Load(_) => "requests per second",
        }
    }
}
