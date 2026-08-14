//! What a case measured, and what its numbers mean.

use crate::support::budget::Budget;
use crate::support::contention::Contention;
use crate::support::figure::Figure;
use crate::support::footprint::Footprint;
use crate::support::growth::Growth;
use crate::support::load::driver::Run;
use crate::support::sample::Samples;

/// What a case measured.
///
/// Each variant is one way of looking at a piece of the library, and each
/// carries exactly what its way needs. Together they are the questions worth
/// asking of any piece of it:
///
/// | Variant        | What it answers                                       |
/// |----------------|-------------------------------------------------------|
/// | [`Time`]       | How long does one call take?                          |
/// | [`Throughput`] | How fast does it get through its octets?              |
/// | [`Footprint`]  | What does one call cost the allocator?                |
/// | [`Growth`]     | Does the cost stay bounded as the input grows?        |
/// | [`Contention`] | How much of it survives being made from many threads? |
/// | [`Load`]       | What does all of it come to over a real socket?       |
///
/// Every variant answers [`Measure::columns`] with the columns its kind is
/// read in, so a report never has to know which kind it is looking at. A new
/// way of looking at something is a new variant and nothing else.
///
/// [`Time`]: Measure::Time
/// [`Throughput`]: Measure::Throughput
/// [`Footprint`]: Measure::Footprint
/// [`Growth`]: Measure::Growth
/// [`Contention`]: Measure::Contention
/// [`Load`]: Measure::Load
#[derive(Debug, Clone)]
pub enum Measure {
    /// How long one iteration takes.
    Time(Samples),

    /// How long one iteration takes, over a payload of this many octets.
    Throughput(Samples, usize),

    /// What one round costs the allocator.
    Footprint(Footprint),

    /// How the cost grows with the size it is given.
    Growth(Growth),

    /// What one iteration costs when several threads run it at once.
    Contention(Contention),

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

    /// Counts what a body costs the allocator, over this many rounds.
    pub fn footprint<T>(rounds: u64, body: impl FnMut(u64) -> T) -> Self {
        Self::Footprint(Footprint::measure(rounds, body))
    }

    /// Measures a body alone and then on this many threads at once.
    pub fn contention<T>(budget: Budget, threads: usize, body: impl Fn() -> T + Sync) -> Self {
        Self::Contention(Contention::measure(budget, threads, body))
    }

    /// The batches this measurement was reduced from, if it was timed.
    pub fn samples(&self) -> Option<&Samples> {
        match self {
            Self::Time(samples) | Self::Throughput(samples, _) => Some(samples),
            Self::Contention(contention) => Some(&contention.alone),
            Self::Footprint(_) | Self::Growth(_) | Self::Load(_) => None,
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

            Self::Footprint(footprint) => vec![
                ("calls", Figure::number(footprint.calls())),
                ("octets", Figure::octets(footprint.octets())),
                ("per call", Figure::octets(footprint.each())),
                ("rounds", Figure::count(footprint.rounds as f64)),
            ],

            Self::Growth(growth) => vec![
                ("smallest", Figure::time(growth.smallest().map(|point| point.each).unwrap_or(0.0))),
                ("largest", Figure::time(growth.largest().map(|point| point.each).unwrap_or(0.0))),
                ("over", growth.span()),
                ("factor", Figure::number(growth.factor())),
                ("slope", Figure::number(growth.slope())),
                ("growth", growth.shape().to_owned()),
            ],

            Self::Contention(contention) => vec![
                ("alone", Figure::time(contention.alone.median())),
                ("together", Figure::time(contention.together.median())),
                ("threads", Figure::count(contention.threads as f64)),
                ("rate", Figure::per_second(contention.rate())),
                ("kept", Figure::share(contention.efficiency())),
            ],

            Self::Load(run) => vec![
                ("requests", Figure::per_second(run.rate())),
                ("body", Figure::bandwidth(run.bandwidth())),
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
            Self::Footprint(footprint) => footprint.calls(),
            Self::Growth(growth) => growth.slope(),
            Self::Contention(contention) => contention.rate(),
            Self::Load(run) => run.rate(),
        }
    }

    /// What [`Measure::value`] is measured in.
    pub fn dimension(&self) -> &'static str {
        match self {
            Self::Time(_) | Self::Throughput(..) => "seconds",
            Self::Footprint(_) => "allocations",
            Self::Growth(_) => "slope",
            Self::Contention(_) => "iterations per second",
            Self::Load(_) => "requests per second",
        }
    }
}
