//! How long a case is measured for.

use std::time::Duration;

/// How long one case is warmed up and then measured for.
///
/// A case is warmed up untimed, then run in batches sized so that each batch
/// outlasts the clock's own noise, and batches are taken until the measuring
/// time runs out. What comes back is a spread rather than one number, which is
/// what [`Samples`] then reduces.
///
/// [`Samples`]: crate::support::sample::Samples
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// How long the timed batches run for, together.
    pub measure: Duration,

    /// How long the untimed warm-up runs for first.
    pub warmup: Duration,

    /// The shortest a batch may take, which is what sets the batch size.
    pub resolution: Duration,

    /// The most iterations one batch may hold, so a body too fast to time
    /// still stops growing its batch.
    pub ceiling: u32,
}

impl Budget {
    /// The variable [`Budget::from_env`] reads the measured seconds from.
    pub const VARIABLE: &'static str = "SOYOKAZE_BENCH_TIME";

    /// How long a case is measured for when nothing says otherwise.
    pub const MEASURE: Duration = Duration::from_millis(500);

    /// A budget that measures for this long, warming up for a fifth as long.
    pub fn new(measure: Duration) -> Self {
        Self { measure, warmup: measure / 5, resolution: Duration::from_micros(500), ceiling: 1 << 20 }
    }

    /// The budget the environment asks for, or [`Budget::MEASURE`] per case.
    pub fn from_env() -> Self {
        Self::new(Self::seconds().map(Duration::from_secs_f64).unwrap_or(Self::MEASURE))
    }

    /// The measured seconds the environment asks for, if it asks for any.
    pub fn seconds() -> Option<f64> {
        std::env::var(Self::VARIABLE).ok()?.parse::<f64>().ok().filter(|seconds| *seconds > 0.0)
    }

    /// How long one case takes at most, warm-up and measurement together.
    pub fn total(&self) -> Duration {
        self.warmup + self.measure
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(Self::MEASURE)
    }
}
