//! What a load run's response times looked like.

use std::time::Duration;

/// A distribution of response times, held as a log-linear histogram.
///
/// Every octave of nanoseconds is split into [`Latency::DIVISIONS`] buckets,
/// so a reading is kept to within about three percent of itself from a
/// nanosecond up to hours, in a fixed amount of memory and with no sorting at
/// the end. That is what lets each virtual client keep its own distribution
/// and have them folded together afterwards, rather than every client writing
/// into one shared place.
#[derive(Debug, Clone)]
pub struct Latency {
    /// How many readings fell in each bucket.
    pub buckets: Vec<u32>,

    /// How many readings were recorded.
    pub count: u64,

    /// How long the readings took together.
    pub total: Duration,

    /// The longest reading, kept exactly rather than to a bucket.
    pub worst: Duration,
}

impl Latency {
    /// How many buckets one octave of nanoseconds is split into.
    pub const DIVISIONS: u64 = 32;

    /// The power of two [`Latency::DIVISIONS`] is.
    pub const SHIFT: u32 = Self::DIVISIONS.trailing_zeros();

    /// How many buckets there are, which is what bounds what can be recorded.
    pub const BUCKETS: usize = (Self::DIVISIONS as usize) * 40;

    /// An empty distribution.
    pub fn new() -> Self {
        Self { buckets: vec![0; Self::BUCKETS], count: 0, total: Duration::ZERO, worst: Duration::ZERO }
    }

    /// Records one reading.
    pub fn record(&mut self, taken: Duration) {
        self.buckets[Self::bucket(taken.as_nanos().min(u64::MAX as u128) as u64)] += 1;
        self.count += 1;
        self.total += taken;
        self.worst = self.worst.max(taken);
    }

    /// Folds another distribution into this one.
    pub fn merge(&mut self, other: &Self) {
        for (held, added) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *held += added;
        }

        self.count += other.count;
        self.total += other.total;
        self.worst = self.worst.max(other.worst);
    }

    /// Which bucket a reading in nanoseconds falls in.
    ///
    /// Below one division the buckets are one nanosecond each; above it, each
    /// octave is split into the same number of buckets, so the buckets widen
    /// with the readings they hold.
    pub fn bucket(nanos: u64) -> usize {
        if nanos < Self::DIVISIONS {
            return nanos as usize;
        }

        let octave = 63 - nanos.leading_zeros();
        let group = (octave - Self::SHIFT + 1) as u64;
        let within = (nanos >> (octave - Self::SHIFT)) - Self::DIVISIONS;

        ((group * Self::DIVISIONS + within) as usize).min(Self::BUCKETS - 1)
    }

    /// The reading just past everything a bucket holds, which is what a
    /// percentile is quoted as so that it never understates the readings
    /// behind it.
    pub fn bound(bucket: usize) -> Duration {
        let bucket = bucket as u64;

        if bucket < Self::DIVISIONS {
            return Duration::from_nanos(bucket + 1);
        }

        let shift = (bucket >> Self::SHIFT) - 1;
        let within = bucket & (Self::DIVISIONS - 1);

        Duration::from_nanos(((Self::DIVISIONS + within) << shift) + (1 << shift))
    }

    /// The reading at this quantile, from `0.0` to `1.0`.
    ///
    /// What comes back is the top of the bucket the quantile falls in, so a
    /// quoted percentile is never shorter than the readings behind it.
    pub fn quantile(&self, at: f64) -> Duration {
        if self.count == 0 {
            return Duration::ZERO;
        }

        let wanted = (at.clamp(0.0, 1.0) * self.count as f64).ceil().max(1.0) as u64;
        let mut seen = 0u64;

        for (bucket, held) in self.buckets.iter().enumerate() {
            seen += *held as u64;

            if seen >= wanted {
                return Self::bound(bucket).min(self.worst);
            }
        }

        self.worst
    }

    /// The mean reading.
    pub fn mean(&self) -> Duration {
        match self.count {
            0 => Duration::ZERO,
            count => Duration::from_secs_f64(self.total.as_secs_f64() / count as f64),
        }
    }

    /// The middle reading.
    pub fn median(&self) -> Duration {
        self.quantile(0.50)
    }
}

impl Default for Latency {
    fn default() -> Self {
        Self::new()
    }
}
