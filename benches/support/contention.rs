//! What a cost becomes when several threads pay it at once.

use crate::support::budget::Budget;
use crate::support::sample::Samples;

/// The same body measured on one thread and on several.
///
/// A shared structure — a cookie jar, an HSTS store, a connection tally, a
/// date cache — is fast on its own and says nothing about what it does to a
/// server, because a server reaches for it from every worker at once. What
/// matters there is not the cost of one call but how much of it survives being
/// made concurrently, and the only way to see that is to make it concurrently.
///
/// Both halves are measured in the same run under the same budget, so the
/// comparison is between two readings of one machine in one state rather than
/// between a reading and a memory of one.
#[derive(Debug, Clone)]
pub struct Contention {
    /// How many threads ran the body together.
    pub threads: usize,

    /// What one iteration took with nothing else running.
    pub alone: Samples,

    /// What one iteration took with every thread running.
    pub together: Samples,
}

impl Contention {
    /// The variable [`Contention::counts`] reads thread counts from.
    pub const VARIABLE: &'static str = "SOYOKAZE_BENCH_THREADS";

    /// Measures a body alone, then on this many threads at once.
    ///
    /// The body is shared rather than cloned, so what the threads contend over
    /// is one structure and not one apiece.
    pub fn measure<T>(budget: Budget, threads: usize, body: impl Fn() -> T + Sync) -> Self {
        let alone = Samples::measure(budget, || body());
        let threads = threads.max(1);

        let together = std::thread::scope(|scope| {
            let running: Vec<_> = (0..threads).map(|_| scope.spawn(|| Samples::measure(budget, || body()))).collect();

            let mut merged = Samples::default();
            for thread in running {
                merged.merge(&thread.join().expect("a thread stopped short"));
            }

            merged
        });

        Self { threads, alone, together }
    }

    /// How many iterations a second every thread manages together.
    pub fn rate(&self) -> f64 {
        match self.together.median() {
            each if each > 0.0 => self.threads as f64 / each,
            _ => 0.0,
        }
    }

    /// What share of one thread's speed each thread keeps.
    ///
    /// One is perfect scaling: every thread runs as fast as it did alone.
    /// A half says each iteration takes twice as long once the threads are
    /// contending, so the structure gives back half of what the threads were
    /// meant to add.
    pub fn efficiency(&self) -> f64 {
        match self.together.median() {
            each if each > 0.0 => self.alone.median() / each,
            _ => 0.0,
        }
    }

    /// The thread counts a sweep runs at, as the environment asks for them.
    ///
    /// One thread is always included, since it is what the others are read
    /// against, and a count past what the machine can run at once would only
    /// measure the scheduler.
    pub fn counts() -> Vec<usize> {
        let asked = std::env::var(Self::VARIABLE).unwrap_or_default();

        let listed: Vec<usize> = asked
            .split(|character: char| !character.is_ascii_digit())
            .filter_map(|count| count.parse::<usize>().ok())
            .filter(|count| *count > 0)
            .collect();

        match listed.is_empty() {
            false => listed,
            true => {
                let cores = soyokaze::Cluster::cores();
                let mut counts = vec![1, 2, 4, cores];
                counts.retain(|count| *count <= cores.max(1));
                counts.sort_unstable();
                counts.dedup();
                counts
            }
        }
    }
}
