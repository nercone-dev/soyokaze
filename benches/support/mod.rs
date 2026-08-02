use std::time::{Duration, Instant};

pub fn budget() -> Duration {
    let seconds = std::env::var("SOYOKAZE_BENCH_TIME")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|seconds| *seconds > 0.0)
        .unwrap_or(0.5);

    Duration::from_secs_f64(seconds)
}

#[inline(always)]
pub fn opaque<T>(value: T) -> T {
    std::hint::black_box(value)
}

pub struct Group;

impl Group {
    pub fn new(name: &str) -> Self {
        println!("\n{name}");
        println!("{}", "-".repeat(name.len()));
        Self
    }

    #[allow(dead_code)]
    pub fn bench<T>(&mut self, case: &str, mut body: impl FnMut() -> T) {
        self.report(case, measure(&mut body), None);
    }

    pub fn throughput<T>(&mut self, case: &str, octets: usize, mut body: impl FnMut() -> T) {
        self.report(case, measure(&mut body), Some(octets));
    }

    fn report(&self, case: &str, seconds: f64, octets: Option<usize>) {
        let rate = match octets {
            Some(octets) if seconds > 0.0 => {
                format!("  {:>8.1} MiB/s", octets as f64 / seconds / (1024.0 * 1024.0))
            }
            _ => String::new(),
        };

        println!("  {case:<38} {:>12}{rate}", human(seconds));
    }
}

fn human(seconds: f64) -> String {
    let nanos = seconds * 1e9;

    match nanos {
        _ if nanos < 1_000.0 => format!("{nanos:.1} ns"),
        _ if nanos < 1_000_000.0 => format!("{:.2} us", nanos / 1e3),
        _ => format!("{:.2} ms", nanos / 1e6),
    }
}

fn measure<T>(body: &mut impl FnMut() -> T) -> f64 {
    for _ in 0..16 {
        opaque(body());
    }

    let mut batch = 1u32;
    while batch < 1 << 22 {
        let started = Instant::now();
        for _ in 0..batch {
            opaque(body());
        }

        if started.elapsed() >= Duration::from_micros(500) {
            break;
        }

        batch *= 4;
    }

    let budget = budget();
    let deadline = Instant::now() + budget;

    let mut best = f64::INFINITY;
    let mut batches = 0u32;

    while Instant::now() < deadline || batches == 0 {
        let started = Instant::now();
        for _ in 0..batch {
            opaque(body());
        }

        best = best.min(started.elapsed().as_secs_f64() / batch as f64);
        batches += 1;
    }

    best
}
