//! Writing a measured number out for a person to read.

/// How a measured number is written.
///
/// Every column in every report goes through here, so that a duration, a size,
/// a count and a rate are written the same way wherever they appear. One
/// function per kind of number, named after the kind: a reader who knows what
/// [`Figure::octets`] gives knows what every size column in every report
/// gives.
pub struct Figure;

impl Figure {
    /// How many octets a mebibyte holds.
    pub const MEBIBYTE: f64 = (1 << 20) as f64;

    /// The suffixes a count is abbreviated with, each a thousand times the last.
    pub const SUFFIXES: &'static [&'static str] = &["", "k", "M", "G", "T"];

    /// The suffixes a size is abbreviated with, each 1024 times the last.
    pub const SIZES: &'static [&'static str] = &["B", "KiB", "MiB", "GiB", "TiB"];

    /// A length of time in seconds, in the largest unit that keeps it
    /// readable.
    ///
    /// Seconds rather than a `Duration`, since a per-iteration time is
    /// routinely faster than the whole nanosecond a `Duration` rounds to.
    pub fn time(seconds: f64) -> String {
        let nanos = seconds * 1e9;

        match nanos {
            _ if nanos < 1e3 => format!("{nanos:.1} ns"),
            _ if nanos < 1e6 => format!("{:.2} us", nanos / 1e3),
            _ if nanos < 1e9 => format!("{:.2} ms", nanos / 1e6),
            _ => format!("{:.2} s", nanos / 1e9),
        }
    }

    /// A count, abbreviated past a thousand.
    pub fn count(value: f64) -> String {
        let mut value = value;
        let mut suffix = 0;

        while value >= 1000.0 && suffix + 1 < Self::SUFFIXES.len() {
            value /= 1000.0;
            suffix += 1;
        }

        match suffix {
            0 => format!("{value:.0}"),
            _ => format!("{value:.2} {}", Self::SUFFIXES[suffix]),
        }
    }

    /// A plain number, as a measurement that is neither a time nor a count is
    /// written — a slope, a ratio, a multiplier.
    pub fn number(value: f64) -> String {
        format!("{value:.2}")
    }

    /// A size in octets, in the largest unit that keeps it readable.
    pub fn octets(value: f64) -> String {
        let mut value = value;
        let mut suffix = 0;

        while value >= 1024.0 && suffix + 1 < Self::SIZES.len() {
            value /= 1024.0;
            suffix += 1;
        }

        match suffix {
            0 => format!("{value:.0} B"),
            _ => format!("{value:.2} {}", Self::SIZES[suffix]),
        }
    }

    /// How many times a second something taking this many seconds happens.
    pub fn rate(each: f64) -> String {
        match each {
            seconds if seconds > 0.0 => format!("{}/s", Self::count(1.0 / seconds)),
            _ => String::new(),
        }
    }

    /// How many mebibytes a second this many octets in this long comes to.
    pub fn throughput(octets: usize, each: f64) -> String {
        match each {
            seconds if seconds > 0.0 => format!("{:.1} MiB/s", octets as f64 / seconds / Self::MEBIBYTE),
            _ => String::new(),
        }
    }

    /// A share, as a percentage.
    pub fn share(value: f64) -> String {
        format!("{:.1} %", value * 100.0)
    }

    /// A count of things per second.
    pub fn per_second(value: f64) -> String {
        format!("{}/s", Self::count(value))
    }

    /// A count of something, with the thing named and made plural when there
    /// is not exactly one of it.
    ///
    /// So that a report says "1 thread" and "4 threads" rather than either of
    /// them twice.
    pub fn many(count: usize, noun: &str) -> String {
        format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
    }

    /// A number of octets a second, as mebibytes.
    pub fn bandwidth(value: f64) -> String {
        format!("{:.1} MiB/s", value / Self::MEBIBYTE)
    }
}
