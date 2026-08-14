//! How a cost grows with the size it is given.

/// One reading in a growth curve: the size it was taken at, and what one
/// iteration took there.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    /// The size the reading was taken at — fields in a set, hosts in a store,
    /// octets in a buffer, streams on a connection.
    pub at: usize,

    /// How long one iteration took there, in seconds.
    pub each: f64,
}

impl Point {
    /// A reading at this size.
    pub fn new(at: usize, each: f64) -> Self {
        Self { at, each }
    }
}

/// A cost measured at several sizes, and what that says about how it grows.
///
/// A sweep reported as one case per size says how fast each size is; it does
/// not say whether the cost is bounded, and that is usually the question. A
/// lookup that stays flat from one field to four thousand is a different thing
/// from one that merely happens to be fast at eight, and only a curve tells
/// them apart. The slope is the least-squares fit through the readings in log
/// space, so it reads as the exponent of the size: zero is flat, one is linear,
/// two is quadratic.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Growth {
    /// The readings, in the order they were taken.
    pub points: Vec<Point>,
}

impl Growth {
    /// The slope up to which a cost is called flat.
    pub const FLAT: f64 = 0.15;

    /// The slope up to which it is called sublinear.
    pub const SUBLINEAR: f64 = 0.65;

    /// The slope up to which it is called linear.
    pub const LINEAR: f64 = 1.4;

    /// The slope up to which it is called quadratic.
    pub const QUADRATIC: f64 = 2.4;

    /// A curve with no readings in it yet.
    pub fn new() -> Self {
        Self { points: Vec::new() }
    }

    /// Records what one iteration took at this size.
    pub fn at(&mut self, at: usize, each: f64) {
        self.points.push(Point::new(at, each));
    }

    /// Whether nothing was measured at all.
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// The reading at the smallest size.
    pub fn smallest(&self) -> Option<&Point> {
        self.points.iter().min_by_key(|point| point.at)
    }

    /// The reading at the largest size.
    pub fn largest(&self) -> Option<&Point> {
        self.points.iter().max_by_key(|point| point.at)
    }

    /// The sizes the curve spans, as they are written in a report.
    pub fn span(&self) -> String {
        match (self.smallest(), self.largest()) {
            (Some(first), Some(last)) => format!("{} - {}", first.at, last.at),
            _ => String::new(),
        }
    }

    /// How many times more expensive the largest size is than the smallest.
    pub fn factor(&self) -> f64 {
        match (self.smallest(), self.largest()) {
            (Some(first), Some(last)) if first.each > 0.0 => last.each / first.each,
            _ => 0.0,
        }
    }

    /// The exponent of the size the cost grows with.
    ///
    /// The least-squares fit through the readings in log space, which is the
    /// slope of the line they lie on when both axes are logarithmic. Readings
    /// at a size or a time of zero are left out, since neither has a logarithm;
    /// fewer than two usable readings leave nothing to fit and answer zero.
    pub fn slope(&self) -> f64 {
        let usable: Vec<(f64, f64)> = self
            .points
            .iter()
            .filter(|point| point.at > 0 && point.each > 0.0)
            .map(|point| ((point.at as f64).ln(), point.each.ln()))
            .collect();

        if usable.len() < 2 {
            return 0.0;
        }

        let count = usable.len() as f64;
        let mean_size = usable.iter().map(|(size, _)| size).sum::<f64>() / count;
        let mean_cost = usable.iter().map(|(_, cost)| cost).sum::<f64>() / count;

        let covariance: f64 = usable.iter().map(|(size, cost)| (size - mean_size) * (cost - mean_cost)).sum();
        let variance: f64 = usable.iter().map(|(size, _)| (size - mean_size).powi(2)).sum();

        match variance {
            spread if spread > 0.0 => covariance / spread,
            _ => 0.0,
        }
    }

    /// What the slope is called.
    pub fn shape(&self) -> &'static str {
        match self.slope() {
            slope if slope < Self::FLAT => "flat",
            slope if slope < Self::SUBLINEAR => "sublinear",
            slope if slope < Self::LINEAR => "linear",
            slope if slope < Self::QUADRATIC => "quadratic",
            _ => "worse",
        }
    }
}
