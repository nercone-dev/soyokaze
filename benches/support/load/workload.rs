//! What a load run offers a server.

use std::time::{Duration, Instant};

use soyokaze::models::{Body, Message, Method, Port, Version};

use crate::support::fixtures::Payload;

/// Whether a request reuses its connection or dials a new one.
///
/// The two measure different halves of a server: [`Reuse::Keep`] measures what
/// a request costs once a connection is up, and [`Reuse::Fresh`] measures what
/// standing a connection up costs — accept, admission, negotiation and, over
/// TLS, a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reuse {
    /// One connection per virtual client, held for the whole run.
    Keep,

    /// A new connection for every round, closed after it.
    Fresh,
}

/// How offered load is paced.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Pacing {
    /// Each client sends again as soon as its last answer arrives.
    ///
    /// This measures how much the server can be made to do, but it cannot
    /// measure how badly it falls behind: a server that slows down slows the
    /// generator down with it, and the queue that would have built up never
    /// does.
    Closed,

    /// Requests go out on a fixed schedule of this many a second, whatever the
    /// answers do.
    ///
    /// Latency is then measured from when a request was due rather than from
    /// when it went out, so a server that falls behind is charged for the
    /// queue it builds instead of hiding it.
    Open(f64),
}

/// One load run: what is served, how it is reached, and how hard.
///
/// Every field is a plain public knob, so a benchmark says only what it
/// changes:
///
/// ```ignore
/// Workload { connections: 256, depth: 16, ..Workload::new("h2 burst", Version::V2_0) }
/// ```
#[derive(Debug, Clone)]
pub struct Workload {
    /// What the run is called in a report.
    pub name: String,

    /// The version every connection speaks.
    pub version: Version,

    /// Whether a stream transport is wrapped in TLS. A QUIC run is always
    /// secure, whatever this says.
    pub secure: bool,

    /// How many virtual clients run at once, each holding its own connection.
    pub connections: usize,

    /// How many requests a client keeps in flight before it reads any answer.
    pub depth: usize,

    /// Whether a client keeps its connection or dials a new one each round.
    pub reuse: Reuse,

    /// How the offered load is paced.
    pub pacing: Pacing,

    /// How long the run lasts.
    pub duration: Duration,

    /// How many octets each request carries, or none for a `GET`.
    pub request_body: usize,

    /// How many octets the server answers with.
    pub response_body: usize,

    /// How long one round may take before it counts as failed.
    pub timeout: Duration,

    /// How many threads the server runs on.
    pub workers: usize,
}

impl Workload {
    /// The variable [`Workload::seconds`] reads a run's length from.
    pub const VARIABLE: &'static str = "SOYOKAZE_LOAD_TIME";

    /// The variable [`Workload::scale`] reads the client multiplier from.
    pub const SCALE: &'static str = "SOYOKAZE_LOAD_SCALE";

    /// How long a run lasts when nothing says otherwise.
    pub const DURATION: Duration = Duration::from_secs(2);

    /// A plaintext keep-alive run of this version, one client per core.
    pub fn new(name: impl Into<String>, version: Version) -> Self {
        Self {
            name: name.into(),
            version,
            secure: false,
            connections: 32,
            depth: 1,
            reuse: Reuse::Keep,
            pacing: Pacing::Closed,
            duration: Self::seconds(),
            request_body: 0,
            response_body: 13,
            timeout: Duration::from_secs(10),
            workers: soyokaze::cores(),
        }
    }

    /// How long a run lasts, as the environment asks for it.
    pub fn seconds() -> Duration {
        std::env::var(Self::VARIABLE)
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|seconds| *seconds > 0.0)
            .map(Duration::from_secs_f64)
            .unwrap_or(Self::DURATION)
    }

    /// What every run's client count is multiplied by, as the environment asks
    /// for it.
    pub fn scale() -> f64 {
        std::env::var(Self::SCALE)
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|scale| *scale > 0.0)
            .unwrap_or(1.0)
    }

    /// How many virtual clients actually run, after the environment's scale.
    pub fn clients(&self) -> usize {
        ((self.connections as f64 * Self::scale()).round() as usize).max(1)
    }

    /// How many requests a round actually holds, which is at least one however
    /// the depth was set.
    pub fn inflight(&self) -> usize {
        self.depth.max(1)
    }

    /// The port this run's version is served over.
    pub fn port(&self, number: u16) -> Port {
        match self.version.transport() {
            soyokaze::TransportKind::Quic => Port::QUIC(number),
            soyokaze::TransportKind::Stream => Port::TCP(number),
        }
    }

    /// Whether the server needs a certificate to run this workload.
    pub fn needs_identity(&self) -> bool {
        self.secure || self.version.transport() == soyokaze::TransportKind::Quic
    }

    /// The request every client sends.
    pub fn request(&self) -> Message {
        match self.request_body {
            0 => Message::request(Method::GET, "/index.html", self.version),

            octets => {
                let mut request = Message::request(Method::POST, "/index.html", self.version);
                request.body = Some(Body::Data(Payload::of(octets)));
                request
            }
        }
    }

    /// When one client's request number `sent` was due to go out, or none when
    /// the pacing has nothing to say about it.
    ///
    /// The schedule is split evenly between the clients, so the run as a whole
    /// offers the rate that was asked for.
    pub fn due(&self, start: Instant, sent: u64) -> Option<Instant> {
        match self.pacing {
            Pacing::Closed => None,
            Pacing::Open(rate) if rate > 0.0 => {
                let interval = self.clients() as f64 / rate;
                Some(start + Duration::from_secs_f64(interval * sent as f64))
            }
            Pacing::Open(_) => None,
        }
    }
}
