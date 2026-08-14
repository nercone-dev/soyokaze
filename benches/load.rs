//! A real server, driven hard.
//!
//! Every run here stands a server up on an ephemeral loopback port, opens as
//! many connections to it as it was told to, drives them for a fixed length of
//! time, and takes the server down again. Nothing is stubbed: the requests
//! cross a socket, the accept path, admission control, negotiation, and — where
//! the run says so — a TLS or QUIC handshake, exactly as a served request does.
//!
//! What each column says:
//!
//! - `requests` — answered requests a second, which is the headline number
//! - `body` — response body octets a second
//! - `p50` / `p99` / `worst` — how long an answer took
//! - `failed` — the share of offered requests that never came back
//!
//! The groups vary one thing each, so that a difference has one cause: the
//! version, the transport, whether a connection is held or dialled afresh, how
//! many run at once, how deep each one is, how large the bodies are, how many
//! workers serve them, and whether the offered rate is tied to the answers or
//! held fixed. What no group varies is the network, because there is not one.
//!
//! A loopback run has no propagation delay, no loss and no reordering, so
//! these latencies are a floor rather than a forecast, and this benchmark is
//! bound by syscalls and the runtime rather than by anything a codec does — so
//! a per-request improvement measured in `--bench protocol` or
//! `--bench allocations` is not expected to move these numbers. What they are
//! good for is comparison: between versions, between transports, between one
//! shape of load and another, and between one revision of the library and the
//! next.
//!
//! ```bash
//! cargo bench --bench load
//! cargo bench --bench load -- "http/3"
//! SOYOKAZE_LOAD_TIME=30 SOYOKAZE_LOAD_SCALE=8 cargo bench --bench load
//! ```

mod support;

use std::time::Duration;

use soyokaze::models::Version;

use support::load::{Driver, Pacing, Reuse, Workload};
use support::{Figure, Filter, Group};

/// How many requests one connection keeps in flight where a version can
/// multiplex.
const DEPTH: usize = 16;

/// How many connections a multiplexing run opens, since each carries
/// [`DEPTH`] requests of its own.
const MULTIPLEXED: usize = 8;

fn http1() {
    let mut group = Group::new("http/1.1 under load");

    group.load(Workload::new("plaintext, connections held", Version::V1_1));
    group.load(Workload { reuse: Reuse::Fresh, ..Workload::new("plaintext, a connection per request", Version::V1_1) });
    group.load(Workload { secure: true, ..Workload::new("TLS, connections held", Version::V1_1) });
    group.load(Workload { secure: true, reuse: Reuse::Fresh, ..Workload::new("TLS, a handshake per request", Version::V1_1) });
    group.load(Workload { depth: DEPTH, connections: MULTIPLEXED, ..Workload::new("plaintext, 16 pipelined", Version::V1_1) });
}

fn http2() {
    let mut group = Group::new("http/2 under load");

    group.load(Workload::new("plaintext, one request at a time", Version::V2_0));
    group.load(Workload { depth: DEPTH, connections: MULTIPLEXED, ..Workload::new("plaintext, 16 in flight", Version::V2_0) });
    group.load(Workload { secure: true, ..Workload::new("TLS, one request at a time", Version::V2_0) });
    group.load(Workload { secure: true, depth: DEPTH, connections: MULTIPLEXED, ..Workload::new("TLS, 16 in flight", Version::V2_0) });
    group.load(Workload { secure: true, reuse: Reuse::Fresh, ..Workload::new("TLS, a handshake per request", Version::V2_0) });
}

fn http3() {
    let mut group = Group::new("http/3 under load");

    group.load(Workload { connections: MULTIPLEXED, ..Workload::new("QUIC, one request at a time", Version::V3_0) });
    group.load(Workload { connections: MULTIPLEXED, depth: DEPTH, ..Workload::new("QUIC, 16 in flight", Version::V3_0) });
    group.load(Workload { connections: MULTIPLEXED, reuse: Reuse::Fresh, ..Workload::new("QUIC, a handshake per request", Version::V3_0) });
}

/// The same load offered to each version in turn, changing nothing else.
///
/// Every other group varies something within one version; this one varies only
/// the version, which is the comparison a reader actually wants and the one
/// that is hardest to make from rows scattered across three groups.
fn versions() {
    let mut group = Group::new("version against version");

    for version in [Version::V1_1, Version::V2_0, Version::V3_0] {
        let secure = version != Version::V3_0;
        group.load(Workload { secure, connections: MULTIPLEXED, ..Workload::new(format!("{version}, one at a time"), version) });
    }

    for version in [Version::V1_1, Version::V2_0, Version::V3_0] {
        let secure = version != Version::V3_0;
        let name = format!("{version}, 16 in flight");
        group.load(Workload { secure, connections: MULTIPLEXED, depth: DEPTH, ..Workload::new(name, version) });
    }

    for version in [Version::V1_1, Version::V2_0, Version::V3_0] {
        let secure = version != Version::V3_0;
        let name = format!("{version}, a handshake per request");
        group.load(Workload { secure, connections: MULTIPLEXED, reuse: Reuse::Fresh, ..Workload::new(name, version) });
    }
}

/// How the server holds up as more connections are opened against it.
///
/// The work offered per connection is the same throughout, so a throughput that
/// stops climbing says the server is saturated and a p99 that climbs says where
/// the queue went. This is the shape of an evening rather than of a burst: the
/// connections are held, and it is their number that grows.
fn connections() {
    let mut group = Group::new("connection count under load");

    for connections in [1usize, 8, 32, 128, 512] {
        let name = format!("http/1.1, {}", Figure::many(connections, "connection"));
        group.load(Workload { connections, ..Workload::new(name, Version::V1_1) });
    }

    for connections in [1usize, 8, 32, 128] {
        let name = format!("http/2, {}", Figure::many(connections, "connection"));
        group.load(Workload { connections, depth: DEPTH, ..Workload::new(name, Version::V2_0) });
    }
}

/// How deep one connection is driven, which is the other way to offer more.
///
/// The connection count is held at one per core throughout, so what changes is
/// only how many requests each one carries before it reads any answer — which
/// is what multiplexing is for and what pipelining approximates.
fn depth() {
    let mut group = Group::new("request depth under load");

    for depth in [1usize, 4, 16, 64] {
        let name = format!("http/2, {} in flight", depth);
        group.load(Workload { depth, connections: MULTIPLEXED, ..Workload::new(name, Version::V2_0) });
    }

    for depth in [1usize, 4, 16, 64] {
        let name = format!("http/3, {} in flight", depth);
        group.load(Workload { depth, connections: MULTIPLEXED, ..Workload::new(name, Version::V3_0) });
    }
}

fn bodies() {
    let mut group = Group::new("body size under load");

    for (name, octets) in [("13 B", 13usize), ("4 KiB", 4096), ("64 KiB", 65_536), ("1 MiB", 1 << 20)] {
        group.load(Workload { response_body: octets, ..Workload::new(format!("http/1.1, {name} responses"), Version::V1_1) });
    }

    for (name, octets) in [("13 B", 13usize), ("64 KiB", 65_536), ("1 MiB", 1 << 20)] {
        let workload = Workload::new(format!("http/2, {name} responses"), Version::V2_0);
        group.load(Workload { response_body: octets, depth: DEPTH, connections: MULTIPLEXED, ..workload });
    }

    group.load(Workload { request_body: 65_536, ..Workload::new("http/1.1, 64 KiB requests", Version::V1_1) });
    group.load(Workload { request_body: 65_536, depth: 8, connections: MULTIPLEXED, ..Workload::new("http/2, 64 KiB requests", Version::V2_0) });
}

/// How many worker threads the server is given, against how many it is offered.
fn workers() {
    let mut group = Group::new("server workers under load");

    for workers in [1usize, 2, 4, soyokaze::Cluster::cores()] {
        let name = format!("http/1.1 on {}", Figure::many(workers, "worker"));
        group.load(Workload { workers, ..Workload::new(name, Version::V1_1) });
    }

    for workers in [1usize, 2, 4, soyokaze::Cluster::cores()] {
        let name = format!("http/2 on {}", Figure::many(workers, "worker"));
        group.load(Workload { workers, depth: DEPTH, connections: MULTIPLEXED, ..Workload::new(name, Version::V2_0) });
    }
}

/// What a closed loop reaches, which the open-loop runs are set as a share of.
///
/// Measured here rather than taken from a run above, so that the group stands
/// on its own however the run was filtered.
fn capacity() -> f64 {
    let probe = Workload { duration: Duration::from_secs(1), ..Workload::new("capacity", Version::V1_1) };

    Driver::run(probe).rate()
}

/// How long an answer takes when the offered rate is fixed rather than tied to
/// how fast the answers come back.
///
/// A closed loop cannot show a server falling behind: as it slows down, so does
/// the generator, and the queue that would have built never does. Holding the
/// rate fixed and timing each answer from when its request was *due* is what
/// makes that queue visible, which is why the p99 here climbs where the closed
/// loop's stays flat.
fn pacing() {
    let name = "http/1.1 at a fixed offered rate";
    if !Filter::from_env().group(name) {
        return;
    }

    let capacity = capacity();
    let mut group = Group::new(format!("{name} (a closed loop reached {})", Figure::per_second(capacity)));

    for (case, share) in [("half of capacity", 0.5), ("four fifths of capacity", 0.8), ("nine tenths of capacity", 0.9), ("all of capacity", 1.0), ("half again over capacity", 1.5)] {
        group.load(Workload { pacing: Pacing::Open(capacity * share), ..Workload::new(case, Version::V1_1) });
    }
}

/// What every run below was given, said once rather than in each row.
fn preamble() {
    let workload = Workload::new("", Version::V1_1);
    let seconds = workload.duration.as_secs_f64();
    let (clients, workers) = (workload.clients(), workload.workers);

    println!("each run lasts {seconds:.1} s against {workers} server workers, with {clients} clients unless its row says otherwise");
}

fn main() {
    preamble();

    http1();
    http2();
    http3();
    versions();
    connections();
    depth();
    bodies();
    workers();
    pacing();
}
