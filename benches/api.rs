//! The server's front door, and what a process pays to open it.
//!
//! Two costs live here and they are nothing alike. [`Gate`] is paid once per
//! connection, on the accept path, before anything has been read — so it is on
//! the critical path of every connection a flood opens, and it is the one piece
//! of the server whose job is to stay cheap exactly when it is being hammered.
//! Standing a [`Cluster`] up is paid once per process, and what it bounds is
//! how quickly a server starts, reloads and gets out of the way.
//!
//! The gate is measured on the shapes a flood really has: one address opening
//! everything, many addresses opening one each, and a history already full of
//! addresses that have gone away. What the same calls cost from every worker at
//! once is in `--bench concurrency`.
//!
//! ```bash
//! cargo bench --bench api
//! cargo bench --bench api -- gate
//! ```

mod support;

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use soyokaze::api::gate::Gate;
use soyokaze::models::{Port, Version};
use soyokaze::{Client, ClientConfig, Cluster, Server, ServerConfig, ServerLimits};

use support::load::{Certificate, Responder};
use support::{Figure, Fixtures, Group};

/// The address a case that is not varying addresses uses.
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// The address at this position in a sweep, so that a case walking many of them
/// walks distinct ones.
fn address(index: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from((index as u32).wrapping_add(0xc000_0200)))
}

/// A gate with no limits at all, which is the floor every other one is read
/// against.
fn open() -> Arc<Gate> {
    Gate::new(0, 0, Vec::new(), 0)
}

/// A gate counting how many connections one address holds, and nothing else.
///
/// No rate limit, so an admit records no history — which is what makes it
/// measurable: a rate-limited admit writes into the window it is checked
/// against, so measuring one repeatedly measures a window the measurement
/// itself filled.
fn counted() -> Arc<Gate> {
    Gate::new(0, 1_000_000, Vec::new(), 0)
}

/// A gate whose rate window for one address is already spent.
///
/// The shape a flood really presents: an address that has used its allowance
/// and keeps dialling anyway. The next attempt is refused, and a refusal
/// records nothing — so this is the one rate-limited path that can be measured
/// without the measurement changing it.
fn saturated(recorded: usize) -> Arc<Gate> {
    let gate = Gate::new(0, 0, vec![(60.0, recorded.max(1) as u32)], 16);
    let now = Instant::now();

    for _ in 0..recorded.max(1) {
        drop(gate.admit(Some(CLIENT), now));
    }

    gate
}

/// A gate whose history already holds this many addresses, and will hold no
/// more.
///
/// Populated to its own ceiling, so admitting one more address evicts one and
/// the history stays exactly this size however long a case runs against it.
fn capped(addresses: usize) -> Arc<Gate> {
    let gate = Gate::new(0, 0, vec![(60.0, 1_000_000)], addresses);
    let now = Instant::now();

    for index in 0..addresses {
        drop(gate.admit(Some(address(index)), now));
    }

    gate
}

fn admission() {
    let mut group = Group::new("api::Gate");
    let now = Instant::now();

    let gate = open();
    group.time("admit and release (no limits)", || drop(black_box(&gate).admit(Some(CLIENT), now)));
    group.time("admit and release (no address)", || drop(black_box(&gate).admit(None, now)));

    let gate = counted();
    group.time("admit and release (a per-address ceiling)", || drop(black_box(&gate).admit(Some(CLIENT), now)));

    let gate = Gate::new(1, 0, Vec::new(), 0);
    let held = gate.admit(Some(CLIENT), now).expect("the first connection was refused");
    group.time("refuse (the connection ceiling)", || black_box(&gate).admit(Some(CLIENT), now).is_some());
    drop(held);

    let gate = Gate::new(0, 1, Vec::new(), 16);
    let held = gate.admit(Some(CLIENT), now).expect("the first connection was refused");
    group.time("refuse (the per-address ceiling)", || black_box(&gate).admit(Some(CLIENT), now).is_some());
    drop(held);

    let gate = saturated(1);
    group.time("refuse (a rate limit of one)", || black_box(&gate).admit(Some(CLIENT), now).is_some());

    let gate = saturated(1_000);
    group.time("refuse (a rate limit of 1000, already spent)", || black_box(&gate).admit(Some(CLIENT), now).is_some());

    let gate = counted();
    group.time("count", || black_box(&gate).count());
    group.time("sweep (an empty history)", || black_box(&gate).sweep(now));

    let gate = capped(1_000);
    group.time("sweep (1000 addresses remembered)", || black_box(&gate).sweep(Instant::now()));

    // A flood is many addresses dialling many times, and the two structures
    // that remember them are exactly where a per-connection cost could turn
    // into a per-flood one. Both curves are taken over a state the case holds
    // still: a refusal records nothing, and a history at its ceiling evicts one
    // address for every one it takes, so neither sweep moves what it measures.
    let mut group = Group::new("api::Gate growth");
    group.growth("refuse, over how much of the window is spent", Fixtures::COUNTS, saturated, |gate| {
        black_box(&*gate).admit(Some(CLIENT), Instant::now()).is_some()
    });
    group.growth("sweep, over the addresses remembered", Fixtures::COUNTS, capped, |gate| black_box(&*gate).sweep(Instant::now()));
    group.growth("admit a new address, over the addresses remembered", Fixtures::COUNTS, |count| (capped(count), count), |(gate, count)| {
        *count += 1;
        black_box(&*gate).admit(Some(address(*count)), Instant::now()).is_some()
    });
}

/// What a client and a server cost to configure, before either has opened
/// anything.
fn configuring() {
    let certificate = Certificate::localhost();

    let mut group = Group::new("api configuration");
    group.time("ClientConfig::default", || ClientConfig::default());
    group.time("ServerConfig::default", || ServerConfig::default());
    group.time("ServerLimits::default", || ServerLimits::default());
    group.time("ServerLimits::gate", || black_box(&ServerLimits::default()).gate());

    group.time("Client::new (plaintext)", || {
        Client::new(ClientConfig { secure: false, versions: vec![Version::V1_1], ..ClientConfig::default() })
    });

    group.time("Client::new (TLS, one root)", || {
        Client::new(ClientConfig { roots: Some(certificate.roots()), versions: vec![Version::V1_1], ..ClientConfig::default() })
    });

    group.time("Server::new (plaintext)", || Server::new(ServerConfig { versions: vec![Version::V1_1], ..ServerConfig::default() }));

    group.time("Server::new (TLS)", || {
        Server::new(ServerConfig {
            versions: vec![Version::V1_1],
            identity: Some(certificate.identity()),
            ..ServerConfig::default()
        })
    });
}

/// Standing a server up on a loopback port and taking it down again.
///
/// Once per process rather than once per request, so what it says is how fast
/// a server starts — which is how long a restart takes to stop refusing
/// connections, and how long a test suite spends before it measures anything.
fn starting() {
    let mut group = Group::new("api::Cluster");

    for workers in [1usize, 2, 4, Cluster::cores()] {
        let name = format!("start and stop on {}", Figure::many(workers, "worker"));

        if !group.wants(&name) {
            continue;
        }

        group.time(&name, || {
            let server = Server::new(ServerConfig { versions: vec![Version::V1_1], ..ServerConfig::default() });
            let cluster = server.run(Responder::new(13), &[Port::TCP(0)], workers).expect("the server did not bind");
            cluster.close(Some(1.0));
        });
    }

    let certificate = Certificate::localhost();
    group.time("start and stop, TLS", || {
        let server = Server::new(ServerConfig {
            versions: vec![Version::V1_1],
            identity: Some(certificate.identity()),
            ..ServerConfig::default()
        });

        let cluster = server.run(Responder::new(13), &[Port::TCP(0)], 1).expect("the server did not bind");
        cluster.close(Some(1.0));
    });

    group.time("start and stop, QUIC", || {
        let server = Server::new(ServerConfig {
            versions: vec![Version::V3_0],
            identity: Some(certificate.identity()),
            ..ServerConfig::default()
        });

        let cluster = server.run(Responder::new(13), &[Port::QUIC(0)], 1).expect("the server did not bind");
        cluster.close(Some(1.0));
    });

    group.growth("start and stop, over the workers", &[1, 2, 4, 8], |workers| workers, |workers| {
        let server = Server::new(ServerConfig { versions: vec![Version::V1_1], ..ServerConfig::default() });
        let cluster = server.run(Responder::new(13), &[Port::TCP(0)], *workers).expect("the server did not bind");
        cluster.close(Some(1.0));
    });
}

fn main() {
    admission();
    configuring();
    starting();
}
