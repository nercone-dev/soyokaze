//! What the shared parts cost when every worker reaches for them at once.
//!
//! A server runs one worker per core and they share very little on purpose —
//! but what they do share, they share completely: one gate counts every
//! connection, one cookie jar holds every cookie, one HSTS store remembers
//! every host, one date cache formats the field every response carries. Each of
//! these is fast on its own, and each is behind a lock, and a lock that is fast
//! on one thread can give back everything the other cores were meant to add.
//!
//! Every case is measured twice in the same run: once alone, and once on every
//! thread count the machine can offer. `alone` and `together` are the same call
//! under the two conditions, `rate` is what all the threads manage between
//! them, and `kept` is the share of one thread's speed each thread still has —
//! 100 % is perfect scaling, and anything far below it is the structure taking
//! back what the threads brought.
//!
//! ```bash
//! cargo bench --bench concurrency
//! cargo bench --bench concurrency -- gate
//! SOYOKAZE_BENCH_THREADS="1 8 32" cargo bench --bench concurrency
//! ```

mod support;

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use soyokaze::api::gate::Gate;
use soyokaze::cookies::CookieJar;
use soyokaze::helpers::sync::Lock;
use soyokaze::hsts::HSTSStore;
use soyokaze::models::URL;
use soyokaze::{Cluster, DateCache};

use support::{Contention, Figure, Group};

/// The `Set-Cookie` every jar case stores.
const SET_COOKIE: &str = "session=8f14e45fceea167a5a36dedd4bea2543; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax";

/// The origin every cookie case is measured against.
fn origin() -> URL {
    URL::parse("https://www.example.com/index.html").expect("the fixture URL did not parse")
}

/// The address at this position, so that a case can spread its load over
/// addresses the way a real one is spread.
fn address(index: u64) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from((index as u32).wrapping_add(0xc000_0200)))
}

/// What the machine can actually run at once, said before anything is
/// measured, since every `kept` below is read against it.
fn preamble() {
    let counts: Vec<String> = Contention::counts().iter().map(usize::to_string).collect();

    println!("{} on this machine; measuring at {} threads", Figure::many(Cluster::cores(), "core"), counts.join(", "));
}

/// The floor every other group is read against.
///
/// An atomic that every thread writes and a mutex that every thread takes,
/// with nothing under either. Whatever these lose is what the machine loses to
/// sharing one cache line, and no structure below can do better.
fn floor() {
    let mut group = Group::new("the floor under a shared structure");

    let counter = AtomicU64::new(0);
    group.contention("an atomic every thread adds to", || black_box(&counter).fetch_add(1, Ordering::Relaxed));

    let mutex = Mutex::new(0u64);
    group.contention("a mutex every thread takes", || {
        let mut held = Lock::on(black_box(&mutex));
        *held += 1;
    });

    let read = AtomicU64::new(1);
    group.contention("an atomic every thread only reads", || black_box(&read).load(Ordering::Relaxed));
}

/// Admission control, which every connection crosses before anything else.
///
/// This is the one shared structure a flood reaches on purpose: the whole
/// point of a gate is to be there when a great many connections arrive at once,
/// so what it costs under exactly that is not a detail.
fn admission() {
    let mut group = Group::new("api::Gate under threads");

    let gate = Gate::new(0, 0, Vec::new(), 0);
    group.contention("admit and release, no limits, one address", || drop(black_box(&gate).admit(Some(address(0)), Instant::now())));

    let gate = Gate::new(0, 0, Vec::new(), 0);
    group.contention("admit and release, no limits, no address", || drop(black_box(&gate).admit(None, Instant::now())));

    // Counted but not rate limited: a rate-limited admit writes into the very
    // window it is checked against, so a loop measuring one measures a window
    // the loop itself filled. The rate limiter's own path is below, where a
    // refusal records nothing and the state stands still.
    let gate = Gate::new(0, 1_000_000, Vec::new(), 0);
    let next = AtomicU64::new(0);
    group.contention("admit and release, a per-address ceiling, a fresh address each time", || {
        let index = next.fetch_add(1, Ordering::Relaxed);
        drop(black_box(&gate).admit(Some(address(index % 4096)), Instant::now()))
    });

    let gate = Gate::new(0, 1_000_000, Vec::new(), 0);
    group.contention("admit and release, a per-address ceiling, one address", || drop(black_box(&gate).admit(Some(address(0)), Instant::now())));

    let spent = Gate::new(0, 0, vec![(60.0, 1_000)], 16);
    let now = Instant::now();
    for _ in 0..1_000 {
        drop(spent.admit(Some(address(0)), now));
    }
    group.contention("refuse, a rate limit already spent", || black_box(&spent).admit(Some(address(0)), Instant::now()).is_some());

    let gate = Gate::new(1, 0, Vec::new(), 0);
    let held = gate.admit(Some(address(0)), Instant::now()).expect("the first connection was refused");
    group.contention("refuse at the ceiling", || black_box(&gate).admit(Some(address(0)), Instant::now()).is_some());
    drop(held);
}

/// The date a response carries.
///
/// One field on every response a server sends, formatted once a second and
/// read the rest of the time — so the read path is taken by every worker on
/// every response, which makes it the most trafficked shared structure here.
fn dates() {
    let mut group = Group::new("finalizer::DateCache under threads");
    let cache = DateCache::new();

    group.contention("now (within the cached second)", || black_box(&cache).now());
    group.contention("format (no cache at all)", || DateCache::format(black_box(1_382_386_401)));
}

/// The client-side stores, which a client shares across every connection it
/// holds open.
fn client_state() {
    let mut group = Group::new("cookies::CookieJar under threads");
    let jar = CookieJar::new();
    let url = origin();
    jar.learn(&url, &[SET_COOKIE], Instant::now());

    group.contention("cookie (one stored)", || black_box(&jar).cookie(&origin(), Instant::now()));

    let filling = CookieJar::new();
    group.contention("learn (one cookie)", || black_box(&filling).learn(&origin(), &[SET_COOKIE], Instant::now()));

    let stocked = CookieJar::new();
    for index in 0..64 {
        stocked.learn(&url, &[&format!("name{index}=value{index}; Path=/")], Instant::now());
    }
    group.contention("cookie (64 stored)", || black_box(&stocked).cookie(&origin(), Instant::now()));

    let mut group = Group::new("hsts::HSTSStore under threads");
    let store = HSTSStore::new();
    store.learn("www.example.com", "max-age=31536000; includeSubDomains", true, Instant::now());

    group.contention("secure (an exact match)", || black_box(&store).secure("www.example.com", Instant::now()));
    group.contention("secure (a host never seen)", || black_box(&store).secure("other.example", Instant::now()));

    let filling = HSTSStore::new();
    let next = AtomicU64::new(0);
    group.contention("learn (a fresh host each time)", || {
        let index = next.fetch_add(1, Ordering::Relaxed);
        black_box(&filling).learn(&format!("host{}.example", index % 4096), "max-age=31536000", true, Instant::now())
    });
}

/// The allocator, which every layer reaches for and none of them shares on
/// purpose.
///
/// Nothing in this crate locks around an allocation, but every worker allocates
/// on every request, so whatever the allocator gives back under threads is
/// spent by all of them. It is a floor rather than a finding.
fn allocating() {
    let mut group = Group::new("the allocator under threads");

    group.contention("one small allocation", || black_box(Vec::<u8>::with_capacity(64)));
    group.contention("one page-sized allocation", || black_box(Vec::<u8>::with_capacity(4096)));
    group.contention("a growth from small to large", || {
        let mut held: Vec<u8> = Vec::with_capacity(16);
        held.resize(black_box(4096), 0);
        held
    });
}

fn main() {
    if Group::new("the floor under a shared structure").wanted() {
        preamble();
    }

    floor();
    admission();
    dates();
    client_state();
    allocating();
}
