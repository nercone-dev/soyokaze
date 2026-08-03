//! Admission control for incoming connections.
//!
//! A [`Gate`] decides whether a connection may proceed before a handler is
//! reached, so a refused connection costs a handshake and nothing more; a
//! [`Permit`] is a connection's claim on a slot, given back when it drops.
//! Nothing here knows about HTTP or the server around it — it counts
//! connections by address and by rate, and that is all.

use std::sync::Arc;

use crate::helpers::sync::lock;

/// The per-address bookkeeping a [`Gate`] keeps behind its lock.
pub struct GateState {
    /// How many connections each address currently holds.
    pub per_ip: std::collections::HashMap<std::net::IpAddr, u32>,
    /// When each address last connected, within the rate window.
    pub history: std::collections::HashMap<std::net::IpAddr, std::collections::VecDeque<std::time::Instant>>,
}

/// Admission control for incoming connections.
///
/// Checked before a handler is reached, so a refused connection costs a
/// handshake and nothing more. Shared across every listener and worker, so the
/// totals are for the server as a whole rather than per port.
///
/// The total count is an atomic, since every connection touches it; the
/// per-address tallies sit behind a lock, since they are only consulted for a
/// connection whose address is known.
pub struct Gate {
    /// The connections that may be open at once. Zero is unbounded.
    pub max_connections: u32,
    /// The connections one address may have open. Zero is unbounded.
    pub max_connections_per_ip: u32,
    /// Rate limits as `[(period in seconds, count), ...]`.
    pub max_connection_rate: Vec<(f64, u32)>,
    /// The addresses whose history is remembered.
    pub max_connection_history: usize,

    /// The longest period in [`Gate::max_connection_rate`], which is how far
    /// back history has to be kept.
    pub window: f64,

    /// How many connections are open right now.
    pub connections: std::sync::atomic::AtomicU32,
    /// The per-address bookkeeping.
    pub state: std::sync::Mutex<GateState>,
}

impl Gate {
    /// A gate with these limits.
    pub fn new(max_connections: u32, max_connections_per_ip: u32, max_connection_rate: Vec<(f64, u32)>, max_connection_history: usize) -> Arc<Self> {
        Arc::new(Self {
            window: max_connection_rate.iter().map(|(period, _)| *period).fold(0.0, f64::max),
            max_connections,
            max_connections_per_ip,
            max_connection_rate,
            max_connection_history,
            connections: std::sync::atomic::AtomicU32::new(0),
            state: std::sync::Mutex::new(GateState {
                per_ip: std::collections::HashMap::new(),
                history: std::collections::HashMap::new(),
            }),
        })
    }

    /// How many connections are open right now.
    pub fn count(&self) -> u32 {
        self.connections.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The longest rate limit period, and so how far back history is kept.
    pub fn window(&self) -> f64 {
        self.window
    }

    /// Admits a connection, or refuses it.
    ///
    /// `None` means turn the connection away. A [`Permit`] means it may
    /// proceed, and releases its slot when dropped — so holding the permit for
    /// as long as the connection lives is what keeps the count honest.
    ///
    /// An `ip` of `None` skips the per-address checks; a Unix socket has no
    /// address to limit by.
    pub fn admit(self: &Arc<Self>, ip: Option<std::net::IpAddr>, now: std::time::Instant) -> Option<Permit> {
        use std::sync::atomic::Ordering;

        loop {
            let current = self.connections.load(Ordering::Acquire);
            if self.max_connections != 0 && current >= self.max_connections {
                return None;
            }
            if self
                .connections
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        if let Some(ip) = ip {
            let mut state = lock(&self.state);

            let count = state.per_ip.get(&ip).copied().unwrap_or(0);
            let over_ip = self.max_connections_per_ip != 0 && count >= self.max_connections_per_ip;

            if over_ip || !self.rate(&mut state, ip, now) {
                drop(state);
                self.connections.fetch_sub(1, Ordering::AcqRel);
                return None;
            }

            self.bound_history(&mut state, ip);
            *state.per_ip.entry(ip).or_insert(0) += 1;
        }

        Some(Permit { gate: Arc::clone(self), ip })
    }

    /// Whether an address is within every rate limit, recording the attempt
    /// when it is.
    ///
    /// Entries older than the longest window are dropped as they are found.
    pub fn rate(&self, state: &mut GateState, ip: std::net::IpAddr, now: std::time::Instant) -> bool {
        let window = self.window();
        let record = state.history.entry(ip).or_default();

        while record.front().is_some_and(|front| now.duration_since(*front).as_secs_f64() > window) {
            record.pop_front();
        }

        for &(period, count) in &self.max_connection_rate {
            let recent = record.iter().filter(|at| now.duration_since(**at).as_secs_f64() <= period).count() as u32;
            if recent >= count {
                return false;
            }
        }

        record.push_back(now);
        true
    }

    /// Bounds how many addresses are remembered, never evicting `keep`.
    ///
    /// Without this, a flood from many addresses would grow the history
    /// without bound — the rate limiter itself becoming the way in.
    pub fn bound_history(&self, state: &mut GateState, keep: std::net::IpAddr) {
        let cap = self.max_connection_history.max(self.max_connections as usize);

        while state.history.len() > cap {
            let Some(victim) = state.history.keys().find(|address| **address != keep).copied() else {
                break;
            };
            state.history.remove(&victim);
        }
    }

    /// Gives a connection's slot back.
    ///
    /// Called by [`Permit`] on drop; there is rarely a reason to call it
    /// directly, and doing so alongside a live permit would double-count.
    pub fn release(&self, ip: Option<std::net::IpAddr>) {
        self.connections.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);

        if let Some(ip) = ip {
            let mut state = lock(&self.state);
            if let Some(count) = state.per_ip.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_ip.remove(&ip);
                }
            }
        }
    }

    /// Drops rate history that has aged out.
    ///
    /// [`Gate::admit`] prunes as it goes, so this is only needed to reclaim
    /// memory on a server that has gone quiet.
    pub fn sweep(&self, now: std::time::Instant) {
        let window = self.window();
        let mut state = lock(&self.state);

        state.history.retain(|_, record| {
            while record.front().is_some_and(|front| now.duration_since(*front).as_secs_f64() > window) {
                record.pop_front();
            }
            !record.is_empty()
        });
    }
}

/// A connection's claim on a [`Gate`] slot.
///
/// Holding it is what keeps the connection counted; dropping it gives the slot
/// back. Keep it alive for as long as the connection is.
pub struct Permit {
    /// The gate the slot belongs to.
    pub gate: Arc<Gate>,
    /// The address the slot was counted against, if any.
    pub ip: Option<std::net::IpAddr>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.release(self.ip);
    }
}
