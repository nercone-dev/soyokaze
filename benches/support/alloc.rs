//! Counting what the allocator is asked for.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

/// How many times [`Counter`] has been asked for memory since the process
/// started.
static CALLS: AtomicU64 = AtomicU64::new(0);

/// How many octets it was asked for over those calls.
static OCTETS: AtomicU64 = AtomicU64::new(0);

/// What something cost the allocator: how many times it was reached for, and
/// how much it was asked for.
///
/// The two are separate questions and a change moves them separately. A buffer
/// that is grown once instead of four times costs three fewer calls and the
/// same octets; a body held twice over costs the same calls and twice the
/// octets. Reporting one without the other hides half of what a request costs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cost {
    /// How many times the allocator was reached for.
    pub calls: u64,

    /// How many octets it was asked for, over those calls.
    pub octets: u64,
}

impl Cost {
    /// A cost of this many calls and this many octets.
    pub fn new(calls: u64, octets: u64) -> Self {
        Self { calls, octets }
    }

    /// What was spent between an earlier reading and this one.
    pub fn since(&self, before: &Self) -> Self {
        Self::new(self.calls.saturating_sub(before.calls), self.octets.saturating_sub(before.octets))
    }

    /// Folds another cost into this one.
    pub fn merge(&mut self, other: &Self) {
        self.calls += other.calls;
        self.octets += other.octets;
    }

    /// Whether nothing was asked for at all.
    pub fn is_empty(&self) -> bool {
        self.calls == 0 && self.octets == 0
    }
}

/// A global allocator that counts every allocation it is asked for.
///
/// It has to be installed by the benchmark that wants it, since only a binary
/// can name a global allocator:
///
/// ```ignore
/// #[global_allocator]
/// static ALLOCATOR: Counter = Counter;
/// ```
///
/// Everywhere else [`Counter::count`] reads zero, because nothing is counting;
/// [`Counter::installed`] says which of the two a benchmark is looking at.
///
/// A free is not counted at all, and what is counted for a growth is the size
/// asked for rather than the difference: what a per-request measurement is
/// after is what the round demanded, not what the allocator happened to have
/// lying next to it.
pub struct Counter;

unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::charge(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::charge(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        Self::charge(size);
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

impl Counter {
    /// Records one request for this many octets.
    pub fn charge(octets: usize) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        OCTETS.fetch_add(octets as u64, Ordering::Relaxed);
    }

    /// What has been asked for since the process started.
    pub fn total() -> Cost {
        Cost::new(CALLS.load(Ordering::Relaxed), OCTETS.load(Ordering::Relaxed))
    }

    /// What a body costs the allocator.
    pub fn count<T>(body: impl FnOnce() -> T) -> Cost {
        let before = Self::total();
        std::hint::black_box(body());
        Self::total().since(&before)
    }

    /// Whether this binary installed the counting allocator.
    pub fn installed() -> bool {
        !Self::count(|| Vec::<u8>::with_capacity(64)).is_empty()
    }
}
