//! Counting what the allocator is asked for.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

/// How many allocations have gone through [`Counter`] since the process
/// started.
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

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
/// Only the requests are counted, not the octets, and a free is not counted at
/// all: what a per-request measurement is after is how many times the
/// allocator was reached for, which is the part that does not scale with the
/// size of what was asked for.
pub struct Counter;

unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

impl Counter {
    /// How many allocations have been made since the process started.
    pub fn total() -> u64 {
        ALLOCATIONS.load(Ordering::Relaxed)
    }

    /// How many allocations a body makes.
    pub fn count<T>(body: impl FnOnce() -> T) -> u64 {
        let before = Self::total();
        std::hint::black_box(body());
        Self::total() - before
    }

    /// Whether this binary installed the counting allocator.
    pub fn installed() -> bool {
        Self::count(|| Vec::<u8>::with_capacity(64)) > 0
    }
}
