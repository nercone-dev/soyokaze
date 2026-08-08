//! The benchmark harness.
//!
//! A benchmark is a [`Group`] of [`Case`]s. Each case is measured under a
//! [`Budget`], the measurement is held as a [`Measure`], and a [`Report`]
//! writes it out. [`Filter`] decides which of them run, [`Fixtures`] holds the
//! messages they are measured over, and [`load`] drives a real server over a
//! loopback port for the runs that measure a whole stack rather than a piece
//! of one.
//!
//! Every part is configurable from the environment, so a run can be made quick
//! or thorough without touching a benchmark:
//!
//! | Variable                  | What it sets                            |
//! |---------------------------|-----------------------------------------|
//! | `SOYOKAZE_BENCH_TIME`     | Seconds each case is measured for       |
//! | `SOYOKAZE_BENCH_FORMAT`   | `table` or `json`                       |
//! | `SOYOKAZE_BENCH_ONLY`     | Which groups and cases run              |
//! | `SOYOKAZE_LOAD_TIME`      | Seconds each load run lasts             |
//! | `SOYOKAZE_LOAD_SCALE`     | Multiplier on every load run's clients  |

#![allow(dead_code, unused_imports)]

pub mod alloc;
pub mod budget;
pub mod case;
pub mod figure;
pub mod filter;
pub mod fixtures;
pub mod load;
pub mod measure;
pub mod report;
pub mod sample;

pub use alloc::Counter;
pub use budget::Budget;
pub use case::{Case, Group};
pub use figure::Figure;
pub use filter::Filter;
pub use fixtures::{Fixtures, Payload, Section, Wire};
pub use measure::Measure;
pub use report::Report;
pub use sample::{Sample, Samples};
