//! The benchmark harness.
//!
//! A benchmark is a [`Group`] of [`Case`]s. Each case is measured one way —
//! timed, counted, swept over sizes, run on several threads, or driven over a
//! socket — and what came of it is a [`Measure`], which a [`Report`] writes
//! out. [`Filter`] decides which of them run, [`Fixtures`] holds the messages
//! they are measured over, and [`load`] drives a real server over a loopback
//! port for the runs that measure a whole stack rather than a piece of one.
//!
//! # Ways of measuring
//!
//! Every part of the library is worth more than one question, and the harness
//! answers each with a measurement of its own:
//!
//! | Method               | Held as              | What it answers                     |
//! |----------------------|----------------------|-------------------------------------|
//! | [`Group::time`]      | [`Samples`]          | How long does one call take?        |
//! | [`Group::throughput`]| [`Samples`]          | How fast does it get through octets?|
//! | [`Group::footprint`] | [`Footprint`]        | What does it cost the allocator?    |
//! | [`Group::growth`]    | [`Growth`]           | Does it stay bounded as input grows?|
//! | [`Group::contention`]| [`Contention`]       | What survives many threads?         |
//! | [`Group::load`]      | [`load::Run`]        | What does the whole stack come to?  |
//!
//! # Configuring a run
//!
//! Every part is configurable from the environment, so a run can be made quick
//! or thorough without touching a benchmark:
//!
//! | Variable                  | What it sets                            |
//! |---------------------------|-----------------------------------------|
//! | `SOYOKAZE_BENCH_TIME`     | Seconds each case is measured for       |
//! | `SOYOKAZE_BENCH_FORMAT`   | `table` or `json`                       |
//! | `SOYOKAZE_BENCH_ONLY`     | Which groups and cases run              |
//! | `SOYOKAZE_BENCH_THREADS`  | Which thread counts a contention sweep runs at |
//! | `SOYOKAZE_LOAD_TIME`      | Seconds each load run lasts             |
//! | `SOYOKAZE_LOAD_SCALE`     | Multiplier on every load run's clients  |

#![allow(dead_code, unused_imports)]

pub mod alloc;
pub mod budget;
pub mod case;
pub mod contention;
pub mod figure;
pub mod filter;
pub mod fixtures;
pub mod footprint;
pub mod growth;
pub mod load;
pub mod measure;
pub mod report;
pub mod sample;

pub use alloc::{Cost, Counter};
pub use budget::Budget;
pub use case::{Case, Group};
pub use contention::Contention;
pub use figure::Figure;
pub use filter::Filter;
pub use fixtures::{Fixtures, Payload, Section, Wire};
pub use footprint::Footprint;
pub use growth::{Growth, Point};
pub use measure::Measure;
pub use report::Report;
pub use sample::{Sample, Samples};
