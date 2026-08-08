//! Driving a real server under load.
//!
//! A [`Workload`] says what to offer, a [`Target`] is the server it is offered
//! to, [`Driver`] offers it, and a [`Run`] is what came of it: how many
//! requests were answered, how many were not, and a [`Latency`] distribution
//! over the ones that were.
//!
//! Everything crosses a real loopback socket, through the same accept path, the
//! same negotiation and the same connection types a served request crosses, so
//! what this measures is the stack rather than a piece of it. What it does not
//! measure is a network: a loopback run has no propagation delay, no loss and
//! no reordering, so the latencies below are a floor and not a forecast.

pub mod driver;
pub mod latency;
pub mod target;
pub mod workload;

pub use driver::{Driver, Outcome, Run};
pub use latency::Latency;
pub use target::{Certificate, Responder, Target};
pub use workload::{Pacing, Reuse, Workload};
