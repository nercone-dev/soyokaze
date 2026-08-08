//! Driving a workload against a server, and what comes of it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use soyokaze::models::{Body, Port};
use soyokaze::protocol::base::{AnyConnection, Connection};
use soyokaze::Client;

use crate::support::load::latency::Latency;
use crate::support::load::target::{Certificate, Target};
use crate::support::load::workload::{Reuse, Workload};

/// What came of a run, from one virtual client or from all of them.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// How many requests were answered.
    pub completed: u64,

    /// How many were not: refused, timed out, or cut off part way.
    pub failed: u64,

    /// How many body octets came back.
    pub octets: u64,

    /// How long the answers took.
    pub latency: Latency,
}

impl Outcome {
    /// An outcome with nothing in it yet.
    pub fn new() -> Self {
        Self { completed: 0, failed: 0, octets: 0, latency: Latency::new() }
    }

    /// Records one answered request.
    pub fn answered(&mut self, octets: usize, taken: Duration) {
        self.completed += 1;
        self.octets += octets as u64;
        self.latency.record(taken);
    }

    /// Records this many requests that were never answered.
    pub fn lost(&mut self, requests: u64) {
        self.failed += requests;
    }

    /// Folds another client's outcome into this one.
    pub fn merge(&mut self, other: &Self) {
        self.completed += other.completed;
        self.failed += other.failed;
        self.octets += other.octets;
        self.latency.merge(&other.latency);
    }

    /// How many requests were offered, answered or not.
    pub fn offered(&self) -> u64 {
        self.completed + self.failed
    }
}

/// One load run: what was offered, and what came back.
#[derive(Debug, Clone)]
pub struct Run {
    /// What was asked for.
    pub workload: Workload,

    /// What came of asking for it.
    pub outcome: Outcome,

    /// How long the run took, wall clock.
    pub elapsed: Duration,
}

impl Run {
    /// How many requests were answered per second.
    pub fn rate(&self) -> f64 {
        match self.elapsed.as_secs_f64() {
            seconds if seconds > 0.0 => self.outcome.completed as f64 / seconds,
            _ => 0.0,
        }
    }

    /// How many body octets came back per second.
    pub fn bandwidth(&self) -> f64 {
        match self.elapsed.as_secs_f64() {
            seconds if seconds > 0.0 => self.outcome.octets as f64 / seconds,
            _ => 0.0,
        }
    }

    /// The share of offered requests that were never answered.
    pub fn failures(&self) -> f64 {
        match self.outcome.offered() {
            0 => 0.0,
            offered => self.outcome.failed as f64 / offered as f64,
        }
    }
}

/// Runs a workload against a server of its own.
///
/// Each run stands its own server up on an ephemeral loopback port, drives it,
/// and takes it down again, so one run never inherits another's connections,
/// caches or worker threads.
pub struct Driver;

impl Driver {
    /// Starts a target, drives the workload against it, and stops it.
    pub fn run(workload: Workload) -> Run {
        let target = Target::start(&workload);
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime for the load driver");

        let started = Instant::now();
        let outcome = runtime.block_on(Self::drive(&target, &workload));
        let elapsed = started.elapsed();

        target.stop();

        Run { workload, outcome, elapsed }
    }

    /// Runs every virtual client at once and folds their outcomes together.
    pub async fn drive(target: &Target, workload: &Workload) -> Outcome {
        let client = Arc::new(target.client(workload));
        let workload = Arc::new(workload.clone());
        let port = target.port(&workload);
        let start = Instant::now();

        let mut running = Vec::with_capacity(workload.clients());
        for _ in 0..workload.clients() {
            running.push(tokio::spawn(Self::client(client.clone(), workload.clone(), port.clone(), start)));
        }

        let mut outcome = Outcome::new();
        for client in running {
            outcome.merge(&client.await.expect("a virtual client stopped short"));
        }

        outcome
    }

    /// What one virtual client does for the length of the run.
    pub async fn client(client: Arc<Client>, workload: Arc<Workload>, port: Port, start: Instant) -> Outcome {
        let deadline = start + workload.duration;

        let mut outcome = Outcome::new();
        let mut connection: Option<AnyConnection> = None;
        let mut sent = 0u64;

        while Instant::now() < deadline {
            if let Some(due) = workload.due(start, sent + workload.inflight() as u64 - 1) {
                if due >= deadline {
                    break;
                }

                tokio::time::sleep_until(due.into()).await;
            }

            let issued = Instant::now();

            if connection.is_none() {
                connection = Self::dial(&client, &port, &workload).await;
            }

            let kept = match connection.as_mut() {
                Some(open) => Self::round(&workload, open, start, sent, issued, &mut outcome).await,
                None => {
                    outcome.lost(workload.inflight() as u64);
                    false
                }
            };

            sent += workload.inflight() as u64;

            if !kept || workload.reuse == Reuse::Fresh {
                Self::hang_up(connection.take()).await;
            }
        }

        Self::hang_up(connection.take()).await;
        outcome
    }

    /// Opens one connection to the target, or nothing when it will not open.
    pub async fn dial(client: &Client, port: &Port, workload: &Workload) -> Option<AnyConnection> {
        tokio::time::timeout(workload.timeout, client.connect(Certificate::NAME, port.clone())).await.ok()?.ok()
    }

    /// Sends one round of requests and reads their answers.
    ///
    /// Answers are matched to requests in the order the requests went out,
    /// which is exact while a version answers in order and, where one does not,
    /// still gives the right spread over requests this alike. Each answer is
    /// timed from when its request was due rather than from when it went out,
    /// so an open-loop run charges the server for a queue it builds rather than
    /// letting the queue slow the generator down instead.
    ///
    /// Returns whether the connection is still worth keeping.
    pub async fn round(workload: &Workload, connection: &mut AnyConnection, start: Instant, sent: u64, issued: Instant, outcome: &mut Outcome) -> bool {
        let round = workload.inflight();
        let mut inflight = 0usize;

        for _ in 0..round {
            match tokio::time::timeout(workload.timeout, connection.send(workload.request())).await {
                Ok(Ok(())) => inflight += 1,
                _ => break,
            }
        }

        outcome.lost((round - inflight) as u64);

        for index in 0..inflight {
            let due = workload.due(start, sent + index as u64).unwrap_or(issued);

            match tokio::time::timeout(workload.timeout, connection.receive()).await {
                Ok(Ok(response)) => outcome.answered(response.body.as_ref().and_then(Body::len).unwrap_or(0), due.elapsed()),
                _ => {
                    outcome.lost((inflight - index) as u64);
                    return false;
                }
            }
        }

        inflight == round
    }

    /// Closes a connection, if there is one still open.
    pub async fn hang_up(held: Option<AnyConnection>) {
        if let Some(mut open) = held {
            open.close().await;
        }
    }
}
