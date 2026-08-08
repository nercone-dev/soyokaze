//! One measured case, and the group it is reported in.

use crate::support::budget::Budget;
use crate::support::filter::Filter;
use crate::support::load::driver::{Driver, Run};
use crate::support::load::workload::Workload;
use crate::support::measure::Measure;
use crate::support::report::Report;

/// One measured case: what it is called, and what came of measuring it.
#[derive(Debug, Clone)]
pub struct Case {
    /// What the case is called, within its group.
    pub name: String,

    /// What was measured, and what the numbers mean.
    pub measure: Measure,
}

impl Case {
    /// A case holding an already-taken measurement.
    pub fn new(name: impl Into<String>, measure: Measure) -> Self {
        Self { name: name.into(), measure }
    }
}

/// A named set of cases, measured under one budget and reported together.
///
/// A group writes each case out as it finishes rather than at the end, so a
/// long benchmark reports as it goes. Everything a group decides — how long to
/// measure for, what to write, what to skip — comes from the environment, so a
/// benchmark says only what it measures.
pub struct Group {
    /// What the group is called.
    pub name: String,

    /// The cases measured so far, in the order they were measured.
    pub cases: Vec<Case>,

    /// How long each case is measured for.
    pub budget: Budget,

    /// How the group is written out.
    pub report: Report,

    /// Which of the group's cases run.
    pub filter: Filter,
}

impl Group {
    /// A group taking its budget, format and filter from the environment.
    ///
    /// Nothing is written yet: a group that turns out to have no case selected
    /// says nothing at all, rather than heading a table it never fills.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cases: Vec::new(),
            budget: Budget::from_env(),
            report: Report::from_env(),
            filter: Filter::from_env(),
        }
    }

    /// Whether this group was named, which is what says whether a fixture
    /// costing more than the measurement it feeds is worth building.
    pub fn wanted(&self) -> bool {
        self.filter.group(&self.name)
    }

    /// Whether this case would run.
    pub fn wants(&self, case: &str) -> bool {
        self.filter.case(&self.name, case)
    }

    /// Takes an already-measured case, reports it, and keeps it.
    pub fn push(&mut self, case: Case) {
        let first = self.cases.is_empty();

        if first {
            self.report.open(&self.name);
        }

        self.report.case(&self.name, &case, first);
        self.cases.push(case);
    }

    /// Times a case.
    pub fn time<T>(&mut self, case: &str, body: impl FnMut() -> T) {
        if self.wants(case) {
            self.push(Case::new(case, Measure::time(self.budget, body)));
        }
    }

    /// Times a case that works over this many octets.
    pub fn throughput<T>(&mut self, case: &str, octets: usize, body: impl FnMut() -> T) {
        if self.wants(case) {
            self.push(Case::new(case, Measure::throughput(self.budget, octets, body)));
        }
    }

    /// Counts the allocations a case makes, over this many rounds.
    pub fn allocations<T>(&mut self, case: &str, rounds: u64, body: impl FnMut(u64) -> T) {
        if self.wants(case) {
            self.push(Case::new(case, Measure::allocations(rounds, body)));
        }
    }

    /// Drives a workload against a server of its own and reports what came of
    /// it.
    pub fn load(&mut self, workload: Workload) {
        if self.wants(&workload.name) {
            let name = workload.name.clone();
            self.push(Case::new(name, Measure::Load(Driver::run(workload))));
        }
    }

    /// The run a load case ended in, by name.
    pub fn run(&self, case: &str) -> Option<&Run> {
        self.cases.iter().find(|held| held.name == case).and_then(|held| match &held.measure {
            Measure::Load(run) => Some(run),
            _ => None,
        })
    }
}
