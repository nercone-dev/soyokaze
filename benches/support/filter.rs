//! Choosing which groups and cases run.

/// Which groups and cases a run measures.
///
/// A pattern selects a case when it is held by the case's group name or by the
/// case's own name, ignoring case and matching anywhere in either. So `hpack`
/// selects every case in every group named after it, and `warm table` selects
/// the warm-table cases wherever they are. Several patterns select the union of
/// what each selects, and no pattern at all selects everything.
///
/// Patterns come from the command line and from [`Filter::VARIABLE`] together,
/// so both of these select the same thing:
///
/// ```bash
/// cargo bench --bench helpers -- hpack qpack
/// SOYOKAZE_BENCH_ONLY="hpack qpack" cargo bench --bench helpers
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// What a name has to hold to be selected.
    pub patterns: Vec<String>,
}

impl Filter {
    /// The variable [`Filter::from_env`] reads patterns from.
    pub const VARIABLE: &'static str = "SOYOKAZE_BENCH_ONLY";

    /// A filter over these patterns.
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns: patterns.into_iter().filter(|pattern| !pattern.is_empty()).collect() }
    }

    /// The patterns the command line and the environment ask for together.
    ///
    /// Arguments beginning with `-` are left alone, since those are the test
    /// harness flags Cargo passes through rather than anything a person typed.
    pub fn from_env() -> Self {
        let arguments = std::env::args().skip(1).filter(|argument| !argument.starts_with('-'));
        let variable = std::env::var(Self::VARIABLE).unwrap_or_default();

        Self::new(arguments.chain(variable.split_whitespace().map(str::to_owned)).collect())
    }

    /// Whether nothing was asked for, so everything runs.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether this group was named.
    ///
    /// A group asks this before building a fixture that costs more than the
    /// measurement it feeds, so it answers to the group's name alone: a
    /// pattern naming only a case cannot be checked before the case exists.
    pub fn group(&self, name: &str) -> bool {
        self.is_empty() || self.patterns.iter().any(|pattern| Self::holds(name, pattern))
    }

    /// Whether this case is selected, by its group's name or by its own.
    pub fn case(&self, group: &str, name: &str) -> bool {
        self.group(group) || self.patterns.iter().any(|pattern| Self::holds(name, pattern))
    }

    /// Whether `text` holds `pattern`, ignoring case.
    pub fn holds(text: &str, pattern: &str) -> bool {
        text.to_ascii_lowercase().contains(&pattern.to_ascii_lowercase())
    }
}
