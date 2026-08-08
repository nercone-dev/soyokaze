//! Writing a run out.

use crate::support::case::Case;

/// How a run is written out.
///
/// [`Report::Table`] is for reading and [`Report::Json`] for collecting; both
/// write one case at a time, as it finishes, so a long run says what it is
/// doing rather than going quiet until the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    /// An aligned table, one group at a time.
    Table,

    /// One JSON object per line, one per case.
    Json,
}

impl Report {
    /// The variable [`Report::from_env`] reads the format from.
    pub const VARIABLE: &'static str = "SOYOKAZE_BENCH_FORMAT";

    /// How wide the case column is.
    pub const NAME: usize = 46;

    /// How wide every column after it is.
    pub const COLUMN: usize = 14;

    /// The format the environment asks for, or a table.
    pub fn from_env() -> Self {
        match std::env::var(Self::VARIABLE).unwrap_or_default().to_ascii_lowercase().as_str() {
            "json" | "jsonl" => Self::Json,
            _ => Self::Table,
        }
    }

    /// Announces a group, before any of its cases have been measured.
    pub fn open(&self, group: &str) {
        if *self == Self::Table {
            println!("\n{group}");
            println!("{}", "-".repeat(group.len()));
        }
    }

    /// Writes one case out, heading the table first when it is the group's
    /// first case, since the headings depend on what the case measured.
    pub fn case(&self, group: &str, case: &Case, first: bool) {
        match self {
            Self::Table => {
                if first {
                    let headings: Vec<(&str, String)> = case.measure.columns().iter().map(|(name, _)| (*name, name.to_string())).collect();
                    println!("{}", Self::row("case", &headings));
                }

                println!("{}", Self::row(&case.name, &case.measure.columns()));
            }

            Self::Json => {
                let columns: Vec<String> = case.measure.columns().iter().map(|(name, cell)| Self::field(name, &Self::quote(cell))).collect();

                let fields = [
                    Self::field("group", &Self::quote(group)),
                    Self::field("case", &Self::quote(&case.name)),
                    Self::field("value", &case.measure.value().to_string()),
                    Self::field("unit", &Self::quote(case.measure.dimension())),
                    Self::field("columns", &format!("{{{}}}", columns.join(","))),
                ];

                println!("{{{}}}", fields.join(","));
            }
        }
    }

    /// One table row: a name, then every column right-aligned under its
    /// heading.
    pub fn row(name: &str, columns: &[(&str, String)]) -> String {
        let mut line = format!("  {name:<width$}", width = Self::NAME);

        for (_, cell) in columns {
            line.push_str(&format!("{cell:>width$}", width = Self::COLUMN));
        }

        line
    }

    /// One JSON member: a quoted name, and a value already written as JSON.
    pub fn field(name: &str, value: &str) -> String {
        format!("{}:{value}", Self::quote(name))
    }

    /// A JSON string.
    pub fn quote(text: &str) -> String {
        let mut quoted = String::with_capacity(text.len() + 2);
        quoted.push('"');

        for character in text.chars() {
            match character {
                '"' => quoted.push_str("\\\""),
                '\\' => quoted.push_str("\\\\"),
                '\n' => quoted.push_str("\\n"),
                '\t' => quoted.push_str("\\t"),
                _ if (character as u32) < 0x20 => quoted.push_str(&format!("\\u{:04x}", character as u32)),
                _ => quoted.push(character),
            }
        }

        quoted.push('"');
        quoted
    }
}
