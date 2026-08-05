//! Renders the coverage table: what the shipped rules see, and what they do
//! not.
//!
//! Most scanners answer "which OWASP categories do you cover?" with a marketing
//! page. The honest answer has holes in it, and printing the holes is the point
//! of this module — a reader deciding whether to trust the tool needs to know
//! what it is *not* looking at in their codebase, and a reader who has just got
//! a clean report needs to know that clean means "clean of these checks".
//!
//! Three states, deliberately distinguished, because collapsing them is how a
//! coverage table becomes a lie:
//!
//! - **covered** — at least one rule maps here.
//! - **gap** — nothing maps here, but source analysis could see it. Backlog.
//! - **out of reach** — nothing maps here and nothing will, because the
//!   category lives in a deployment or a design rather than in a file. Not a
//!   backlog item, and saying "0%" about it would imply otherwise.

use std::fmt::Write as _;

use anstyle::Style;
use owlwarden_core::coverage::{CategoryEntry, CoverageReport};

use crate::theme::{Glyphs, bold, dim};

/// How to draw the table.
#[derive(Debug, Clone, Copy)]
pub struct CoverageOptions {
    /// Emit ANSI styling.
    pub color: bool,
    /// Use box-drawing characters rather than ASCII.
    pub unicode: bool,
}

impl Default for CoverageOptions {
    fn default() -> Self {
        Self {
            color: false,
            unicode: true,
        }
    }
}

/// Longest category id we lay out for; the ids are fixed-width in practice.
const ID_WIDTH: usize = 8;

/// Renders the table as text.
#[must_use]
pub fn render(report: &CoverageReport, options: CoverageOptions) -> String {
    let glyphs = Glyphs::for_unicode(options.unicode);
    let heading = if options.color {
        bold()
    } else {
        Style::default()
    };
    let muted = if options.color {
        dim()
    } else {
        Style::default()
    };
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{heading}owlwarden {}{heading:#} coverage",
        report.version
    );
    let _ = writeln!(
        out,
        "{muted}{}{muted:#}",
        String::from(glyphs.rule).repeat(64)
    );

    write_owasp(&mut out, report, options, heading, muted);
    write_frameworks(&mut out, report, heading, muted);

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{muted}Static analysis only. Categories marked out-of-reach need runtime or{muted:#}"
    );
    let _ = writeln!(
        out,
        "{muted}deployment context that source cannot supply; see docs/explanation/coverage.md.{muted:#}"
    );

    out
}

/// The OWASP half of the table, one category per row with its rules beneath.
fn write_owasp(
    out: &mut String,
    report: &CoverageReport,
    options: CoverageOptions,
    heading: Style,
    muted: Style,
) {
    let _ = writeln!(out);
    let _ = writeln!(out, "{heading}OWASP Top 10 (2021){heading:#}");
    let _ = writeln!(out);

    for entry in &report.owasp {
        let status = status_of(entry);
        let _ = writeln!(
            out,
            "  {:<ID_WIDTH$}  {:<9}  {}",
            entry.id,
            status.label(options.unicode),
            entry.title
        );
        let detail = if entry.rules.is_empty() {
            status.explanation().to_owned()
        } else {
            entry.rules.join(", ")
        };
        let _ = writeln!(
            out,
            "  {:<ID_WIDTH$}  {:<9}  {muted}{detail}{muted:#}",
            "", ""
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {} of 10 categories have at least one rule, from {} rule{} total.",
        report.categories_covered,
        report.rule_count,
        if report.rule_count == 1 { "" } else { "s" }
    );

    let gaps = report
        .owasp
        .iter()
        .filter(|entry| status_of(entry) == Status::Gap)
        .count();
    if gaps > 0 {
        let _ = writeln!(
            out,
            "  {muted}{gaps} further categor{} within reach of source analysis and not yet covered.{muted:#}",
            if gaps == 1 { "y is" } else { "ies are" }
        );
    }
}

/// The framework half: how many rules speak each framework's dialect.
fn write_frameworks(out: &mut String, report: &CoverageReport, heading: Style, muted: Style) {
    let _ = writeln!(out);
    let _ = writeln!(out, "{heading}Frameworks{heading:#}");
    let _ = writeln!(out);

    for framework in &report.frameworks {
        let note = if framework.rules_falling_back == 0 {
            "every rule has framework-specific remediation".to_owned()
        } else {
            format!(
                "{} rule(s) fall back to generic advice",
                framework.rules_falling_back
            )
        };
        let _ = writeln!(
            out,
            "  {:<10}  {:>2} rules  {muted}{note}{muted:#}",
            framework.id, framework.rules_with_specific_fix
        );
    }
}

/// The three honest states a category can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// At least one rule maps here.
    Covered,
    /// No rule, but source analysis could reach it.
    Gap,
    /// No rule, and none is coming from a static engine.
    OutOfReach,
}

impl Status {
    fn label(self, unicode: bool) -> &'static str {
        match (self, unicode) {
            (Self::Covered, true) => "✓ covered",
            (Self::Covered, false) => "covered",
            (Self::Gap, true) => "· gap",
            (Self::Gap, false) => "gap",
            (Self::OutOfReach, true) => "— dynamic",
            (Self::OutOfReach, false) => "dynamic",
        }
    }

    fn explanation(self) -> &'static str {
        match self {
            Self::Covered => "",
            Self::Gap => "no rule yet; source analysis can see this",
            Self::OutOfReach => "needs runtime or deployment context, not source",
        }
    }
}

/// Classifies a row. `poor` reachability with no rule is a limit of the method;
/// anything else with no rule is work we have not done.
fn status_of(entry: &CategoryEntry) -> Status {
    if !entry.rules.is_empty() {
        Status::Covered
    } else if entry.reachability == "poor" {
        Status::OutOfReach
    } else {
        Status::Gap
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_table_names_every_category_including_the_empty_ones() {
        let report = owlwarden_detectors::coverage_report();
        let text = render(&report, CoverageOptions::default());
        for entry in &report.owasp {
            assert!(
                text.contains(&entry.id),
                "{} is missing from the table",
                entry.id
            );
        }
    }

    #[test]
    fn an_unreachable_category_is_not_presented_as_a_backlog_item() {
        // A05 is covered; A04 (Insecure Design) is not reachable from source.
        // The two empty-looking states must render differently or the table
        // implies we simply have not got around to design flaws yet.
        let report = owlwarden_detectors::coverage_report();
        let out_of_reach = report
            .owasp
            .iter()
            .filter(|entry| status_of(entry) == Status::OutOfReach)
            .count();
        assert!(
            out_of_reach > 0,
            "at least one Top 10 category is genuinely beyond static analysis; \
             if this fails, the reachability data has been overstated"
        );
    }

    #[test]
    fn ascii_output_carries_no_escape_sequences() {
        let report = owlwarden_detectors::coverage_report();
        let text = render(
            &report,
            CoverageOptions {
                color: false,
                unicode: false,
            },
        );
        assert!(!text.contains('\u{1b}'), "colour leaked into plain output");
        assert!(text.is_ascii(), "non-ascii leaked into the ascii table");
    }
}
