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
    write_asi(&mut out, report, options, heading, muted);
    write_profiles(
        &mut out,
        "Frameworks",
        &report.frameworks,
        report.web_app_rule_count,
        "framework",
        heading,
        muted,
    );
    write_profiles(
        &mut out,
        "Agent hosts",
        &report.hosts,
        report.agent_workspace_rule_count,
        "host",
        heading,
        muted,
    );
    write_agent_paths(&mut out, report, heading, muted);

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

/// The ASI half of the table.
///
/// A separate section rather than more rows in the OWASP one: the two
/// taxonomies answer different questions, and a reader who scans for "how much
/// of the Top 10?" must not have that number quietly inflated by agent rules.
fn write_asi(
    out: &mut String,
    report: &CoverageReport,
    options: CoverageOptions,
    heading: Style,
    muted: Style,
) {
    if report.asi.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{heading}OWASP ASI {} (agentic){heading:#}",
        report.asi_edition
    );
    let _ = writeln!(out);

    for entry in &report.asi {
        let status = status_of(entry);
        let _ = writeln!(
            out,
            "  {:<ID_WIDTH$}  {:<9}  {}",
            entry.id,
            status.label(options.unicode),
            entry.title
        );
        let detail = if entry.rules.is_empty() {
            status.agent_explanation().to_owned()
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
        "  {} of 10 agentic categories have at least one rule, from {} agent-surface rule{}.",
        report.asi_categories_covered,
        report.agent_workspace_rule_count,
        if report.agent_workspace_rule_count == 1 {
            ""
        } else {
            "s"
        }
    );
}

/// One profile table: how many of a surface's rules speak each dialect.
///
/// Shared between frameworks and hosts because the question is identical, and
/// two copies would be two places for the phrasing to drift.
fn write_profiles(
    out: &mut String,
    title: &str,
    profiles: &[owlwarden_core::coverage::FrameworkEntry],
    total: usize,
    noun: &str,
    heading: Style,
    muted: Style,
) {
    if profiles.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{heading}{title}{heading:#}");
    let _ = writeln!(out);

    for profile in profiles {
        let note = if profile.rules_falling_back == 0 {
            format!("every rule has {noun}-specific remediation")
        } else {
            format!(
                "{} rule(s) fall back to generic advice",
                profile.rules_falling_back
            )
        };
        let _ = writeln!(
            out,
            "  {:<12}  {:>2} of {total} rules  {muted}{note}{muted:#}",
            profile.id, profile.rules_with_specific_fix
        );
    }
}

/// What the agent surface reads, stated as a list.
///
/// The counterpart of the OWASP gaps: on this surface the honest answer to
/// "what do you not look at?" is a path list, because the allowlist is closed.
/// Printing it means a reader can tell in one glance whether their host's
/// configuration is even in scope.
fn write_agent_paths(out: &mut String, report: &CoverageReport, heading: Style, muted: Style) {
    let globs = &report.agent_paths;
    if globs.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{heading}Agent workspace paths read{heading:#}");
    let _ = writeln!(out);
    for chunk in globs.chunks(3) {
        let _ = writeln!(out, "  {}", chunk.join("  "));
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {muted}A closed list, matched at the repository root and under any prefix.{muted:#}"
    );
    let _ = writeln!(
        out,
        "  {muted}A path not on it is not scanned, including agent config inside node_modules.{muted:#}"
    );
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

    /// The same three states, worded for the agent surface, where the limit is
    /// the run-time behaviour of an agent rather than a deployment.
    fn agent_explanation(self) -> &'static str {
        match self {
            Self::Covered => "",
            Self::Gap => "no rule yet; configuration can show this",
            Self::OutOfReach => "needs the agent's run-time behaviour, not its configuration",
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
    fn the_agent_surface_states_its_own_gaps_in_the_same_voice() {
        // ADR 0025 exit criterion 8: the ASI table prints with its gaps stated,
        // the way the OWASP table does. A table that only listed what we cover
        // would be an advertisement.
        let report = owlwarden_detectors::coverage_report();
        let text = render(&report, CoverageOptions::default());
        assert!(text.contains("OWASP ASI"), "the ASI table is printed");
        for entry in &report.asi {
            assert!(text.contains(&entry.id), "{} is missing", entry.id);
        }
        let uncovered = report
            .asi
            .iter()
            .filter(|entry| entry.rules.is_empty())
            .count();
        assert!(
            uncovered > 0,
            "some agentic categories are beyond a configuration scanner; if this fails, check \
             the claim is genuine before updating the test"
        );
        assert!(
            text.contains("Agent hosts") && text.contains("claude-code"),
            "the host support table is printed"
        );
        assert!(
            text.contains(".claude/settings.local.json"),
            "the path list is what tells a reader whether their config is in scope at all"
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
