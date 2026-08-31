//! The turn verdict, rendered.
//!
//! The layout answers one question in the first line and stops:
//!
//! ```text
//! ◉ᴥ◉ turn · 7 files · since HEAD a1b2c3d · 0.31s
//! ✔ clean — nothing introduced
//!   2 fixed · 5 carried (already at a1b2c3d, not this turn's)
//! ```
//!
//! # Why carried findings are counted and not printed
//!
//! Because printing them is the thing this release is arguing against. A turn
//! report that renders five inherited findings with code frames and fixes is a
//! `scan` with extra steps, and the reader learns nothing about what they just
//! did. They are named on one line so that "clean" cannot be mistaken for "this
//! repository is clean", and that is the whole of their appearance.
//!
//! # Why the base is on every line
//!
//! `clean` is a claim about a comparison, and a comparison is meaningless
//! without the thing compared against. The base commit is printed next to the
//! verdict, in the counts line, and in the JSON, so that a screenshot of this
//! output carries its own caveat.

use std::io::Write;

use owlwarden_core::turn::{TurnReport, Verdict};

use crate::pretty::{PrettyOptions, PrettyReporter};
use crate::theme::{bold, dim, severity_style};

/// Most carried or fixed findings named on one line before it is summarised.
///
/// Six is about what fits on a terminal line at the widths this reporter uses.
/// Past that the list stops being scannable and becomes the flat list again.
const MAX_NAMED: usize = 6;

/// Renders a turn record for a human.
///
/// # Errors
/// [`owlwarden_core::reporter::ReportError`] if the rendered bytes are not
/// valid UTF-8, which would mean a bug here rather than bad input.
pub fn render_to_string(
    record: &TurnReport,
    options: PrettyOptions,
) -> Result<String, owlwarden_core::reporter::ReportError> {
    let mut buffer: Vec<u8> = Vec::new();
    write(&mut buffer, record, options).map_err(|source| {
        owlwarden_core::reporter::ReportError::Io {
            destination: "stdout".to_owned(),
            source,
        }
    })?;
    String::from_utf8(buffer).map_err(|error| owlwarden_core::reporter::ReportError::Encode {
        format: "turn",
        message: error.to_string(),
    })
}

/// Writes a turn record to a sink.
///
/// # Errors
/// Propagates write failures.
pub fn write(
    sink: &mut impl Write,
    record: &TurnReport,
    options: PrettyOptions,
) -> std::io::Result<()> {
    let mut reporter = PrettyReporter::new(Box::new(sink), options);
    let glyphs = reporter.glyphs();

    let separator = glyphs.separator;
    let base = describe_base(record);
    let header = format!(
        "{} turn{separator}{} file{}{separator}{base}{separator}{}.{:02}s",
        crate::banner::owl_mark(options.unicode),
        record.files_changed,
        if record.files_changed == 1 { "" } else { "s" },
        record.duration_ms / 1000,
        (record.duration_ms % 1000) / 10,
    );
    let painted = reporter.paint(dim(), &header);
    writeln!(reporter.writer, "\n{painted}")?;

    match record.verdict {
        Verdict::Clean => {
            let mark = if options.unicode { "✔" } else { "ok" };
            // Two different clean sentences, because they are two different
            // facts. A turn that introduced a medium under a `high` gate is
            // clean *at the threshold*, and printing "nothing introduced" over
            // it would be the one lie this command cannot afford.
            let text = if record.counts.introduced == 0 {
                format!("{mark} clean {} nothing introduced", glyphs.dash)
            } else {
                format!(
                    "{mark} clean at {} {} {} introduced below the bar, shown anyway",
                    record.gate.fail_on.as_str(),
                    glyphs.dash,
                    record.counts.introduced,
                )
            };
            let painted = reporter.paint(bold(), &text);
            writeln!(reporter.writer, "{painted}")?;
        }
        Verdict::Blocked => {
            let mark = if options.unicode { "✘" } else { "!!" };
            // The threshold is in the sentence because "1 introduced" alone
            // invites the reader to argue with the number rather than the bar.
            let text = format!(
                "{mark} blocked {} {} introduced at or above {}",
                glyphs.dash,
                record.counts.introduced,
                record.gate.fail_on.as_str()
            );
            let painted = reporter.paint(severity_style(record.gate.fail_on), &text);
            writeln!(reporter.writer, "{painted}")?;
        }
    }

    write_counts(&mut reporter, record, &base, separator)?;
    write_surface(&mut reporter, record)?;

    for note in &record.notes {
        let text = format!("  ! {note}");
        let painted = reporter.paint(bold(), &text);
        writeln!(reporter.writer, "{painted}")?;
    }

    if record.introduced.is_empty() {
        return reporter.writer.flush();
    }

    writeln!(reporter.writer)?;
    for finding in &record.introduced {
        let note = format!(
            "introduced this turn; {} does not have it",
            short_base(record)
        );
        reporter.write_finding_with_note(finding, Some(("new", note.as_str())))?;
    }

    if record.counts.carried > 0 {
        let footer = format!(
            "Only the {} above {} this turn's. The other {} finding{} on these files {} \
             already at {} — `owlwarden scan` when you want the whole repository.",
            if record.counts.introduced == 1 {
                "finding"
            } else {
                "findings"
            },
            if record.counts.introduced == 1 {
                "is"
            } else {
                "are"
            },
            record.counts.carried,
            plural(record.counts.carried),
            if record.counts.carried == 1 {
                "was"
            } else {
                "were"
            },
            short_base(record),
        );
        let painted = reporter.paint(dim(), &footer);
        writeln!(reporter.writer, "{painted}")?;
    }
    reporter.writer.flush()
}

/// `2 fixed · 5 carried (already at a1b2c3d)`.
///
/// Fixed comes first on purpose. It is the only line in this tool that reports
/// something going right, and a turn that removed two findings deserves to say
/// so before it lists what it left alone.
fn write_counts(
    reporter: &mut PrettyReporter<'_>,
    record: &TurnReport,
    base: &str,
    separator: &str,
) -> std::io::Result<()> {
    if record.counts.fixed == 0 && record.counts.carried == 0 {
        return Ok(());
    }

    let mut parts: Vec<String> = Vec::new();
    if record.counts.fixed > 0 {
        parts.push(format!("{} fixed", record.counts.fixed));
    }
    if record.counts.carried > 0 {
        parts.push(format!(
            "{} carried (already at {}, not this turn's)",
            record.counts.carried,
            base.trim_start_matches("since ")
        ));
    }
    let line = format!("  {}", parts.join(separator));
    let painted = reporter.paint(dim(), &line);
    writeln!(reporter.writer, "{painted}")?;

    if record.counts.fixed > 0 && record.counts.fixed as usize <= MAX_NAMED {
        for entry in &record.fixed {
            let text = format!("    - {} {}", entry.id, entry.at);
            let painted = reporter.paint(dim(), &text);
            writeln!(reporter.writer, "{painted}")?;
        }
    }
    Ok(())
}

/// The agent execution surface, when the seal could read it.
fn write_surface(reporter: &mut PrettyReporter<'_>, record: &TurnReport) -> std::io::Result<()> {
    let Some(surface) = &record.surface else {
        return Ok(());
    };
    // A repository with no agent configuration has no surface to report on, and
    // `surface unsealed · 0 files · 0 hooks` is a line that teaches the reader
    // to skip the place where the loud news goes.
    if surface.files == 0 && surface.hooks == 0 && surface.mcp_servers == 0 {
        return Ok(());
    }
    let separator = reporter.glyphs().separator;
    let inventory = format!(
        "{} file{}{separator}{} hook{}{separator}{} MCP server{}",
        surface.files,
        plural(surface.files),
        surface.hooks,
        plural(surface.hooks),
        surface.mcp_servers,
        plural(surface.mcp_servers),
    );
    let line = format!("  surface {} · {inventory}", surface.state);
    // A moved surface is the one thing on this screen that is louder than a
    // finding: nothing else in the report means *the thing that executes when
    // you open this folder is different from when you last looked*.
    let style = if surface.changes.is_empty() {
        dim()
    } else {
        bold()
    };
    let painted = reporter.paint(style, &line);
    writeln!(reporter.writer, "{painted}")?;
    for change in surface.changes.iter().take(MAX_NAMED) {
        let text = format!("    {change}");
        let painted = reporter.paint(bold(), &text);
        writeln!(reporter.writer, "{painted}")?;
    }
    if surface.changes.len() > MAX_NAMED {
        let text = format!(
            "    …and {} more — `owlwarden seal --diff`",
            surface.changes.len() - MAX_NAMED
        );
        let painted = reporter.paint(dim(), &text);
        writeln!(reporter.writer, "{painted}")?;
    }
    Ok(())
}

const fn plural(count: u32) -> &'static str {
    if count == 1 { "" } else { "s" }
}

/// `since HEAD a1b2c3d`, or `since HEAD (no commit)` outside a repository.
fn describe_base(record: &TurnReport) -> String {
    match &record.base.commit {
        Some(commit) => format!("since {} {}", record.base.reference, short(commit)),
        None => format!("since {} (no commit)", record.base.reference),
    }
}

/// The shortest honest name for the base, for use mid-sentence.
fn short_base(record: &TurnReport) -> String {
    record
        .base
        .commit
        .as_deref()
        .map_or_else(|| record.base.reference.clone(), short)
}

fn short(commit: &str) -> String {
    commit.chars().take(7).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use owlwarden_core::finding::{
        Confidence, FindingContext, Location, RuleId, Severity, SourceLocation,
    };
    use owlwarden_core::turn::{TurnBase, TurnDiff, TurnGate, TurnSurface};

    fn plain() -> PrettyOptions {
        PrettyOptions {
            color: false,
            unicode: true,
            hyperlinks: false,
        }
    }

    fn finding(rule: &'static str, path: &str, line: u32) -> owlwarden_core::finding::Finding {
        owlwarden_core::finding::Finding::builder(RuleId::new_static(rule), Severity::High, "Leak")
            .confidence(Confidence::Likely)
            .location(Location::Source(SourceLocation {
                path: path.to_owned(),
                line,
                col: 1,
            }))
            .context(FindingContext {
                evidence: Some("err.stack".to_owned()),
                ..FindingContext::default()
            })
            .build()
    }

    fn gate() -> TurnGate {
        TurnGate {
            fail_on: Severity::High,
            min_confidence: Confidence::Possible,
            fail_on_exposure: None,
        }
    }

    fn base() -> TurnBase {
        TurnBase {
            reference: "HEAD".to_owned(),
            commit: Some("a1b2c3d4e5f6".to_owned()),
        }
    }

    #[test]
    fn a_clean_turn_names_the_base_it_was_clean_against() {
        let record = TurnReport::new(&TurnDiff::between(&[], &[]), base(), 7, 310, gate());
        let out = render_to_string(&record, plain()).unwrap();
        assert!(out.contains("clean \u{2014} nothing introduced"), "{out}");
        assert!(
            out.contains("since HEAD a1b2c3d"),
            "a verdict is a claim about a comparison and must name it: {out}"
        );
    }

    #[test]
    fn carried_findings_are_counted_and_never_rendered() {
        let debt = vec![finding("insecure-cookie", "legacy.ts", 4)];
        let record = TurnReport::new(&TurnDiff::between(&debt, &debt), base(), 1, 90, gate());
        let out = render_to_string(&record, plain()).unwrap();

        assert!(out.contains("1 carried"), "{out}");
        assert!(
            !out.contains("insecure-cookie"),
            "a carried finding rendered in full is the flat list again: {out}"
        );
        assert!(out.contains("clean"), "{out}");
    }

    #[test]
    fn an_introduced_finding_is_rendered_in_full_and_marked_new() {
        let after = vec![finding("stack-trace-leak", "app/api/users/route.ts", 13)];
        let record = TurnReport::new(&TurnDiff::between(&[], &after), base(), 1, 420, gate());
        let out = render_to_string(&record, plain()).unwrap();

        assert!(
            out.contains("blocked \u{2014} 1 introduced at or above high"),
            "{out}"
        );
        assert!(out.contains("app/api/users/route.ts:13"), "{out}");
        assert!(
            out.contains("introduced this turn; a1b2c3d does not have it"),
            "{out}"
        );
    }

    #[test]
    fn a_clean_turn_that_introduced_something_below_the_bar_does_not_claim_otherwise() {
        let cookie = owlwarden_core::finding::Finding::builder(
            RuleId::new_static("insecure-cookie"),
            Severity::Medium,
            "Cookie missing protections",
        )
        .confidence(Confidence::Likely)
        .location(Location::Source(SourceLocation {
            path: "a.ts".to_owned(),
            line: 4,
            col: 1,
        }))
        .context(FindingContext {
            evidence: Some("secure: false".to_owned()),
            ..FindingContext::default()
        })
        .build();

        let after = vec![cookie];
        let record = TurnReport::new(&TurnDiff::between(&[], &after), base(), 1, 30, gate());
        let out = render_to_string(&record, plain()).unwrap();

        assert!(out.contains("clean at high"), "{out}");
        assert!(
            !out.contains("nothing introduced"),
            "the turn introduced one finding; saying otherwise is the lie: {out}"
        );
        assert!(
            out.contains("insecure-cookie") || out.contains("Cookie missing"),
            "{out}"
        );
    }

    #[test]
    fn a_fixed_finding_is_named_because_it_is_the_only_good_news_here() {
        let before = vec![finding("stack-trace-leak", "a.ts", 3)];
        let record = TurnReport::new(&TurnDiff::between(&before, &[]), base(), 1, 80, gate());
        let out = render_to_string(&record, plain()).unwrap();

        assert!(out.contains("1 fixed"), "{out}");
        assert!(out.contains("stack-trace-leak a.ts:3"), "{out}");
        assert!(out.contains("clean"), "{out}");
    }

    #[test]
    fn a_moved_surface_is_stated_even_on_a_clean_turn() {
        // The case the whole seal exists for: no finding fires, and the thing
        // that executes when you open the folder is different from yesterday.
        let mut record = TurnReport::new(&TurnDiff::between(&[], &[]), base(), 3, 120, gate());
        record.surface = Some(TurnSurface {
            state: "moved".to_owned(),
            files: 4,
            hooks: 2,
            mcp_servers: 1,
            changes: vec!["added SessionStart hook running node .claude/setup.mjs".to_owned()],
        });
        let out = render_to_string(&record, plain()).unwrap();

        assert!(out.contains("clean \u{2014} nothing introduced"), "{out}");
        assert!(out.contains("surface moved"), "{out}");
        assert!(out.contains("added SessionStart hook"), "{out}");
    }

    #[test]
    fn outside_a_repository_the_missing_anchor_is_stated_not_implied() {
        let record = TurnReport::new(
            &TurnDiff::between(&[], &[]),
            TurnBase {
                reference: "HEAD".to_owned(),
                commit: None,
            },
            0,
            10,
            gate(),
        );
        let out = render_to_string(&record, plain()).unwrap();
        assert!(out.contains("(no commit)"), "{out}");
    }

    #[test]
    fn ascii_mode_never_emits_a_glyph_a_ci_log_will_mangle() {
        let after = vec![finding("stack-trace-leak", "a.ts", 3)];
        let record = TurnReport::new(&TurnDiff::between(&[], &after), base(), 1, 20, gate());
        let out = render_to_string(
            &record,
            PrettyOptions {
                color: false,
                unicode: false,
                hyperlinks: false,
            },
        )
        .unwrap();
        assert!(out.is_ascii(), "{out}");
    }
}
