//! Inline suppressions with a mandatory reason.
//!
//! Syntax (ARCHITECTURE.md §5):
//!
//! ```text
//! // owlwarden-disable-next-line stack-trace-leak -- dev-only route, gated by NODE_ENV
//! ```
//!
//! The reason is not ceremony. It is what a reviewer reads in the diff, and what
//! stops an agent from "fixing" a finding by silencing it with no explanation.
//! A directive without `-- <reason>` is ignored and reported as malformed so the
//! author learns why their suppression did nothing.
//!
//! Matching is next-line only for now: the directive sits on the line
//! immediately above the finding. Block and file-wide forms are a later
//! addition; shipping a half-working blanket first would teach people to hide
//! more than they meant to.

use crate::finding::{Finding, RuleId};

/// Maximum suppressions collected from one file. A file with more is almost
/// certainly generated or being used as a mute switch; we stop rather than
/// grow without bound.
pub const MAX_PER_FILE: usize = 64;

/// Maximum reason length kept in the report. Longer reasons still count as
/// present (the directive is valid), but the stored copy is truncated so a
/// hostile comment cannot inflate report size.
pub const MAX_REASON_LEN: usize = 280;

/// One parsed directive, before it is matched against findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// Project-relative path with `/` separators.
    pub path: String,
    /// 1-based line of the comment itself.
    pub comment_line: u32,
    /// The line the directive applies to (`comment_line + 1`).
    pub applies_to_line: u32,
    /// Rule id named in the directive.
    pub rule: RuleId,
    /// Mandatory reason, already trimmed. Empty means the directive was
    /// malformed and must not suppress anything.
    pub reason: String,
    /// True when the comment named a rule but omitted `-- <reason>`.
    pub missing_reason: bool,
}

/// A suppression as it appears in the report and under `--report-suppressions`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuppressionRecord {
    /// Rule id the directive named.
    pub rule: String,
    /// File the comment lives in.
    pub path: String,
    /// Line of the comment (not the finding).
    pub line: u32,
    /// The author's reason.
    pub reason: String,
    /// True when no finding was hidden by this directive — the annotation has
    /// rotted, or it never matched.
    pub stale: bool,
    /// True when the comment named a rule but forgot the mandatory reason.
    /// These never suppress; they exist so the author can see why.
    pub missing_reason: bool,
}

/// Result of applying directives to a finding list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionOutcome {
    /// Findings that were not suppressed.
    pub findings: Vec<Finding>,
    /// How many findings a valid directive hid.
    pub suppressed_count: u32,
    /// Every directive encountered, with stale / missing-reason flags set.
    pub records: Vec<SuppressionRecord>,
}

/// What a run does with the inline suppressions it finds.
///
/// Three states rather than a boolean, because a third case appeared and a
/// boolean had nowhere to put it. `gate` runs automatically, on a tree the
/// agent is actively editing, and the honest rule there is not "honour" or
/// "ignore" — it is *honour what the team already agreed to, and refuse what
/// appeared during this session*. A suppression written thirty seconds ago by
/// the thing being gated is not a team decision
/// ([ADR 0026](../../../docs/adr/0026-deterministic-agent-gate.md) §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuppressionPolicy {
    /// Honour every directive. Local interactive scans.
    Honour,
    /// List every directive, hide nothing. `--ci` on an untrusted tree, and
    /// `vet`, where the target's suppression surface is evidence rather than
    /// instruction.
    ReportOnly,
    /// Honour directives except those in these project-relative paths.
    ///
    /// The gate's posture: the paths are the files written during this session.
    /// A directive in one of them is reported as ignored, so the developer sees
    /// what the agent tried to silence.
    HonourExcept(Vec<String>),
}

impl SuppressionPolicy {
    /// Whether a directive in `path` is honoured.
    #[must_use]
    pub fn honours(&self, path: &str) -> bool {
        match self {
            Self::Honour => true,
            Self::ReportOnly => false,
            Self::HonourExcept(paths) => !paths.iter().any(|excluded| excluded == path),
        }
    }

    /// Whether anything at all is honoured, for the fast path.
    #[must_use]
    pub fn honours_anything(&self) -> bool {
        !matches!(self, Self::ReportOnly)
    }
}

/// Extracts directives from one file's source text.
///
/// Accepts `//`, `///`, and `/* … */` comment forms, and the `#` form used in
/// YAML workflow files. Anything that is not a whole-line (or block-comment)
/// directive is ignored — inline trailing comments on code lines are too easy
/// to mis-attribute.
#[must_use]
pub fn parse_directives(path: &str, source: &str) -> Vec<Directive> {
    let mut out = Vec::new();
    // File size is already capped by the source provider; bound the directive
    // count, not the line walk — a long file with one directive at the end
    // must still be seen.
    for (index, raw_line) in source.lines().enumerate() {
        if out.len() >= MAX_PER_FILE {
            break;
        }
        let line_no = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if let Some(directive) = parse_line(path, line_no, raw_line) {
            out.push(directive);
        }
    }
    out
}

/// Applies directives to findings. Each valid directive may hide at most one
/// finding on its target line for its named rule; extras stay visible.
#[must_use]
pub fn apply(findings: Vec<Finding>, directives: &[Directive]) -> SuppressionOutcome {
    let mut used = vec![false; directives.len()];
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed_count = 0u32;

    for finding in findings {
        if let Some(index) = matching_directive(&finding, directives, &used) {
            if let Some(slot) = used.get_mut(index) {
                *slot = true;
            }
            suppressed_count = suppressed_count.saturating_add(1);
        } else {
            kept.push(finding);
        }
    }

    // Every directive that participated in matching appears in the report.
    // Callers must already have capped `directives` (see `MAX_SUPPRESSIONS`);
    // truncating here would let a finding be suppressed without a record.
    let records = directives
        .iter()
        .enumerate()
        .map(|(index, directive)| SuppressionRecord {
            rule: directive.rule.to_string(),
            path: directive.path.clone(),
            line: directive.comment_line,
            reason: if directive.reason.is_empty() {
                String::new()
            } else {
                directive.reason.clone()
            },
            stale: !directive.missing_reason && !used.get(index).copied().unwrap_or(false),
            missing_reason: directive.missing_reason,
        })
        .collect();

    SuppressionOutcome {
        findings: kept,
        suppressed_count,
        records,
    }
}

fn matching_directive(finding: &Finding, directives: &[Directive], used: &[bool]) -> Option<usize> {
    let location = finding.location.as_source()?;
    directives
        .iter()
        .enumerate()
        .find_map(|(index, directive)| {
            if used.get(index).copied().unwrap_or(true) {
                return None;
            }
            if directive.missing_reason {
                return None;
            }
            if directive.rule != finding.id {
                return None;
            }
            if directive.path != location.path {
                return None;
            }
            if directive.applies_to_line != location.line {
                return None;
            }
            Some(index)
        })
}

fn parse_line(path: &str, line_no: u32, raw_line: &str) -> Option<Directive> {
    let trimmed = raw_line.trim();
    let body = comment_body(trimmed)?;
    let rest = body
        .strip_prefix("owlwarden-disable-next-line")?
        .trim_start();
    if rest.is_empty() {
        return None;
    }

    let (rule_part, reason_part) = match rest.split_once("--") {
        Some((rule, reason)) => (rule.trim(), Some(reason.trim())),
        None => (rest.trim(), None),
    };

    // One rule per directive. A comma list would invite "disable everything on
    // this line", which is the opposite of a mandatory-reason design.
    let rule_token = rule_part.split_whitespace().next()?.trim();
    let rule = RuleId::parse(rule_token).ok()?;

    let (reason, missing_reason) = match reason_part {
        Some(text) if !text.is_empty() => (truncate_reason(text), false),
        _ => (String::new(), true),
    };

    Some(Directive {
        path: path.to_owned(),
        comment_line: line_no,
        applies_to_line: line_no.saturating_add(1),
        rule,
        reason,
        missing_reason,
    })
}

/// Pulls the directive body out of a comment line, if the whole line is a
/// comment that could hold one.
fn comment_body(trimmed: &str) -> Option<&str> {
    if let Some(body) = trimmed.strip_prefix("//") {
        return Some(body.trim_start().trim_start_matches('/').trim_start());
    }
    if let Some(body) = trimmed.strip_prefix('#') {
        // YAML / shell. Require a space or the directive keyword so `#foo` is
        // not mistaken for a directive.
        let body = body.strip_prefix(' ').unwrap_or(body);
        return Some(body.trim_start());
    }
    if let Some(body) = trimmed.strip_prefix("/*") {
        let body = body.trim_end().strip_suffix("*/")?.trim();
        return Some(body);
    }
    None
}

fn truncate_reason(reason: &str) -> String {
    let mut out = String::new();
    for (count, ch) in reason.chars().enumerate() {
        if count >= MAX_REASON_LEN {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use crate::finding::{Confidence, Location, Severity, SourceLocation};

    fn finding(rule: &'static str, path: &str, line: u32) -> Finding {
        Finding::builder(RuleId::new_static(rule), Severity::High, "t")
            .confidence(Confidence::Likely)
            .location(Location::Source(SourceLocation {
                path: path.to_owned(),
                line,
                col: 1,
            }))
            .build()
    }

    #[test]
    fn parses_next_line_directive_with_reason() {
        let source = "// owlwarden-disable-next-line stack-trace-leak -- gated by NODE_ENV\nreturn err.stack;\n";
        let directives = parse_directives("app/route.ts", source);
        assert_eq!(directives.len(), 1);
        let directive = &directives[0];
        assert_eq!(directive.rule.as_str(), "stack-trace-leak");
        assert_eq!(directive.comment_line, 1);
        assert_eq!(directive.applies_to_line, 2);
        assert_eq!(directive.reason, "gated by NODE_ENV");
        assert!(!directive.missing_reason);
    }

    #[test]
    fn reason_is_mandatory() {
        let source = "// owlwarden-disable-next-line stack-trace-leak\nreturn err.stack;\n";
        let directives = parse_directives("app/route.ts", source);
        assert_eq!(directives.len(), 1);
        assert!(directives[0].missing_reason);

        let outcome = apply(
            vec![finding("stack-trace-leak", "app/route.ts", 2)],
            &directives,
        );
        assert_eq!(outcome.findings.len(), 1, "no reason means no suppression");
        assert_eq!(outcome.suppressed_count, 0);
        assert!(outcome.records[0].missing_reason);
    }

    #[test]
    fn suppresses_matching_finding_and_marks_unused_as_stale() {
        let directives = parse_directives(
            "app/route.ts",
            "// owlwarden-disable-next-line stack-trace-leak -- legacy\n\
             // owlwarden-disable-next-line cors-permissive -- gone\nx\n",
        );
        let outcome = apply(
            vec![finding("stack-trace-leak", "app/route.ts", 2)],
            &directives,
        );
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.suppressed_count, 1);
        assert!(!outcome.records[0].stale);
        assert!(outcome.records[1].stale);
    }

    #[test]
    fn hash_comment_form_works_for_yaml() {
        let source =
            "# owlwarden-disable-next-line ci-unpinned-action -- pin later\nuses: a/b@main\n";
        let directives = parse_directives(".github/workflows/ci.yml", source);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].rule.as_str(), "ci-unpinned-action");
    }

    #[test]
    fn rejects_unknown_rule_id_shape() {
        let source = "// owlwarden-disable-next-line Not_A_Rule -- nope\nx\n";
        assert!(parse_directives("a.ts", source).is_empty());
    }

    #[test]
    fn block_comment_form() {
        let source = "/* owlwarden-disable-next-line weak-crypto -- test vector */\nmd5(x)\n";
        let directives = parse_directives("a.ts", source);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].reason, "test vector");
    }

    #[test]
    fn blank_line_between_directive_and_code_does_not_suppress() {
        // Next-line only: a blank line means the comment no longer sits on the
        // line immediately above the finding.
        let directives = parse_directives(
            "a.ts",
            "// owlwarden-disable-next-line stack-trace-leak -- too far\n\nreturn err.stack;\n",
        );
        assert_eq!(directives[0].applies_to_line, 2); // the blank line
        let outcome = apply(vec![finding("stack-trace-leak", "a.ts", 3)], &directives);
        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.records[0].stale);
    }

    #[test]
    fn wrong_rule_id_does_not_suppress() {
        let directives = parse_directives(
            "a.ts",
            "// owlwarden-disable-next-line cors-permissive -- wrong rule\nreturn err.stack;\n",
        );
        let outcome = apply(vec![finding("stack-trace-leak", "a.ts", 2)], &directives);
        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.records[0].stale);
    }

    #[test]
    fn per_file_cap_stops_collecting() {
        let mut source = String::new();
        for _ in 0..(MAX_PER_FILE + 10) {
            source.push_str("// owlwarden-disable-next-line stack-trace-leak -- flood\nx\n");
        }
        let directives = parse_directives("a.ts", &source);
        assert_eq!(directives.len(), MAX_PER_FILE);
    }
}
