//! The `Report`: one scan's result, and the JSON contract with everything
//! downstream.
//!
//! The serialized shape is public API. `packages/sdk` carries a zod schema for
//! the same shape, and a contract test parses a Rust-generated golden report
//! with it, so a field renamed on this side fails the TypeScript build instead
//! of surfacing as `undefined` at a user's terminal
//! (`docs/adr/0010-cross-language-contract.md`). `REPORTERS.md` §3 documents
//! the shape for consumers.

use serde::{Deserialize, Serialize};

use crate::finding::{Confidence, Finding, Severity};
use crate::suppression::SuppressionRecord;

/// Version of the JSON report format. Bumped on any breaking change to the
/// shape; consumers should refuse a major version they do not know.
pub const SCHEMA_VERSION: &str = "1.0";

/// Which tool produced the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolInfo {
    /// Always `"owlwarden"`.
    pub name: String,
    /// Engine version.
    pub version: String,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            name: "owlwarden".to_owned(),
            version: crate::ENGINE_VERSION.to_owned(),
        }
    }
}

/// What was scanned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanTarget {
    /// Project root, as the user gave it.
    pub project: String,
    /// Declared network scope. Empty for a passive scan.
    #[serde(default)]
    pub scope: Vec<String>,
    /// Source files actually parsed.
    pub files_scanned: u32,
    /// Agent and editor configuration files read.
    ///
    /// Counted separately from `files_scanned` because they are read and not
    /// parsed as source — and because a `vet` that reported "0 files" while
    /// producing fourteen findings would be describing the wrong number.
    #[serde(default)]
    pub config_files_scanned: u32,
    /// Live routes probed. Zero until the dynamic engine lands.
    pub routes_probed: u32,
    /// Preset in force.
    pub preset: String,
    /// What the scan was narrowed to, when it was: `"since origin/main"`,
    /// `"staged"`, `"3 paths"`.
    ///
    /// Present in every format, because a diff-scoped clean result must never
    /// render as a clean repository. The pretty reporter puts it in the summary
    /// line for exactly that reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_scope: Option<String>,
}

/// Finding counts by severity. Present even when zero so consumers can render a
/// table without special-casing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportSummary {
    /// High-severity count.
    pub high: u32,
    /// Medium-severity count.
    pub medium: u32,
    /// Low-severity count.
    pub low: u32,
    /// Informational count.
    pub info: u32,
}

impl ReportSummary {
    /// Counts findings by severity.
    #[must_use]
    pub fn of(findings: &[Finding]) -> Self {
        let mut summary = Self::default();
        for finding in findings {
            let slot = match finding.severity {
                Severity::High => &mut summary.high,
                Severity::Medium => &mut summary.medium,
                Severity::Low => &mut summary.low,
                Severity::Info => &mut summary.info,
            };
            *slot = slot.saturating_add(1);
        }
        summary
    }

    /// Total across all severities.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.high
            .saturating_add(self.medium)
            .saturating_add(self.low)
            .saturating_add(self.info)
    }

    /// Count at or above `threshold` — the number `--fail-on` acts on.
    #[must_use]
    pub fn at_or_above(&self, threshold: Severity) -> u32 {
        let mut total = 0u32;
        if Severity::High >= threshold {
            total = total.saturating_add(self.high);
        }
        if Severity::Medium >= threshold {
            total = total.saturating_add(self.medium);
        }
        if Severity::Low >= threshold {
            total = total.saturating_add(self.low);
        }
        if Severity::Info >= threshold {
            total = total.saturating_add(self.info);
        }
        total
    }
}

/// A detector that failed. Surfaced rather than swallowed: a scan that silently
/// skipped half its rules and printed "no findings" is worse than no scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectorFailure {
    /// Rule id that failed.
    pub rule: String,
    /// Message, safe to display.
    pub message: String,
}

/// One scan's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Format version, see [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// Tool identity.
    pub tool: ToolInfo,
    /// RFC 3339 UTC timestamp.
    pub scanned_at: String,
    /// Scan duration in milliseconds.
    pub duration_ms: u64,
    /// What was scanned.
    pub target: ScanTarget,
    /// Counts by severity.
    pub summary: ReportSummary,
    /// The findings, already sorted and filtered.
    pub findings: Vec<Finding>,
    /// How many findings an inline suppression hid.
    ///
    /// Always emitted so that "0 findings" is never mistaken for "0 problems"
    /// — by a human or by an agent. See [`crate::suppression`].
    pub suppressed_count: u32,
    /// Every inline suppression found in the scanned tree.
    ///
    /// Includes stale and missing-reason directives so `--report-suppressions`
    /// (and agents reading JSON) can see annotations that no longer hide
    /// anything. Empty when the tree has none.
    #[serde(default)]
    pub suppressions: Vec<SuppressionRecord>,
    /// Findings hidden because they matched `--baseline`. Distinct from
    /// [`Self::suppressed_count`]: a baseline is project-level debt, a
    /// suppression is a line-level claim with a reason.
    #[serde(default)]
    pub baseline_hidden_count: u32,
    /// True when [`crate::limits::scan::MAX_FINDINGS`] was hit and findings
    /// were dropped. A truncated report is not a clean report.
    pub truncated: bool,
    /// Detectors that failed to complete.
    #[serde(default)]
    pub errors: Vec<DetectorFailure>,
}

impl Report {
    /// Whether the scan should fail a build, given the thresholds.
    ///
    /// `Possible`-confidence findings never fail CI on their own: acting on a
    /// guess is how a tool gets removed from a pipeline.
    ///
    /// A truncated report always fails: the findings cap was hit, so the scan
    /// cannot prove the project is clean — exiting 0 would hide the rest.
    #[must_use]
    pub fn should_fail(&self, fail_on: Severity, min_confidence: Confidence) -> bool {
        if self.truncated {
            return true;
        }
        self.findings.iter().any(|finding| {
            finding.severity >= fail_on
                && finding.confidence >= min_confidence
                && finding.confidence > Confidence::Possible
        })
    }

    /// Drops findings below `min_confidence` and recomputes the summary.
    ///
    /// Applied after correlation (ADR 0014) so a `Possible` static finding can
    /// still be raised to `Confirmed` by a matching dynamic observation.
    pub fn apply_min_confidence(&mut self, min_confidence: Confidence) {
        self.findings
            .retain(|finding| finding.confidence >= min_confidence);
        self.summary = ReportSummary::of(&self.findings);
    }
}

/// RFC 3339 timestamp for "now", in UTC, truncated to whole seconds.
///
/// Sub-second precision would make two reports of the same code differ for no
/// useful reason, which matters for snapshot tests and for diffing CI output.
///
/// Falls back to the Unix epoch if formatting fails — that cannot happen with a
/// well-known format, and returning a wrong-but-valid timestamp beats failing a
/// whole scan over a cosmetic field.
#[must_use]
pub fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::finding::{Finding, RuleId};

    fn finding(severity: Severity, confidence: Confidence) -> Finding {
        Finding::builder(RuleId::new_static("stack-trace-leak"), severity, "t")
            .confidence(confidence)
            .build()
    }

    fn report_of(findings: Vec<Finding>) -> Report {
        Report {
            schema_version: SCHEMA_VERSION.to_owned(),
            tool: ToolInfo::default(),
            scanned_at: now_rfc3339(),
            duration_ms: 0,
            target: ScanTarget::default(),
            summary: ReportSummary::of(&findings),
            findings,
            suppressed_count: 0,
            suppressions: Vec::new(),
            baseline_hidden_count: 0,
            truncated: false,
            errors: Vec::new(),
        }
    }

    #[test]
    fn summary_counts_each_band() {
        let summary = ReportSummary::of(&[
            finding(Severity::High, Confidence::Likely),
            finding(Severity::High, Confidence::Likely),
            finding(Severity::Low, Confidence::Possible),
        ]);
        assert_eq!(summary.high, 2);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.total(), 3);
        assert_eq!(summary.at_or_above(Severity::Medium), 2);
    }

    #[test]
    fn possible_findings_never_fail_ci_alone() {
        let report = report_of(vec![finding(Severity::High, Confidence::Possible)]);
        assert!(!report.should_fail(Severity::Info, Confidence::Possible));

        let report = report_of(vec![finding(Severity::High, Confidence::Likely)]);
        assert!(report.should_fail(Severity::Info, Confidence::Possible));
    }

    #[test]
    fn fail_on_respects_the_severity_floor() {
        let report = report_of(vec![finding(Severity::Low, Confidence::Confirmed)]);
        assert!(!report.should_fail(Severity::High, Confidence::Possible));
        assert!(report.should_fail(Severity::Low, Confidence::Possible));
    }

    #[test]
    fn a_truncated_report_always_fails_ci() {
        let mut report = report_of(Vec::new());
        report.truncated = true;
        assert!(
            report.should_fail(Severity::High, Confidence::Confirmed),
            "truncation must fail even with no retained findings and the strictest gate"
        );
    }

    #[test]
    fn timestamp_is_rfc3339_utc() {
        let now = now_rfc3339();
        assert!(now.ends_with('Z'), "expected UTC timestamp, got {now}");
        assert_eq!(now.len(), 20, "expected second precision, got {now}");
    }
}
