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

use crate::finding::{Confidence, Exposure, Finding, Severity};
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
    /// The runtime the project resolved to, and whether that was detected or
    /// inferred, as `"node"` / `"edge (defaulted)"`.
    ///
    /// On the summary line in every non-machine format, and **not droppable in
    /// quiet modes**: runtime detection is inference, and a fix chosen from an
    /// inferred runtime has to say what it inferred
    /// ([ADR 0031](../../../docs/adr/0031-runtime-overlay.md) §1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// How many detectors actually ran.
    ///
    /// On the summary line of a **clean** report, and only there. `No findings`
    /// on its own is the least useful sentence this tool produces: it is
    /// indistinguishable from a scan that ran no rules, matched no files, or
    /// silently skipped half its catalogue, and
    /// `docs/explanation/compared.md` has claimed since 1.0 that a clean
    /// report you cannot calibrate is worse than no report. This is the number
    /// that makes it calibratable.
    #[serde(default)]
    pub rules_run: u32,
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

/// Finding counts by [`Exposure`]. Present even when zero, for the same reason
/// [`ReportSummary`] is: a consumer renders the distribution without
/// special-casing, and a zero is a statement rather than an absence.
///
/// This is the line that changes how the tool feels on a legacy repository.
/// "23 findings" is a backlog; "3 internet-reachable" is an afternoon.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposureSummary {
    /// On a request path with no gate identified.
    pub internet: u32,
    /// On a request path behind an identified gate.
    pub authenticated: u32,
    /// Not on a request path.
    pub internal: u32,
    /// Could not be placed. Counts findings that carry no exposure at all —
    /// the agent surface — as well as those explicitly classified `unknown`,
    /// because to a reader of the distribution they are the same statement.
    pub unknown: u32,
}

impl ExposureSummary {
    /// Counts findings by exposure.
    #[must_use]
    pub fn of(findings: &[Finding]) -> Self {
        let mut summary = Self::default();
        for finding in findings {
            let slot = match finding.exposure {
                Some(Exposure::Internet) => &mut summary.internet,
                Some(Exposure::Authenticated) => &mut summary.authenticated,
                Some(Exposure::Internal) => &mut summary.internal,
                Some(Exposure::Unknown) | None => &mut summary.unknown,
            };
            *slot = slot.saturating_add(1);
        }
        summary
    }

    /// The count for one value.
    #[must_use]
    pub const fn count(&self, exposure: Exposure) -> u32 {
        match exposure {
            Exposure::Internet => self.internet,
            Exposure::Authenticated => self.authenticated,
            Exposure::Internal => self.internal,
            Exposure::Unknown => self.unknown,
        }
    }

    /// Total across all values.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.internet
            .saturating_add(self.authenticated)
            .saturating_add(self.internal)
            .saturating_add(self.unknown)
    }

    /// The share of findings that could not be placed, as a percentage
    /// rounded to the nearest whole number. Reported by `coverage`, because an
    /// unclassified rate that is only felt is one nobody fixes.
    #[must_use]
    pub fn unclassified_percent(&self) -> u32 {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        // `u64` so a report at the findings cap cannot overflow the numerator.
        let scaled = u64::from(self.unknown)
            .saturating_mul(100)
            .saturating_add(u64::from(total) / 2);
        u32::try_from(scaled / u64::from(total)).unwrap_or(100)
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
    /// Counts by exposure. Added in 1.2; a consumer written against the 1.1
    /// shape sees a new object and is unaffected, which is why this is a
    /// minor-version change rather than a schema break.
    #[serde(default)]
    pub exposure_summary: ExposureSummary,
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
        self.should_fail_with(fail_on, min_confidence, None)
    }

    /// [`Self::should_fail`] with the independent exposure gate from
    /// [ADR 0029](../../../docs/adr/0029-exposure-model.md) §4.
    ///
    /// The two thresholds compose as an **OR**, because they express different
    /// policies — *nothing worse than medium* and *nothing an anonymous caller
    /// can reach* — and a team should be able to hold both. The confidence
    /// floor applies to each: a `possible` finding on an internet-reachable
    /// route is still a guess, and failing a build on a guess is how a tool
    /// gets removed from a pipeline.
    #[must_use]
    pub fn should_fail_with(
        &self,
        fail_on: Severity,
        min_confidence: Confidence,
        fail_on_exposure: Option<Exposure>,
    ) -> bool {
        if self.truncated {
            return true;
        }
        self.findings
            .iter()
            .any(|finding| fails_gate(finding, fail_on, min_confidence, fail_on_exposure))
    }

    /// Drops findings below `min_confidence` and recomputes the summary.
    ///
    /// Applied after correlation (ADR 0014) so a `Possible` static finding can
    /// still be raised to `Confirmed` by a matching dynamic observation.
    pub fn apply_min_confidence(&mut self, min_confidence: Confidence) {
        self.findings
            .retain(|finding| finding.confidence >= min_confidence);
        self.recount();
    }

    /// Recomputes both summaries from the current findings.
    ///
    /// One call rather than two so a pass that filters findings cannot update
    /// the severity distribution and forget the exposure one — which would
    /// leave the summary line contradicting the list underneath it.
    pub fn recount(&mut self) {
        self.summary = ReportSummary::of(&self.findings);
        self.exposure_summary = ExposureSummary::of(&self.findings);
    }
}

/// Whether one finding trips the gate.
///
/// Extracted from [`Report::should_fail_with`] because [`crate::turn`] applies
/// the *same* predicate to a different set — the findings a single turn
/// introduced. Two copies of this would be two definitions of "bad enough to
/// stop the build", and they would drift the first time one threshold changed.
///
/// `Possible`-confidence findings never trip it, at any severity and any
/// exposure. Acting on a guess is how a tool gets removed from a pipeline.
#[must_use]
pub fn fails_gate(
    finding: &Finding,
    fail_on: Severity,
    min_confidence: Confidence,
    fail_on_exposure: Option<Exposure>,
) -> bool {
    if finding.confidence < min_confidence || finding.confidence <= Confidence::Possible {
        return false;
    }
    let by_severity = finding.severity >= fail_on;
    let by_exposure = fail_on_exposure.is_some_and(|threshold| {
        finding
            .exposure
            .is_some_and(|exposure| exposure >= threshold)
    });
    by_severity || by_exposure
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
    use crate::finding::{Exposure, Finding, RuleId};

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
            exposure_summary: ExposureSummary::default(),
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
    fn the_exposure_gate_trips_independently_of_the_severity_gate() {
        // ADR 0029 exit criterion 5. `--fail-on high` alone passes a medium
        // finding; `--fail-on-exposure internet` alone fails it; together they
        // behave as an OR rather than an AND.
        let reachable =
            Finding::builder(RuleId::new_static("insecure-cookie"), Severity::Medium, "t")
                .confidence(Confidence::Likely)
                .exposure(
                    Exposure::Internet,
                    crate::finding::ExposureEvidence::default(),
                )
                .build();
        let report = report_of(vec![reachable]);

        assert!(!report.should_fail(Severity::High, Confidence::Possible));
        assert!(report.should_fail_with(
            Severity::High,
            Confidence::Possible,
            Some(Exposure::Internet)
        ));
        assert!(report.should_fail_with(
            Severity::Medium,
            Confidence::Possible,
            Some(Exposure::Internet)
        ));
    }

    #[test]
    fn the_exposure_gate_respects_the_confidence_floor() {
        // Failing a build on a guess is how a tool gets removed from a
        // pipeline, and an internet-reachable guess is still a guess.
        let guess = Finding::builder(RuleId::new_static("ssrf"), Severity::High, "t")
            .confidence(Confidence::Possible)
            .exposure(
                Exposure::Internet,
                crate::finding::ExposureEvidence::default(),
            )
            .build();
        let report = report_of(vec![guess]);
        assert!(!report.should_fail_with(
            Severity::High,
            Confidence::Possible,
            Some(Exposure::Internet)
        ));
    }

    #[test]
    fn a_finding_with_no_exposure_never_trips_the_exposure_gate() {
        // Every agent-surface finding carries no exposure. Tripping the gate on
        // them would make `--fail-on-exposure internet` mean "fail on
        // everything" the moment `vet` findings appear in the same report.
        let agent = Finding::builder(
            RuleId::new_static("agent-hook-autoexec"),
            Severity::Low,
            "t",
        )
        .confidence(Confidence::Likely)
        .build();
        let report = report_of(vec![agent]);
        assert!(!report.should_fail_with(
            Severity::High,
            Confidence::Possible,
            Some(Exposure::Internet)
        ));
    }

    #[test]
    fn the_exposure_distribution_counts_absent_values_as_unclassified() {
        let findings = vec![
            Finding::builder(RuleId::new_static("ssrf"), Severity::High, "t")
                .exposure(
                    Exposure::Internet,
                    crate::finding::ExposureEvidence::default(),
                )
                .build(),
            Finding::builder(RuleId::new_static("ssrf"), Severity::High, "t").build(),
        ];
        let distribution = ExposureSummary::of(&findings);
        assert_eq!(distribution.internet, 1);
        assert_eq!(distribution.unknown, 1);
        assert_eq!(distribution.total(), 2);
        assert_eq!(distribution.unclassified_percent(), 50);
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
