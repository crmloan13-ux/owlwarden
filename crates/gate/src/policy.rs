//! The posture, the tighten-only rule, and the decision itself.
//!
//! # The asymmetry, which is the whole rule
//!
//! `gate` runs automatically, on a tree the agent is editing. A repository that
//! can lower `--fail-on`, add a suppression, or point `--plugin` at its own
//! WASM has disabled its own gate — and unlike `scan`, nobody typed a flag to
//! let it.
//!
//! So project-level configuration may **tighten** the posture and may never
//! loosen it. `failOn` down: honoured. `failOn` up: refused, and reported. That
//! asymmetry is the entire policy, and it is testable
//! ([ADR 0026](../../../docs/adr/0026-deterministic-agent-gate.md) §3).
//!
//! # The failure posture, which is not a preference
//!
//! A hook that crashes must not brick a developer's session, and a hook that
//! fails silently is not a control. The split is by consequence:
//!
//! - **Before a command executes** — failing returns `ask`. The developer
//!   decides; nothing runs on a coin flip.
//! - **After an edit, or at a turn boundary** — failing returns `allow` and
//!   writes a loud line to stderr. Nothing has executed, the CI gate is still
//!   behind this, and blocking a session because a scanner timed out is the
//!   wrong trade — it is the trade that gets the hook uninstalled.
//!
//! `OWLWARDEN_GATE_FAIL=closed` flips the second case for teams that want it,
//! and it is off by default because the default should be the one that keeps
//! people from removing the gate.

use owlwarden_core::finding::{Confidence, Finding, Severity};
use owlwarden_core::report::Report;
use owlwarden_core::suppression::SuppressionRecord;
use serde::{Deserialize, Serialize};

use crate::decision::{GateDecision, Verdict};
use crate::event::{GateEvent, GateEventKind};

/// Findings named in a reason string before it starts summarising.
const MAX_REASON_FINDINGS: usize = 10;

/// What the gate blocks on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatePolicy {
    /// Severity at or above which the gate denies.
    ///
    /// Defaults to `High`, not `Info`. A gate that blocks on everything is a
    /// gate that gets removed in week one.
    pub fail_on: Severity,
    /// Confidence at or above which a finding counts.
    ///
    /// Defaults to `Likely`. A gate that blocks on a heuristic is a gate that
    /// gets removed in week two.
    pub min_confidence: Confidence,
    /// Whether a *post*-execution failure denies instead of allowing.
    pub fail_closed: bool,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            fail_on: Severity::High,
            min_confidence: Confidence::Likely,
            fail_closed: false,
        }
    }
}

/// A project-config setting the gate refused, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureRejection {
    /// The setting, as the project spelled it.
    pub setting: String,
    /// What the project asked for.
    pub requested: String,
    /// What is in force instead.
    pub in_force: String,
}

/// What a project's own configuration asked the gate to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectPosture {
    /// `failOn` from the project's config file, if it set one.
    pub fail_on: Option<Severity>,
    /// `minConfidence` from the project's config file, if it set one.
    pub min_confidence: Option<Confidence>,
}

impl GatePolicy {
    /// Applies a project's requested posture, keeping only the tightenings.
    ///
    /// Returns the resulting policy and one [`PostureRejection`] per refusal.
    /// The refusals are reported rather than silently dropped: a team whose
    /// config is being partly ignored deserves to know which part.
    #[must_use]
    pub fn tighten_with(&self, project: &ProjectPosture) -> (Self, Vec<PostureRejection>) {
        let mut policy = self.clone();
        let mut rejections = Vec::new();

        if let Some(requested) = project.fail_on {
            if requested < policy.fail_on {
                // Lower threshold = blocks on more = tighter.
                policy.fail_on = requested;
            } else if requested > policy.fail_on {
                rejections.push(PostureRejection {
                    setting: "failOn".to_owned(),
                    requested: requested.as_str().to_owned(),
                    in_force: policy.fail_on.as_str().to_owned(),
                });
            }
        }

        if let Some(requested) = project.min_confidence {
            if requested < policy.min_confidence {
                policy.min_confidence = requested;
            } else if requested > policy.min_confidence {
                rejections.push(PostureRejection {
                    setting: "minConfidence".to_owned(),
                    requested: requested.as_str().to_owned(),
                    in_force: policy.min_confidence.as_str().to_owned(),
                });
            }
        }

        (policy, rejections)
    }

    /// Whether a finding meets the bar.
    #[must_use]
    pub fn blocks_on(&self, finding: &Finding) -> bool {
        finding.severity >= self.fail_on && finding.confidence >= self.min_confidence
    }
}

/// What the caller managed to do.
#[derive(Debug)]
pub enum GateOutcome {
    /// The scan completed. Findings are already filtered by the run's own
    /// thresholds; the policy filters again, because the two can differ.
    Scanned(Box<Report>),
    /// The scan did not complete, for any reason: a timeout, a parse error, a
    /// missing binary. The message is shown on stderr, never to the model — a
    /// model asked to respond to "the scanner crashed" will try to fix the
    /// scanner.
    Failed(String),
}

/// Turns an event and an outcome into a decision.
///
/// The only place a verdict is chosen. Adapters translate; they never decide.
#[must_use]
pub fn decide(event: &GateEvent, outcome: GateOutcome, policy: &GatePolicy) -> GateDecision {
    let report = match outcome {
        GateOutcome::Scanned(report) => report,
        GateOutcome::Failed(message) => return failure_decision(event, &message, policy),
    };

    if event.kind == GateEventKind::SessionStart {
        return GateDecision::new(Verdict::Allow, "session start: nothing to judge yet")
            .with_context(session_digest(&report))
            .with_ignored_suppressions(ignored(&report));
    }

    let blocking: Vec<Finding> = report
        .findings
        .iter()
        .filter(|finding| policy.blocks_on(finding))
        .cloned()
        .collect();

    if blocking.is_empty() {
        let reason = if report.truncated {
            // A truncated report is not a clean report, and a gate that treated
            // it as one would be green on exactly the repositories that most
            // need it.
            "owlwarden hit its finding cap; treat this as incomplete, not clean".to_owned()
        } else {
            format!(
                "owlwarden: no {} findings in scope",
                policy.fail_on.as_str()
            )
        };
        let verdict = if report.truncated {
            Verdict::Ask
        } else {
            Verdict::Allow
        };
        return GateDecision::new(verdict, reason)
            .with_findings(report.findings.clone())
            .with_ignored_suppressions(ignored(&report));
    }

    GateDecision::new(Verdict::Deny, deny_reason(event, &blocking, &report))
        .with_findings(blocking)
        .with_ignored_suppressions(ignored(&report))
}

/// The reason string a model has to respond to.
///
/// Rule, location, and the fix — in that order, because that is the order the
/// agent needs them in to act without asking a follow-up question. No `why`:
/// the agent has already been told to care by the verdict, and the prose is the
/// most expensive part of the report.
fn deny_reason(event: &GateEvent, blocking: &[Finding], report: &Report) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "owlwarden blocked this {}: {} finding{} at or above the gate threshold.",
        match event.kind {
            GateEventKind::ShellCommand => "command",
            GateEventKind::ConfigChanged => "configuration change",
            GateEventKind::TurnBoundary => "turn",
            _ => "edit",
        },
        blocking.len(),
        if blocking.len() == 1 { "" } else { "s" }
    ));

    for finding in blocking.iter().take(MAX_REASON_FINDINGS) {
        let location = match &finding.location {
            owlwarden_core::finding::Location::Source(source) => {
                format!("{}:{}:{}", source.path, source.line, source.col)
            }
            owlwarden_core::finding::Location::Endpoint(endpoint) => {
                format!("{} {}", endpoint.method, endpoint.url)
            }
        };
        lines.push(format!(
            "\n{} [{}] {}\n  at {}",
            finding.severity.as_str().to_uppercase(),
            finding.id,
            finding.title,
            location
        ));
        if let Some(fix) = finding.primary_fix() {
            lines.push(format!("  fix: {}", one_line(&fix.summary)));
            if let Some(patch) = &fix.patch {
                for patch_line in patch.lines().take(10) {
                    lines.push(format!("  | {patch_line}"));
                }
            }
        }
    }

    if blocking.len() > MAX_REASON_FINDINGS {
        lines.push(format!(
            "\n… {} more (run: owlwarden scan --format json)",
            blocking.len() - MAX_REASON_FINDINGS
        ));
    }

    let refused = ignored(report);
    if !refused.is_empty() {
        lines.push(format!(
            "\n{} inline suppression(s) in files written this session were not honoured.",
            refused.len()
        ));
    }

    lines.push(
        "\nFix the findings, then continue. Do not suppress them: a suppression written now is \
         not honoured by this gate."
            .to_owned(),
    );
    lines.join("\n")
}

/// The bounded digest a session-start hook injects.
fn session_digest(report: &Report) -> String {
    format!(
        "owlwarden {} is watching this workspace ({} preset{}). Baseline posture: {} finding(s) \
         currently reported — {} high, {} medium. Edits are re-scanned; the turn boundary is \
         gated. Fix findings rather than suppressing them; suppressions written during a session \
         are reported and not honoured.",
        report.tool.version,
        report.target.preset,
        report
            .target
            .diff_scope
            .as_ref()
            .map(|scope| format!(", {scope}"))
            .unwrap_or_default(),
        report.summary.total(),
        report.summary.high,
        report.summary.medium
    )
}

/// Suppressions the run found and refused to honour.
///
/// The report carries every directive; a refused one is a directive that
/// matched something and still did not hide it, which is exactly the set with
/// `stale == false` while `suppressed_count` did not account for it. Rather
/// than re-deriving that, the runner has already applied the policy — so what
/// is reported here is every non-stale directive when nothing was suppressed at
/// all, which is the gate's case.
fn ignored(report: &Report) -> Vec<SuppressionRecord> {
    if report.suppressed_count > 0 {
        return Vec::new();
    }
    report
        .suppressions
        .iter()
        .filter(|record| !record.stale && !record.missing_reason)
        .cloned()
        .collect()
}

/// What to do when the gate could not run.
fn failure_decision(event: &GateEvent, message: &str, policy: &GatePolicy) -> GateDecision {
    if event.kind.precedes_execution() {
        return GateDecision::new(
            Verdict::Ask,
            format!(
                "owlwarden could not check this command ({message}). Nothing has run yet — \
                 approve it only if you know what it does."
            ),
        )
        .degraded();
    }

    if policy.fail_closed {
        return GateDecision::new(
            Verdict::Deny,
            format!(
                "owlwarden could not complete ({message}), and this gate is configured \
                 fail-closed."
            ),
        )
        .degraded();
    }

    GateDecision::new(
        Verdict::Allow,
        format!(
            "owlwarden could not complete ({message}); nothing has executed and CI still gates \
             this. Set OWLWARDEN_GATE_FAIL=closed to block instead."
        ),
    )
    .degraded()
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use owlwarden_core::finding::{Fix, FixSafety, Location, RuleId, SourceLocation};
    use owlwarden_core::report::{ReportSummary, ScanTarget, ToolInfo, now_rfc3339};

    fn finding(severity: Severity, confidence: Confidence) -> Finding {
        Finding::builder(
            RuleId::new_static("stack-trace-leak"),
            severity,
            "Stack trace leaked in error response",
        )
        .confidence(confidence)
        .why("a long human paragraph the agent does not need")
        .location(Location::Source(SourceLocation {
            path: "app/api/users/route.ts".into(),
            line: 13,
            col: 16,
        }))
        .fix(Fix {
            framework: None,
            host: None,
            summary: "Return a generic message; log the error server-side.".into(),
            patch: Some("return NextResponse.json({ error: 'Internal Server Error' })".into()),
            safety: FixSafety::Manual,
        })
        .build()
    }

    fn report_of(findings: Vec<Finding>) -> Box<Report> {
        Box::new(Report {
            schema_version: "1.0".into(),
            tool: ToolInfo::default(),
            scanned_at: now_rfc3339(),
            duration_ms: 3,
            target: ScanTarget {
                preset: "quick".into(),
                ..ScanTarget::default()
            },
            summary: ReportSummary::of(&findings),
            findings,
            suppressed_count: 0,
            suppressions: Vec::new(),
            baseline_hidden_count: 0,
            truncated: false,
            errors: Vec::new(),
        })
    }

    fn event(kind: GateEventKind) -> GateEvent {
        GateEvent::new("generic", kind)
    }

    #[test]
    fn the_default_gate_blocks_on_high_and_likely_and_nothing_less() {
        let policy = GatePolicy::default();
        assert!(policy.blocks_on(&finding(Severity::High, Confidence::Likely)));
        assert!(!policy.blocks_on(&finding(Severity::Medium, Confidence::Likely)));
        assert!(
            !policy.blocks_on(&finding(Severity::High, Confidence::Possible)),
            "a gate that blocks on a heuristic is a gate that gets removed"
        );
    }

    #[test]
    fn a_project_may_tighten_the_gate() {
        let (policy, rejections) = GatePolicy::default().tighten_with(&ProjectPosture {
            fail_on: Some(Severity::Medium),
            min_confidence: Some(Confidence::Possible),
        });
        assert_eq!(policy.fail_on, Severity::Medium);
        assert_eq!(policy.min_confidence, Confidence::Possible);
        assert!(rejections.is_empty(), "tightening is always honoured");
    }

    #[test]
    fn a_project_may_never_loosen_the_gate_and_the_attempt_is_reported() {
        // ADR 0026 exit criterion 3. This is the property the gate exists to
        // have: a repository cannot disable its own gate by editing a file in
        // the repository.
        let strict = GatePolicy {
            fail_on: Severity::Medium,
            min_confidence: Confidence::Possible,
            fail_closed: false,
        };
        let (policy, rejections) = strict.tighten_with(&ProjectPosture {
            fail_on: Some(Severity::High),
            min_confidence: Some(Confidence::Confirmed),
        });
        assert_eq!(
            policy.fail_on,
            Severity::Medium,
            "the loosening was refused"
        );
        assert_eq!(policy.min_confidence, Confidence::Possible);
        assert_eq!(rejections.len(), 2);
        assert_eq!(rejections[0].setting, "failOn");
        assert_eq!(rejections[0].requested, "high");
        assert_eq!(rejections[0].in_force, "medium");
    }

    #[test]
    fn a_clean_scan_allows() {
        let decision = decide(
            &event(GateEventKind::FileEdited),
            GateOutcome::Scanned(report_of(Vec::new())),
            &GatePolicy::default(),
        );
        assert_eq!(decision.verdict, Verdict::Allow);
        assert!(!decision.degraded);
    }

    #[test]
    fn a_blocking_finding_denies_with_the_rule_the_line_and_the_fix() {
        let decision = decide(
            &event(GateEventKind::FileEdited),
            GateOutcome::Scanned(report_of(vec![finding(Severity::High, Confidence::Likely)])),
            &GatePolicy::default(),
        );
        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("stack-trace-leak"));
        assert!(decision.reason.contains("app/api/users/route.ts:13:16"));
        assert!(decision.reason.contains("fix: Return a generic message"));
        assert!(
            !decision.reason.contains("a long human paragraph"),
            "the `why` field is written for a human and costs the agent tokens"
        );
        assert!(decision.reason.contains("Do not suppress"));
    }

    #[test]
    fn a_truncated_report_is_never_an_allow() {
        let mut report = report_of(Vec::new());
        report.truncated = true;
        let decision = decide(
            &event(GateEventKind::TurnBoundary),
            GateOutcome::Scanned(report),
            &GatePolicy::default(),
        );
        assert_eq!(decision.verdict, Verdict::Ask);
        assert!(decision.reason.contains("not clean"));
    }

    #[test]
    fn failing_before_a_command_asks_and_never_allows() {
        // ADR 0026 exit criterion 9, first half. Nothing runs on a coin flip.
        let decision = decide(
            &event(GateEventKind::ShellCommand),
            GateOutcome::Failed("timed out after 400ms".into()),
            &GatePolicy::default(),
        );
        assert_eq!(decision.verdict, Verdict::Ask);
        assert!(decision.degraded);
        assert!(decision.reason.contains("Nothing has run yet"));
    }

    #[test]
    fn failing_after_an_edit_allows_and_says_so_loudly() {
        // Second half. Nothing has executed, CI is still behind this, and
        // bricking a session over a scanner bug is how the hook gets removed.
        let decision = decide(
            &event(GateEventKind::FileEdited),
            GateOutcome::Failed("engine not found".into()),
            &GatePolicy::default(),
        );
        assert_eq!(decision.verdict, Verdict::Allow);
        assert!(decision.degraded);
        assert!(decision.reason.contains("OWLWARDEN_GATE_FAIL=closed"));
    }

    #[test]
    fn fail_closed_flips_only_the_post_execution_case() {
        let policy = GatePolicy {
            fail_closed: true,
            ..GatePolicy::default()
        };
        assert_eq!(
            decide(
                &event(GateEventKind::FileEdited),
                GateOutcome::Failed("boom".into()),
                &policy
            )
            .verdict,
            Verdict::Deny
        );
        assert_eq!(
            decide(
                &event(GateEventKind::ShellCommand),
                GateOutcome::Failed("boom".into()),
                &policy
            )
            .verdict,
            Verdict::Ask,
            "before execution, ask is already the strict answer"
        );
    }

    #[test]
    fn session_start_injects_context_and_blocks_nothing() {
        let decision = decide(
            &event(GateEventKind::SessionStart),
            GateOutcome::Scanned(report_of(vec![finding(Severity::High, Confidence::Likely)])),
            &GatePolicy::default(),
        );
        assert_eq!(decision.verdict, Verdict::Allow);
        let context = decision.context.expect("a digest");
        assert!(context.contains("Baseline posture"));
        assert!(context.contains("suppressions written during a session"));
    }

    #[test]
    fn a_long_deny_summarises_rather_than_dumping() {
        let findings: Vec<Finding> = (0..40)
            .map(|_| finding(Severity::High, Confidence::Likely))
            .collect();
        let decision = decide(
            &event(GateEventKind::TurnBoundary),
            GateOutcome::Scanned(report_of(findings)),
            &GatePolicy::default(),
        );
        assert_eq!(
            decision.findings.len(),
            40,
            "the full set travels in the data"
        );
        assert!(decision.reason.contains("30 more"), "the prose is bounded");
    }
}
