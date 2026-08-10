//! The scheduler: runs detectors, enforces the run-level rules, assembles the
//! report.
//!
//! Three things happen here that are easy to get wrong if each detector is left
//! to do them itself:
//!
//! - **Capability gating.** A detector that needs the network during a passive
//!   run is skipped before it executes, not trusted to check.
//! - **Failure isolation.** One detector erroring records an entry in
//!   `report.errors` and the scan continues. A scan that dies on the first bad
//!   file is a scan nobody runs twice.
//! - **Bounded everything.** Detector count, concurrency, and total findings
//!   all have caps, so neither a hostile target nor an over-enthusiastic plugin
//!   set can exhaust the machine.

use std::sync::Arc;

use futures_util::StreamExt;

use crate::context::ScanContext;
use crate::detector::{Detector, DetectorError};
use crate::finding::Finding;
use crate::limits;
use crate::report::{DetectorFailure, Report, ReportSummary, SCHEMA_VERSION, ScanTarget, ToolInfo};

/// Fatal scan failure. Detector-level problems are *not* here — they land in
/// [`Report::errors`]; only a broken run reaches this type.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// No detector survived selection, so the "no findings" result would be a
    /// lie. Usually a preset that names rules which do not exist.
    #[error("no detectors are enabled for preset {preset:?}")]
    NoDetectorsEnabled {
        /// Preset in force.
        preset: String,
    },

    /// The whole scan exceeded its wall-clock budget.
    #[error("scan exceeded its time budget of {}s", budget.as_secs())]
    TimeBudgetExhausted {
        /// The budget that elapsed.
        budget: std::time::Duration,
    },
}

/// Runs a set of detectors against one context.
pub struct Scheduler {
    detectors: Vec<Arc<dyn Detector>>,
    concurrency: usize,
}

impl Scheduler {
    /// Builds a scheduler.
    ///
    /// Detectors past [`limits::scan::MAX_DETECTORS`] are dropped: a run with
    /// more rules than that is a misconfiguration, and silently accepting it
    /// would mean an unbounded loop later.
    #[must_use]
    pub fn new(detectors: Vec<Arc<dyn Detector>>) -> Self {
        let detectors = detectors
            .into_iter()
            .take(limits::scan::MAX_DETECTORS)
            .collect();
        Self {
            detectors,
            concurrency: limits::scan::MAX_CONCURRENCY,
        }
    }

    /// Overrides concurrency. Clamped to `1..=MAX_CONCURRENCY`; zero would
    /// deadlock and unbounded would defeat the point.
    #[must_use]
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.clamp(1, limits::scan::MAX_CONCURRENCY);
        self
    }

    /// Runs every eligible detector and assembles the report.
    ///
    /// # Errors
    /// [`ScanError`] when the run itself could not proceed.
    pub async fn run(
        &self,
        ctx: &ScanContext<'_>,
        target: ScanTarget,
    ) -> Result<Report, ScanError> {
        let settings = ctx.settings();
        let eligible: Vec<&Arc<dyn Detector>> = self
            .detectors
            .iter()
            .filter(|detector| is_eligible(detector.as_ref(), ctx))
            .collect();

        if eligible.is_empty() {
            return Err(ScanError::NoDetectorsEnabled {
                preset: settings.preset.clone(),
            });
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut errors: Vec<DetectorFailure> = Vec::new();
        let mut truncated = false;

        // buffer_unordered gives us a fixed number of detectors in flight;
        // FuturesUnordered alone would start all of them at once.
        let mut running =
            futures_util::stream::iter(eligible.into_iter().map(|detector| async move {
                let id = detector.meta().id;
                (id, detector.run(ctx).await)
            }))
            .buffer_unordered(self.concurrency);

        while let Some((id, outcome)) = running.next().await {
            match outcome {
                Ok(produced) => {
                    // A detector that already returned a full cap cannot prove
                    // the project is clean — even when every finding fits
                    // exactly and the merge loop never sees an "extra" one.
                    if produced.len() >= limits::scan::MAX_FINDINGS {
                        truncated = true;
                    }
                    for finding in produced {
                        if findings.len() >= limits::scan::MAX_FINDINGS {
                            truncated = true;
                            break;
                        }
                        // Severity is filtered here. Confidence waits until
                        // after correlation (ADR 0014): a Possible static
                        // finding must still be present so a matching dynamic
                        // observation can raise it to Confirmed.
                        if finding.severity >= settings.min_severity {
                            findings.push(finding);
                        }
                    }
                }
                Err(error) => errors.push(failure(&id, &error)),
            }

            if ctx.budget().is_expired() {
                errors.push(DetectorFailure {
                    rule: "*".to_owned(),
                    message: format!(
                        "scan stopped after {}s: time budget exhausted",
                        ctx.budget().elapsed().as_secs()
                    ),
                });
                break;
            }
        }

        findings.sort_by(Finding::cmp_for_report);

        Ok(Report {
            schema_version: SCHEMA_VERSION.to_owned(),
            tool: ToolInfo::default(),
            scanned_at: crate::report::now_rfc3339(),
            duration_ms: u64::try_from(ctx.budget().elapsed().as_millis()).unwrap_or(u64::MAX),
            summary: ReportSummary::of(&findings),
            target,
            findings,
            suppressed_count: 0,
            suppressions: Vec::new(),
            baseline_hidden_count: 0,
            truncated,
            errors,
        })
    }
}

/// Whether a detector may run given the current settings.
///
/// The `active` check is the important one: a detector that declares `active`
/// stays unexecuted unless the user passed `--allow-active` for this run. There
/// is no config key that turns it on permanently, by design.
fn is_eligible(detector: &dyn Detector, ctx: &ScanContext<'_>) -> bool {
    let capabilities = detector.capabilities();
    if capabilities.active && !ctx.settings().allow_active {
        return false;
    }
    if capabilities.network && ctx.transport().is_none() {
        return false;
    }
    if capabilities.advisory && ctx.advisory().is_none() {
        return false;
    }
    true
}

/// Turns a detector error into a report entry. Never includes anything that
/// might carry a secret — the error types are already written to hold only
/// redacted messages, and this is the last place to keep that true.
fn failure(id: &crate::finding::RuleId, error: &DetectorError) -> DetectorFailure {
    DetectorFailure {
        rule: id.to_string(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    // The stub detector stores its outcome as a `fn` pointer, so the helpers
    // below must keep the `Result` return type even when they never fail.
    #![allow(clippy::unnecessary_wraps)]

    use std::path::{Path, PathBuf};

    use async_trait::async_trait;

    use super::*;
    use crate::budget::Budget;
    use crate::context::ScanSettings;
    use crate::detector::{Capabilities, DetectorKind, DetectorMeta};
    use crate::finding::{Confidence, RuleId, Severity};
    use crate::scope::DenyAllScope;
    use crate::source::{FileSelector, SourceError, SourceFile, SourceProvider};

    struct NoSource(PathBuf);

    impl SourceProvider for NoSource {
        fn root(&self) -> &Path {
            &self.0
        }
        fn files(&self, _selector: &FileSelector) -> Result<Vec<SourceFile>, SourceError> {
            Ok(Vec::new())
        }
        fn read(&self, file: &SourceFile) -> Result<std::sync::Arc<str>, SourceError> {
            Err(SourceError::PathEscapesRoot {
                path: file.path.to_string(),
            })
        }
    }

    struct Stub {
        id: &'static str,
        capabilities: Capabilities,
        outcome: fn() -> Result<Vec<Finding>, DetectorError>,
    }

    #[async_trait]
    impl Detector for Stub {
        fn meta(&self) -> DetectorMeta {
            DetectorMeta {
                id: RuleId::new_static(self.id),
                title: "stub".into(),
                severity: Severity::High,
                max_confidence: Confidence::Likely,
                owasp: None,
                cwe: None,
                category: "test".into(),
                description: "stub detector".into(),
            }
        }
        fn kind(&self) -> DetectorKind {
            DetectorKind::Static
        }
        fn capabilities(&self) -> Capabilities {
            self.capabilities
        }
        async fn run(&self, _ctx: &ScanContext<'_>) -> Result<Vec<Finding>, DetectorError> {
            (self.outcome)()
        }
    }

    fn one_finding() -> Result<Vec<Finding>, DetectorError> {
        Ok(vec![
            Finding::builder(RuleId::new_static("stub-a"), Severity::High, "found")
                .confidence(Confidence::Likely)
                .build(),
        ])
    }

    fn boom() -> Result<Vec<Finding>, DetectorError> {
        Err(DetectorError::Other("detector exploded".to_owned()))
    }

    fn low_finding() -> Result<Vec<Finding>, DetectorError> {
        Ok(vec![
            Finding::builder(RuleId::new_static("stub-a"), Severity::Low, "minor").build(),
        ])
    }

    async fn run_with(detectors: Vec<Arc<dyn Detector>>, settings: ScanSettings) -> Report {
        let source = NoSource(PathBuf::from("/tmp"));
        let scope = DenyAllScope;
        let budget = Budget::passive();
        let ctx = ScanContext::new(&source, None, &scope, &settings, &budget);
        Scheduler::new(detectors)
            .run(&ctx, ScanTarget::default())
            .await
            .expect("scheduler run should succeed")
    }

    #[tokio::test]
    async fn a_failing_detector_does_not_sink_the_scan() {
        let report = run_with(
            vec![
                Arc::new(Stub {
                    id: "stub-a",
                    capabilities: Capabilities::source_only(),
                    outcome: one_finding,
                }),
                Arc::new(Stub {
                    id: "stub-b",
                    capabilities: Capabilities::source_only(),
                    outcome: boom,
                }),
            ],
            ScanSettings::default(),
        )
        .await;

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.errors.len(), 1, "the failure must be surfaced");
        assert_eq!(
            report.errors.first().map(|e| e.rule.as_str()),
            Some("stub-b")
        );
    }

    #[tokio::test]
    async fn active_detectors_are_skipped_without_allow_active() {
        let active = Capabilities {
            source: true,
            network: false,
            advisory: false,
            active: true,
        };
        let report = run_with(
            vec![
                Arc::new(Stub {
                    id: "stub-a",
                    capabilities: Capabilities::source_only(),
                    outcome: one_finding,
                }),
                Arc::new(Stub {
                    id: "stub-active",
                    capabilities: active,
                    outcome: boom,
                }),
            ],
            ScanSettings::default(),
        )
        .await;

        // The active detector would have errored had it run.
        assert!(report.errors.is_empty());
        assert_eq!(report.findings.len(), 1);
    }

    #[tokio::test]
    async fn network_detectors_are_skipped_without_a_transport() {
        let source = NoSource(PathBuf::from("/tmp"));
        let scope = DenyAllScope;
        let budget = Budget::passive();
        let settings = ScanSettings::default();
        let ctx = ScanContext::new(&source, None, &scope, &settings, &budget);

        let result = Scheduler::new(vec![Arc::new(Stub {
            id: "stub-net",
            capabilities: Capabilities::passive_network(),
            outcome: one_finding,
        })])
        .run(&ctx, ScanTarget::default())
        .await;

        assert!(matches!(result, Err(ScanError::NoDetectorsEnabled { .. })));
    }

    #[tokio::test]
    async fn min_severity_filters_before_reporting() {
        let settings = ScanSettings {
            min_severity: Severity::Medium,
            ..ScanSettings::default()
        };

        let report = run_with(
            vec![Arc::new(Stub {
                id: "stub-a",
                capabilities: Capabilities::source_only(),
                outcome: low_finding,
            })],
            settings,
        )
        .await;

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.total(), 0);
    }

    fn flood_at_cap() -> Result<Vec<Finding>, DetectorError> {
        let n = crate::limits::scan::MAX_FINDINGS;
        Ok((0..n)
            .map(|i| {
                Finding::builder(
                    RuleId::new_static("stub-a"),
                    Severity::High,
                    format!("finding-{i}"),
                )
                .confidence(Confidence::Likely)
                .build()
            })
            .collect())
    }

    #[tokio::test]
    async fn a_detector_returning_exactly_the_cap_marks_truncated() {
        // Regression: when produced.len() == MAX_FINDINGS, the merge loop
        // never sees an "extra" finding, so truncation must be detected from
        // the batch size itself — otherwise CI exits 0 on a partial scan.
        let report = run_with(
            vec![Arc::new(Stub {
                id: "stub-flood",
                capabilities: Capabilities::source_only(),
                outcome: flood_at_cap,
            })],
            ScanSettings::default(),
        )
        .await;

        assert_eq!(report.findings.len(), crate::limits::scan::MAX_FINDINGS);
        assert!(report.truncated, "exact-cap flood must set truncated");
        assert!(
            report.should_fail(Severity::High, Confidence::Confirmed),
            "truncated reports must fail CI even under the strictest gate"
        );
    }

    fn flood_over_cap() -> Result<Vec<Finding>, DetectorError> {
        let n = crate::limits::scan::MAX_FINDINGS + 3;
        Ok((0..n)
            .map(|i| {
                Finding::builder(
                    RuleId::new_static("stub-a"),
                    Severity::Medium,
                    format!("finding-{i}"),
                )
                .confidence(Confidence::Likely)
                .build()
            })
            .collect())
    }

    #[tokio::test]
    async fn findings_beyond_the_cap_are_dropped_and_flagged() {
        let report = run_with(
            vec![Arc::new(Stub {
                id: "stub-flood",
                capabilities: Capabilities::source_only(),
                outcome: flood_over_cap,
            })],
            ScanSettings::default(),
        )
        .await;

        assert_eq!(report.findings.len(), crate::limits::scan::MAX_FINDINGS);
        assert!(report.truncated);
        assert!(report.should_fail(Severity::Info, Confidence::Possible));
    }
}
