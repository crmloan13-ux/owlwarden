//! One function that performs a scan of a project directory.
//!
//! The CLI, the napi bridge, and the fixture tests all call this. That is the
//! point: if the tests took a different path from the CLI, they would be
//! testing something the user never runs.
//!
//! A run without [`ScanRequest::network`] stays passive by construction: no
//! transport is built, the scope resolver denies everything, and the request
//! budget is zero. Dynamic probing is wired by the caller (see ADR 0014).

use std::path::PathBuf;
use std::sync::Arc;

use owlwarden_core::advisory::AdvisoryClient;
use owlwarden_core::baseline::BaselineFile;
use owlwarden_core::budget::Budget;
use owlwarden_core::context::{ScanContext, ScanSettings};
use owlwarden_core::detector::Detector;
use owlwarden_core::finding::Finding;
use owlwarden_core::report::{Report, ScanTarget};
use owlwarden_core::scheduler::{ScanError, Scheduler};
use owlwarden_core::scope::{DenyAllScope, ScopeResolver};
use owlwarden_core::source::SourceError;
use owlwarden_core::transport::Transport;

use crate::engine::StaticEngine;
use crate::fs_source::FsSourceProvider;
use crate::incremental;
use crate::postprocess::{apply_baseline, apply_suppressions_with};
use crate::rule::{FileRule, ProjectRule};

/// A scan could not be performed at all.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The project directory could not be opened or walked.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// The run itself was invalid — no rules enabled, or out of time.
    #[error(transparent)]
    Scan(#[from] ScanError),
    /// A baseline file could not be written.
    #[error("could not write baseline to {path}: {message}")]
    BaselineWrite {
        /// Destination path.
        path: String,
        /// Underlying message.
        message: String,
    },
    /// Incremental watch received an invalid dirty-path list.
    #[error("invalid dirty paths: {message}")]
    InvalidDirtyPaths {
        /// Why the list was rejected.
        message: String,
    },
}

/// Network stack for a live (passive-dynamic) scan.
///
/// Built by the CLI/napi layer from `--target` / `--scope`. The static engine
/// does not construct a transport itself — that keeps reqwest out of this crate.
pub struct NetworkStack {
    /// Scope-enforcing transport.
    pub transport: Arc<dyn Transport>,
    /// Allowlist consulted by the transport (and exposed for defence in depth).
    pub scope: Arc<dyn ScopeResolver>,
    /// Shared request/time budget.
    pub budget: Arc<Budget>,
    /// Wire forms for `Report.target.scope`.
    pub scope_labels: Vec<String>,
}

/// Optional inputs that sit beside the rule set.
///
/// Kept separate from [`ScanSettings`] on purpose: settings travel into every
/// detector, while baseline is a post-pass the detectors must not see.
pub struct ScanRequest {
    /// Thresholds and preset name.
    pub settings: ScanSettings,
    /// When set, findings whose fingerprint is in the baseline are dropped.
    pub baseline: Option<BaselineFile>,
    /// When set, write the post-suppression findings to this path *before*
    /// applying [`Self::baseline`], so `--write-baseline` captures current debt
    /// and `--baseline` can still filter the displayed report against an older
    /// file in the same run.
    pub write_baseline: Option<PathBuf>,
    /// When false, inline suppressions are listed but do not hide findings.
    /// CI on an untrusted tree sets this false unless the operator opted in.
    pub honor_suppressions: bool,
    /// Extra detectors to run alongside the static engine (e.g. dynamic).
    pub extra_detectors: Vec<Arc<dyn Detector>>,
    /// When set, detectors may use the network under this stack.
    pub network: Option<NetworkStack>,
    /// Opt-in advisory client (`--osv`). Never shares `--target` scope.
    pub advisory: Option<Arc<dyn AdvisoryClient>>,
    /// Optional correlation post-pass (static + dynamic → `Confirmed`).
    pub correlate: Option<fn(Vec<Finding>) -> Vec<Finding>>,
    /// Project-relative paths that changed since the last scan. Empty/absent → full scan.
    pub dirty_paths: Option<Vec<String>>,
    /// Previous report for incremental merge in watch mode.
    pub previous_report: Option<Report>,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            settings: ScanSettings::default(),
            baseline: None,
            write_baseline: None,
            honor_suppressions: true,
            extra_detectors: Vec::new(),
            network: None,
            advisory: None,
            correlate: None,
            dirty_paths: None,
            previous_report: None,
        }
    }
}

/// Scans a project directory with the given rules.
///
/// The scan is passive by construction, not by promise: no transport is built,
/// so there is nothing for a detector to send a request through, and the scope
/// resolver denies everything as a second line of defence.
///
/// # Errors
/// [`RunError`] if the directory cannot be read or no rules are enabled.
pub async fn scan_project(
    root: impl AsRef<std::path::Path>,
    file_rules: Vec<Arc<dyn FileRule>>,
    project_rules: Vec<Arc<dyn ProjectRule>>,
    settings: ScanSettings,
) -> Result<Report, RunError> {
    scan_project_with(
        root,
        file_rules,
        project_rules,
        ScanRequest {
            settings,
            baseline: None,
            write_baseline: None,
            honor_suppressions: true,
            extra_detectors: Vec::new(),
            network: None,
            advisory: None,
            correlate: None,
            dirty_paths: None,
            previous_report: None,
        },
    )
    .await
}

/// Scans a project with optional baseline, network, and correlation.
///
/// # Errors
/// [`RunError`] if the directory cannot be read or no rules are enabled.
pub async fn scan_project_with(
    root: impl AsRef<std::path::Path>,
    file_rules: Vec<Arc<dyn FileRule>>,
    project_rules: Vec<Arc<dyn ProjectRule>>,
    request: ScanRequest,
) -> Result<Report, RunError> {
    let root = root.as_ref();
    let provider = FsSourceProvider::new(root)?;
    let project_rules_for_merge = project_rules.clone();
    let engine = Arc::new(StaticEngine::new(file_rules, project_rules));

    let (settings, merge_previous, merge_dirty) = prepare_incremental(
        root,
        request.settings,
        request.dirty_paths.clone(),
        request.previous_report.clone(),
    )?;

    let deny_all = DenyAllScope;
    let passive_budget = Budget::passive();

    let (transport, scope, budget, scope_labels) = match &request.network {
        Some(network) => (
            Some(network.transport.as_ref()),
            network.scope.as_ref() as &dyn ScopeResolver,
            network.budget.as_ref(),
            network.scope_labels.clone(),
        ),
        None => (
            None,
            &deny_all as &dyn ScopeResolver,
            &passive_budget,
            Vec::new(),
        ),
    };

    let advisory = request.advisory.as_deref();
    let context =
        ScanContext::with_advisory(&provider, transport, advisory, scope, &settings, budget);

    let target = ScanTarget {
        project: root.display().to_string(),
        scope: scope_labels,
        files_scanned: 0,
        routes_probed: 0,
        preset: settings.preset.clone(),
    };

    let mut detectors: Vec<Arc<dyn Detector>> =
        Vec::with_capacity(1 + request.extra_detectors.len());
    detectors.push(engine.clone());
    detectors.extend(request.extra_detectors.iter().cloned());

    let mut report = Scheduler::new(detectors).run(&context, target).await?;

    // Fill in what only the engine knows, and surface anything it could not
    // read. A report that quietly omits half the project is worse than one that
    // admits it.
    let stats = engine.stats();
    report.target.files_scanned = stats.files_scanned;
    // Per-file caps live inside the engine; the scheduler only sees the
    // returned Vec. Surface truncation so CI cannot go green on a partial scan.
    if stats.truncated {
        report.truncated = true;
    }
    for skipped in stats.skip_examples {
        report.errors.push(owlwarden_core::report::DetectorFailure {
            rule: "static-engine".to_owned(),
            message: format!("skipped {skipped}"),
        });
    }

    if let Some(correlate) = request.correlate {
        report.findings = correlate(std::mem::take(&mut report.findings));
        report.summary = owlwarden_core::report::ReportSummary::of(&report.findings);
    }

    if let (Some(previous), Some(dirty)) = (merge_previous.as_ref(), merge_dirty.as_ref()) {
        incremental::merge_into_report(&mut report, previous, dirty, &project_rules_for_merge);
    }

    // After correlation so a Possible static finding can still become Confirmed.
    report.apply_min_confidence(settings.min_confidence);

    // Suppression re-reads files; do not double-charge the byte budget.
    provider.reset_bytes_read();
    apply_suppressions_with(&mut report, &provider, request.honor_suppressions);

    if let Some(path) = &request.write_baseline {
        let file = BaselineFile::from_findings(&report.findings, owlwarden_core::ENGINE_VERSION);
        let json = file.to_json().map_err(|error| RunError::BaselineWrite {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        // Atomic rename so a planted symlink at `path` is replaced, not followed.
        crate::safe_io::write_replacing(path, format!("{json}\n").as_bytes()).map_err(|error| {
            RunError::BaselineWrite {
                path: path.display().to_string(),
                message: error.to_string(),
            }
        })?;
    }

    if let Some(baseline) = request.baseline.as_ref() {
        apply_baseline(&mut report, baseline);
    }

    Ok(report)
}

/// Settings + optional previous report + validated dirty paths for a merge.
type IncrementalPlan = (ScanSettings, Option<Report>, Option<Vec<String>>);

/// Resolves incremental inputs into engine settings and optional merge inputs.
fn prepare_incremental(
    root: &std::path::Path,
    mut base_settings: ScanSettings,
    dirty_paths: Option<Vec<String>>,
    previous_report: Option<Report>,
) -> Result<IncrementalPlan, RunError> {
    let Some(raw_dirty) = dirty_paths.filter(|paths| !paths.is_empty()) else {
        return Ok((base_settings, None, None));
    };

    if incremental::any_forces_full_rescan(&raw_dirty) {
        return Ok((base_settings, None, None));
    }

    let validated = incremental::validate_dirty_paths(root, &raw_dirty)?;
    let Some(previous) = previous_report else {
        // Partial file scan without a previous report would drop untouched findings.
        return Ok((base_settings, None, None));
    };
    base_settings.dirty_paths = Some(validated.clone());
    Ok((base_settings, Some(previous), Some(validated)))
}
