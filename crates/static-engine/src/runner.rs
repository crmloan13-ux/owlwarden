//! One function that performs a passive scan of a project directory.
//!
//! The CLI, the napi bridge, and the fixture tests all call this. That is the
//! point: if the tests took a different path from the CLI, they would be
//! testing something the user never runs.

use std::path::PathBuf;
use std::sync::Arc;

use owlwarden_core::baseline::BaselineFile;
use owlwarden_core::budget::Budget;
use owlwarden_core::context::{ScanContext, ScanSettings};
use owlwarden_core::detector::Detector;
use owlwarden_core::report::{Report, ScanTarget};
use owlwarden_core::scheduler::{ScanError, Scheduler};
use owlwarden_core::scope::DenyAllScope;
use owlwarden_core::source::SourceError;

use crate::engine::StaticEngine;
use crate::fs_source::FsSourceProvider;
use crate::postprocess::{apply_baseline, apply_suppressions};
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
}

/// Optional inputs that sit beside the rule set.
///
/// Kept separate from [`ScanSettings`] on purpose: settings travel into every
/// detector, while baseline is a post-pass the detectors must not see.
#[derive(Debug, Clone, Default)]
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
        },
    )
    .await
}

/// Scans a project with an optional baseline.
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
    let engine = Arc::new(StaticEngine::new(file_rules, project_rules));

    let scope = DenyAllScope;
    let budget = Budget::passive();
    let context = ScanContext::new(&provider, None, &scope, &request.settings, &budget);

    let target = ScanTarget {
        project: root.display().to_string(),
        scope: Vec::new(),
        files_scanned: 0,
        routes_probed: 0,
        preset: request.settings.preset.clone(),
    };

    let detectors: Vec<Arc<dyn Detector>> = vec![engine.clone()];
    let mut report = Scheduler::new(detectors).run(&context, target).await?;

    // Fill in what only the engine knows, and surface anything it could not
    // read. A report that quietly omits half the project is worse than one that
    // admits it.
    let stats = engine.stats();
    report.target.files_scanned = stats.files_scanned;
    for skipped in stats.skip_examples {
        report.errors.push(owlwarden_core::report::DetectorFailure {
            rule: "static-engine".to_owned(),
            message: format!("skipped {skipped}"),
        });
    }

    // Suppression re-reads files; do not double-charge the byte budget.
    provider.reset_bytes_read();
    apply_suppressions(&mut report, &provider);

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
