//! One function that performs a passive scan of a project directory.
//!
//! The CLI, the napi bridge, and the fixture tests all call this. That is the
//! point: if the tests took a different path from the CLI, they would be
//! testing something the user never runs.

use std::sync::Arc;

use owlwarden_core::budget::Budget;
use owlwarden_core::context::{ScanContext, ScanSettings};
use owlwarden_core::detector::Detector;
use owlwarden_core::report::{Report, ScanTarget};
use owlwarden_core::scheduler::{ScanError, Scheduler};
use owlwarden_core::scope::DenyAllScope;
use owlwarden_core::source::SourceError;

use crate::engine::StaticEngine;
use crate::fs_source::FsSourceProvider;
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
    let root = root.as_ref();
    let provider = FsSourceProvider::new(root)?;
    let engine = Arc::new(StaticEngine::new(file_rules, project_rules));

    let scope = DenyAllScope;
    let budget = Budget::passive();
    let context = ScanContext::new(&provider, None, &scope, &settings, &budget);

    let target = ScanTarget {
        project: root.display().to_string(),
        scope: Vec::new(),
        files_scanned: 0,
        routes_probed: 0,
        preset: settings.preset.clone(),
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

    Ok(report)
}
