//! Wiring a live (passive-dynamic) scan from operator-supplied target/scope.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use owlwarden_core::budget::Budget;
use owlwarden_core::limits;
use owlwarden_core::report::Report;
use owlwarden_core::scope::{AllowlistScope, ScopeParseError, ScopeResolver, Target};
use owlwarden_static::rule::{FileRule, ProjectRule};
use owlwarden_static::{NetworkStack, RunError, ScanRequest, scan_project_with};
use owlwarden_transport::{ReqwestTransport, TransportBuildError};

use crate::engine::{DynamicEngine, ProbeTarget};

/// Failure preparing a live scan before any request is sent.
#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    /// `--target` / `--scope` could not be parsed.
    #[error(transparent)]
    Scope(#[from] ScopeParseError),
    /// `--target` is outside the allowlist in `--scope`.
    #[error("target is not covered by --scope; every probe URL must match an allowlist entry")]
    TargetNotInScope,
    /// The HTTP client could not be constructed.
    #[error(transparent)]
    Transport(#[from] TransportBuildError),
    /// Tokio could not start (needed for the HTTP client).
    #[error("could not start the async runtime for a live probe: {0}")]
    Runtime(std::io::Error),
}

/// Drives a future that may use the Tokio-backed HTTP transport.
///
/// Static-only scans can stay on `futures_executor::block_on`. Live probes
/// go through reqwest, which panics without a Tokio reactor — so napi and the
/// native CLI call this when `--target` is set.
///
/// # Errors
/// [`LiveError::Runtime`] when the reactor cannot be created.
pub fn block_on<F>(future: F) -> Result<F::Output, LiveError>
where
    F: Future,
{
    // Multi-thread: a current-thread runtime inside the napi/Node process was
    // observed to time out on outbound HTTP without ever delivering the SYN
    // to a local listener. Two workers is enough for one passive probe.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(LiveError::Runtime)
        .map(|runtime| runtime.block_on(future))
}

/// Failure driving a prepared scan to completion.
#[derive(Debug, thiserror::Error)]
pub enum DriveError {
    /// Tokio could not start for a live probe.
    #[error(transparent)]
    Live(#[from] LiveError),
    /// The scan itself failed.
    #[error(transparent)]
    Run(#[from] RunError),
}

/// Runs a scan, using Tokio when a live network stack is attached.
///
/// Fills `routes_probed` from `engine` when present.
///
/// # Errors
/// [`DriveError`] when the reactor or the scan fails.
pub fn run_scan(
    root: impl AsRef<Path>,
    file_rules: Vec<Arc<dyn FileRule>>,
    project_rules: Vec<Arc<dyn ProjectRule>>,
    request: ScanRequest,
    engine: Option<Arc<DynamicEngine>>,
) -> Result<Report, DriveError> {
    let live = request.network.is_some();
    let future = scan_project_with(root, file_rules, project_rules, request);
    let mut report = if live {
        block_on(future)??
    } else {
        futures_executor::block_on(future)?
    };
    if let Some(engine) = engine {
        report.target.routes_probed = engine.routes_probed();
    }
    Ok(report)
}

/// Everything the runner needs for a passive-dynamic scan.
pub struct LiveScan {
    /// Transport + scope + budget for [`owlwarden_static::ScanRequest::network`].
    pub network: NetworkStack,
    /// Detector to place in `extra_detectors`.
    pub engine: Arc<DynamicEngine>,
}

/// Builds the network stack and dynamic engine from CLI/napi inputs.
///
/// When `scope_entries` is empty, the allowlist is exactly the origin of
/// `target_url` (ADR 0014).
///
/// # Errors
/// [`LiveError`] when the URL/scope is invalid or the client cannot build.
pub fn prepare_live(
    target_url: &str,
    scope_entries: &[String],
    allow_active: bool,
) -> Result<LiveScan, LiveError> {
    let target = Target::parse(target_url)?;
    let scope = if scope_entries.is_empty() {
        AllowlistScope::from_target_origin(&target)
    } else {
        AllowlistScope::parse(scope_entries)?
    };
    // The target itself must be in scope — otherwise we would build a transport
    // that immediately refuses the only URL we intend to probe.
    if !scope.in_scope(&target).is_allowed() {
        return Err(LiveError::TargetNotInScope);
    }

    let scope_labels = scope.as_report_strings();
    let scope = Arc::new(scope);
    let budget = Arc::new(Budget::new(
        limits::scan::MAX_REQUESTS,
        limits::scan::TOTAL_TIME,
    ));
    let transport = Arc::new(ReqwestTransport::new(
        Arc::clone(&scope) as Arc<dyn owlwarden_core::scope::ScopeResolver>,
        Arc::clone(&budget),
        allow_active,
    )?);

    let engine = Arc::new(DynamicEngine::new(ProbeTarget::from_target(&target)));

    Ok(LiveScan {
        network: NetworkStack {
            transport,
            scope,
            budget,
            scope_labels,
        },
        engine,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn empty_scope_defaults_to_target_origin() {
        let live = prepare_live("http://127.0.0.1:3000/app", &[], false).unwrap();
        assert_eq!(
            live.network.scope_labels,
            vec!["http://127.0.0.1:3000".to_owned()]
        );
    }

    #[test]
    fn target_outside_explicit_scope_is_refused() {
        assert!(matches!(
            prepare_live(
                "http://127.0.0.1:3000/",
                &["http://127.0.0.1:3001/".to_owned()],
                false,
            ),
            Err(LiveError::TargetNotInScope)
        ));
    }

    #[test]
    fn credentials_in_target_are_refused() {
        assert!(matches!(
            prepare_live("http://user:pass@127.0.0.1:3000/", &[], false),
            Err(LiveError::Scope(_))
        ));
    }

    #[test]
    fn path_scoped_allowlist_still_covers_exact_target() {
        let live = prepare_live(
            "http://127.0.0.1:3000/api/health",
            &["http://127.0.0.1:3000/api".to_owned()],
            false,
        )
        .unwrap();
        assert!(!live.network.scope_labels.is_empty());
    }

    #[test]
    fn file_scheme_target_is_refused() {
        assert!(matches!(
            prepare_live("file:///etc/passwd", &[], false),
            Err(LiveError::Scope(_))
        ));
    }
}
