//! `ScanContext` — the mediator handed to every detector.
//!
//! A detector receives capabilities, not constructors. It cannot build a
//! transport, open a file, or widen its own scope; it can only ask the context,
//! and the context is built once, by the runner, from validated settings.

use crate::advisory::AdvisoryClient;
use crate::budget::Budget;
use crate::finding::{Confidence, Severity};
use crate::scope::ScopeResolver;
use crate::source::SourceProvider;
use crate::transport::Transport;

/// Run-wide settings a detector may read.
#[derive(Debug, Clone)]
pub struct ScanSettings {
    /// Whether state-changing requests are permitted (`--allow-active`).
    /// Passive is the default and stays the default.
    pub allow_active: bool,
    /// Findings below this confidence are dropped before reporting.
    pub min_confidence: Confidence,
    /// Findings below this severity are dropped before reporting.
    pub min_severity: Severity,
    /// Name of the preset in force, for the report header.
    pub preset: String,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            allow_active: false,
            min_confidence: Confidence::Possible,
            min_severity: Severity::Info,
            preset: "quick".to_owned(),
        }
    }
}

/// What a detector is given.
///
/// `transport` is `Option` on purpose: a passive run has no transport at all,
/// so a detector that reaches for the network during one gets a clear
/// `MissingCapability` rather than a silently permitted request.
/// `advisory` is likewise optional and opt-in (`--osv`).
pub struct ScanContext<'a> {
    source: &'a dyn SourceProvider,
    transport: Option<&'a dyn Transport>,
    advisory: Option<&'a dyn AdvisoryClient>,
    scope: &'a dyn ScopeResolver,
    settings: &'a ScanSettings,
    budget: &'a Budget,
}

impl<'a> ScanContext<'a> {
    /// Builds a context. Called by the runner, once per scan.
    #[must_use]
    pub fn new(
        source: &'a dyn SourceProvider,
        transport: Option<&'a dyn Transport>,
        scope: &'a dyn ScopeResolver,
        settings: &'a ScanSettings,
        budget: &'a Budget,
    ) -> Self {
        Self::with_advisory(source, transport, None, scope, settings, budget)
    }

    /// Builds a context that may perform advisory lookups.
    #[must_use]
    pub fn with_advisory(
        source: &'a dyn SourceProvider,
        transport: Option<&'a dyn Transport>,
        advisory: Option<&'a dyn AdvisoryClient>,
        scope: &'a dyn ScopeResolver,
        settings: &'a ScanSettings,
        budget: &'a Budget,
    ) -> Self {
        Self {
            source,
            transport,
            advisory,
            scope,
            settings,
            budget,
        }
    }

    /// Read-only project source.
    #[must_use]
    pub fn source(&self) -> &'a dyn SourceProvider {
        self.source
    }

    /// The transport, if this run has one. `None` during a passive scan.
    #[must_use]
    pub fn transport(&self) -> Option<&'a dyn Transport> {
        self.transport
    }

    /// The advisory client, if this run opted into `--osv`.
    #[must_use]
    pub fn advisory(&self) -> Option<&'a dyn AdvisoryClient> {
        self.advisory
    }

    /// The scope resolver.
    #[must_use]
    pub fn scope(&self) -> &'a dyn ScopeResolver {
        self.scope
    }

    /// Run settings.
    #[must_use]
    pub fn settings(&self) -> &'a ScanSettings {
        self.settings
    }

    /// Remaining time and requests.
    #[must_use]
    pub fn budget(&self) -> &'a Budget {
        self.budget
    }
}
