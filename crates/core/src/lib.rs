//! owlwarden engine core.
//!
//! This crate holds the *domain*: the finding model, the ports (traits) that
//! every adapter implements, the scheduler that drives them, and the resource
//! limits that keep a hostile target from turning the scanner into the victim.
//!
//! # The one architectural rule
//!
//! Core performs **no I/O**. It never opens a socket, never touches the
//! filesystem, never spawns a runtime. HTTP lives in a transport adapter,
//! source reading in the static engine, rendering in the reporters. Everything
//! reaches core through a trait defined here. That is what makes scope
//! enforcement and the resource caps unbypassable: a detector cannot construct
//! its own transport, so it cannot route around the limits.
//!
//! See `ARCHITECTURE.md` §3–§4.

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![warn(clippy::pedantic)]
// `-D warnings` is applied by CI (`cargo clippy -- -D warnings`) rather than
// `#![deny(warnings)]` in source: an in-source deny turns every new lint in a
// future compiler into a broken build for downstream users.
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

pub mod advisory;
pub mod baseline;
pub mod budget;
pub mod context;
pub mod coverage;
pub mod detector;
pub mod finding;
pub mod limits;
pub mod owasp;
pub mod remediation;
pub mod report;
pub mod reporter;
pub mod scheduler;
pub mod scope;
pub mod source;
pub mod suppression;
pub mod surface;
pub mod taxonomy;
pub mod transport;

pub use advisory::{AdvisoryClient, AdvisoryError, AdvisoryHit, PackageQuery};
pub use baseline::{
    BaselineEntry, BaselineError, BaselineFile, BaselineFilter, MAX_BASELINE_BYTES, MAX_ENTRIES,
};
pub use budget::Budget;
pub use context::{ScanContext, ScanSettings};
pub use detector::{Capabilities, Detector, DetectorError, DetectorKind, DetectorMeta};
pub use finding::{
    AgentHost, AsiRef, CodeFrame, Confidence, Finding, FindingContext, Fix, FixSafety, Framework,
    Highlight, Location, OwaspRef, Reference, ReferenceKind, RuleId, RuntimeScope, Severity,
    SourceLocation,
};
pub use report::{Report, ReportSummary, ScanTarget, ToolInfo};
pub use reporter::{ReportError, Reporter};
pub use scheduler::{ScanError, Scheduler};
pub use scope::{
    AllowlistScope, DenyAllScope, ScopeDecision, ScopeEntry, ScopeParseError, ScopeResolver, Target,
};
pub use source::{FileSelector, RelPath, SourceError, SourceFile, SourceProvider};
pub use suppression::{Directive, SuppressionOutcome, SuppressionRecord};
pub use surface::{Profile, SUPPORTED_AGENT_HOSTS, SUPPORTED_FRAMEWORKS, Surface};
pub use transport::{BoundedRequest, BoundedResponse, HttpLimits, Transport, TransportError};

/// The version of this engine, as reported in `Report.tool.version`.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The project's canonical home.
///
/// Every URL owlwarden prints is built from this, in one place, for a reason
/// that is specific to this kind of tool: a security report full of dead links
/// is worse than one with no links at all. A reader who follows a 404 while
/// trying to understand a finding concludes the tool is abandoned, and they are
/// making a reasonable inference.
///
/// So these point at the repository, which exists, rather than at a
/// documentation site that may not. If a docs domain is ever stood up, this is
/// the only thing that changes.
pub const PROJECT_URL: &str = "https://github.com/suthat/owlwarden";

/// Where to read about a rule, given its id.
///
/// `RULES.md` is generated from the compiled-in rules and checked in CI, so the
/// anchor is guaranteed to exist for every rule that can produce a finding.
/// The whole write-up also ships in the binary — `owlwarden explain <id>` needs
/// no network — so this link is an enhancement, never a dependency.
#[must_use]
pub fn rule_url(rule_id: &str) -> String {
    format!("{PROJECT_URL}/blob/main/RULES.md#{rule_id}")
}

/// Where to read about an engine error code.
///
/// GitHub slugs a heading by lowercasing it and dropping punctuation, but it
/// keeps underscores — so `## E_UNKNOWN_PRESET` becomes `#e_unknown_preset`.
#[must_use]
pub fn error_url(code: &str) -> String {
    format!(
        "{PROJECT_URL}/blob/main/docs/reference/errors.md#{}",
        code.to_ascii_lowercase()
    )
}
