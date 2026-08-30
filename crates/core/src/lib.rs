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
pub mod runtime;
pub mod scheduler;
pub mod scope;
pub mod source;
pub mod suppression;
pub mod surface;
pub mod taxonomy;
pub mod transport;
pub mod untrusted_text;

pub use advisory::{AdvisoryClient, AdvisoryError, AdvisoryHit, PackageQuery};
pub use baseline::{
    BaselineEntry, BaselineError, BaselineFile, BaselineFilter, MAX_BASELINE_BYTES, MAX_ENTRIES,
};
pub use budget::Budget;
pub use context::{ScanContext, ScanSettings};
pub use detector::{Capabilities, Detector, DetectorError, DetectorKind, DetectorMeta};
pub use finding::{
    AgentHost, AsiRef, CodeFrame, Confidence, Exposure, ExposureEvidence, Finding, FindingContext,
    Fix, FixSafety, Framework, Highlight, Location, OwaspRef, Reference, ReferenceKind, RuleId,
    RuntimeScope, Severity, SourceLocation,
};
pub use report::{ExposureSummary, Report, ReportSummary, ScanTarget, ToolInfo};
pub use reporter::{ReportError, Reporter};
pub use runtime::{Runtime, RuntimeSource};
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

/// The repository. Fixed: it is where the code is, and that does not move.
pub const PROJECT_URL: &str = "https://github.com/suthat/owlwarden";

/// The documentation site.
///
/// Read from `site.url` at the repository root — **one file, one line, and the
/// only place this string exists**. The Rust binary, the npm manifest, the
/// generated site, `robots.txt`, `sitemap.xml`, and `llms.txt` all resolve to
/// it, and `pnpm site:check` fails the build when any of them disagree.
///
/// # Why it is a file rather than a constant
///
/// Moving to a custom domain is a decision, not a refactor, and it should cost
/// one edit rather than a search across six file types. `docs/how-to/custom-domain.md`
/// is the checklist for making it; this is the switch it flips.
///
/// # Why `rule_url` does not point here
///
/// A security report full of dead links is worse than one with no links at all:
/// a reader who follows a 404 while trying to understand a finding concludes
/// the tool is abandoned, and they are making a reasonable inference. `RULES.md`
/// is generated from the compiled-in rules and checked in CI, so its anchor is
/// guaranteed to exist for every rule that can produce a finding. A site page
/// is guaranteed only once the site has been deployed, which is not something a
/// binary can know. So findings link to the repository, and the site links to
/// itself.
pub const SITE_URL: &str = include_str!("../../../site.url").trim_ascii_end();

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

/// The page on the documentation site for one rule.
///
/// Used by the site generator and by anything rendering a link for a human with
/// a browser. Deliberately *not* used on findings — see [`SITE_URL`].
#[must_use]
pub fn rule_page_url(rule_id: &str) -> String {
    format!("{SITE_URL}/rules/{rule_id}/")
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_site_url_is_one_absolute_url_with_no_trailing_slash() {
        // `site.url` is edited by a human moving the project to a domain. These
        // are the three ways that edit goes wrong, and each would produce a
        // double slash or a broken scheme in every generated canonical tag.
        assert!(
            SITE_URL.starts_with("https://"),
            "site.url must be an absolute https URL, got {SITE_URL:?}"
        );
        assert!(
            !SITE_URL.ends_with('/'),
            "site.url must not end with a slash; every consumer adds one"
        );
        assert!(
            !SITE_URL.contains(char::is_whitespace),
            "site.url is one line and nothing else, got {SITE_URL:?}"
        );
    }

    #[test]
    fn every_url_the_binary_prints_is_built_from_a_constant() {
        assert!(rule_url("stack-trace-leak").starts_with(PROJECT_URL));
        assert!(rule_page_url("stack-trace-leak").starts_with(SITE_URL));
        assert!(error_url("E_UNKNOWN_PRESET").starts_with(PROJECT_URL));
        // The error anchor is lowercased because GitHub slugs headings that
        // way, and keeps its underscores because GitHub keeps those.
        assert!(error_url("E_UNKNOWN_PRESET").ends_with("#e_unknown_preset"));
    }
}
