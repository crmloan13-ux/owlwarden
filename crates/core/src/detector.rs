//! The `Detector` port: one unit of security analysis.
//!
//! A detector declares what it needs before it runs. The scheduler compares
//! that declaration against the run's settings and skips anything it must not
//! execute — a detector that never runs cannot bypass a rule it was not told
//! about. This is the same capability idea as the plugin sandbox, applied one
//! level up.

use std::borrow::Cow;

use async_trait::async_trait;

use crate::context::ScanContext;
use crate::finding::{AsiRef, Confidence, Finding, OwaspRef, RuleId, Severity};
use crate::surface::Surface;

/// Which engine a detector belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectorKind {
    /// Reads source. No network, ever.
    Static,
    /// Probes a live target.
    Dynamic,
    /// Correlates both, and can only produce `Confirmed` findings when both
    /// halves ran.
    Hybrid,
}

/// What a detector needs in order to run. Anything not declared is not
/// granted.
///
/// Four independent grants, not a state machine — a detector can need source
/// and advisory without network, and folding them into an enum would invent
/// combinations the scheduler does not care about.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Needs to read project source.
    pub source: bool,
    /// Needs to probe a live `--target` through [`crate::transport::Transport`].
    pub network: bool,
    /// Needs advisory-DB lookup through [`crate::advisory::AdvisoryClient`].
    /// Distinct from `network`: OSV traffic must not share the target scope
    /// ([ADR 0016](../../../docs/adr/0016-osv-advisory-lookup.md)).
    pub advisory: bool,
    /// Needs to make state-changing requests. Requires `--allow-active` at run
    /// time on top of this declaration.
    pub active: bool,
}

impl Capabilities {
    /// A detector that only reads source: the safe default.
    #[must_use]
    pub const fn source_only() -> Self {
        Self {
            source: true,
            network: false,
            advisory: false,
            active: false,
        }
    }

    /// A detector that sends passive (non-state-changing) requests.
    #[must_use]
    pub const fn passive_network() -> Self {
        Self {
            source: false,
            network: true,
            advisory: false,
            active: false,
        }
    }

    /// A detector that reads lockfiles and queries an advisory database.
    #[must_use]
    pub const fn source_and_advisory() -> Self {
        Self {
            source: true,
            network: false,
            advisory: true,
            active: false,
        }
    }

    /// A detector that sends state-changing requests (needs `--allow-active`).
    #[must_use]
    pub const fn active_network() -> Self {
        Self {
            source: false,
            network: true,
            advisory: false,
            active: true,
        }
    }
}

/// Everything about a rule that is stable, public, and documentable.
///
/// This is the source of `RULES.md`, of `explain <id>`, and of the MCP
/// `list_rules` tool. It is generated from here rather than maintained
/// separately so the catalogue cannot drift from the code.
///
/// `title`, `category`, and `description` are `Cow<'static, str>` rather than
/// `&'static str` so a plugin can own them: a first-party rule still writes a
/// string literal (`"foo".into()` borrows it for free), but a `WasmDetector`
/// building its metadata from a JSON manifest has no `'static` string to
/// borrow and needs `Cow::Owned` instead.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectorMeta {
    /// Permanent public identifier.
    pub id: RuleId,
    /// One line, sentence case: what the rule looks for.
    pub title: Cow<'static, str>,
    /// Severity findings from this rule carry by default.
    pub severity: Severity,
    /// The best confidence this rule can reach on its own. A static-only rule
    /// tops out at `Likely`; only correlation produces `Confirmed`.
    pub max_confidence: Confidence,
    /// OWASP Top 10 category, when one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<OwaspRef>,
    /// OWASP ASI (Agentic Applications) category, when one applies.
    ///
    /// Secondary to `cwe` by design: CWE is stable, and this edition is new
    /// enough that it will be renumbered. See [`crate::taxonomy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asi: Option<AsiRef>,
    /// CWE number, when one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<u32>,
    /// What kind of artefact the rule reads, and therefore which profile set
    /// its remediation table has to cover.
    ///
    /// `#[serde(default)]` is load-bearing: a plugin manifest written against
    /// `schemaVersion: 1` predates this field, and must keep loading and keep
    /// being checked against the twelve frameworks
    /// ([ADR 0024](../../../docs/adr/0024-plugin-api-v1.md) §9).
    #[serde(default)]
    pub surface: Surface,
    /// Grouping used by presets and by the docs site, e.g. `error-handling`.
    pub category: Cow<'static, str>,
    /// Two or three sentences for `RULES.md` and `explain`. Written for
    /// someone who has just seen the finding and wants to know if it matters.
    pub description: Cow<'static, str>,
}

/// One unit of analysis.
///
/// Detectors are pure with respect to I/O: they ask [`ScanContext`] to act on
/// their behalf. They cannot open a socket or a file directly, which is what
/// makes scope, sandboxing, and the resource caps unbypassable rather than
/// merely conventional.
#[async_trait]
pub trait Detector: Send + Sync {
    /// Stable metadata.
    fn meta(&self) -> DetectorMeta;

    /// Which engine this belongs to.
    fn kind(&self) -> DetectorKind;

    /// What it needs to run.
    fn capabilities(&self) -> Capabilities;

    /// Runs the analysis.
    ///
    /// Implementations must bound their own work: cap the files they walk, the
    /// findings they emit, and the requests they send. The scheduler enforces a
    /// time slice on top, but a detector that has to be killed has already
    /// wasted the user's time.
    ///
    /// # Errors
    /// [`DetectorError`] when the analysis could not complete. A detector that
    /// merely found nothing returns an empty `Vec`, not an error.
    async fn run(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, DetectorError>;
}

/// Failure inside a detector. One detector failing must never abort the scan:
/// the scheduler records it and carries on with the rest.
#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    /// Could not read project source.
    #[error(transparent)]
    Source(#[from] crate::source::SourceError),

    /// Could not complete a request.
    #[error(transparent)]
    Transport(#[from] crate::transport::TransportError),

    /// A source file could not be parsed. Not fatal: unparseable files are
    /// skipped, because a project mid-edit or using syntax we do not support
    /// yet must not break the whole scan.
    #[error("failed to parse {path}: {message}")]
    Parse {
        /// Project-relative path.
        path: String,
        /// Parser message.
        message: String,
    },

    /// The detector ran out of its time slice.
    #[error("detector {id} exceeded its time slice of {}ms", slice.as_millis())]
    TimeSliceExceeded {
        /// Rule id.
        id: RuleId,
        /// The slice that elapsed.
        slice: std::time::Duration,
    },

    /// The detector was asked to do something it did not declare.
    #[error("detector {id} requires the {capability} capability, which was not granted")]
    MissingCapability {
        /// Rule id.
        id: RuleId,
        /// Capability name.
        capability: &'static str,
    },

    /// Anything else, with a message safe to show a user.
    #[error("{0}")]
    Other(String),
}
