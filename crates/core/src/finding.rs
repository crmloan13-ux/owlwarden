//! The finding model — the single shape every engine produces and every
//! reporter renders.
//!
//! Reporters never re-derive facts. If the terminal output shows it, it is a
//! field here; that is what stops the JSON and terminal formats from drifting
//! apart.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Identifier of the **rule** that produced a finding, e.g. `stack-trace-leak`.
///
/// Named for what it identifies — the rule, not the individual finding. The
/// JSON field is `"id"`, which is what the published schema documents.
///
/// **Rule ids are permanent public API.** Baselines, inline suppressions,
/// SARIF, and `--fail-on` all key off them; a rename silently invalidates every
/// downstream baseline, so it requires an alias retained for two minor versions
/// (`ARCHITECTURE.md` §5).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(Cow<'static, str>);

impl RuleId {
    /// Longest accepted rule id. Ids come from plugin manifests, which are
    /// untrusted input; an unbounded id would flow into baselines and reports.
    pub const MAX_LEN: usize = 64;

    /// Creates a rule id from a compile-time string (the built-in rules).
    #[must_use]
    pub const fn new_static(id: &'static str) -> Self {
        Self(Cow::Borrowed(id))
    }

    /// Creates a rule id from untrusted input (a plugin manifest).
    ///
    /// # Errors
    /// Returns [`RuleIdError`] if the id is empty, longer than [`Self::MAX_LEN`],
    /// or contains anything other than `[a-z0-9-]`. The character set is
    /// restricted because rule ids end up in file paths, URLs, and CLI flags.
    pub fn parse(id: &str) -> Result<Self, RuleIdError> {
        if id.is_empty() {
            return Err(RuleIdError::Empty);
        }
        if id.len() > Self::MAX_LEN {
            return Err(RuleIdError::TooLong { len: id.len() });
        }
        if let Some(bad) = id
            .chars()
            .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
        {
            return Err(RuleIdError::InvalidChar { ch: bad });
        }
        Ok(Self(Cow::Owned(id.to_owned())))
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a rule id was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleIdError {
    /// The id was an empty string.
    #[error("rule id is empty")]
    Empty,
    /// The id exceeded [`RuleId::MAX_LEN`].
    #[error("rule id is {len} bytes, maximum is {max}", max = RuleId::MAX_LEN)]
    TooLong {
        /// Length of the offending id.
        len: usize,
    },
    /// The id contained a character outside `[a-z0-9-]`.
    #[error("rule id contains {ch:?}; allowed characters are a-z, 0-9 and '-'")]
    InvalidChar {
        /// The first offending character.
        ch: char,
    },
}

/// How much this finding matters. Ordered so `High > Medium > Low > Info`,
/// which is the sort order reporters use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational: worth knowing, never a build failure.
    Info,
    /// Low impact or hard to exploit.
    Low,
    /// Meaningful risk in a realistic deployment.
    Medium,
    /// Exploitable and damaging; fix before shipping.
    High,
}

impl Severity {
    /// Lowercase wire/CLI name (`"high"`, `"medium"`, ...).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Parses a CLI/config value. Case-insensitive.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How sure we are that the finding is real.
///
/// This exists because a tool that presents guesses as facts gets uninstalled.
/// `Possible` findings are shown but never fail CI by default, and are never
/// autofixed (`AGENTS.md` §4). Ordered `Confirmed > Likely > Possible`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Heuristic. Plausible, not corroborated.
    Possible,
    /// One engine, strong signal (e.g. the exact expression in source).
    Likely,
    /// Both engines agree: runtime behaviour *and* the source that causes it.
    Confirmed,
}

impl Confidence {
    /// Lowercase wire/CLI name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Possible => "possible",
            Self::Likely => "likely",
            Self::Confirmed => "confirmed",
        }
    }

    /// Parses a CLI/config value. Case-insensitive.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "possible" => Some(Self::Possible),
            "likely" => Some(Self::Likely),
            "confirmed" => Some(Self::Confirmed),
            _ => None,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The web framework a finding applies to. Drives which remediation is shown:
/// the same missing header is a `next.config.js` edit in one project and
/// `app.use(helmet())` in another.
///
/// # Why this is an open id and not an enum
///
/// It was an enum — `Next | Nest | Express | Generic` — and that made framework
/// support a property of this crate. Everything downstream matched on it
/// exhaustively, so adding Fastify meant editing `core` and recompiling every
/// rule, and a plugin could never add a framework at all. Since the whole point
/// of the plugin tier is that someone can teach owlwarden about a stack we have
/// never heard of, the closed enum was a permanent ceiling on that.
///
/// So the id is open, like [`RuleId`]. What a framework *is* — how to detect
/// it, where it puts routes, what its response objects are called — lives in a
/// `FrameworkProfile` in the static engine, which is the registry a plugin
/// extends. This type is only the name that travels on findings and fixes.
///
/// The wire format did not change: it is still `"next"`, `"nest"`, `"generic"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Framework(Cow<'static, str>);

impl Framework {
    /// Longest accepted framework id. Ids reach here from plugin manifests.
    pub const MAX_LEN: usize = 32;

    /// Next.js, App Router or Pages Router.
    pub const NEXT: Self = Self::new_static("next");
    /// Nuxt, including its Nitro server routes.
    pub const NUXT: Self = Self::new_static("nuxt");
    /// `NestJS`.
    pub const NEST: Self = Self::new_static("nest");
    /// Express.
    pub const EXPRESS: Self = Self::new_static("express");
    /// Fastify.
    pub const FASTIFY: Self = Self::new_static("fastify");
    /// Hono.
    pub const HONO: Self = Self::new_static("hono");
    /// Koa.
    pub const KOA: Self = Self::new_static("koa");
    /// Hapi (`@hapi/hapi`).
    pub const HAPI: Self = Self::new_static("hapi");
    /// Sails.js (Express-based meta-framework).
    pub const SAILS: Self = Self::new_static("sails");
    /// Astro (SSR and API routes).
    pub const ASTRO: Self = Self::new_static("astro");
    /// Remix.
    pub const REMIX: Self = Self::new_static("remix");
    /// Gatsby (including Functions).
    pub const GATSBY: Self = Self::new_static("gatsby");
    /// No framework detected, or one we have no specific advice for.
    pub const GENERIC: Self = Self::new_static("generic");

    /// Creates an id from a compile-time string (the built-in profiles).
    #[must_use]
    pub const fn new_static(id: &'static str) -> Self {
        Self(Cow::Borrowed(id))
    }

    /// Creates an id from untrusted input (a plugin manifest).
    ///
    /// # Errors
    /// [`FrameworkIdError`] if the id is empty, longer than [`Self::MAX_LEN`],
    /// or contains anything outside `[a-z0-9-]`. Same character set as a rule
    /// id, and for the same reason: these end up in config files, CLI flags,
    /// and URLs.
    pub fn parse(id: &str) -> Result<Self, FrameworkIdError> {
        if id.is_empty() {
            return Err(FrameworkIdError::Empty);
        }
        if id.len() > Self::MAX_LEN {
            return Err(FrameworkIdError::TooLong { len: id.len() });
        }
        if let Some(bad) = id
            .chars()
            .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
        {
            return Err(FrameworkIdError::InvalidChar { ch: bad });
        }
        Ok(Self(Cow::Owned(id.to_owned())))
    }

    /// The lowercase wire name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the "no framework detected" id.
    #[must_use]
    pub fn is_generic(&self) -> bool {
        self.0 == "generic"
    }

    /// Human-facing label used in reporter output, e.g. `fix (Next.js)`.
    ///
    /// Presentation only, so it lives here rather than in the profile registry:
    /// a reporter has a [`Fix`] in hand and no way to reach the static engine.
    /// An id we do not have a display name for renders verbatim, which is the
    /// right outcome for a plugin's framework — a wrong pretty name would be
    /// worse than the id the author chose.
    #[must_use]
    pub fn label(&self) -> &str {
        match self.as_str() {
            "next" => "Next.js",
            "nuxt" => "Nuxt",
            "nest" => "NestJS",
            "express" => "Express",
            "fastify" => "Fastify",
            "hono" => "Hono",
            "koa" => "Koa",
            "hapi" => "Hapi",
            "sails" => "Sails.js",
            "astro" => "Astro",
            "remix" => "Remix",
            "gatsby" => "Gatsby",
            other => other,
        }
    }
}

impl fmt::Display for Framework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Why a framework id was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameworkIdError {
    /// The id was an empty string.
    #[error("framework id is empty")]
    Empty,
    /// The id exceeded [`Framework::MAX_LEN`].
    #[error("framework id is {len} bytes, maximum is {max}", max = Framework::MAX_LEN)]
    TooLong {
        /// Length of the offending id.
        len: usize,
    },
    /// The id contained a character outside `[a-z0-9-]`.
    #[error("framework id contains {ch:?}; allowed characters are a-z, 0-9 and '-'")]
    InvalidChar {
        /// The first offending character.
        ch: char,
    },
}

/// An OWASP Top 10 category reference, e.g. `A05:2021`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OwaspRef(pub Cow<'static, str>);

impl OwaspRef {
    /// Builds a reference from a compile-time category string.
    #[must_use]
    pub const fn new_static(id: &'static str) -> Self {
        Self(Cow::Borrowed(id))
    }

    /// The category id, e.g. `"A05:2021"`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OwaspRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a finding lives.
///
/// Serialized untagged, so a source finding is plainly
/// `{"path": "...", "line": 15, "col": 15}` with no tag to unwrap. The variants
/// have disjoint required fields, so round-tripping is unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Location {
    /// A position in project source, produced by the static engine.
    Source(SourceLocation),
    /// A live endpoint, produced by the dynamic engine (v0.1).
    Endpoint(EndpointLocation),
}

impl Location {
    /// The source position, if this is a source finding.
    #[must_use]
    pub fn as_source(&self) -> Option<&SourceLocation> {
        match self {
            Self::Source(loc) => Some(loc),
            Self::Endpoint(_) => None,
        }
    }
}

/// A `path:line:col` position. Paths are project-relative and always use `/`
/// separators, including on Windows, so reports are comparable across machines
/// (that matters for baselines).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLocation {
    /// Project-relative path with `/` separators.
    pub path: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column, counted in characters (not bytes).
    pub col: u32,
}

/// A live HTTP endpoint. Used by the dynamic engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointLocation {
    /// Absolute URL that was probed.
    pub url: String,
    /// HTTP method used.
    pub method: String,
}

/// The lines of source shown around a finding, plus the span to underline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeFrame {
    /// Project-relative path with `/` separators.
    pub path: String,
    /// 1-based line number of `lines[0]`.
    pub start_line: u32,
    /// The source lines, verbatim (tabs and all — reporters decide how to
    /// render whitespace, the model does not lie about it).
    pub lines: Vec<String>,
    /// The span to underline.
    pub highlight: Highlight,
}

/// The underlined span inside a [`CodeFrame`], with the message that goes
/// beneath it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Highlight {
    /// 1-based line the span sits on.
    pub line: u32,
    /// 1-based, inclusive start column in characters.
    pub start_col: u32,
    /// 1-based, exclusive end column in characters.
    pub end_col: u32,
    /// The one-line message printed under the `~~~`, e.g.
    /// "leaks internal stack trace to the client".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// What the detector knows about the surroundings of the finding. Drives
/// remediation selection and gives the reader orientation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingContext {
    /// Framework detected for this project/file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<Framework>,
    /// Route path, when the finding sits in a routed handler, e.g. `/api/users`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// HTTP method, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Short, redacted evidence: what the detector actually saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// Whether a fix can be applied automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FixSafety {
    /// Cannot change program behaviour beyond removing the vulnerability.
    /// Only these are applied by `--fix`.
    Safe,
    /// Correct, but may change behaviour. Requires `--fix-unsafe`.
    Unsafe,
    /// Needs a human decision; `--fix` will never apply it.
    Manual,
}

/// One remediation, for one framework. A detector returns one per applicable
/// framework; the reporter shows the one matching the detected stack first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    /// `None` means the advice is framework-independent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<Framework>,
    /// One line: what to do.
    pub summary: String,
    /// Copy-paste-ready replacement code, if the fix is that concrete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    /// Whether `--fix` may apply this automatically.
    pub safety: FixSafety,
}

/// What kind of thing a [`Reference`] points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReferenceKind {
    /// An OWASP Top 10 category page.
    Owasp,
    /// A CWE entry.
    Cwe,
    /// Framework or vendor documentation.
    Docs,
}

/// A curated link. One to three per finding — a dump of links is noise, and the
/// reader has to be able to tell which one to open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    /// Kind of reference.
    pub kind: ReferenceKind,
    /// Display id, e.g. `A05:2021` or `CWE-209`.
    pub id: String,
    /// Canonical URL.
    pub url: String,
}

impl Reference {
    /// Builds the OWASP Top 10 reference for a category id such as `A05:2021`.
    ///
    /// Returns `None` for an unrecognised category rather than guessing a URL —
    /// a broken link in a security report costs more than a missing one.
    #[must_use]
    pub fn owasp(category: &OwaspRef) -> Option<Self> {
        let entry = crate::owasp::category(category.as_str())?;
        Some(Self {
            kind: ReferenceKind::Owasp,
            id: entry.id.to_owned(),
            url: entry.url(),
        })
    }

    /// Builds a CWE reference from its numeric id.
    #[must_use]
    pub fn cwe(id: u32) -> Self {
        Self {
            kind: ReferenceKind::Cwe,
            id: format!("CWE-{id}"),
            url: format!("https://cwe.mitre.org/data/definitions/{id}.html"),
        }
    }

    /// Builds a documentation reference.
    #[must_use]
    pub fn docs(id: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            kind: ReferenceKind::Docs,
            id: id.into(),
            url: url.into(),
        }
    }

    /// The rule's entry in the generated catalogue.
    ///
    /// The displayed id is short and says where it goes, rather than a bare URL
    /// long enough to wrap in a terminal. The page is an enhancement, never a
    /// dependency: `owlwarden explain <id>` prints the same content with no
    /// network at all.
    #[must_use]
    pub fn rule_page(rule: &RuleId) -> Self {
        Self {
            kind: ReferenceKind::Docs,
            id: format!("RULES.md#{rule}"),
            url: crate::rule_url(rule.as_str()),
        }
    }
}

/// One security problem, with everything a reporter or an agent needs to act on
/// it: where it is, why it matters, and how to fix it *in this codebase*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// The rule that produced it.
    pub id: RuleId,
    /// Impact band.
    pub severity: Severity,
    /// How sure we are.
    pub confidence: Confidence,
    /// OWASP Top 10 category, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp: Option<OwaspRef>,
    /// CWE number, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<u32>,
    /// One line, sentence case, no trailing period.
    pub title: String,
    /// Why this matters, in plain language. Shown as the `why` line.
    pub why: String,
    /// Where it is.
    pub location: Location,
    /// Source lines to display, when the finding has a source location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<CodeFrame>,
    /// Framework/route/evidence.
    #[serde(default)]
    pub context: FindingContext,
    /// One fix per applicable framework.
    #[serde(default)]
    pub remediation: Vec<Fix>,
    /// One to three curated links.
    #[serde(default)]
    pub references: Vec<Reference>,
}

impl Finding {
    /// Starts building a finding. Everything else has a sensible default:
    /// `Possible` confidence and no remediation, both of which a detector
    /// should override.
    #[must_use]
    pub fn builder(id: RuleId, severity: Severity, title: impl Into<String>) -> FindingBuilder {
        FindingBuilder {
            finding: Self {
                id,
                severity,
                confidence: Confidence::Possible,
                owasp: None,
                cwe: None,
                title: title.into(),
                why: String::new(),
                location: Location::Source(SourceLocation {
                    path: String::new(),
                    line: 1,
                    col: 1,
                }),
                snippet: None,
                context: FindingContext::default(),
                remediation: Vec::new(),
                references: Vec::new(),
            },
        }
    }

    /// The fix to show first: the one matching the detected framework, else the
    /// framework-independent one, else whatever came first.
    #[must_use]
    pub fn primary_fix(&self) -> Option<&Fix> {
        let detected = self.context.framework.as_ref();
        self.remediation
            .iter()
            .find(|fix| detected.is_some() && fix.framework.as_ref() == detected)
            .or_else(|| self.remediation.iter().find(|fix| fix.framework.is_none()))
            .or_else(|| self.remediation.first())
    }

    /// Report ordering: severity desc, confidence desc, then path/line/rule id
    /// so the result is fully deterministic. Snapshot tests and CI diffs both
    /// depend on two runs producing byte-identical output.
    #[must_use]
    pub fn cmp_for_report(&self, other: &Self) -> std::cmp::Ordering {
        other
            .severity
            .cmp(&self.severity)
            .then_with(|| other.confidence.cmp(&self.confidence))
            .then_with(|| self.location_key().cmp(&other.location_key()))
            .then_with(|| self.id.cmp(&other.id))
    }

    /// `(path-or-url, line)` used only for ordering.
    fn location_key(&self) -> (&str, u32) {
        match &self.location {
            Location::Source(loc) => (loc.path.as_str(), loc.line),
            Location::Endpoint(loc) => (loc.url.as_str(), 0),
        }
    }
}

/// Step-by-step [`Finding`] construction. Detectors read better this way than
/// with a twelve-field struct literal.
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    /// Sets confidence.
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.finding.confidence = confidence;
        self
    }

    /// Sets the OWASP category and, when the category is recognised, appends
    /// its reference link.
    #[must_use]
    pub fn owasp(mut self, category: OwaspRef) -> Self {
        if let Some(reference) = Reference::owasp(&category) {
            self.finding.references.push(reference);
        }
        self.finding.owasp = Some(category);
        self
    }

    /// Sets the CWE number and appends its reference link.
    #[must_use]
    pub fn cwe(mut self, cwe: u32) -> Self {
        self.finding.cwe = Some(cwe);
        self.finding.references.push(Reference::cwe(cwe));
        self
    }

    /// Sets the "why it matters" line.
    #[must_use]
    pub fn why(mut self, why: impl Into<String>) -> Self {
        self.finding.why = why.into();
        self
    }

    /// Sets the location.
    #[must_use]
    pub fn location(mut self, location: Location) -> Self {
        self.finding.location = location;
        self
    }

    /// Attaches the code frame.
    #[must_use]
    pub fn snippet(mut self, snippet: CodeFrame) -> Self {
        self.finding.snippet = Some(snippet);
        self
    }

    /// Sets the surrounding context.
    #[must_use]
    pub fn context(mut self, context: FindingContext) -> Self {
        self.finding.context = context;
        self
    }

    /// Appends a fix.
    #[must_use]
    pub fn fix(mut self, fix: Fix) -> Self {
        self.finding.remediation.push(fix);
        self
    }

    /// Appends several fixes, in order.
    ///
    /// Takes what [`Remediation::select`](crate::remediation::Remediation::select)
    /// returns, so a rule attaches its whole applicable set in one call rather
    /// than looping.
    #[must_use]
    pub fn fixes(mut self, fixes: impl IntoIterator<Item = Fix>) -> Self {
        self.finding.remediation.extend(fixes);
        self
    }

    /// Appends a reference.
    #[must_use]
    pub fn reference(mut self, reference: Reference) -> Self {
        self.finding.references.push(reference);
        self
    }

    /// Finishes the finding.
    #[must_use]
    pub fn build(self) -> Finding {
        self.finding
    }
}

#[cfg(test)]
mod tests {
    // Tests may panic on failure; that is what a test is.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn rule_id_rejects_hostile_input() {
        assert_eq!(RuleId::parse(""), Err(RuleIdError::Empty));
        assert_eq!(
            RuleId::parse("../../etc/passwd"),
            Err(RuleIdError::InvalidChar { ch: '.' })
        );
        assert_eq!(
            RuleId::parse("Stack-Trace-Leak"),
            Err(RuleIdError::InvalidChar { ch: 'S' })
        );
        let long = "a".repeat(RuleId::MAX_LEN + 1);
        assert_eq!(
            RuleId::parse(&long),
            Err(RuleIdError::TooLong {
                len: RuleId::MAX_LEN + 1
            })
        );
        assert!(RuleId::parse("stack-trace-leak").is_ok());
    }

    #[test]
    fn severity_orders_high_first() {
        let mut all = vec![
            Severity::Low,
            Severity::High,
            Severity::Info,
            Severity::Medium,
        ];
        all.sort_by_key(|s| std::cmp::Reverse(*s));
        assert_eq!(
            all,
            vec![
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info
            ]
        );
    }

    #[test]
    fn primary_fix_prefers_the_detected_framework() {
        let finding = Finding::builder(
            RuleId::new_static("security-headers-missing"),
            Severity::Medium,
            "Security headers not configured",
        )
        .context(FindingContext {
            framework: Some(Framework::NEST),
            ..FindingContext::default()
        })
        .fix(Fix {
            framework: Some(Framework::NEXT),
            summary: "next.config.js headers()".into(),
            patch: None,
            safety: FixSafety::Manual,
        })
        .fix(Fix {
            framework: Some(Framework::NEST),
            summary: "app.use(helmet())".into(),
            patch: None,
            safety: FixSafety::Manual,
        })
        .build();

        let fix = finding.primary_fix();
        assert_eq!(
            fix.and_then(|fix| fix.framework.as_ref()),
            Some(&Framework::NEST)
        );
    }

    #[test]
    fn a_framework_id_from_a_plugin_is_validated_like_a_rule_id() {
        assert_eq!(
            Framework::parse("my-framework").map(|id| id.as_str().to_owned()),
            Ok("my-framework".to_owned())
        );
        assert_eq!(Framework::parse(""), Err(FrameworkIdError::Empty));
        assert!(matches!(
            Framework::parse("Next"),
            Err(FrameworkIdError::InvalidChar { ch: 'N' })
        ));
        assert!(matches!(
            Framework::parse(&"a".repeat(Framework::MAX_LEN + 1)),
            Err(FrameworkIdError::TooLong { .. })
        ));
    }

    #[test]
    fn an_unknown_framework_id_renders_as_itself_rather_than_guessing() {
        // A plugin id we do not ship a pretty name for must render verbatim —
        // inventing "Elysia" from "elysia" would be worse than the author's id.
        let plugin = Framework::parse("elysia").expect("valid id");
        assert_eq!(plugin.label(), "elysia");
        assert_eq!(Framework::NEXT.label(), "Next.js");
        assert_eq!(Framework::HONO.label(), "Hono");
    }

    #[test]
    fn unknown_owasp_category_yields_no_link() {
        // Better a missing reference than a 404 in a security report.
        assert!(Reference::owasp(&OwaspRef::new_static("A99:1999")).is_none());
        assert!(Reference::owasp(&OwaspRef::new_static("A05:2021")).is_some());
    }

    #[test]
    fn source_location_json_matches_the_documented_shape() {
        let json = serde_json::to_value(Location::Source(SourceLocation {
            path: "app/api/users/route.ts".into(),
            line: 15,
            col: 15,
        }))
        .expect("serializing a location cannot fail");
        assert_eq!(
            json,
            serde_json::json!({"path": "app/api/users/route.ts", "line": 15, "col": 15})
        );
    }
}
