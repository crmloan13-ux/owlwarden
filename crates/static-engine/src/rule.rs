//! The two rule shapes and the bounded sink they write to.

use owlwarden_core::detector::{DetectorError, DetectorMeta};
use owlwarden_core::finding::Finding;
use owlwarden_core::limits;
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::RelPath;

use crate::project::Project;
use crate::unit::FileUnit;

/// What every rule declares, whatever shape it is.
///
/// Split out from the two rule traits so that anything wanting to catalogue,
/// explain, or check the coverage of a rule can do so without caring whether it
/// runs per file or per project. `owlwarden explain` used to key off a central
/// `match rule_id { ... }` to find a rule's fixes, which meant a new rule that
/// forgot to register there silently had no remediation. Asking the rule
/// removes the register-it-twice step, and with it the chance to skip one.
pub trait RuleInfo: Send + Sync {
    /// Stable metadata. The `id` here is what appears on every finding the rule
    /// produces.
    fn meta(&self) -> DetectorMeta;

    /// Every fix this rule can offer, for every framework it knows.
    ///
    /// Declared rather than computed inside `check`, so `explain` and the rule
    /// catalogue can show the complete set without running a scan.
    fn remediation(&self) -> Remediation;

    /// What this rule reads, so a diff-scoped scan knows whether to run it.
    ///
    /// Declared rather than inferred, because the inference is wrong in the
    /// direction that matters. Under `--since HEAD` with only a `package.json`
    /// edit, a heuristic that runs project rules "when source changed" would
    /// skip `unpinned-dependency` — and report clean about the one file that
    /// did change ([ADR 0026](../../../docs/adr/0026-deterministic-agent-gate.md) §4).
    ///
    /// The default is [`RuleInputs::AnySource`], which is both the safe answer
    /// and the true one for a file rule: it reads whatever file it is handed.
    fn inputs(&self) -> RuleInputs {
        RuleInputs::AnySource
    }
}

/// What a rule reads.
///
/// A closed pair rather than a glob string: the patterns are compiled nowhere
/// and matched by four explicit shapes, so a rule cannot accidentally declare
/// an input set that a glob engine reads differently from how its author meant
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleInputs {
    /// Any application source file. The rule runs whenever anything in scope
    /// changed.
    AnySource,
    /// Only these path shapes. Supported forms, matched against
    /// project-relative paths:
    ///
    /// - `package.json` — exactly this path, at the root.
    /// - `.github/workflows/**` — anything under this directory.
    /// - `**/pnpm-lock.yaml` — this file name, at any depth.
    Paths(&'static [&'static str]),
}

impl RuleInputs {
    /// Whether any of `changed` is an input to this rule.
    ///
    /// `AnySource` is true for a non-empty list: a rule that reads whatever it
    /// is handed has an input whenever anything was handed to it.
    #[must_use]
    pub fn touched_by(&self, changed: &[String]) -> bool {
        match self {
            Self::AnySource => !changed.is_empty(),
            Self::Paths(patterns) => changed
                .iter()
                .any(|path| patterns.iter().any(|pattern| matches_shape(pattern, path))),
        }
    }

    /// The declared patterns, for `RULES.md` and for tests. `AnySource` yields
    /// an empty slice.
    #[must_use]
    pub const fn patterns(&self) -> &'static [&'static str] {
        match self {
            Self::AnySource => &[],
            Self::Paths(patterns) => patterns,
        }
    }
}

/// One pattern against one project-relative path.
fn matches_shape(pattern: &str, path: &str) -> bool {
    if let Some(directory) = pattern.strip_suffix("/**") {
        return path
            .strip_prefix(directory)
            .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1);
    }
    if let Some(name) = pattern.strip_prefix("**/") {
        return path == name || path.ends_with(&format!("/{name}"));
    }
    path == pattern
}

/// A rule that looks at one file at a time.
///
/// `check` cannot fail. A rule that finds nothing returns nothing; a rule that
/// does not understand what it is looking at stays quiet. There is no third
/// outcome worth reporting to the user, and an error type here would tempt
/// rules to report their own confusion as a security finding.
pub trait FileRule: RuleInfo {
    /// Whether this rule wants to see the file, decided from the path alone.
    ///
    /// Checked *before* parsing: if no rule is interested, the file is never
    /// read or parsed, which is what keeps a project-wide scan proportional to
    /// the code that matters rather than to the repository size.
    fn applies_to(&self, _path: &RelPath) -> bool {
        true
    }

    /// Examines the file, pushing findings into `sink`.
    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink);
}

/// A rule that needs the whole project in view.
///
/// This is the shape that can detect *absence*: no `next.config.js`, no
/// `helmet()` anywhere in the bootstrap. A per-file pass structurally cannot
/// see a file that does not exist.
pub trait ProjectRule: RuleInfo {
    /// Examines the project.
    ///
    /// # Errors
    /// [`DetectorError`] only when the rule could not complete — for instance a
    /// configuration file that exists but cannot be read. Finding nothing is
    /// `Ok(())`.
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink) -> Result<(), DetectorError>;
}

/// Where rules put their findings.
///
/// Bounded on purpose. A rule with a bug — or a generated file that trips it on
/// every line — must not be able to produce a million findings and exhaust
/// memory. When the cap is hit the sink stops accepting and records that it
/// truncated, which the engine surfaces rather than hides.
#[derive(Debug)]
pub struct FindingSink {
    findings: Vec<Finding>,
    limit: usize,
    truncated: bool,
}

impl FindingSink {
    /// A sink with the default per-file cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(limits::source::MAX_FINDINGS_PER_FILE)
    }

    /// A sink with an explicit cap.
    #[must_use]
    pub fn with_limit(limit: usize) -> Self {
        Self {
            findings: Vec::new(),
            limit,
            truncated: false,
        }
    }

    /// Adds a finding. Returns `false` once the cap is reached, so a rule
    /// looping over nodes can stop early instead of building work it will
    /// throw away.
    pub fn push(&mut self, finding: Finding) -> bool {
        if self.findings.len() >= self.limit {
            self.truncated = true;
            return false;
        }
        self.findings.push(finding);
        true
    }

    /// Whether the cap was hit.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// How many findings are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Whether nothing was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Takes the findings out, leaving the sink empty and reusable.
    #[must_use]
    pub fn drain(&mut self) -> Vec<Finding> {
        self.truncated = false;
        std::mem::take(&mut self.findings)
    }
}

impl Default for FindingSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use owlwarden_core::finding::{RuleId, Severity};

    fn finding() -> Finding {
        Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t").build()
    }

    #[test]
    fn any_source_is_touched_by_anything_and_by_nothing() {
        let inputs = RuleInputs::AnySource;
        assert!(inputs.touched_by(&["app/route.ts".to_owned()]));
        assert!(!inputs.touched_by(&[]), "an empty diff touches no rule");
    }

    #[test]
    fn declared_paths_match_the_three_documented_shapes() {
        let inputs =
            RuleInputs::Paths(&["package.json", ".github/workflows/**", "**/pnpm-lock.yaml"]);

        assert!(inputs.touched_by(&["package.json".to_owned()]));
        assert!(inputs.touched_by(&[".github/workflows/ci.yml".to_owned()]));
        assert!(inputs.touched_by(&["packages/api/pnpm-lock.yaml".to_owned()]));
        assert!(inputs.touched_by(&["pnpm-lock.yaml".to_owned()]));

        // The near misses, which are the whole reason the shapes are explicit.
        assert!(!inputs.touched_by(&["app/package.json".to_owned()]));
        assert!(!inputs.touched_by(&[".github/workflows".to_owned()]));
        assert!(!inputs.touched_by(&[".github/dependabot.yml".to_owned()]));
        assert!(!inputs.touched_by(&["my-pnpm-lock.yaml".to_owned()]));
        assert!(!inputs.touched_by(&["app/route.ts".to_owned()]));
    }

    #[test]
    fn the_sink_stops_at_its_limit() {
        let mut sink = FindingSink::with_limit(2);
        assert!(sink.push(finding()));
        assert!(sink.push(finding()));
        assert!(!sink.push(finding()), "third push must be refused");
        assert!(sink.truncated());
        assert_eq!(sink.len(), 2);
    }

    #[test]
    fn draining_resets_the_sink_for_the_next_file() {
        let mut sink = FindingSink::with_limit(1);
        sink.push(finding());
        sink.push(finding());
        assert_eq!(sink.drain().len(), 1);
        assert!(sink.is_empty());
        assert!(!sink.truncated());
    }

    #[test]
    fn truncation_is_visible_before_drain() {
        // The engine must read `truncated()` before `drain()` — drain clears the
        // flag so the next file starts clean. Losing that bit is how a flood
        // became a green CI exit.
        let mut sink = FindingSink::with_limit(1);
        assert!(sink.push(finding()));
        assert!(!sink.push(finding()));
        assert!(sink.truncated());
        let drained = sink.drain();
        assert_eq!(drained.len(), 1);
        assert!(!sink.truncated());
    }
}
