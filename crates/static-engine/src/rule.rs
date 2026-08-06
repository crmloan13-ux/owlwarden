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
