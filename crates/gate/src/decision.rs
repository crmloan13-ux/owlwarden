//! The one decision type.
//!
//! Every host gets the same four verdicts and the same reason string. What
//! differs between hosts is only how that gets spelled on stdout, which is the
//! adapter's whole job.

use owlwarden_core::finding::Finding;
use owlwarden_core::suppression::SuppressionRecord;
use serde::{Deserialize, Serialize};

/// Longest reason string handed to a host.
///
/// The reason is shown to the model, which pays for it by the token, and to the
/// developer, who reads it in a terminal. Neither wants the full report.
pub const MAX_REASON_CHARS: usize = 4_000;

/// What the gate decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Proceed. The default, and what a clean scan produces.
    Allow,
    /// Refuse, with a reason the model must respond to.
    Deny,
    /// Hand the decision to the developer.
    ///
    /// What a *failed* pre-execution gate returns. Nothing runs on a coin flip,
    /// and nothing is blocked on a scanner bug either.
    Ask,
    /// No opinion: the event was not one this gate judges.
    ///
    /// Distinct from `Allow` on purpose. "I looked and it is fine" and "this is
    /// not mine to judge" are different facts, and a host that logs verdicts
    /// should be able to tell them apart.
    Defer,
}

impl Verdict {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
            Self::Defer => "defer",
        }
    }

    /// Whether this verdict stops the agent.
    #[must_use]
    pub const fn blocks(self) -> bool {
        matches!(self, Self::Deny)
    }
}

/// The gate's answer, before a host has spelled it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateDecision {
    /// The verdict.
    pub verdict: Verdict,
    /// Shown to the model: the rule, the line, and the fix.
    ///
    /// Written to be acted on rather than read — this is the text the agent
    /// gets back and has to respond to, so it names the file and the patch and
    /// leaves out the prose.
    pub reason: String,
    /// Injected without blocking. Used by `session-start`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// The normal report, for whoever wants it.
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Suppressions that were found and deliberately not honoured, because the
    /// file they sit in was written during this session.
    #[serde(default)]
    pub ignored_suppressions: Vec<SuppressionRecord>,
    /// Project-config settings the gate refused to apply, and why.
    #[serde(default)]
    pub posture_rejections: Vec<crate::policy::PostureRejection>,
    /// True when the gate could not complete and the verdict is a posture
    /// rather than a result. Hosts surface this on stderr.
    #[serde(default)]
    pub degraded: bool,
}

impl GateDecision {
    /// A decision with no findings behind it.
    #[must_use]
    pub fn new(verdict: Verdict, reason: impl Into<String>) -> Self {
        Self {
            verdict,
            reason: clamp(&reason.into()),
            context: None,
            findings: Vec::new(),
            ignored_suppressions: Vec::new(),
            posture_rejections: Vec::new(),
            degraded: false,
        }
    }

    /// Attaches the findings the verdict came from.
    #[must_use]
    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }

    /// Attaches non-blocking context.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(clamp(&context.into()));
        self
    }

    /// Marks the decision as one taken because the gate could not run.
    #[must_use]
    pub fn degraded(mut self) -> Self {
        self.degraded = true;
        self
    }

    /// Records suppressions the gate refused to honour.
    #[must_use]
    pub fn with_ignored_suppressions(mut self, records: Vec<SuppressionRecord>) -> Self {
        self.ignored_suppressions = records;
        self
    }

    /// Records project-config settings the gate refused.
    #[must_use]
    pub fn with_rejections(mut self, rejections: Vec<crate::policy::PostureRejection>) -> Self {
        self.posture_rejections = rejections;
        self
    }
}

/// Bounds a string handed to a host.
fn clamp(text: &str) -> String {
    if text.chars().count() <= MAX_REASON_CHARS {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(MAX_REASON_CHARS).collect();
    out.push_str("\n… truncated; run `owlwarden scan --format json` for the full report");
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn only_deny_blocks() {
        assert!(Verdict::Deny.blocks());
        for verdict in [Verdict::Allow, Verdict::Ask, Verdict::Defer] {
            assert!(!verdict.blocks(), "{verdict:?}");
        }
    }

    #[test]
    fn a_reason_is_bounded_and_says_where_the_rest_went() {
        let decision = GateDecision::new(Verdict::Deny, "x".repeat(MAX_REASON_CHARS * 2));
        assert!(decision.reason.chars().count() <= MAX_REASON_CHARS + 80);
        assert!(decision.reason.contains("truncated"));
    }

    #[test]
    fn defer_is_not_allow() {
        // A host logging verdicts must be able to tell "checked, fine" from
        // "not mine to judge".
        assert_ne!(Verdict::Defer, Verdict::Allow);
        assert_ne!(Verdict::Defer.as_str(), Verdict::Allow.as_str());
    }
}
