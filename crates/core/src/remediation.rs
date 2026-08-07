//! How a rule declares its fixes.
//!
//! # Why this is not just `Vec<Fix>`
//!
//! Rules used to build remediation with a `match framework { ... }` inside the
//! rule. Three things were wrong with that, and all three get worse with every
//! framework added:
//!
//! 1. **Adding a framework meant editing every rule.** `rules × frameworks`
//!    edits, each of which could be forgotten.
//! 2. **Forgetting one was invisible.** A `match` arm that falls through to
//!    generic advice compiles, passes, and quietly gives a Fastify user advice
//!    written for Express.
//! 3. **`explain` had to know which rule it was explaining.** A central
//!    `match rule_id { ... }` mapped ids to fix functions, so a new rule that
//!    forgot to register there had no `explain` output at all.
//!
//! A [`Remediation`] is a declared table. The rule states one entry per
//! framework it has real advice for, plus the fallback everyone gets. Selecting
//! by framework, listing every fix for `explain`, and testing that the table
//! covers the frameworks we ship all become properties of the table rather than
//! of each rule's control flow.
//!
//! # The fallback is mandatory
//!
//! [`Remediation::new`] takes the framework-independent advice, not an option.
//! A finding without a fix is a finding a reader cannot act on, and in an
//! agentic loop it is worse than that: the agent has been told there is a
//! problem and given nothing to do, so it invents something.

use crate::finding::{Fix, FixSafety, Framework};

/// Every fix one rule can offer, keyed by framework.
#[derive(Debug, Clone)]
pub struct Remediation {
    specific: Vec<Fix>,
    generic: Fix,
}

impl Remediation {
    /// Starts a table with the advice that applies regardless of framework.
    #[must_use]
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            specific: Vec::new(),
            generic: Fix {
                framework: None,
                summary: summary.into(),
                patch: None,
                safety: FixSafety::Manual,
            },
        }
    }

    /// Attaches a patch to the framework-independent advice.
    #[must_use]
    pub fn generic_patch(mut self, patch: impl Into<String>) -> Self {
        self.generic.patch = Some(patch.into());
        self
    }

    /// Marks how safely the framework-independent fix can be applied.
    #[must_use]
    pub fn generic_safety(mut self, safety: FixSafety) -> Self {
        self.generic.safety = safety;
        self
    }

    /// Adds advice for one framework.
    ///
    /// Order is preserved and matters only for `explain`, which lists them all;
    /// selection for a scan is by id, not position.
    #[must_use]
    pub fn fix(
        mut self,
        framework: Framework,
        summary: impl Into<String>,
        patch: Option<String>,
        safety: FixSafety,
    ) -> Self {
        self.specific.push(Fix {
            framework: Some(framework),
            summary: summary.into(),
            patch,
            safety,
        });
        self
    }

    /// Adds `Manual` advice for one framework — the common case.
    ///
    /// Most security fixes are `Manual`: the correct replacement depends on
    /// what the code is supposed to do, and a tool that guesses at an API
    /// contract to close a finding breaks production to fix a warning.
    #[must_use]
    pub fn manual(
        self,
        framework: Framework,
        summary: impl Into<String>,
        patch: impl Into<String>,
    ) -> Self {
        self.fix(framework, summary, Some(patch.into()), FixSafety::Manual)
    }

    /// Adds the same `Manual` advice for every framework in `frameworks`.
    ///
    /// For fixes that truly do not vary by stack (pin a SHA, read from
    /// `process.env`). Prefer [`Self::manual`] when the patch should name the
    /// framework's own API.
    #[must_use]
    pub fn manual_each(
        mut self,
        frameworks: &[Framework],
        summary: impl Into<String>,
        patch: impl Into<String>,
    ) -> Self {
        let summary = summary.into();
        let patch = patch.into();
        for framework in frameworks {
            self = self.manual(framework.clone(), summary.clone(), patch.clone());
        }
        self
    }

    /// The fixes to attach to a finding in a project using `framework`: the
    /// specific one if there is one, then the fallback.
    ///
    /// Always at least one entry, so a reader is never left with nothing.
    #[must_use]
    pub fn select(&self, framework: &Framework) -> Vec<Fix> {
        self.specific
            .iter()
            .filter(|fix| fix.framework.as_ref() == Some(framework))
            .cloned()
            .chain(std::iter::once(self.generic.clone()))
            .collect()
    }

    /// Every fix, for `owlwarden explain` and the rule catalogue.
    ///
    /// `explain` must work with no network at all — the reader may be an agent
    /// with no browser — so the complete set ships in the binary rather than
    /// living on a documentation site.
    #[must_use]
    pub fn all(&self) -> Vec<Fix> {
        self.specific
            .iter()
            .cloned()
            .chain(std::iter::once(self.generic.clone()))
            .collect()
    }

    /// The frameworks this table has specific advice for.
    #[must_use]
    pub fn frameworks(&self) -> Vec<&Framework> {
        self.specific
            .iter()
            .filter_map(|fix| fix.framework.as_ref())
            .collect()
    }

    /// Whether there is specific advice for a framework.
    #[must_use]
    pub fn covers(&self, framework: &Framework) -> bool {
        self.frameworks().contains(&framework)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn table() -> Remediation {
        Remediation::new("Do the framework-independent thing.")
            .manual(Framework::NEXT, "Next advice", "next patch")
            .manual(Framework::FASTIFY, "Fastify advice", "fastify patch")
    }

    #[test]
    fn selecting_puts_the_specific_fix_first_and_always_includes_the_fallback() {
        let selected = table().select(&Framework::NEXT);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected.first().and_then(|fix| fix.framework.as_ref()),
            Some(&Framework::NEXT)
        );
        assert_eq!(selected.get(1).and_then(|fix| fix.framework.as_ref()), None);
    }

    #[test]
    fn an_uncovered_framework_still_gets_advice() {
        let selected = table().select(&Framework::NUXT);
        assert_eq!(selected.len(), 1, "the fallback, and only the fallback");
        assert!(selected.first().is_some_and(|fix| fix.framework.is_none()));
    }

    #[test]
    fn explain_gets_every_framework_not_just_the_detected_one() {
        let all = table().all();
        assert_eq!(all.len(), 3);
        assert!(table().covers(&Framework::NEXT));
        assert!(!table().covers(&Framework::EXPRESS));
    }

    #[test]
    fn the_fallback_can_carry_a_patch_and_a_safety_level() {
        let table = Remediation::new("Remove the flag.")
            .generic_patch("delete this line")
            .generic_safety(FixSafety::Safe);
        let fix = table.select(&Framework::GENERIC);
        let fix = fix.first().expect("the fallback");
        assert_eq!(fix.safety, FixSafety::Safe);
        assert_eq!(fix.patch.as_deref(), Some("delete this line"));
    }
}
