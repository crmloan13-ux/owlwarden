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

use crate::finding::{AgentHost, Fix, FixSafety, Framework};
use crate::runtime::Runtime;
use crate::surface::Profile;

/// Every fix one rule can offer, keyed by profile.
///
/// Two keyed tables rather than one, because a rule has exactly one surface and
/// therefore fills exactly one of them. Keeping them apart means the matrix
/// test can say *which* table is short, and it means a `WebApp` rule cannot
/// accidentally satisfy its coverage with a fix written for Cursor.
#[derive(Debug, Clone)]
pub struct Remediation {
    specific: Vec<Fix>,
    host_specific: Vec<Fix>,
    /// Fixes that exist only because the framework's base advice does not run
    /// on a particular runtime. Keyed by `(framework, runtime)`.
    ///
    /// A separate list rather than more entries in `specific`, so that "does
    /// this rule have a delta here?" is a question with an answer — which is
    /// what the build's execution invariant asks
    /// ([ADR 0031](../../../docs/adr/0031-runtime-overlay.md) §3).
    deltas: Vec<Fix>,
    generic: Fix,
}

impl Remediation {
    /// Starts a table with the advice that applies regardless of profile.
    #[must_use]
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            specific: Vec::new(),
            host_specific: Vec::new(),
            deltas: Vec::new(),
            generic: Fix {
                framework: None,
                host: None,
                runtime: None,
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
            host: None,
            runtime: None,
            summary: summary.into(),
            patch,
            safety,
        });
        self
    }

    /// Adds advice for one agent host.
    ///
    /// The `AgentWorkspace` counterpart of [`Self::fix`]. Agent-config fixes
    /// are `Manual` without exception so far — the correct replacement for a
    /// hostile hook depends on what the team meant to do — but the safety level
    /// is a parameter here rather than a constant so the contract stays the
    /// same shape on both surfaces.
    #[must_use]
    pub fn host_fix(
        mut self,
        host: AgentHost,
        summary: impl Into<String>,
        patch: Option<String>,
        safety: FixSafety,
    ) -> Self {
        self.host_specific.push(Fix {
            framework: None,
            host: Some(host),
            runtime: None,
            summary: summary.into(),
            patch,
            safety,
        });
        self
    }

    /// Adds `Manual` advice for one agent host — the common case.
    #[must_use]
    pub fn host(
        self,
        host: AgentHost,
        summary: impl Into<String>,
        patch: impl Into<String>,
    ) -> Self {
        self.host_fix(host, summary, Some(patch.into()), FixSafety::Manual)
    }

    /// Adds the same `Manual` advice for every host in `hosts`.
    ///
    /// For the genuinely host-independent half of an agent-config fix — "delete
    /// the entry" reads the same everywhere. Prefer [`Self::host`] whenever the
    /// patch can name the host's own file and key, which is most of the time:
    /// a fix a reader cannot paste is the thing this project exists not to
    /// ship.
    #[must_use]
    pub fn host_each(
        mut self,
        hosts: &[AgentHost],
        summary: impl Into<String>,
        patch: impl Into<String>,
    ) -> Self {
        let summary = summary.into();
        let patch = patch.into();
        for host in hosts {
            self = self.host(host.clone(), summary.clone(), patch.clone());
        }
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

    /// Adds a `Safe` single-line patch for one framework.
    ///
    /// `--fix` applies these as a highlight-span replacement. The patch must
    /// be a drop-in for the underlined expression — never a multi-line example.
    #[must_use]
    pub fn safe(
        self,
        framework: Framework,
        summary: impl Into<String>,
        patch: impl Into<String>,
    ) -> Self {
        self.fix(framework, summary, Some(patch.into()), FixSafety::Safe)
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

    /// Adds the same `Safe` single-line patch for every framework in `frameworks`.
    #[must_use]
    pub fn safe_each(
        mut self,
        frameworks: &[Framework],
        summary: impl Into<String>,
        patch: impl Into<String>,
    ) -> Self {
        let summary = summary.into();
        let patch = patch.into();
        for framework in frameworks {
            self = self.safe(framework.clone(), summary.clone(), patch.clone());
        }
        self
    }

    /// Adds a fix that replaces the framework's advice on one runtime.
    ///
    /// **Only where the base fix genuinely does not run, or is genuinely
    /// wrong.** A delta added because it reads better is the padding this design
    /// exists to avoid, and the build has no way to tell the two apart — the
    /// discipline is the reviewer's
    /// ([ADR 0031](../../../docs/adr/0031-runtime-overlay.md) §2).
    #[must_use]
    pub fn delta(
        mut self,
        framework: Framework,
        runtime: Runtime,
        summary: impl Into<String>,
        patch: impl Into<String>,
    ) -> Self {
        self.deltas.push(Fix {
            framework: Some(framework),
            host: None,
            runtime: Some(runtime),
            summary: summary.into(),
            patch: Some(patch.into()),
            safety: FixSafety::Manual,
        });
        self
    }

    /// Adds the same delta for several frameworks on one runtime.
    ///
    /// The common shape: `node:crypto` is absent on the fetch-API tier for
    /// every framework that targets it, and the replacement is the same Web
    /// Crypto call in each.
    #[must_use]
    pub fn delta_each(
        mut self,
        frameworks: &[Framework],
        runtime: Runtime,
        summary: impl Into<String>,
        patch: impl Into<String>,
    ) -> Self {
        let summary = summary.into();
        let patch = patch.into();
        for framework in frameworks {
            self = self.delta(framework.clone(), runtime, summary.clone(), patch.clone());
        }
        self
    }

    /// Whether this rule patches `framework` on `runtime`.
    ///
    /// The predicate the execution invariant asks: a rule with no delta here is
    /// asserting that its base fix runs on that runtime, and the fixture suite
    /// then has to prove it.
    #[must_use]
    pub fn has_delta(&self, framework: &Framework, runtime: Runtime) -> bool {
        self.deltas
            .iter()
            .any(|fix| fix.framework.as_ref() == Some(framework) && fix.runtime == Some(runtime))
    }

    /// Every delta, for the catalogue and the execution test.
    #[must_use]
    pub fn deltas(&self) -> &[Fix] {
        &self.deltas
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

    /// [`Self::select`], with the runtime delta first when there is one.
    ///
    /// The delta leads because it exists precisely where the base fix does not
    /// run. The base fix is still included below it: a reader who is *not* on
    /// the inferred runtime — and the summary line tells them when it was
    /// inferred — needs the one they can actually use.
    #[must_use]
    pub fn select_for_runtime(&self, framework: &Framework, runtime: Runtime) -> Vec<Fix> {
        self.deltas
            .iter()
            .filter(|fix| fix.framework.as_ref() == Some(framework) && fix.runtime == Some(runtime))
            .cloned()
            .chain(self.select(framework))
            .collect()
    }

    /// The fixes to attach to a finding in a workspace using `host`.
    ///
    /// Always at least one entry, for the same reason as [`Self::select`].
    #[must_use]
    pub fn select_for_host(&self, host: &AgentHost) -> Vec<Fix> {
        self.host_specific
            .iter()
            .filter(|fix| fix.host.as_ref() == Some(host))
            .cloned()
            .chain(std::iter::once(self.generic.clone()))
            .collect()
    }

    /// The fixes for whichever profile a finding carries.
    #[must_use]
    pub fn select_for(&self, profile: &Profile) -> Vec<Fix> {
        match profile {
            Profile::Framework(framework) => self.select(framework),
            Profile::Host(host) => self.select_for_host(host),
        }
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
            .chain(self.host_specific.iter())
            .chain(self.deltas.iter())
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

    /// The agent hosts this table has specific advice for.
    #[must_use]
    pub fn hosts(&self) -> Vec<&AgentHost> {
        self.host_specific
            .iter()
            .filter_map(|fix| fix.host.as_ref())
            .collect()
    }

    /// Whether there is specific advice for a framework.
    #[must_use]
    pub fn covers(&self, framework: &Framework) -> bool {
        self.frameworks().contains(&framework)
    }

    /// Whether there is specific advice for an agent host.
    #[must_use]
    pub fn covers_host(&self, host: &AgentHost) -> bool {
        self.hosts().contains(&host)
    }

    /// Whether there is specific advice for a profile, whichever set it is
    /// from. This is the predicate the matrix test asserts, once per profile of
    /// the rule's own surface.
    #[must_use]
    pub fn covers_profile(&self, profile: &Profile) -> bool {
        match profile {
            Profile::Framework(framework) => self.covers(framework),
            Profile::Host(host) => self.covers_host(host),
        }
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
    fn a_host_table_selects_by_host_and_still_carries_the_fallback() {
        let table = Remediation::new("Remove the entry.")
            .host(AgentHost::CLAUDE_CODE, "Claude advice", "claude patch")
            .host(AgentHost::CURSOR, "Cursor advice", "cursor patch");

        let selected = table.select_for_host(&AgentHost::CLAUDE_CODE);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected.first().and_then(|fix| fix.host.as_ref()),
            Some(&AgentHost::CLAUDE_CODE)
        );
        assert!(table.covers_host(&AgentHost::CURSOR));
        assert!(!table.covers_host(&AgentHost::VSCODE));
        assert_eq!(table.select_for_host(&AgentHost::VSCODE).len(), 1);
    }

    #[test]
    fn framework_advice_never_satisfies_a_host_profile() {
        // The whole point of two tables: a WebApp fix must not be able to close
        // an AgentWorkspace coverage gap, or the matrix test would accept
        // advice written for the wrong kind of environment entirely.
        let table = table();
        assert!(!table.covers_host(&AgentHost::CLAUDE_CODE));
        assert!(!table.covers_profile(&Profile::Host(AgentHost::CLAUDE_CODE)));
        assert!(table.covers_profile(&Profile::Framework(Framework::NEXT)));

        let hosts = Remediation::new("g").host(AgentHost::GENERIC, "s", "p");
        assert!(!hosts.covers(&Framework::NEXT));
    }

    #[test]
    fn a_runtime_delta_leads_and_the_base_fix_still_follows() {
        // The delta first because the base does not run there; the base still
        // present because a reader on a different runtime — and the summary
        // line says when the runtime was inferred — needs the one they can use.
        let table = Remediation::new("Use a CSPRNG.")
            .manual(Framework::HONO, "Node advice", "randomBytes(32)")
            .delta(
                Framework::HONO,
                Runtime::WebWorker,
                "Workers advice",
                "crypto.getRandomValues(new Uint8Array(32))",
            );

        let selected = table.select_for_runtime(&Framework::HONO, Runtime::WebWorker);
        assert_eq!(selected.len(), 3, "delta, framework fix, fallback");
        assert_eq!(
            selected.first().and_then(|fix| fix.runtime),
            Some(Runtime::WebWorker)
        );
        assert_eq!(selected.get(1).and_then(|fix| fix.runtime), None);
    }

    #[test]
    fn a_runtime_with_no_delta_gets_the_base_fix_unchanged() {
        // Twenty of twenty-five rules are in this shape, and the build asserts
        // their base fix actually runs there rather than assuming it.
        let table = Remediation::new("Use a CSPRNG.").manual(
            Framework::HONO,
            "Node advice",
            "randomBytes(32)",
        );
        assert_eq!(
            table.select_for_runtime(&Framework::HONO, Runtime::Bun),
            table.select(&Framework::HONO)
        );
        assert!(!table.has_delta(&Framework::HONO, Runtime::Bun));
    }

    #[test]
    fn explain_lists_deltas_too() {
        // A delta `explain` did not print would be advice that exists and
        // cannot be found, which is the failure the whole declared-table design
        // was built to remove.
        let table = Remediation::new("generic")
            .manual(Framework::HONO, "n", "np")
            .delta(Framework::HONO, Runtime::Deno, "d", "dp");
        assert_eq!(table.all().len(), 3);
        assert!(
            table
                .all()
                .iter()
                .any(|fix| fix.runtime == Some(Runtime::Deno))
        );
    }

    #[test]
    fn explain_lists_both_tables() {
        let table = Remediation::new("generic")
            .manual(Framework::NEXT, "n", "np")
            .host(AgentHost::CURSOR, "c", "cp");
        assert_eq!(table.all().len(), 3);
    }

    #[test]
    fn host_each_fills_a_whole_profile_set() {
        let table = Remediation::new("generic").host_each(
            crate::surface::SUPPORTED_AGENT_HOSTS,
            "Delete the entry.",
            "remove it",
        );
        for host in crate::surface::SUPPORTED_AGENT_HOSTS {
            assert!(table.covers_host(host), "{host} uncovered");
        }
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
