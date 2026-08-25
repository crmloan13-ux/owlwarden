//! The OWASP Top 10 for Agentic Applications (ASI), 2026 edition.
//!
//! A second taxonomy, kept beside [`crate::owasp`] rather than folded into it,
//! because the two answer different questions. The Top 10 (2021) is about the
//! web application in the repository. The ASI list is about the agent that
//! works in it — goal hijack, privilege abuse, supply chain, unexpected
//! execution. A rule on [`Surface::AgentWorkspace`](crate::surface::Surface)
//! maps here; a rule on `WebApp` maps to OWASP. Blurring them would make the
//! `owasp-top10` preset a marketing word rather than a claim
//! ([ADR 0025](../../../docs/adr/0025-agent-surface-and-supply-chain.md) §8).
//!
//! # Why CWE is the primary mapping and this is secondary
//!
//! CWE ids are stable across decades. The agentic list is new and will be
//! renumbered. Every rule in the agent family therefore declares a CWE, and the
//! ASI reference is additional context — so a renumbering costs us a table edit
//! here rather than invalidating the taxonomy on findings already in someone's
//! baseline.
//!
//! # Why there are no per-category URLs
//!
//! The project publishes its categories under URLs that have moved more than
//! once during the edition's drafting. A dead link in a security report costs
//! more than a missing one (the same reasoning as
//! [`Reference::owasp`](crate::finding::Reference::owasp) returning `None` for
//! an unknown category), so every ASI reference points at the project's own
//! home page, which resolves, and the category id carries the specificity.

use crate::detector::DetectorMeta;
use crate::finding::RuleId;

/// The edition this catalogue describes.
///
/// Pinned as data so that moving to a later edition is a reviewed change with a
/// visible diff, not a drift. `RULES.md`, `owlwarden coverage`, and the SARIF
/// taxonomy block all print it.
pub const ASI_EDITION: &str = "2026";

/// Where an ASI reference points.
///
/// One URL for every category, on purpose — see the module docs.
pub const ASI_PROJECT_URL: &str = "https://genai.owasp.org/";

/// One ASI category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsiCategory {
    /// Canonical id, e.g. `"ASI05"`.
    pub id: &'static str,
    /// Category title as the edition words it.
    pub title: &'static str,
    /// What the category covers, in the words we would use to explain it to
    /// someone who has just been handed a finding.
    pub summary: &'static str,
    /// Whether reading configuration out of a working tree can see this
    /// category at all.
    ///
    /// The agent surface has the same honesty problem as the OWASP table: some
    /// of these categories are properties of a running agent's behaviour, and
    /// no amount of parsing `.claude/settings.json` will reach them. Saying so
    /// is more useful than an empty row that reads like a backlog item.
    pub static_reachability: Reachability,
}

pub use crate::owasp::Reachability;

impl AsiCategory {
    /// The canonical URL for the category.
    #[must_use]
    pub fn url(&self) -> String {
        ASI_PROJECT_URL.to_owned()
    }
}

/// The ASI 2026 categories, in order.
///
/// Only the four this project maps rules onto are load-bearing; the rest are
/// present so the coverage table can show the shape of what is *not* covered.
/// An id that is not in this list does not resolve, and a rule referencing one
/// fails the catalogue test in this crate — the same guard the OWASP table has.
pub const ASI_2026: &[AsiCategory] = &[
    AsiCategory {
        id: "ASI01",
        title: "Agent Goal Hijack",
        summary: "The agent is redirected to pursue an attacker's objective — through instruction \
                  text it reads as authoritative, or content it treats as data and then obeys.",
        // Instruction files are checked into the repository and are exactly
        // what this surface reads.
        static_reachability: Reachability::Good,
    },
    AsiCategory {
        id: "ASI02",
        title: "Tool Misuse and Exploitation",
        summary: "A tool the agent legitimately holds is used for something it was not scoped \
                  for, or is fed arguments that turn it into a different capability.",
        // What a tool does with an argument at run time is not in the config.
        static_reachability: Reachability::Poor,
    },
    AsiCategory {
        id: "ASI03",
        title: "Agent Identity and Privilege Abuse",
        summary: "The agent acts with more authority than the task needs: credentials in reach of \
                  repository-controlled commands, pre-approved permissions, redirected traffic.",
        static_reachability: Reachability::Partial,
    },
    AsiCategory {
        id: "ASI04",
        title: "Agentic Supply Chain Compromise",
        summary: "Code, tools, or instructions reach the agent from a source nobody vetted: a \
                  run-time package resolve, an unpinned MCP server, a third-party marketplace.",
        static_reachability: Reachability::Good,
    },
    AsiCategory {
        id: "ASI05",
        title: "Unexpected Code Execution",
        summary: "Opening a repository, or letting the agent take one step in it, runs code the \
                  developer never asked to run.",
        static_reachability: Reachability::Good,
    },
    AsiCategory {
        id: "ASI06",
        title: "Memory and Context Poisoning",
        summary: "Durable state the agent carries between turns or sessions is written by an \
                  attacker and read back as trusted context.",
        // Memory is run-time state, not a file in the tree.
        static_reachability: Reachability::Poor,
    },
    AsiCategory {
        id: "ASI07",
        title: "Insufficient Human Oversight",
        summary: "The approval step that was supposed to bound the blast radius is absent, \
                  pre-answered, or worded so it is always accepted.",
        // A repository that pre-approves permissions is visible; whether a
        // human actually looked is not.
        static_reachability: Reachability::Partial,
    },
    AsiCategory {
        id: "ASI08",
        title: "Multi-Agent and Orchestration Exploitation",
        summary: "One agent's output becomes another's instruction, and a boundary that existed \
                  on paper does not exist in the message flow.",
        static_reachability: Reachability::Poor,
    },
    AsiCategory {
        id: "ASI09",
        title: "Insufficient Agent Observability",
        summary: "What the agent did cannot be reconstructed afterwards: no record of the tool \
                  calls, the inputs, or the decision that authorised them.",
        static_reachability: Reachability::Poor,
    },
    AsiCategory {
        id: "ASI10",
        title: "Unbounded Autonomy",
        summary: "The agent is permitted to act without a ceiling on scope, spend, or duration, \
                  so a single wrong step is not a bounded mistake.",
        static_reachability: Reachability::Poor,
    },
];

/// Resolves an ASI category id.
///
/// Case-sensitive, and `None` for anything not in [`ASI_2026`]. A typo must not
/// become a reference the reader cannot look up.
#[must_use]
pub fn category(id: &str) -> Option<&'static AsiCategory> {
    ASI_2026.iter().find(|entry| entry.id == id)
}

/// Whether a reference resolves to a category we ship.
#[must_use]
pub fn is_known(reference: &crate::finding::AsiRef) -> bool {
    category(reference.as_str()).is_some()
}

/// One row of the ASI coverage table: a category and the rules mapping to it.
#[derive(Debug, Clone)]
pub struct AsiCoverage {
    /// The category.
    pub category: &'static AsiCategory,
    /// Rules that map to it, sorted by id.
    pub rules: Vec<RuleId>,
}

impl AsiCoverage {
    /// Whether any shipped rule maps here.
    #[must_use]
    pub fn is_covered(&self) -> bool {
        !self.rules.is_empty()
    }
}

/// Builds the ASI coverage table from the rules actually compiled in.
///
/// Every category is listed, covered or not, for the same reason the OWASP
/// table lists all ten: the gaps are the useful half of the answer.
#[must_use]
pub fn coverage(metas: &[DetectorMeta]) -> Vec<AsiCoverage> {
    ASI_2026
        .iter()
        .map(|category| {
            let mut rules: Vec<RuleId> = metas
                .iter()
                .filter(|meta| {
                    meta.asi
                        .as_ref()
                        .is_some_and(|reference| reference.as_str() == category.id)
                })
                .map(|meta| meta.id.clone())
                .collect();
            rules.sort();
            AsiCoverage { category, rules }
        })
        .collect()
}

/// How many categories have at least one rule.
#[must_use]
pub fn covered_count(table: &[AsiCoverage]) -> usize {
    table.iter().filter(|entry| entry.is_covered()).count()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::finding::{AsiRef, Confidence, Severity};
    use crate::surface::Surface;

    fn meta(id: &'static str, asi: Option<&'static str>) -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(id),
            title: "t".into(),
            severity: Severity::High,
            max_confidence: Confidence::Likely,
            owasp: None,
            asi: asi.map(AsiRef::new_static),
            cwe: None,
            surface: Surface::AgentWorkspace,
            category: "c".into(),
            description: "d".into(),
        }
    }

    #[test]
    fn the_catalogue_is_ten_categories_in_order() {
        assert_eq!(ASI_2026.len(), 10);
        for (index, entry) in ASI_2026.iter().enumerate() {
            let expected = format!("ASI{:02}", index + 1);
            assert_eq!(entry.id, expected, "categories must be in order");
            assert!(!entry.title.is_empty());
            assert!(!entry.summary.is_empty());
        }
    }

    #[test]
    fn every_category_points_at_a_url_that_exists() {
        // Deliberately one URL for all ten: per-category deep links for this
        // edition have moved, and a 404 in a security report is worse than a
        // less specific link.
        for entry in ASI_2026 {
            assert_eq!(entry.url(), ASI_PROJECT_URL);
            assert!(entry.url().starts_with("https://"));
        }
    }

    #[test]
    fn an_unknown_category_does_not_resolve() {
        assert!(category("ASI11").is_none());
        assert!(category("asi05").is_none(), "ids are case-sensitive");
        assert!(category("").is_none());
        assert!(!is_known(&AsiRef::new_static("ASI-05")));
        assert!(is_known(&AsiRef::new_static("ASI05")));
    }

    #[test]
    fn coverage_lists_every_category_including_the_empty_ones() {
        let table = coverage(&[meta("agent-hook-autoexec", Some("ASI05"))]);
        assert_eq!(table.len(), 10);
        assert_eq!(covered_count(&table), 1);

        let execution = table
            .iter()
            .find(|entry| entry.category.id == "ASI05")
            .expect("ASI05 is in the catalogue");
        assert!(execution.is_covered());

        let memory = table
            .iter()
            .find(|entry| entry.category.id == "ASI06")
            .expect("ASI06 is in the catalogue");
        assert!(
            !memory.is_covered(),
            "an uncovered category is still listed"
        );
    }

    #[test]
    fn rules_with_no_or_unknown_mapping_do_not_land_anywhere() {
        let table = coverage(&[meta("rule-a", None), meta("rule-b", Some("ASI99"))]);
        assert_eq!(covered_count(&table), 0);
    }

    #[test]
    fn the_edition_is_pinned_rather_than_implied() {
        assert_eq!(ASI_EDITION, "2026");
    }
}
