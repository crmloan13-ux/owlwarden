//! What the shipped rules can and cannot see, as data.
//!
//! This is the model behind `owlwarden coverage`, and the reason it is computed
//! rather than written down is simple: a hand-maintained answer to "how much of
//! the OWASP Top 10 does this cover?" is wrong within two releases and nobody
//! notices. Everything here is derived from the rules compiled into the binary,
//! so the tool cannot advertise a category it does not check or a framework it
//! does not know.
//!
//! The types live in `core` rather than beside the built-in rules so that
//! reporters can render the table without depending on a detector crate, and so
//! that a plugin's rules land in the same table as the first-party ones. The
//! builder lives with the rules, because only they know what exists.

use serde::{Deserialize, Serialize};

/// The full coverage picture for one build of the tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageReport {
    /// Tool version, so a pasted table can be dated.
    pub version: String,
    /// One entry per OWASP Top 10 (2021) category, covered or not.
    pub owasp: Vec<CategoryEntry>,
    /// One entry per OWASP ASI (agentic) category, covered or not.
    ///
    /// A second table rather than more rows in the first: the two taxonomies
    /// describe different things, and merging them would let an agent rule
    /// appear to raise OWASP Top 10 coverage
    /// ([ADR 0025](../../../docs/adr/0025-agent-surface-and-supply-chain.md) §8).
    #[serde(default)]
    pub asi: Vec<CategoryEntry>,
    /// The ASI edition the `asi` table describes.
    #[serde(default)]
    pub asi_edition: String,
    /// Frameworks with a profile, and how well the rules serve them.
    pub frameworks: Vec<FrameworkEntry>,
    /// Agent hosts with a profile, and how well the agent-surface rules serve
    /// them. The `AgentWorkspace` counterpart of `frameworks`.
    #[serde(default)]
    pub hosts: Vec<FrameworkEntry>,
    /// The closed path allowlist the agent surface reads.
    ///
    /// Carried in the report rather than read from the engine by the renderer,
    /// so `coverage` stays a pure rendering of one value — and so a consumer of
    /// the JSON can answer "is my host's configuration even in scope?" without
    /// running the binary.
    #[serde(default)]
    pub agent_paths: Vec<String>,
    /// Total rules compiled in.
    pub rule_count: usize,
    /// Rules reading application source.
    #[serde(default)]
    pub web_app_rule_count: usize,
    /// Rules reading agent and editor configuration.
    #[serde(default)]
    pub agent_workspace_rule_count: usize,
    /// OWASP Top 10 categories with at least one rule, out of ten.
    pub categories_covered: usize,
    /// ASI categories with at least one rule, out of ten.
    #[serde(default)]
    pub asi_categories_covered: usize,
}

/// One row of the OWASP side of the table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryEntry {
    /// e.g. `"A05:2021"`.
    pub id: String,
    /// Official category title.
    pub title: String,
    /// Rule ids mapping to this category, sorted. Empty means no coverage.
    pub rules: Vec<String>,
    /// How much of this category source analysis can reach at all: `good`,
    /// `partial`, or `poor`.
    ///
    /// This is what stops the table from being misleading. A `poor` category
    /// with no rules is a limit of the method — no parser will ever find a
    /// design flaw — while a `good` category with no rules is work we have not
    /// done. Rendering both as "0 rules" would invite the reader to wait for a
    /// release that is never coming.
    pub reachability: String,
    /// What the category covers, for readers who do not have the list
    /// memorised.
    pub summary: String,
}

/// One row of a profile side of the table — a framework, or an agent host.
///
/// One type for both because the question is identical ("how many rules carry
/// advice written for this environment, and how many fall back?"), and a second
/// struct with the same three fields would only give the two tables a chance to
/// diverge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameworkEntry {
    /// Framework id, e.g. `"fastify"`.
    pub id: String,
    /// Rules carrying remediation written specifically for it.
    pub rules_with_specific_fix: usize,
    /// Rules that would fall back to generic advice.
    ///
    /// Zero is the target and a test enforces it. It is printed anyway, because
    /// a contributor adding a sixth framework wants to see the remaining work
    /// in one command rather than one CI failure at a time.
    pub rules_falling_back: usize,
}
