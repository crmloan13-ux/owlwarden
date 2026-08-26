//! First-party detectors, and the presets that group them.
//!
//! Every rule here is static and passive: it reads source and nothing else.
//!
//! # Adding a rule
//!
//! 1. Implement [`RuleInfo`](owlwarden_static::RuleInfo) plus either
//!    [`FileRule`](owlwarden_static::FileRule) or
//!    [`ProjectRule`](owlwarden_static::ProjectRule), in its own module.
//! 2. Register it in [`all_file_rules`] / [`all_project_rules`]. That is the
//!    only registration: presets, `explain`, `RULES.md`, and the OWASP coverage
//!    table are all derived from the rule's own metadata, so there is no second
//!    list to forget.
//! 3. Add a fixture under `fixtures/vulnerable/` **and** one under
//!    `fixtures/should-not-fire/`. The second is not optional: precision is a
//!    tested property here, not an aspiration.
//!
//! # Adding a framework
//!
//! Nothing in this crate. A rule never names a framework to decide what an
//! expression means — it asks the project's detected
//! [`FrameworkSet`](owlwarden_static::FrameworkSet). Framework knowledge lives
//! in `owlwarden_static::framework::profiles`; the only thing a rule declares
//! per framework is remediation, and
//! [`remediation_gaps`] fails the build when a rule is missing one.
//!
//! # Adding an agent host
//!
//! The same shape, one surface over. A rule on
//! [`Surface::AgentWorkspace`](owlwarden_core::surface::Surface) owes a fix per
//! [`SUPPORTED_AGENT_HOSTS`] entry and no framework fixes at all, and the same
//! matrix test fails the build when one is missing.

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

pub mod agent;
pub mod build;
pub mod ci_unpinned_action;
pub mod cors;
pub mod csrf_cross_origin_post;
pub mod decorator;
pub mod hardcoded_secret;
pub mod insecure_cookie;
pub mod install_lifecycle_script;
pub mod known_vulnerable_dependency;
pub mod lockfile;
pub mod open_redirect;
pub mod security_headers;
pub mod sensitive_data_logged;
pub mod sql_injection;
pub mod ssrf;
pub mod stack_trace_leak;
pub mod unpinned_dependency;
pub mod weak_crypto;

use std::sync::Arc;

use owlwarden_core::coverage::{CategoryEntry, CoverageReport, FrameworkEntry};
use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::Confidence;
use owlwarden_core::owasp::{self, CategoryCoverage};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::surface::{Profile, Surface};
use owlwarden_core::taxonomy::{self, AsiCoverage};
use owlwarden_static::rule::{FileRule, ProjectRule, RuleInfo};

pub use agent::config::{
    AgentConfigEnvRedirect, AgentConfigLoaderScript, AgentConfigSecretReachable,
};
pub use agent::hooks::{AgentHookAutoexec, AgentHookUntrustedCommand};
pub use agent::instructions::{AgentInstructionsDirective, AgentInstructionsHiddenText};
pub use agent::permissions::AgentPermissionWildcard;
pub use agent::supply_chain::{AgentMarketplaceUntrusted, AgentMcpUnpinnedRemote};
pub use ci_unpinned_action::CiUnpinnedAction;
pub use cors::CorsPermissive;
pub use csrf_cross_origin_post::{
    CsrfCrossOriginPost, CsrfCrossOriginPostDetector, csrf_cross_origin_post_detector,
};
pub use hardcoded_secret::HardcodedSecret;
pub use insecure_cookie::InsecureCookie;
pub use install_lifecycle_script::InstallLifecycleScript;
pub use known_vulnerable_dependency::{
    KnownVulnerableDependency, OsvAdvisoryDetector, osv_detector,
};
pub use open_redirect::OpenRedirect;
pub use security_headers::SecurityHeadersMissing;
pub use sensitive_data_logged::SensitiveDataLogged;
pub use sql_injection::SqlInjection;
pub use ssrf::Ssrf;
pub use stack_trace_leak::StackTraceLeak;
pub use unpinned_dependency::UnpinnedDependency;
pub use weak_crypto::WeakCrypto;

/// The frameworks every `WebApp` rule is expected to have remediation for.
///
/// Re-exported from `core` rather than declared again here. Two lists would be
/// two lists to keep in step, and the one that drifts is always the one the
/// matrix test does not read.
///
/// Checked by [`remediation_gaps`], which the test suite fails on. Without it,
/// adding Fastify would leave every existing rule quietly handing Fastify users
/// generic advice — technically correct, useless in practice, and invisible
/// until someone complained.
pub use owlwarden_core::surface::SUPPORTED_FRAMEWORKS;

/// The agent hosts every `AgentWorkspace` rule is expected to have remediation
/// for. The same invariant, one surface over.
pub use owlwarden_core::surface::SUPPORTED_AGENT_HOSTS;

/// A named bundle of rules.
///
/// Presets are how a user says "check the obvious things" without learning the
/// rule catalogue. `--preset` is the flag; there is no `--profile`.
#[derive(Clone, Copy)]
pub struct Preset {
    /// Name used on the command line and in config.
    pub name: &'static str,
    /// One line for `--help` and the docs.
    pub description: &'static str,
    /// Which rules belong, decided from their metadata.
    ///
    /// A predicate rather than a list of ids. A list has to be edited every
    /// time a rule is added, and the failure mode of forgetting is a rule that
    /// exists, passes its tests, and never runs for anybody.
    pub selects: fn(&DetectorMeta) -> bool,
}

impl std::fmt::Debug for Preset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Preset")
            .field("name", &self.name)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

/// The built-in presets.
///
/// Each definition is a property of a rule, not a list of names, so a preset's
/// *meaning* is what users configure against and it stays true as rules are
/// added.
pub const PRESETS: &[Preset] = &[
    Preset {
        name: "quick",
        description: "Fast, high-signal rules. The zero-config default.",
        // A rule that can never exceed `Possible` is a heuristic. Useful, worth
        // reading, and not what someone wants on every save.
        selects: |meta| meta.max_confidence > Confidence::Possible,
    },
    Preset {
        name: "owasp-top10",
        description: "Rules mapped to an OWASP Top 10 (2021) category.",
        selects: |meta| {
            meta.owasp
                .as_ref()
                .is_some_and(|category| owasp::category(category.as_str()).is_some())
        },
    },
    Preset {
        name: "deep",
        description: "Every rule, including the noisier heuristics.",
        selects: |_| true,
    },
    Preset {
        name: "agent-surface",
        description: "Agent and editor configuration only. What `vet` runs.",
        // Defined by the rule's surface, not by a list of ids, so a rule added
        // to the family is in the preset the moment it compiles.
        selects: |meta| meta.surface == Surface::AgentWorkspace,
    },
];

/// The preset used when the user names none.
pub const DEFAULT_PRESET: &str = "quick";

/// Looks up a preset by name.
#[must_use]
pub fn preset(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|preset| preset.name == name)
}

/// Every per-file rule that ships with owlwarden.
#[must_use]
pub fn all_file_rules() -> Vec<Arc<dyn FileRule>> {
    vec![
        Arc::new(StackTraceLeak),
        Arc::new(SqlInjection),
        Arc::new(InsecureCookie),
        Arc::new(CorsPermissive),
        Arc::new(HardcodedSecret),
        Arc::new(Ssrf),
        Arc::new(WeakCrypto),
        Arc::new(OpenRedirect),
        Arc::new(SensitiveDataLogged),
    ]
}

/// Every project-wide rule that ships with owlwarden.
#[must_use]
pub fn all_project_rules() -> Vec<Arc<dyn ProjectRule>> {
    vec![
        Arc::new(SecurityHeadersMissing),
        Arc::new(UnpinnedDependency),
        Arc::new(CiUnpinnedAction),
        Arc::new(AgentHookAutoexec),
        Arc::new(AgentHookUntrustedCommand),
        Arc::new(AgentConfigLoaderScript),
        Arc::new(AgentConfigEnvRedirect),
        Arc::new(AgentConfigSecretReachable),
        Arc::new(AgentPermissionWildcard),
        Arc::new(AgentMcpUnpinnedRemote),
        Arc::new(AgentMarketplaceUntrusted),
        Arc::new(AgentInstructionsHiddenText),
        Arc::new(AgentInstructionsDirective),
        Arc::new(InstallLifecycleScript),
    ]
}

/// Advisory-only rules that are catalogue entries but run via
/// [`osv_detector`] when `--osv` is set — not as FileRule/ProjectRule.
#[must_use]
pub fn advisory_rule_infos() -> Vec<Arc<dyn RuleInfo>> {
    vec![Arc::new(KnownVulnerableDependency)]
}

/// Active-network rules that are catalogue entries but run via
/// [`csrf_cross_origin_post_detector`] when `--allow-active` is set.
#[must_use]
pub fn active_rule_infos() -> Vec<Arc<dyn RuleInfo>> {
    vec![Arc::new(CsrfCrossOriginPost)]
}

/// Every rule, as the shape that only needs its metadata and remediation.
///
/// The catalogue, `explain`, the coverage table, and the framework-coverage
/// test all read this, so none of them can go stale relative to what actually
/// runs. Includes opt-in advisory rules (see [`advisory_rule_infos`]).
#[must_use]
pub fn all_rules() -> Vec<Arc<dyn RuleInfo>> {
    let mut rules: Vec<Arc<dyn RuleInfo>> = Vec::new();
    for rule in all_project_rules() {
        rules.push(rule);
    }
    for rule in all_file_rules() {
        rules.push(rule);
    }
    for rule in advisory_rule_infos() {
        rules.push(rule);
    }
    for rule in active_rule_infos() {
        rules.push(rule);
    }
    rules.sort_by(|left, right| left.meta().id.cmp(&right.meta().id));
    rules
}

/// The two kinds of rule a preset resolves to: per-file, then project-wide.
///
/// They stay separate because the engine drives them differently — file rules
/// see one parsed file each, project rules see the whole tree.
pub type RuleSet = (Vec<Arc<dyn FileRule>>, Vec<Arc<dyn ProjectRule>>);

/// The rules a preset enables.
///
/// An unknown preset name yields empty sets rather than silently falling back
/// to the default. A typo in CI must fail loudly, not quietly scan less than
/// the user asked for.
#[must_use]
pub fn rules_for_preset(name: &str) -> RuleSet {
    let Some(preset) = preset(name) else {
        return (Vec::new(), Vec::new());
    };
    let selects = preset.selects;

    (
        all_file_rules()
            .into_iter()
            .filter(|rule| selects(&rule.meta()))
            .collect(),
        all_project_rules()
            .into_iter()
            .filter(|rule| selects(&rule.meta()))
            .collect(),
    )
}

/// The rule ids a preset enables, sorted.
///
/// Derived from the same predicate the scan uses, so `owlwarden rules` cannot
/// list a preset's contents differently from what the preset actually runs.
#[must_use]
pub fn preset_rule_ids(name: &str) -> Vec<String> {
    let Some(preset) = preset(name) else {
        return Vec::new();
    };
    let selects = preset.selects;
    let mut ids: Vec<String> = all_rule_metas()
        .into_iter()
        .filter(selects)
        .map(|meta| meta.id.to_string())
        .collect();
    ids.sort();
    ids
}

/// Everything `owlwarden explain <id>` needs, with no network access.
///
/// Remediation comes from the rule itself rather than from a lookup table here,
/// so a new rule cannot ship with an empty explanation because someone forgot a
/// `match` arm.
#[must_use]
pub fn explain(rule_id: &str) -> Option<RuleExplanation> {
    let rule = all_rules()
        .into_iter()
        .find(|rule| rule.meta().id.as_str() == rule_id)?;
    let meta = rule.meta();

    let mut references = Vec::new();
    if let Some(owasp) = &meta.owasp
        && let Some(reference) = owlwarden_core::finding::Reference::owasp(owasp)
    {
        references.push(reference);
    }
    if let Some(cwe) = meta.cwe {
        references.push(owlwarden_core::finding::Reference::cwe(cwe));
    }
    references.push(owlwarden_core::finding::Reference::rule_page(&meta.id));

    Some(RuleExplanation {
        meta,
        fixes: rule.remediation().all(),
        references,
    })
}

/// The long-form write-up for one rule.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleExplanation {
    /// Stable rule metadata.
    pub meta: DetectorMeta,
    /// Every framework's remediation, not just the detected one.
    pub fixes: Vec<owlwarden_core::finding::Fix>,
    /// Curated references.
    pub references: Vec<owlwarden_core::finding::Reference>,
}

/// Metadata for every built-in rule, sorted by id.
///
/// This is the single source for `RULES.md`, for `owlwarden explain`, and for
/// the MCP `list_rules` tool — so the catalogue cannot drift from the code.
#[must_use]
pub fn all_rule_metas() -> Vec<DetectorMeta> {
    all_rules().iter().map(|rule| rule.meta()).collect()
}

/// Which OWASP Top 10 categories the shipped rules cover, and which they do
/// not.
///
/// Computed from the compiled-in rules, so it cannot claim coverage that does
/// not exist. `owlwarden coverage` prints it and `RULES.md` embeds it.
#[must_use]
pub fn owasp_coverage() -> Vec<CategoryCoverage> {
    owasp::coverage(&all_rule_metas())
}

/// Which OWASP ASI (agentic) categories the shipped rules cover, and which they
/// do not. Same contract as [`owasp_coverage`], one taxonomy over.
#[must_use]
pub fn asi_coverage() -> Vec<AsiCoverage> {
    taxonomy::coverage(&all_rule_metas())
}

/// A rule that lacks remediation for a profile we claim to support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingRemediation {
    /// The rule with the gap.
    pub rule: String,
    /// The surface the rule declared.
    pub surface: Surface,
    /// The profile it has no specific advice for — a framework on `WebApp`, an
    /// agent host on `AgentWorkspace`.
    pub profile: String,
}

/// Every (rule, profile) pair with no specific remediation, across both
/// surfaces.
///
/// Empty is the only acceptable answer, and a test enforces that. The reason it
/// is a function rather than only a test is that it is also worth printing:
/// `owlwarden coverage` shows it, so a contributor adding a framework or a host
/// can see the work remaining rather than discovering it one CI failure at a
/// time.
///
/// Note what this does *not* do: it never checks a rule against the other
/// surface's profile set. A `WebApp` rule owes twelve framework fixes and no
/// host fixes; an `AgentWorkspace` rule owes seven host fixes and no framework
/// fixes. Writing the same paragraph twelve times to satisfy a list that does
/// not apply is the padding
/// [ADR 0018](../../docs/adr/0018-corpus-depth-bar.md) rejected, and
/// [ADR 0025](../../docs/adr/0025-agent-surface-and-supply-chain.md) §1 is the
/// decision to generalise the invariant instead of holing it.
#[must_use]
pub fn remediation_gaps() -> Vec<MissingRemediation> {
    let mut gaps = Vec::new();
    for rule in all_rules() {
        let meta = rule.meta();
        let remediation: Remediation = rule.remediation();
        for profile in meta.surface.profiles() {
            if !remediation.covers_profile(&profile) {
                gaps.push(MissingRemediation {
                    rule: meta.id.to_string(),
                    surface: meta.surface,
                    profile: profile.as_str().to_owned(),
                });
            }
        }
    }
    gaps
}

/// Builds the coverage report from the compiled-in rules.
///
/// The model lives in `core` so that reporters can render it without depending
/// on this crate; the builder lives here because only this crate knows which
/// rules exist.
#[must_use]
pub fn coverage_report() -> CoverageReport {
    let metas = all_rule_metas();
    let table = owasp::coverage(&metas);
    let asi_table = taxonomy::coverage(&metas);

    let owasp_rows = table.iter().map(owasp_row).collect();
    let asi_rows = asi_table.iter().map(asi_row).collect();

    let gaps = remediation_gaps();
    let web_app_rules = rules_on(Surface::WebApp);
    let agent_rules = rules_on(Surface::AgentWorkspace);

    let frameworks = SUPPORTED_FRAMEWORKS
        .iter()
        .map(|framework| profile_row(&Profile::Framework(framework.clone()), web_app_rules, &gaps))
        .collect();
    let hosts = SUPPORTED_AGENT_HOSTS
        .iter()
        .map(|host| profile_row(&Profile::Host(host.clone()), agent_rules, &gaps))
        .collect();

    CoverageReport {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        categories_covered: owasp::covered_count(&table),
        asi_categories_covered: taxonomy::covered_count(&asi_table),
        asi_edition: taxonomy::ASI_EDITION.to_owned(),
        rule_count: metas.len(),
        web_app_rule_count: web_app_rules,
        agent_workspace_rule_count: agent_rules,
        owasp: owasp_rows,
        asi: asi_rows,
        frameworks,
        hosts,
        agent_paths: owlwarden_static::agentws::paths::allowlist_globs()
            .into_iter()
            .map(str::to_owned)
            .collect(),
    }
}

/// How many shipped rules read a given surface.
#[must_use]
pub fn rules_on(surface: Surface) -> usize {
    all_rule_metas()
        .iter()
        .filter(|meta| meta.surface == surface)
        .count()
}

fn owasp_row(entry: &CategoryCoverage) -> CategoryEntry {
    CategoryEntry {
        id: entry.category.id.to_owned(),
        title: entry.category.title.to_owned(),
        rules: entry
            .rules
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect(),
        reachability: entry.category.static_reachability.as_str().to_owned(),
        summary: entry.category.summary.to_owned(),
    }
}

fn asi_row(entry: &AsiCoverage) -> CategoryEntry {
    CategoryEntry {
        id: entry.category.id.to_owned(),
        title: entry.category.title.to_owned(),
        rules: entry
            .rules
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect(),
        reachability: entry.category.static_reachability.as_str().to_owned(),
        summary: entry.category.summary.to_owned(),
    }
}

/// One row of a profile table: how many of that surface's rules speak this
/// profile's dialect, and how many fall back.
///
/// The denominator is the rule count *for that surface*, not the whole
/// catalogue: reporting that Cursor has "14 rules falling back" because
/// `sql-injection` has no Cursor advice would be an invented gap.
fn profile_row(
    profile: &Profile,
    surface_rule_count: usize,
    gaps: &[MissingRemediation],
) -> FrameworkEntry {
    let falling_back = gaps
        .iter()
        .filter(|gap| gap.profile == profile.as_str() && gap.surface == profile.surface())
        .count();
    FrameworkEntry {
        id: profile.as_str().to_owned(),
        rules_with_specific_fix: surface_rule_count.saturating_sub(falling_back),
        rules_falling_back: falling_back,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use owlwarden_core::finding::{AgentHost, Framework};

    #[test]
    fn the_coverage_report_counts_what_is_actually_compiled_in() {
        let report = coverage_report();
        assert_eq!(report.rule_count, all_rules().len());
        assert_eq!(report.owasp.len(), 10, "all ten categories, gaps included");
        assert_eq!(
            report.asi.len(),
            10,
            "all ten ASI categories, gaps included"
        );
        assert_eq!(report.frameworks.len(), SUPPORTED_FRAMEWORKS.len());
        assert_eq!(report.hosts.len(), SUPPORTED_AGENT_HOSTS.len());
        assert_eq!(
            report.web_app_rule_count + report.agent_workspace_rule_count,
            report.rule_count,
            "every rule belongs to exactly one surface"
        );

        let counted: usize = report
            .owasp
            .iter()
            .filter(|entry| !entry.rules.is_empty())
            .count();
        assert_eq!(counted, report.categories_covered);

        for profile in report.frameworks.iter().chain(report.hosts.iter()) {
            assert_eq!(
                profile.rules_falling_back, 0,
                "{} has rules with only generic advice",
                profile.id
            );
        }
    }

    #[test]
    fn the_default_preset_exists_and_enables_rules() {
        let (file_rules, project_rules) = rules_for_preset(DEFAULT_PRESET);
        assert!(!file_rules.is_empty());
        assert!(!project_rules.is_empty());
    }

    #[test]
    fn deep_enables_everything() {
        let (file_rules, project_rules) = rules_for_preset("deep");
        assert_eq!(file_rules.len(), all_file_rules().len());
        assert_eq!(project_rules.len(), all_project_rules().len());
    }

    #[test]
    fn quick_leaves_out_the_heuristics() {
        let (quick, _) = rules_for_preset("quick");
        for rule in quick {
            assert!(
                rule.meta().max_confidence > Confidence::Possible,
                "{} tops out at Possible and does not belong in the default preset",
                rule.meta().id
            );
        }
    }

    #[test]
    fn owasp_top10_selects_exactly_the_mapped_rules() {
        // Preset membership is derived from metadata (including advisory-only
        // catalogue entries). Compare ids, not FileRule/ProjectRule counts —
        // `known-vulnerable-dependency` is catalogued but runs via `--osv`.
        let selected = preset_rule_ids("owasp-top10");
        let mut mapped: Vec<String> = all_rule_metas()
            .into_iter()
            .filter(|meta| meta.owasp.is_some())
            .map(|meta| meta.id.to_string())
            .collect();
        mapped.sort();
        assert_eq!(selected, mapped);
    }

    #[test]
    fn an_unknown_preset_enables_nothing_rather_than_guessing() {
        let (file_rules, project_rules) = rules_for_preset("owasp-top-ten");
        assert!(file_rules.is_empty());
        assert!(project_rules.is_empty());
    }

    #[test]
    fn rule_ids_are_valid_and_unique() {
        let metas = all_rule_metas();
        let mut ids: Vec<String> = metas.iter().map(|meta| meta.id.to_string()).collect();
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate rule id");

        for meta in &metas {
            assert!(
                owlwarden_core::finding::RuleId::parse(meta.id.as_str()).is_ok(),
                "rule id {:?} is not a valid id",
                meta.id
            );
            assert!(
                !meta.description.is_empty(),
                "{} has no description",
                meta.id
            );
            assert!(
                meta.owasp.is_some() || meta.cwe.is_some(),
                "{} maps to neither OWASP nor CWE",
                meta.id
            );
        }
    }

    #[test]
    fn every_owasp_reference_resolves_to_a_real_category() {
        // An unchecked category string produces a finding that links nowhere.
        for meta in all_rule_metas() {
            let Some(category) = &meta.owasp else {
                continue;
            };
            assert!(
                owasp::is_known(category),
                "{} references unknown OWASP category {category}",
                meta.id
            );
        }
    }

    #[test]
    fn every_rule_has_remediation_for_every_profile_of_its_own_surface() {
        let gaps = remediation_gaps();
        assert!(
            gaps.is_empty(),
            "rules missing profile-specific remediation: {gaps:?}"
        );
    }

    #[test]
    fn removing_one_remediation_cell_from_either_surface_is_caught() {
        // The invariant is only worth having if it fails. This proves the
        // matrix test is load-bearing on *both* profile sets rather than
        // silently passing on the one that has no rules yet
        // (ADR 0025 exit criterion 1).
        struct Holed {
            meta: DetectorMeta,
            remediation: Remediation,
        }
        impl RuleInfo for Holed {
            fn meta(&self) -> DetectorMeta {
                self.meta.clone()
            }
            fn remediation(&self) -> Remediation {
                self.remediation.clone()
            }
        }

        let mut web = Remediation::new("generic");
        for framework in SUPPORTED_FRAMEWORKS.iter().skip(1) {
            web = web.manual(framework.clone(), "s", "p");
        }
        let mut agent = Remediation::new("generic");
        for host in SUPPORTED_AGENT_HOSTS.iter().skip(1) {
            agent = agent.host(host.clone(), "s", "p");
        }

        for (surface, remediation, missing) in [
            (
                Surface::WebApp,
                web,
                SUPPORTED_FRAMEWORKS.first().map(Framework::as_str),
            ),
            (
                Surface::AgentWorkspace,
                agent,
                SUPPORTED_AGENT_HOSTS.first().map(AgentHost::as_str),
            ),
        ] {
            let rule = Holed {
                meta: DetectorMeta {
                    id: owlwarden_core::finding::RuleId::new_static("holed"),
                    title: "t".into(),
                    severity: owlwarden_core::finding::Severity::High,
                    max_confidence: Confidence::Likely,
                    owasp: None,
                    asi: None,
                    cwe: Some(1),
                    surface,
                    category: "c".into(),
                    description: "d".into(),
                },
                remediation,
            };
            let gaps: Vec<String> = rule
                .meta()
                .surface
                .profiles()
                .into_iter()
                .filter(|profile| !rule.remediation().covers_profile(profile))
                .map(|profile| profile.as_str().to_owned())
                .collect();
            assert_eq!(
                gaps.first().map(String::as_str),
                missing,
                "{surface} did not report its hole"
            );
        }
    }

    #[test]
    fn a_rule_is_never_checked_against_the_other_surfaces_profiles() {
        // Padding twelve identical framework strings onto an agent rule is what
        // ADR 0025 refused to do; this asserts nothing asks for them.
        for rule in all_rules() {
            let meta = rule.meta();
            let profiles = meta.surface.profiles();
            match meta.surface {
                Surface::WebApp => assert_eq!(profiles.len(), SUPPORTED_FRAMEWORKS.len()),
                Surface::AgentWorkspace => {
                    assert_eq!(profiles.len(), SUPPORTED_AGENT_HOSTS.len());
                }
            }
        }
    }

    #[test]
    fn the_agent_surface_preset_is_exactly_the_agent_rules() {
        let selected = preset_rule_ids("agent-surface");
        let mut expected: Vec<String> = all_rule_metas()
            .into_iter()
            .filter(|meta| meta.surface == Surface::AgentWorkspace)
            .map(|meta| meta.id.to_string())
            .collect();
        expected.sort();
        assert_eq!(selected, expected);
    }

    #[test]
    fn no_agent_surface_rule_claims_it_can_be_confirmed() {
        // ADR 0025 §6: `Confirmed` means corroborated against a running target.
        // There is no running target for a config file, and a second meaning for
        // the word would break the property the whole project sells.
        for meta in all_rule_metas() {
            if meta.surface == Surface::AgentWorkspace {
                assert!(
                    meta.max_confidence < Confidence::Confirmed,
                    "{} claims Confirmed on a surface that cannot reach it",
                    meta.id
                );
            }
        }
    }

    #[test]
    fn every_rule_offers_a_fallback_fix() {
        // A finding with no actionable fix is worse than no finding: an agent
        // told there is a problem and given nothing to do will invent
        // something.
        for rule in all_rules() {
            let fixes = rule.remediation().select(&Framework::GENERIC);
            assert!(
                !fixes.is_empty(),
                "{} has no framework-independent fix",
                rule.meta().id
            );
        }
    }

    #[test]
    fn explain_works_for_every_rule_without_a_central_registration() {
        for meta in all_rule_metas() {
            let explanation = explain(meta.id.as_str())
                .unwrap_or_else(|| panic!("{} has no explanation", meta.id));
            assert!(
                !explanation.fixes.is_empty(),
                "{} explains nothing actionable",
                meta.id
            );
            assert!(
                explanation.references.len() <= 3,
                "{} lists {} references; the cap is 3",
                meta.id,
                explanation.references.len()
            );
        }
        assert!(explain("no-such-rule").is_none());
    }

    #[test]
    fn the_coverage_table_reports_gaps_rather_than_hiding_them() {
        let table = owasp_coverage();
        assert_eq!(table.len(), 10, "every category is listed");
        assert!(
            table.iter().any(CategoryCoverage::is_covered),
            "no category is covered at all"
        );
        // This is not a target to raise by padding metadata. If it ever equals
        // 10, check that the rules earning each category are real.
        assert!(
            owasp::covered_count(&table) < 10,
            "ten of ten covered — verify this is genuine before updating the test"
        );
    }
}
