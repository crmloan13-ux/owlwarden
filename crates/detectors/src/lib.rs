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
//! [`framework_coverage`] fails the build when a rule is missing one.

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

pub mod build;
pub mod ci_unpinned_action;
pub mod cors;
pub mod csrf_cross_origin_post;
pub mod decorator;
pub mod hardcoded_secret;
pub mod insecure_cookie;
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
use owlwarden_core::finding::{Confidence, Framework};
use owlwarden_core::owasp::{self, CategoryCoverage};
use owlwarden_core::remediation::Remediation;
use owlwarden_static::rule::{FileRule, ProjectRule, RuleInfo};

pub use ci_unpinned_action::CiUnpinnedAction;
pub use cors::CorsPermissive;
pub use csrf_cross_origin_post::{
    CsrfCrossOriginPost, CsrfCrossOriginPostDetector, csrf_cross_origin_post_detector,
};
pub use hardcoded_secret::HardcodedSecret;
pub use insecure_cookie::InsecureCookie;
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

/// The frameworks every rule is expected to have remediation for.
///
/// Checked by [`framework_coverage`], which the test suite fails on. Without
/// it, adding Fastify would leave every existing rule quietly handing Fastify
/// users generic advice — technically correct, useless in practice, and
/// invisible until someone complained.
pub const SUPPORTED_FRAMEWORKS: &[Framework] = &[
    Framework::NEXT,
    Framework::NUXT,
    Framework::NEST,
    Framework::EXPRESS,
    Framework::FASTIFY,
    Framework::HONO,
    Framework::KOA,
    Framework::HAPI,
    Framework::SAILS,
    Framework::ASTRO,
    Framework::REMIX,
    Framework::GATSBY,
];

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

/// A rule that lacks remediation for a framework we claim to support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingRemediation {
    /// The rule with the gap.
    pub rule: String,
    /// The framework it has no specific advice for.
    pub framework: Framework,
}

/// Every (rule, framework) pair with no specific remediation.
///
/// Empty is the only acceptable answer, and a test enforces that. The reason it
/// is a function rather than only a test is that it is also worth printing:
/// `owlwarden coverage` shows it, so a contributor adding a framework can see
/// the work remaining rather than discovering it one CI failure at a time.
#[must_use]
pub fn framework_coverage() -> Vec<MissingRemediation> {
    let mut gaps = Vec::new();
    for rule in all_rules() {
        let remediation: Remediation = rule.remediation();
        for framework in SUPPORTED_FRAMEWORKS {
            if !remediation.covers(framework) {
                gaps.push(MissingRemediation {
                    rule: rule.meta().id.to_string(),
                    framework: framework.clone(),
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

    let owasp_rows = table
        .iter()
        .map(|entry| CategoryEntry {
            id: entry.category.id.to_owned(),
            title: entry.category.title.to_owned(),
            rules: entry
                .rules
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            reachability: entry.category.static_reachability.as_str().to_owned(),
            summary: entry.category.summary.to_owned(),
        })
        .collect();

    let gaps = framework_coverage();
    let frameworks = SUPPORTED_FRAMEWORKS
        .iter()
        .map(|framework| {
            let falling_back = gaps
                .iter()
                .filter(|gap| &gap.framework == framework)
                .count();
            FrameworkEntry {
                id: framework.as_str().to_owned(),
                rules_with_specific_fix: metas.len().saturating_sub(falling_back),
                rules_falling_back: falling_back,
            }
        })
        .collect();

    CoverageReport {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        categories_covered: owasp::covered_count(&table),
        rule_count: metas.len(),
        owasp: owasp_rows,
        frameworks,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_coverage_report_counts_what_is_actually_compiled_in() {
        let report = coverage_report();
        assert_eq!(report.rule_count, all_rules().len());
        assert_eq!(report.owasp.len(), 10, "all ten categories, gaps included");
        assert_eq!(report.frameworks.len(), SUPPORTED_FRAMEWORKS.len());

        let counted: usize = report
            .owasp
            .iter()
            .filter(|entry| !entry.rules.is_empty())
            .count();
        assert_eq!(counted, report.categories_covered);

        for framework in &report.frameworks {
            assert_eq!(
                framework.rules_falling_back, 0,
                "{} has rules with only generic advice",
                framework.id
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
    fn every_rule_has_remediation_for_every_supported_framework() {
        let gaps = framework_coverage();
        assert!(
            gaps.is_empty(),
            "rules missing framework-specific remediation: {gaps:?}"
        );
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
