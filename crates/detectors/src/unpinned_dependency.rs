//! `unpinned-dependency` — a package.json range that accepts anything.
//!
//! # What this is, and what it is not
//!
//! A06 (Vulnerable and Outdated Components) needs an advisory database for
//! known CVEs — that is `known-vulnerable-dependency` behind `--osv`
//! (ADR 0016). This rule answers the offline half: a dependency whose range is
//! literally `"*"` or `"latest"`, so every install can pull a different major
//! version with no review.
//!
//! `^1.2.3` and `~1.2.3` are deliberate choices and stay silent. Flagging every
//! caret range would drown a Node project in noise on day one.

use owlwarden_core::detector::{DetectorError, DetectorMeta};
use owlwarden_core::finding::{
    Confidence, Finding, FindingContext, Framework, Location, OwaspRef, Reference, RuleId,
    Severity, SourceLocation,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::FileSelector;
use owlwarden_core::surface::Surface;
use owlwarden_static::project::Project;
use owlwarden_static::rule::{FindingSink, ProjectRule, RuleInfo};

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "unpinned-dependency";

/// Ranges that mean "whatever is newest when I install".
const UNPINNED: &[&str] = &["*", "latest", "x", "X"];

/// Cap findings so a malicious package.json cannot inflate the report.
const MAX_FINDINGS: usize = 32;
/// Cap on package name + range kept in evidence.
const MAX_EVIDENCE_CHARS: usize = 160;

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnpinnedDependency;

impl UnpinnedDependency {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Dependency version is unpinned".into(),
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A06:2021")),
            asi: None,
            cwe: Some(1104),
            surface: Surface::WebApp,
            category: "dependencies".into(),
            description: "A package.json dependency uses '*' or 'latest', so every install can \
                          pull a different major version with no review. Pin a lower bound (or \
                          an exact version) so upgrades are a deliberate change."
                .into(),
        }
    }
}

impl RuleInfo for UnpinnedDependency {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl ProjectRule for UnpinnedDependency {
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink) -> Result<(), DetectorError> {
        // `package.json` is not in the engine's JS/TS file list (it is not
        // source), so we ask the provider for it directly — the same way the
        // project loads the manifest at discovery time.
        let Ok(files) = project
            .source()
            .files(&FileSelector::include(["package.json".to_owned()]))
        else {
            return Ok(());
        };
        let Some(manifest_file) = files
            .iter()
            .find(|file| file.path.as_str() == "package.json")
        else {
            return Ok(());
        };
        let text = project.source().read(manifest_file).map_err(|error| {
            DetectorError::Other(format!("could not read package.json: {error}"))
        })?;

        let mut emitted = 0usize;
        for (name, range) in &project.manifest().dependencies {
            if emitted >= MAX_FINDINGS {
                break;
            }
            let trimmed = range.trim();
            if !UNPINNED.contains(&trimmed) {
                continue;
            }
            let line = line_containing(&text, name).unwrap_or(1);
            if !sink.push(build_finding(project.framework(), name, trimmed, line)) {
                break;
            }
            emitted = emitted.saturating_add(1);
        }
        Ok(())
    }
}

fn build_finding(framework: &Framework, name: &str, range: &str, line: u32) -> Finding {
    let meta = UnpinnedDependency::meta();
    finding_builder(&meta)
        .confidence(Confidence::Likely)
        .why(
            "An unpinned range lets the next install resolve a different major version, \
             including one with a known vulnerability or a breaking API change, without \
             anyone reviewing the bump.",
        )
        .location(Location::Source(SourceLocation {
            path: "package.json".to_owned(),
            line,
            col: 1,
        }))
        .context(FindingContext {
            framework: Some(framework.clone()),
            host: None,
            route: None,
            method: None,
            evidence: Some(truncate_evidence(&format!("{name}: {range}"))),
        })
        .fixes(remediation().select(framework))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

fn line_containing(source: &str, needle: &str) -> Option<u32> {
    for (index, line) in source.lines().enumerate().take(10_000) {
        if line.contains(needle) {
            return Some(u32::try_from(index + 1).unwrap_or(1));
        }
    }
    None
}

fn truncate_evidence(value: &str) -> String {
    let mut out = String::new();
    for (count, ch) in value.chars().enumerate() {
        if count >= MAX_EVIDENCE_CHARS {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

fn remediation() -> Remediation {
    Remediation::new(
        "Replace '*' or 'latest' with a lower-bounded range (or an exact version), then \
         regenerate the lockfile.",
    )
    .manual(
        Framework::NEXT,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"next\": \"^14.2.0\"\n  }\n}",
    )
    .manual(
        Framework::NUXT,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"nuxt\": \"^3.12.0\"\n  }\n}",
    )
    .manual(
        Framework::NEST,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"@nestjs/core\": \"^10.0.0\"\n  }\n}",
    )
    .manual(
        Framework::EXPRESS,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"express\": \"^4.19.0\"\n  }\n}",
    )
    .manual(
        Framework::FASTIFY,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"fastify\": \"^4.28.0\"\n  }\n}",
    )
    .manual(
        Framework::HONO,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"hono\": \"^4.5.0\"\n  }\n}",
    )
    .manual(
        Framework::KOA,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"koa\": \"^2.15.0\"\n  }\n}",
    )
    .manual(
        Framework::HAPI,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"@hapi/hapi\": \"^21.3.0\"\n  }\n}",
    )
    .manual(
        Framework::SAILS,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"sails\": \"^1.5.0\"\n  }\n}",
    )
    .manual(
        Framework::ASTRO,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"astro\": \"^4.11.0\"\n  }\n}",
    )
    .manual(
        Framework::REMIX,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"@remix-run/node\": \"^2.10.0\"\n  }\n}",
    )
    .manual(
        Framework::GATSBY,
        "Pin the dependency in package.json and reinstall so the lockfile records it.",
        "{\n  \"dependencies\": {\n    \"gatsby\": \"^5.13.0\"\n  }\n}",
    )
    .manual(
        Framework::SVELTEKIT,
        "Pin the range in package.json and commit the lockfile.",
        "{\n  \"dependencies\": {\n    \"@sveltejs/kit\": \"^2.5.0\"\n  }\n}",
    )
    .manual(
        Framework::TANSTACK_START,
        "Pin the range in package.json and commit the lockfile.",
        "{\n  \"dependencies\": {\n    \"@tanstack/start\": \"^1.0.0\"\n  }\n}",
    )
    .manual(
        Framework::SOLIDSTART,
        "Pin the range in package.json and commit the lockfile.",
        "{\n  \"dependencies\": {\n    \"@solidjs/start\": \"^1.0.0\"\n  }\n}",
    )
    .manual(
        Framework::ELYSIA,
        "Pin the range in package.json and commit bun.lockb.",
        "{\n  \"dependencies\": {\n    \"elysia\": \"^1.1.0\"\n  }\n}",
    )
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_literal_wildcards_count_as_unpinned() {
        assert!(UNPINNED.contains(&"*"));
        assert!(UNPINNED.contains(&"latest"));
        // Deliberate ranges and pnpm workspace protocol stay silent — flagging
        // them would drown a monorepo on day one.
        assert!(!UNPINNED.contains(&"^14.2.0"));
        assert!(!UNPINNED.contains(&"~1.0.0"));
        assert!(!UNPINNED.contains(&"workspace:*"));
        assert!(!UNPINNED.contains(&"1.2.3"));
    }
}
