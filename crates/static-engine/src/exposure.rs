//! Placing a finding on the request path, and deciding whether anything guards
//! it.
//!
//! The third axis from
//! [ADR 0029](../../../docs/adr/0029-exposure-model.md), computed here rather
//! than in each rule for the same reason the `runtime_scope` ceiling is applied
//! by the engine: twenty-five rules that had to remember it is twenty-five
//! chances to forget, and the failure mode of forgetting is a report that
//! reassures.
//!
//! # The one non-negotiable property
//!
//! **A finding is classified `authenticated` only when a gate is positively
//! identified. Absence of evidence yields `internet`.**
//!
//! Everything in this module is shaped by that sentence. A middleware module
//! that does not resolve is not a gate. A name that does not read as a gate is
//! not a gate. A session call whose result is never checked is not a gate. Each
//! of those could plausibly be treated as weak evidence *for* a gate; treating
//! them that way would mean the tool told a reader a route was behind auth
//! without having checked, which is the only new way 1.2 could make somebody
//! less safe.
//!
//! # What it costs
//!
//! Two bounded parse passes over files the scan would otherwise not open: the
//! framework's own middleware and bootstrap files, and the files that produced
//! findings. Both are capped, and the caps are here rather than in
//! `limits.rs` because they are properties of this pass rather than of the
//! scan.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use owlwarden_core::finding::{Exposure, ExposureEvidence, Finding, Location};
use owlwarden_core::source::SourceFile;

use crate::framework::auth::{self, AuthVocabulary};
use crate::framework::{FrameworkProfile, FrameworkSet};
use crate::project::Project;
use crate::unit::FileUnit;

mod facts;

pub use facts::{FileFacts, GateRef, RouteMount, collect_facts, collect_facts_in};

/// Middleware, bootstrap, and configuration files opened to look for gates.
///
/// A project declares a handful; the cap exists because `middleware_dirs` is a
/// directory walk and a repository can put a thousand files in one.
pub const MAX_GATE_FILES: usize = 64;

/// Files re-parsed to classify the findings in them.
///
/// Bounded by findings rather than by repository size: a scan with three
/// findings opens three files, and a scan at the findings cap opens this many.
pub const MAX_CLASSIFIED_FILES: usize = 256;

/// Path prefixes that are not a request path in any framework.
///
/// Conservative, and checked *after* route resolution — `app/api/scripts/route.ts`
/// is a route, and gets classified as one, before this list is ever consulted.
const INTERNAL_PREFIXES: &[&str] = &[
    "scripts/",
    "script/",
    "bin/",
    "tools/",
    "tooling/",
    "migrations/",
    "migration/",
    "db/migrations/",
    "db/migrate/",
    "prisma/migrations/",
    "prisma/seed",
    "drizzle/",
    "seeds/",
    "seed/",
    "jobs/",
    "queues/",
    "cron/",
    "workers/",
    "worker/",
    "src/workers/",
    "src/jobs/",
    "src/queues/",
    "src/scripts/",
    "src/migrations/",
    "test/",
    "tests/",
    "spec/",
    "e2e/",
    "__tests__/",
    "__mocks__/",
    "benchmarks/",
    "bench/",
    "fixtures/",
    "examples/",
    "example/",
    "docs/",
    "doc/",
];

/// File-name suffixes that are not a request path.
const INTERNAL_SUFFIXES: &[&str] = &[
    ".test.ts",
    ".test.tsx",
    ".test.js",
    ".test.mjs",
    ".spec.ts",
    ".spec.tsx",
    ".spec.js",
    ".spec.mjs",
    ".config.ts",
    ".config.js",
    ".config.mjs",
    ".config.cjs",
    ".d.ts",
    ".stories.tsx",
    ".stories.ts",
    ".worker.ts",
    ".worker.js",
    ".job.ts",
    ".job.js",
    ".seed.ts",
    ".seed.js",
];

/// Whole file names that are build tooling wherever they sit.
const INTERNAL_STEMS: &[&str] = &[
    "gulpfile",
    "gruntfile",
    "makefile",
    "webpack",
    "rollup",
    "esbuild",
    "tsup",
    "vite",
    "vitest",
    "jest",
    "playwright",
    "cypress",
];

/// One scan's answer to "can anything reach this?".
///
/// Built once per scan, after the rules have run and before the report is
/// assembled.
pub struct ExposureClassifier<'a> {
    project: &'a Project<'a>,
    frameworks: Arc<FrameworkSet>,
    /// Gates that cover every route the server serves.
    global: Option<GateRef>,
    /// Gates mounted on a path prefix, from files opened during the build pass.
    mounts: Vec<RouteMount>,
    /// Per-file facts, filled lazily as findings are classified.
    facts: BTreeMap<String, Option<FileFacts>>,
    /// Files opened so far, against [`MAX_CLASSIFIED_FILES`].
    opened: usize,
}

impl<'a> ExposureClassifier<'a> {
    /// Reads the project's declared middleware and bootstrap files and builds
    /// the gate map.
    ///
    /// Never fails: a middleware file that cannot be read or parsed contributes
    /// no gate, which classifies the routes it would have covered as
    /// `internet`. That is the loud direction, and it is the correct one — we
    /// did not see a gate.
    #[must_use]
    pub fn build(project: &'a Project<'a>) -> Self {
        let frameworks = Arc::clone(project.frameworks_arc());
        let mut classifier = Self {
            project,
            frameworks,
            global: None,
            mounts: Vec::new(),
            facts: BTreeMap::new(),
            opened: 0,
        };
        classifier.scan_gate_files();
        classifier
    }

    /// Classifies every finding in place.
    ///
    /// Agent-surface findings are left untouched: "is this reachable from a
    /// request" is not a question about a `settings.json`, and answering it
    /// with `unknown` would put every agent finding into the unclassified
    /// bucket and make that number meaningless.
    pub fn classify_all(&mut self, findings: &mut [Finding]) {
        for finding in findings.iter_mut() {
            if finding.context.host.is_some() {
                continue;
            }
            let (exposure, evidence) = self.classify(finding);
            finding.exposure = Some(exposure);
            finding.exposure_evidence = if evidence.is_empty() {
                None
            } else {
                Some(evidence)
            };
        }
    }

    /// The classification for one finding.
    #[must_use]
    pub fn classify(&mut self, finding: &Finding) -> (Exposure, ExposureEvidence) {
        let path = match &finding.location {
            Location::Source(location) => location.path.clone(),
            // A dynamic finding is an observation of a live endpoint. Nothing
            // static needs to establish reachability for something we reached.
            Location::Endpoint(location) => {
                return (
                    Exposure::Internet,
                    ExposureEvidence {
                        route: Some(location.url.clone()),
                        gate: None,
                        gate_location: None,
                        reason: Some("observed on a live endpoint".to_owned()),
                    },
                );
            }
        };

        let declared_route = finding
            .context
            .route
            .clone()
            .or_else(|| self.frameworks.route(&path).map(|route| route.path));

        let facts = self.facts_for(&path);
        let route = declared_route.or_else(|| {
            facts
                .as_ref()
                .and_then(|facts| facts.routes.first().cloned())
        });

        let on_request_path = route.is_some()
            || facts.as_ref().is_some_and(|facts| {
                !facts.routes.is_empty() || facts.declares_handler || facts.exports_fetch
            });

        if !on_request_path {
            return if is_internal_path(&path) {
                (
                    Exposure::Internal,
                    ExposureEvidence {
                        reason: Some("not on a request-handling path".to_owned()),
                        ..ExposureEvidence::default()
                    },
                )
            } else {
                (
                    Exposure::Unknown,
                    ExposureEvidence {
                        reason: Some(
                            "no route resolved for this file, and its path is not a recognised \
                             non-request location"
                                .to_owned(),
                        ),
                        ..ExposureEvidence::default()
                    },
                )
            };
        }

        if let Some(gate) = self.gate_for(&path, route.as_deref(), facts.as_ref()) {
            return (
                Exposure::Authenticated,
                ExposureEvidence {
                    route,
                    gate: Some(gate.name.clone()),
                    gate_location: Some(gate.location.clone()),
                    reason: Some(gate.reason.clone()),
                },
            );
        }

        (
            Exposure::Internet,
            ExposureEvidence {
                route,
                gate: None,
                gate_location: None,
                reason: Some("no authentication gate identified on this path".to_owned()),
            },
        )
    }

    /// The gate covering a file, if one was positively identified.
    fn gate_for(
        &self,
        path: &str,
        route: Option<&str>,
        facts: Option<&FileFacts>,
    ) -> Option<GateRef> {
        if let Some(global) = &self.global {
            return Some(global.clone());
        }
        if let Some(facts) = facts {
            if let Some(inline) = &facts.inline_gate {
                return Some(inline.clone());
            }
            // A mount declared in the same file covers the routes that file
            // registers: `router.use(requireAuth)` above the handlers is the
            // Express idiom, and it is the whole gate for that router.
            if let Some(gate) = facts
                .mounts
                .iter()
                .find(|mount| mount.covers(route))
                .and_then(|mount| mount.gate.clone())
            {
                return Some(gate);
            }
        }
        let _ = path;
        self.mounts
            .iter()
            .filter(|mount| mount.covers(route))
            .find_map(|mount| mount.gate.clone())
    }

    /// Facts for a file, parsing it at most once and at most
    /// [`MAX_CLASSIFIED_FILES`] times per scan.
    fn facts_for(&mut self, path: &str) -> Option<FileFacts> {
        if let Some(cached) = self.facts.get(path) {
            return cached.clone();
        }
        if self.opened >= MAX_CLASSIFIED_FILES {
            return None;
        }
        self.opened = self.opened.saturating_add(1);
        let facts = self.parse_facts(path);
        self.facts.insert(path.to_owned(), facts.clone());
        facts
    }

    /// Parses one file and extracts its exposure facts.
    fn parse_facts(&self, path: &str) -> Option<FileFacts> {
        let file = self
            .project
            .files()
            .iter()
            .find(|file| file.path.as_str() == path)?;
        self.facts_of_file(file)
    }

    fn facts_of_file(&self, file: &SourceFile) -> Option<FileFacts> {
        self.facts_of_file_in(file, false)
    }

    /// [`Self::facts_of_file`], told whether the file is declared middleware.
    fn facts_of_file_in(&self, file: &SourceFile, middleware: bool) -> Option<FileFacts> {
        let resolver = ModuleResolver::new(self.project);
        let profiles: Vec<&FrameworkProfile> = self.applicable_profiles();
        self.project
            .with_parsed_file(file, |unit: &FileUnit<'_>| {
                collect_facts_in(unit, &profiles, &resolver, middleware)
            })
            .ok()
    }

    /// Whether a path is on a framework's declared middleware list.
    fn is_middleware_path(&self, path: &str) -> bool {
        self.applicable_profiles().iter().any(|profile| {
            profile
                .auth
                .middleware_files
                .iter()
                .any(|candidate| candidate == path)
                || profile.auth.middleware_dirs.iter().any(|directory| {
                    path.starts_with(&format!("{}/", directory.trim_end_matches('/')))
                })
        })
    }

    /// The profiles whose vocabulary applies, falling back to the primary when
    /// nothing was detected.
    fn applicable_profiles(&self) -> Vec<&FrameworkProfile> {
        if self.frameworks.all().is_empty() {
            vec![self.frameworks.primary()]
        } else {
            self.frameworks
                .all()
                .iter()
                .map(std::convert::AsRef::as_ref)
                .collect()
        }
    }

    /// Opens the declared middleware, bootstrap, and configuration files and
    /// records what gates them.
    fn scan_gate_files(&mut self) {
        let candidates = self.gate_file_candidates();
        for path in candidates.iter().take(MAX_GATE_FILES) {
            let Some(file) = self
                .project
                .files()
                .iter()
                .find(|file| file.path.as_str() == path.as_str())
            else {
                continue;
            };
            let middleware = self.is_middleware_path(path);
            let Some(facts) = self.facts_of_file_in(file, middleware) else {
                continue;
            };
            if self.global.is_none() {
                self.global.clone_from(&facts.global_gate);
            }
            self.mounts.extend(facts.mounts.iter().cloned());
            if middleware {
                self.mounts.extend(middleware_mounts(path, &facts));
            }
            self.facts.insert(path.clone(), Some(facts));
        }
        // Order is by path, then by declaration, so two runs over the same tree
        // pick the same gate to name as evidence.
        self.mounts.sort_by(|left, right| {
            left.prefix
                .cmp(&right.prefix)
                .then_with(|| left.declared_at.cmp(&right.declared_at))
        });
    }

    /// Every file worth opening for a gate, deduplicated and in a stable order.
    fn gate_file_candidates(&self) -> Vec<String> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out: Vec<String> = Vec::new();
        let push = |path: String, out: &mut Vec<String>, seen: &mut BTreeSet<String>| {
            if seen.insert(path.clone()) {
                out.push(path);
            }
        };

        for profile in self.applicable_profiles() {
            for name in &profile.auth.middleware_files {
                push(name.clone(), &mut out, &mut seen);
            }
            for name in &profile.bootstrap_files {
                push(name.clone(), &mut out, &mut seen);
            }
            for name in &profile.config_files {
                push(name.clone(), &mut out, &mut seen);
            }
            for directory in &profile.auth.middleware_dirs {
                let prefix = format!("{}/", directory.trim_end_matches('/'));
                for file in self.project.files() {
                    if file.path.as_str().starts_with(&prefix) {
                        push(file.path.to_string(), &mut out, &mut seen);
                    }
                }
            }
        }
        out
    }
}

/// The mounts a middleware file contributes.
///
/// The file's position on the load path is the mount, so a gate named in it
/// covers whatever its matcher covers — everything, when there is no matcher.
///
/// A matcher that was present and yielded no prefix produces **no mount at
/// all**. That is the whole reason `matcher_parsed` exists: an unreadable
/// matcher means we do not know which routes the middleware runs on, and
/// guessing "all of them" would mark every route in the application as behind
/// auth on the strength of a file we failed to read.
fn middleware_mounts(path: &str, facts: &FileFacts) -> Vec<RouteMount> {
    if facts.declared_gates.is_empty() {
        return Vec::new();
    }
    let gate = facts.declared_gates.first().cloned();
    if facts.matcher_parsed {
        return facts
            .matcher_prefixes
            .iter()
            .map(|prefix| RouteMount {
                prefix: Some(prefix.clone()),
                gate: gate.clone(),
                declared_at: format!("{path}:1"),
            })
            .collect();
    }
    vec![RouteMount {
        prefix: None,
        gate,
        declared_at: format!("{path}:1"),
    }]
}

/// Whether a path is somewhere no request reaches.
///
/// Only consulted when route resolution has already failed, so a route that
/// happens to live under `/scripts/` is never caught by it.
#[must_use]
pub fn is_internal_path(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    // A finding in a manifest, a lockfile, or a workflow is not in code a
    // request reaches — it is in the build. Deciding this by extension rather
    // than by path keeps it true wherever the file sits.
    let extension = lowered.rsplit_once('.').map_or("", |(_, ext)| ext);
    if !crate::SUPPORTED_EXTENSIONS.contains(&extension) {
        return true;
    }
    if INTERNAL_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
    {
        return true;
    }
    // The same directories one level down, which is where a monorepo puts them.
    if INTERNAL_PREFIXES.iter().any(|prefix| {
        let needle = format!("/{prefix}");
        lowered.contains(&needle)
    }) {
        return true;
    }
    if INTERNAL_SUFFIXES
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
    {
        return true;
    }
    let stem = lowered
        .rsplit('/')
        .next()
        .unwrap_or(&lowered)
        .split('.')
        .next()
        .unwrap_or_default();
    INTERNAL_STEMS.contains(&stem)
}

/// Resolves a module specifier against the files the scan actually walked.
///
/// The load-bearing half of "a local module that cannot be resolved is not a
/// gate". Without it, `import { requireAuth } from './middleware/auth'` would
/// gate a route whether or not that file exists — which means a deleted or
/// renamed middleware would leave every route it used to guard reported as
/// safe.
pub struct ModuleResolver {
    paths: BTreeSet<String>,
}

impl ModuleResolver {
    /// Indexes the project's file list.
    #[must_use]
    pub fn new(project: &Project<'_>) -> Self {
        Self {
            paths: project
                .files()
                .iter()
                .map(|file| file.path.to_string())
                .collect(),
        }
    }

    /// Whether a relative specifier, imported from `from`, names a file that
    /// exists.
    ///
    /// Tries the extensions the ecosystem resolves, plus the `index.*` form.
    /// Alias prefixes (`@/`, `~/`, `#`) are resolved against the project root
    /// and `src/`, which covers the two conventions `tsconfig` paths almost
    /// always encode; an alias pointing anywhere else does not resolve, and the
    /// route stays `internet`.
    #[must_use]
    pub fn resolves(&self, from: &str, specifier: &str) -> bool {
        for base in Self::candidate_bases(from, specifier) {
            if self.paths.contains(&base) {
                return true;
            }
            for extension in ["ts", "tsx", "js", "jsx", "mjs", "cjs"] {
                if self.paths.contains(&format!("{base}.{extension}"))
                    || self.paths.contains(&format!("{base}/index.{extension}"))
                {
                    return true;
                }
            }
        }
        false
    }

    fn candidate_bases(from: &str, specifier: &str) -> Vec<String> {
        let trimmed = specifier.trim_end_matches('/');
        if let Some(rest) = trimmed
            .strip_prefix("@/")
            .or_else(|| trimmed.strip_prefix("~/"))
            .or_else(|| trimmed.strip_prefix("#/"))
        {
            return vec![rest.to_owned(), format!("src/{rest}")];
        }
        if trimmed.starts_with("./") || trimmed.starts_with("../") {
            let directory = from.rsplit_once('/').map_or("", |(head, _)| head);
            return normalise(directory, trimmed).into_iter().collect();
        }
        if trimmed.starts_with("src/") {
            return vec![trimmed.to_owned()];
        }
        Vec::new()
    }
}

/// Joins a relative specifier onto a directory, resolving `.` and `..`.
///
/// Returns `None` when the specifier climbs above the project root: a path that
/// escapes the tree cannot name a file we walked, and treating it as resolvable
/// would let `../../../../etc/auth` count as a gate.
fn normalise(directory: &str, specifier: &str) -> Option<String> {
    let mut segments: Vec<&str> = if directory.is_empty() {
        Vec::new()
    } else {
        directory.split('/').collect()
    };
    for segment in specifier.split('/').take(64) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    if segments.is_empty() {
        return None;
    }
    Some(segments.join("/"))
}

/// Whether an identifier bound to `specifier` is a gate.
///
/// Three ways to be one, and every one of them is a positive identification:
/// the module is a known auth package, the module resolves inside the project
/// *and* the name reads as a gate, or the name is one of the exports that is a
/// gate wherever it comes from.
#[must_use]
pub fn imported_name_is_gate(
    resolver: &ModuleResolver,
    from: &str,
    name: &str,
    specifier: &str,
) -> bool {
    if auth::is_auth_package(specifier) {
        return true;
    }
    if auth::is_relative_specifier(specifier) {
        return resolver.resolves(from, specifier)
            && (auth::is_gate_name(name) || module_reads_as_auth(specifier));
    }
    // A bare specifier that is not a known auth package is a third-party
    // package we have no opinion about. Silence, which classifies as
    // `internet`.
    false
}

/// Whether a module path itself announces that it holds authentication.
fn module_reads_as_auth(specifier: &str) -> bool {
    specifier
        .rsplit('/')
        .take(2)
        .any(|segment| auth::is_gate_name(segment.trim_end_matches(".ts")))
}

/// A framework's auth vocabulary, or the empty one.
#[must_use]
pub fn vocabulary(profile: &FrameworkProfile) -> &AuthVocabulary {
    &profile.auth
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn internal_paths_are_the_ones_no_request_reaches() {
        for path in [
            "scripts/seed.ts",
            "packages/api/scripts/migrate.ts",
            "prisma/migrations/001_init/migration.ts",
            "src/jobs/nightly.ts",
            "next.config.js",
            "vitest.config.ts",
            "app/lib/user.test.ts",
            "src/queue.worker.ts",
            "package.json",
            ".github/workflows/ci.yml",
            "pnpm-lock.yaml",
        ] {
            assert!(is_internal_path(path), "{path} should be internal");
        }
    }

    #[test]
    fn ordinary_source_is_not_internal_it_is_unclassified() {
        // The difference matters: `internal` is a claim that nothing reaches
        // it, and we have no basis for that claim about a library file.
        for path in [
            "src/lib/db.ts",
            "app/api/users/route.ts",
            "src/routes/admin.ts",
            "middleware.ts",
        ] {
            assert!(
                !is_internal_path(path),
                "{path} must not claim to be internal"
            );
        }
    }

    #[test]
    fn a_relative_specifier_cannot_escape_the_tree() {
        assert_eq!(
            normalise("src/routes", "../middleware/auth"),
            Some("src/middleware/auth".to_owned())
        );
        assert_eq!(normalise("src", "../../etc/passwd"), None);
        assert_eq!(normalise("", "../auth"), None);
    }
}
