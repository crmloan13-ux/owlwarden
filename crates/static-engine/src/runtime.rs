//! Working out where a file runs.
//!
//! # Evidence, in order
//!
//! 1. **An explicit declaration.** `wrangler.toml`, `deno.json`, `bunfig.toml`,
//!    a `runtime` export in a route, a Nitro preset, a framework adapter in the
//!    config.
//! 2. **The lockfile and `engines`.**
//! 3. **The framework default.**
//!
//! The source travels with the answer, because a fix chosen from an inferred
//! runtime should say what it inferred. A finding whose fix depends on the
//! runtime and whose runtime came from a default says `defaulted` in one word,
//! and that word must not be droppable in quiet modes
//! ([ADR 0031](../../../docs/adr/0031-runtime-overlay.md) §1).
//!
//! # Per file, not per project
//!
//! Mixed-runtime repositories are normal: a Next application with three edge
//! routes, a monorepo with a Workers API next to a Node worker. So resolution
//! walks *upward* from the file to the nearest evidence, and a project-level
//! answer is only the last one found.
//!
//! That is more work than a single project-level lookup, so the project-wide
//! evidence is gathered once and the per-file part is a cache lookup plus a
//! prefix walk. A repository whose files all sit under one declaration pays for
//! one read.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use owlwarden_core::runtime::{Runtime, RuntimeSource};
use owlwarden_core::source::{FileSelector, SourceProvider};

use crate::framework::FrameworkSet;

/// Declaration files opened in one scan.
///
/// A monorepo can hold one `wrangler.toml` per package, which is exactly the
/// case per-file resolution exists for; past this the answer is not getting
/// more accurate and the walk is getting longer.
pub const MAX_DECLARATIONS: usize = 64;

/// Largest declaration file read. These are configuration, not data.
pub const MAX_DECLARATION_BYTES: u64 = 256 * 1024;

/// What a file runs on, and how we know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRuntime {
    /// The runtime.
    pub runtime: Runtime,
    /// Where the answer came from.
    pub source: RuntimeSource,
}

impl ResolvedRuntime {
    /// A framework default, which is an inference and says so.
    #[must_use]
    pub const fn defaulted(runtime: Runtime) -> Self {
        Self {
            runtime,
            source: RuntimeSource::Default,
        }
    }
}

/// File names that declare a runtime outright, and what they declare.
///
/// A closed list rather than a pattern: each entry is a file whose *presence*
/// is the declaration, and a heuristic that guessed from a name would resolve
/// `deno-lint-config.json` to Deno.
const DECLARATIONS: &[(&str, Runtime)] = &[
    ("wrangler.toml", Runtime::WebWorker),
    ("wrangler.json", Runtime::WebWorker),
    ("wrangler.jsonc", Runtime::WebWorker),
    ("deno.json", Runtime::Deno),
    ("deno.jsonc", Runtime::Deno),
    ("bunfig.toml", Runtime::Bun),
];

/// Lockfiles that imply a runtime.
///
/// Weaker evidence than a declaration and stronger than a default: `bun.lockb`
/// means the developer installs with Bun, which usually but not always means
/// they run with it.
const LOCKFILES: &[(&str, Runtime)] = &[
    ("bun.lockb", Runtime::Bun),
    ("bun.lock", Runtime::Bun),
    ("deno.lock", Runtime::Deno),
];

/// The runtime of every file in one project.
pub struct RuntimeMap {
    /// Directory prefix → what it declares. Longest prefix wins.
    declarations: Vec<(String, ResolvedRuntime)>,
    /// Files with an in-file declaration, e.g. `export const runtime = 'edge'`.
    ///
    /// Filled as files are parsed rather than up front: the declaration is in
    /// the source, and reading every file twice to find it would put a second
    /// pass over the tree on the cold-scan budget this overlay has to stay
    /// inside. A `Mutex` because the engine records into it from `&self`, and a
    /// poisoned lock costs the override rather than the scan.
    per_file: Mutex<BTreeMap<String, ResolvedRuntime>>,
    /// The project-wide fallback.
    fallback: ResolvedRuntime,
}

impl RuntimeMap {
    /// Reads a project's runtime evidence.
    ///
    /// Never fails: a declaration file that cannot be read contributes nothing,
    /// which leaves the framework default in force. That is the right direction
    /// — the default is disclosed as an inference, and a scan that refused to
    /// advise because it could not read a `wrangler.toml` would be worse than
    /// one that advised and said so.
    #[must_use]
    pub fn build(source: &dyn SourceProvider, frameworks: &FrameworkSet) -> Self {
        let fallback = ResolvedRuntime::defaulted(frameworks.primary().default_runtime());
        let mut map = Self {
            declarations: Vec::new(),
            per_file: Mutex::new(BTreeMap::new()),
            fallback,
        };
        map.read_declarations(source);
        map.read_lockfiles(source);
        // Longest prefix first, so a package's own declaration beats the
        // repository root's.
        map.declarations
            .sort_by(|left, right| right.0.len().cmp(&left.0.len()).then(left.0.cmp(&right.0)));
        map
    }

    /// A map with no evidence at all, for tests and single-file entry points.
    #[must_use]
    pub fn defaulted(runtime: Runtime) -> Self {
        Self {
            declarations: Vec::new(),
            per_file: Mutex::new(BTreeMap::new()),
            fallback: ResolvedRuntime::defaulted(runtime),
        }
    }

    /// Records that one file declares its own runtime.
    ///
    /// Next's `export const runtime = 'edge'` is per route, not per project,
    /// and it is the single most common way a mixed-runtime repository comes
    /// about.
    pub fn declare_file(&self, path: &str, runtime: Runtime) {
        let Ok(mut per_file) = self.per_file.lock() else {
            return;
        };
        if per_file.len() < MAX_DECLARATIONS {
            per_file.insert(
                path.to_owned(),
                ResolvedRuntime {
                    runtime,
                    source: RuntimeSource::Declared,
                },
            );
        }
    }

    /// The runtime of one project-relative path.
    #[must_use]
    pub fn for_path(&self, path: &str) -> ResolvedRuntime {
        if let Ok(per_file) = self.per_file.lock()
            && let Some(resolved) = per_file.get(path)
        {
            return *resolved;
        }
        // Nearest evidence upward: the deepest declaration whose directory is a
        // prefix of this path.
        for (prefix, resolved) in &self.declarations {
            if prefix.is_empty() || path.starts_with(prefix.as_str()) {
                return *resolved;
            }
        }
        self.fallback
    }

    /// The project-wide answer, for the report header.
    #[must_use]
    pub fn project(&self) -> ResolvedRuntime {
        // The shallowest declaration, which is the one that covers most files.
        self.declarations
            .last()
            .map_or(self.fallback, |(_, resolved)| *resolved)
    }

    fn read_declarations(&mut self, source: &dyn SourceProvider) {
        let globs: Vec<String> = DECLARATIONS
            .iter()
            .flat_map(|(name, _)| [(*name).to_owned(), format!("**/{name}")])
            .collect();
        let Ok(files) = source.files(&FileSelector::include(globs)) else {
            return;
        };
        for file in files.iter().take(MAX_DECLARATIONS) {
            let path = file.path.as_str();
            let name = path.rsplit('/').next().unwrap_or(path);
            let Some((_, runtime)) = DECLARATIONS
                .iter()
                .find(|(candidate, _)| *candidate == name)
            else {
                continue;
            };
            self.declarations.push((
                directory_prefix(path),
                ResolvedRuntime {
                    runtime: *runtime,
                    source: RuntimeSource::Declared,
                },
            ));
        }
    }

    fn read_lockfiles(&mut self, source: &dyn SourceProvider) {
        let globs: Vec<String> = LOCKFILES
            .iter()
            .flat_map(|(name, _)| [(*name).to_owned(), format!("**/{name}")])
            .collect();
        let Ok(files) = source.files(&FileSelector::include(globs)) else {
            return;
        };
        for file in files.iter().take(MAX_DECLARATIONS) {
            let path = file.path.as_str();
            let name = path.rsplit('/').next().unwrap_or(path);
            let Some((_, runtime)) = LOCKFILES.iter().find(|(candidate, _)| *candidate == name)
            else {
                continue;
            };
            let prefix = directory_prefix(path);
            // A declaration at the same level is stronger evidence and stays.
            if self.declarations.iter().any(|(existing, resolved)| {
                *existing == prefix && resolved.source == RuntimeSource::Declared
            }) {
                continue;
            }
            self.declarations.push((
                prefix,
                ResolvedRuntime {
                    runtime: *runtime,
                    source: RuntimeSource::Lockfile,
                },
            ));
        }
    }
}

/// The directory a project-relative file sits in, with a trailing slash.
///
/// The empty string for a root-level file, which then matches every path — a
/// declaration at the repository root covers the repository.
fn directory_prefix(path: &str) -> String {
    path.rsplit_once('/')
        .map_or_else(String::new, |(head, _)| format!("{head}/"))
}

/// Bytes of a source file scanned for an in-file runtime declaration.
///
/// The declaration is a top-level export, so it is near the top of the file by
/// convention and by the language's own hoisting rules for readability. A cap
/// keeps this off the cold-scan budget on a generated 40 MB bundle.
const MAX_SOURCE_SCAN_BYTES: usize = 8 * 1024;

/// The runtime a source file declares for itself, if it declares one.
///
/// `export const runtime = 'edge'` — Next's per-route declaration, and the
/// single most common way a mixed-runtime repository comes about.
///
/// # Why this is a line scan and not an AST walk
///
/// The declaration is a top-level `export const` with a string literal, and the
/// question is asked *before* the file is parsed, because the answer decides
/// which remediation the rules attach as they run. Parsing twice to learn one
/// string would put a second parse of every file on the cold-scan budget, which
/// is the budget this whole overlay has to stay inside.
///
/// The scan is correspondingly strict: the line must begin with `export`, must
/// name `runtime` as the binding, and must assign a quoted value this engine
/// recognises. A commented-out line does not match, because a `//` prefix is
/// refused. Anything it does not understand yields `None`, which leaves the
/// directory-level answer in force.
#[must_use]
pub fn declared_in_source(text: &str) -> Option<Runtime> {
    let window = text.get(..text.len().min(MAX_SOURCE_SCAN_BYTES))?;
    // Every failure below is a `continue`, never an early return: a line this
    // does not understand must not stop the scan, or one `export default` above
    // the declaration would hide it.
    window
        .lines()
        .take(512)
        .find_map(|line| runtime_from_export(line.trim_start()))
}

/// The runtime one already-trimmed line declares, if it declares one.
fn runtime_from_export(line: &str) -> Option<Runtime> {
    if line.starts_with("//") {
        return None;
    }
    let rest = line.strip_prefix("export")?.trim_start();
    let rest = rest
        .strip_prefix("const")
        .or_else(|| rest.strip_prefix("let"))
        .or_else(|| rest.strip_prefix("var"))?
        .trim_start();
    let rest = rest.strip_prefix("runtime")?;
    // `runtimeConfig` is a different export in more than one framework, so the
    // binding has to *end* here.
    if rest
        .chars()
        .next()
        .is_some_and(|next| next.is_alphanumeric() || next == '_' || next == '$')
    {
        return None;
    }
    // Skip an optional type annotation: `export const runtime: Runtime = 'edge'`.
    let (_, assigned) = rest.split_once('=')?;
    // `==` is a comparison, not a declaration.
    let assigned = assigned.strip_prefix('=').map_or(assigned, |_| "");
    let value = assigned.trim().trim_start_matches(['\'', '"', '`']);
    let value = value
        .split(['\'', '"', '`', ';'])
        .next()
        .unwrap_or_default()
        .trim();
    Runtime::from_str_opt(value)
}

/// Whether a path is a runtime declaration file, for the incremental watcher.
#[must_use]
pub fn is_declaration(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    DECLARATIONS.iter().any(|(candidate, _)| *candidate == name)
        || LOCKFILES.iter().any(|(candidate, _)| *candidate == name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn map_of(declarations: &[(&str, Runtime, RuntimeSource)], fallback: Runtime) -> RuntimeMap {
        let mut map = RuntimeMap::defaulted(fallback);
        for (prefix, runtime, source) in declarations {
            map.declarations.push((
                (*prefix).to_owned(),
                ResolvedRuntime {
                    runtime: *runtime,
                    source: *source,
                },
            ));
        }
        map.declarations
            .sort_by(|left, right| right.0.len().cmp(&left.0.len()).then(left.0.cmp(&right.0)));
        map
    }

    #[test]
    fn the_deepest_declaration_wins() {
        // The monorepo case: a Workers API next to a Node worker, each with its
        // own declaration, under a repository root that has none.
        let map = map_of(
            &[
                ("apps/api/", Runtime::WebWorker, RuntimeSource::Declared),
                ("apps/jobs/", Runtime::Node, RuntimeSource::Declared),
            ],
            Runtime::Node,
        );
        assert_eq!(
            map.for_path("apps/api/src/index.ts").runtime,
            Runtime::WebWorker
        );
        assert_eq!(map.for_path("apps/jobs/src/run.ts").runtime, Runtime::Node);
        // Outside both, the fallback — and it says it was inferred.
        let elsewhere = map.for_path("packages/shared/util.ts");
        assert_eq!(elsewhere.runtime, Runtime::Node);
        assert!(elsewhere.source.is_inferred());
    }

    #[test]
    fn a_root_declaration_covers_the_repository() {
        let map = map_of(
            &[("", Runtime::Deno, RuntimeSource::Declared)],
            Runtime::Node,
        );
        assert_eq!(
            map.for_path("src/deep/nested/file.ts").runtime,
            Runtime::Deno
        );
        assert!(!map.for_path("src/x.ts").source.is_inferred());
    }

    #[test]
    fn a_per_file_declaration_beats_every_directory_one() {
        // `export const runtime = 'edge'` on one route of a Node application is
        // the most common way a mixed-runtime repository comes about, and a
        // directory-level answer would be wrong for exactly that route.
        let map = map_of(
            &[("", Runtime::Node, RuntimeSource::Declared)],
            Runtime::Node,
        );
        map.declare_file("app/api/edge/route.ts", Runtime::WebWorker);
        assert_eq!(
            map.for_path("app/api/edge/route.ts").runtime,
            Runtime::WebWorker
        );
        assert_eq!(
            map.for_path("app/api/other/route.ts").runtime,
            Runtime::Node
        );
    }

    #[test]
    fn a_default_is_reported_as_inferred_and_a_declaration_is_not() {
        let bare = RuntimeMap::defaulted(Runtime::Node);
        assert!(bare.for_path("src/x.ts").source.is_inferred());
        assert_eq!(bare.project().source, RuntimeSource::Default);

        let declared = map_of(
            &[("", Runtime::Bun, RuntimeSource::Declared)],
            Runtime::Node,
        );
        assert!(!declared.project().source.is_inferred());
    }

    #[test]
    fn a_lockfile_is_evidence_but_not_a_declaration() {
        let map = map_of(
            &[("", Runtime::Bun, RuntimeSource::Lockfile)],
            Runtime::Node,
        );
        assert_eq!(map.for_path("src/x.ts").runtime, Runtime::Bun);
        assert_eq!(map.for_path("src/x.ts").source, RuntimeSource::Lockfile);
        assert!(!map.for_path("src/x.ts").source.is_inferred());
    }

    #[test]
    fn per_file_declarations_are_bounded() {
        let map = RuntimeMap::defaulted(Runtime::Node);
        for index in 0..(MAX_DECLARATIONS * 4) {
            map.declare_file(&format!("app/api/{index}/route.ts"), Runtime::WebWorker);
        }
        assert!(map.per_file.lock().unwrap().len() <= MAX_DECLARATIONS);
    }

    #[test]
    fn an_in_file_runtime_export_is_read_and_a_lookalike_is_not() {
        assert_eq!(
            declared_in_source("export const runtime = 'edge'\n"),
            Some(Runtime::WebWorker)
        );
        assert_eq!(
            declared_in_source("export const runtime = \"nodejs\";\n"),
            Some(Runtime::Node)
        );
        assert_eq!(
            declared_in_source("export const runtime: Runtime = 'edge'\n"),
            Some(Runtime::WebWorker)
        );

        // A commented-out declaration is not a declaration.
        assert_eq!(
            declared_in_source("// export const runtime = 'edge'\n"),
            None
        );
        // A different export that happens to start the same way.
        assert_eq!(
            declared_in_source("export const runtimeConfig = { public: {} }\n"),
            None
        );
        // A value this engine does not know leaves the directory answer alone
        // rather than defaulting to Node.
        assert_eq!(
            declared_in_source("export const runtime = 'wasmer'\n"),
            None
        );
        assert_eq!(declared_in_source("const runtime = 'edge'\n"), None);
    }

    #[test]
    fn the_source_scan_is_bounded() {
        // The input is a file in a repository nobody vetted, and this runs
        // before parsing on every file the engine opens.
        let padded = format!("{}export const runtime = 'edge'\n", " ".repeat(64 * 1024));
        assert_eq!(declared_in_source(&padded), None);
        let deep = "\n".repeat(1_000_000);
        assert_eq!(declared_in_source(&deep), None);
    }

    #[test]
    fn a_declaration_file_is_recognised_by_name_only() {
        assert!(is_declaration(Path::new("apps/api/wrangler.toml")));
        assert!(is_declaration(Path::new("deno.json")));
        assert!(is_declaration(Path::new("bun.lockb")));
        // A heuristic on the name would resolve this to Deno, and it is a lint
        // configuration.
        assert!(!is_declaration(Path::new("deno-lint-config.json")));
        assert!(!is_declaration(Path::new("src/wrangler.ts")));
    }
}
