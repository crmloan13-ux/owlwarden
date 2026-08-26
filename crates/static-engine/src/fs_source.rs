//! `FsSourceProvider` — the filesystem adapter for
//! [`SourceProvider`](owlwarden_core::SourceProvider).
//!
//! This is a sandbox boundary, so it is written like one:
//!
//! - The root is canonicalized once at construction. Every path is
//!   re-canonicalized and checked against it before being read, so a symlink
//!   pointing at `~/.ssh/id_rsa` yields an error, not a code frame containing
//!   someone's private key. The open itself uses `O_NOFOLLOW` (Unix) so a
//!   TOCTOU swap to a symlink after the check cannot be followed.
//! - The walker does not follow symlinks and does not descend past
//!   [`limits::source::MAX_DEPTH`].
//! - Files over [`limits::source::MAX_FILE_BYTES`] are skipped; reads are also
//!   bounded with `Read::take`, and the run has a total byte budget on top.
//! - `.gitignore` is honoured, plus a built-in deny list, because scanning
//!   `node_modules` is slow and finds nothing you can fix.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use globset::{GlobSet, GlobSetBuilder};
use owlwarden_core::limits;
use owlwarden_core::source::{FileSelector, RelPath, SourceError, SourceFile, SourceProvider};

/// Directories never walked, whatever `.gitignore` says.
///
/// These are build outputs and dependency trees. A finding inside one is not
/// actionable — you cannot fix a vulnerability in generated code by editing the
/// generated code.
const ALWAYS_EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".vercel",
    ".vscode",
    ".idea",
    ".cursor",
    ".husky",
    "dist",
    "build",
    "out",
    "coverage",
    "target",
    "vendor",
    ".venv",
    "__pycache__",
];

/// Hidden directories we still walk. `.github/workflows` is where CI integrity
/// rules look; skipping every dot-directory would make those rules permanently
/// silent on a real repository.
const HIDDEN_DIRS_ALLOWED: &[&str] = &[".github"];

/// Reads one project's source, and nothing else.
#[derive(Debug)]
pub struct FsSourceProvider {
    root: PathBuf,
    bytes_read: AtomicU64,
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl FsSourceProvider {
    /// Opens a project root.
    ///
    /// # Errors
    /// [`SourceError::Io`] if the path does not exist or cannot be
    /// canonicalized, [`SourceError::PathEscapesRoot`] if it is not a
    /// directory. The latter reuses the escape error deliberately: pointing the
    /// scanner at a single file is a scope mistake, and it should read like one.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, SourceError> {
        let raw = root.as_ref();
        let canonical = std::fs::canonicalize(raw).map_err(|source| SourceError::Io {
            path: raw.display().to_string(),
            source,
        })?;
        if !canonical.is_dir() {
            return Err(SourceError::PathEscapesRoot {
                path: canonical.display().to_string(),
            });
        }
        Ok(Self {
            root: canonical,
            bytes_read: AtomicU64::new(0),
            max_files: limits::source::MAX_FILES,
            max_file_bytes: limits::source::MAX_FILE_BYTES,
            max_total_bytes: limits::source::MAX_TOTAL_BYTES,
        })
    }

    /// Tightens the limits, for tests and for config that wants a smaller
    /// budget. Values above the built-in caps are clamped down — config can
    /// make a scan more careful, never less.
    #[must_use]
    pub fn with_limits(mut self, max_files: usize, max_file_bytes: u64) -> Self {
        self.max_files = max_files.min(limits::source::MAX_FILES);
        self.max_file_bytes = max_file_bytes.min(limits::source::MAX_FILE_BYTES);
        self
    }

    /// Total bytes read so far in this scan.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Acquire)
    }

    /// Resets the byte budget counter.
    ///
    /// The suppression pass re-reads files the engine already saw; without a
    /// reset those second reads would double-charge the same bytes and trip
    /// [`SourceError::BudgetExhausted`] on a tree that fit the first pass.
    pub fn reset_bytes_read(&self) {
        self.bytes_read.store(0, Ordering::Release);
    }

    /// Resolves a project-relative path to an absolute one, refusing anything
    /// that leaves the root once symlinks are resolved.
    ///
    /// The check is on the *canonical* path, not the joined one: `a/../..` is
    /// already rejected by [`RelPath`], but a symlink is only visible after
    /// resolution.
    fn resolve(&self, relative: &RelPath) -> Result<PathBuf, SourceError> {
        let joined = self.root.join(relative.as_str());
        let canonical = std::fs::canonicalize(&joined).map_err(|source| SourceError::Io {
            path: relative.to_string(),
            source,
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(SourceError::PathEscapesRoot {
                path: relative.to_string(),
            });
        }
        Ok(canonical)
    }
}

/// Compiles glob patterns, mapping a bad pattern to a typed error instead of a
/// panic. Patterns come from user config, so they are untrusted input.
fn build_globs(patterns: &[String]) -> Result<Option<GlobSet>, SourceError> {
    build_globs_with(patterns, false)
}

/// [`build_globs`], with an option to ignore case.
///
/// The agent-workspace surface compiles case-insensitively, because macOS and
/// Windows do. A repository containing `.Claude/settings.json` is, to a host on
/// a Mac, `.claude/settings.json` — it opens it and runs what is in it, and a
/// case-sensitive walker would never have listed the file. Application source
/// keeps the exact-case behaviour: nothing there depends on the filesystem's
/// opinion, and matching `README.MD` as `readme.md` would be surprising.
fn build_globs_with(
    patterns: &[String],
    case_insensitive: bool,
) -> Result<Option<GlobSet>, SourceError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns.iter().take(256) {
        let glob = globset::GlobBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .literal_separator(false)
            .build()
            .map_err(|error| SourceError::InvalidPattern {
                pattern: pattern.clone(),
                reason: error.to_string(),
            })?;
        builder.add(glob);
    }
    builder
        .build()
        .map(Some)
        .map_err(|error| SourceError::InvalidPattern {
            pattern: patterns.join(","),
            reason: error.to_string(),
        })
}

/// Directories skipped even on the agent-workspace surface.
///
/// Much shorter than [`ALWAYS_EXCLUDED_DIRS`], because most of that list exists
/// to keep editor and tool directories out of an application-source scan — and
/// those directories are the entire point here. What stays excluded is
/// dependency and VCS trees: an agent config inside `node_modules` is a real
/// vector and a very large scan, named as out of scope in ADR 0025 rather than
/// left unsaid.
const WORKSPACE_EXCLUDED_DIRS: &[&str] = &["node_modules", ".git", ".svn", ".hg", "target"];

impl FsSourceProvider {
    /// Walks the tree, honouring `.gitignore` and the deny list, or not.
    ///
    /// One walker with a switch rather than two: the containment, depth, and
    /// size guarantees are then written once, and a future change to them
    /// cannot apply to one surface and miss the other.
    fn walk(
        &self,
        include: Option<&GlobSet>,
        exclude: Option<&GlobSet>,
        honour_ignore_files: bool,
    ) -> Vec<SourceFile> {
        let excluded: &[&str] = if honour_ignore_files {
            ALWAYS_EXCLUDED_DIRS
        } else {
            WORKSPACE_EXCLUDED_DIRS
        };
        let walker = ignore::WalkBuilder::new(&self.root)
            .hidden(false)
            .git_ignore(honour_ignore_files)
            .git_global(false)
            .parents(false)
            .follow_links(false)
            .max_depth(Some(limits::source::MAX_DEPTH))
            .filter_entry(move |entry| {
                let Some(name) = entry.file_name().to_str() else {
                    return false;
                };
                if excluded.contains(&name) {
                    return false;
                }
                if !honour_ignore_files {
                    // The agent surface *is* the dot-directories.
                    return true;
                }
                // Skip dotfiles and most dot-directories. `.github` is the
                // exception: workflow files live there and are not themselves
                // hidden (the directory is).
                if name.starts_with('.') {
                    let is_dir = entry.file_type().is_some_and(|kind| kind.is_dir());
                    return is_dir && HIDDEN_DIRS_ALLOWED.contains(&name);
                }
                true
            })
            .build();

        let mut files = Vec::new();
        for entry in walker {
            if files.len() >= self.max_files {
                break;
            }
            // A directory we cannot read is not fatal: skip it and keep going,
            // the way `grep` does. Aborting the scan over one unreadable folder
            // would make the tool useless on a real machine.
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            let Ok(relative) = entry.path().strip_prefix(&self.root) else {
                continue;
            };
            let Ok(path) = RelPath::new(relative) else {
                continue;
            };
            if let Some(globs) = include
                && !globs.is_match(path.as_str())
            {
                continue;
            }
            if let Some(globs) = exclude
                && globs.is_match(path.as_str())
            {
                continue;
            }
            let size_bytes = entry.metadata().map(|meta| meta.len()).unwrap_or_default();
            if size_bytes > self.max_file_bytes && honour_ignore_files {
                continue;
            }
            // On the agent-workspace surface an oversized file is *listed*
            // anyway, and fails at `read` with a typed error the loader turns
            // into a reported "could not read this".
            //
            // Skipping it here instead — which is right for application source,
            // where one enormous generated file is noise — would mean a 5 MB
            // `.claude/settings.json` was invisible: not scanned, not reported,
            // and indistinguishable from a repository that has no agent
            // configuration at all. Silence is the one answer this surface must
            // never give by accident.
            files.push(SourceFile { path, size_bytes });
        }

        // Deterministic order: two runs over the same tree must produce the
        // same report, and filesystem walk order is not stable across systems.
        files.sort_by(|left, right| left.path.cmp(&right.path));
        files
    }
}

impl SourceProvider for FsSourceProvider {
    fn root(&self) -> &Path {
        &self.root
    }

    fn agent_workspace_files(&self, patterns: &[&str]) -> Result<Vec<SourceFile>, SourceError> {
        // Each pattern is matched at the root and under any prefix. The prefix
        // form is what finds a `examples/…/.claude/settings.json` so it can be
        // reported as a template rather than missed entirely; the caller
        // decides what a prefixed match means.
        let mut expanded: Vec<String> = Vec::with_capacity(patterns.len().saturating_mul(2));
        for pattern in patterns {
            expanded.push((*pattern).to_owned());
            expanded.push(format!("**/{pattern}"));
        }
        let include = build_globs_with(&expanded, true)?;
        Ok(self.walk(include.as_ref(), None, false))
    }

    fn files(&self, selector: &FileSelector) -> Result<Vec<SourceFile>, SourceError> {
        let include = build_globs(&selector.include)?;
        let exclude = build_globs(&selector.exclude)?;

        Ok(self.walk(include.as_ref(), exclude.as_ref(), true))
    }

    fn read(&self, file: &SourceFile) -> Result<Arc<str>, SourceError> {
        let absolute = self.resolve(&file.path)?;

        // Bound the read itself — metadata can lie under a race, and
        // `fs::read` would otherwise load an unbounded file into memory.
        let bytes =
            crate::safe_io::read_bounded(&absolute, self.max_file_bytes).map_err(|source| {
                if source.kind() == std::io::ErrorKind::InvalidData {
                    SourceError::FileTooLarge {
                        path: file.path.to_string(),
                        size: self.max_file_bytes.saturating_add(1),
                        max: self.max_file_bytes,
                    }
                } else {
                    SourceError::Io {
                        path: file.path.to_string(),
                        source,
                    }
                }
            })?;

        let added = bytes.len() as u64;
        let previous = self.bytes_read.fetch_add(added, Ordering::AcqRel);
        if previous.saturating_add(added) > self.max_total_bytes {
            self.bytes_read.fetch_sub(added, Ordering::AcqRel);
            return Err(SourceError::BudgetExhausted {
                max: self.max_total_bytes,
            });
        }

        let text = String::from_utf8(bytes).map_err(|_| SourceError::NotUtf8 {
            path: file.path.to_string(),
        })?;
        Ok(Arc::from(text))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn walks_source_and_skips_dependency_trees() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "app/api/users/route.ts",
            "export const GET = () => {}",
        );
        write(root, "node_modules/evil/index.js", "module.exports = 1");
        write(root, "dist/bundle.js", "console.log(1)");
        write(root, ".git/config", "[core]");

        let provider = FsSourceProvider::new(root).unwrap();
        let files = provider.files(&FileSelector::all()).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();

        assert_eq!(paths, vec!["app/api/users/route.ts"]);
    }

    #[test]
    fn include_and_exclude_globs_apply() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app/api/users/route.ts", "");
        write(root, "app/page.tsx", "");
        write(root, "app/api/legacy/route.ts", "");

        let provider = FsSourceProvider::new(root).unwrap();
        let selector = FileSelector {
            include: vec!["app/**/route.ts".to_owned()],
            exclude: vec!["**/legacy/**".to_owned()],
        };
        let files = provider.files(&selector).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();

        assert_eq!(paths, vec!["app/api/users/route.ts"]);
    }

    #[test]
    fn invalid_glob_is_a_typed_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let provider = FsSourceProvider::new(dir.path()).unwrap();
        let selector = FileSelector::include(["app/**/[".to_owned()]);
        assert!(matches!(
            provider.files(&selector),
            Err(SourceError::InvalidPattern { .. })
        ));
    }

    #[test]
    fn oversized_files_are_skipped_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "huge.ts", &"x".repeat(4096));
        write(root, "small.ts", "const a = 1");

        let provider = FsSourceProvider::new(root).unwrap().with_limits(100, 1024);
        let files = provider.files(&FileSelector::all()).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();

        assert_eq!(paths, vec!["small.ts"]);
    }

    #[test]
    fn file_count_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for index in 0..20 {
            write(root, &format!("file{index}.ts"), "const a = 1");
        }

        let provider = FsSourceProvider::new(root).unwrap().with_limits(5, 1024);
        assert_eq!(provider.files(&FileSelector::all()).unwrap().len(), 5);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_root_cannot_be_read() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.ts"), "const token = 'hunter2'").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::os::unix::fs::symlink(outside.path().join("secret.ts"), root.join("linked.ts"))
            .unwrap();

        let provider = FsSourceProvider::new(root).unwrap();
        // Even if the path is constructed by hand rather than obtained from the
        // walker, reading it must fail.
        let forged = SourceFile {
            path: RelPath::new(Path::new("linked.ts")).unwrap(),
            size_bytes: 0,
        };
        assert!(matches!(
            provider.read(&forged),
            Err(SourceError::PathEscapesRoot { .. })
        ));
    }

    #[test]
    fn non_utf8_files_are_rejected_rather_than_guessed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("latin1.ts"), [0xff, 0xfe, 0x00]).unwrap();

        let provider = FsSourceProvider::new(root).unwrap();
        let file = SourceFile {
            path: RelPath::new(Path::new("latin1.ts")).unwrap(),
            size_bytes: 3,
        };
        assert!(matches!(
            provider.read(&file),
            Err(SourceError::NotUtf8 { .. })
        ));
    }

    #[test]
    fn reading_reports_bytes_against_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "a.ts", "const a = 1");

        let provider = FsSourceProvider::new(root).unwrap();
        let files = provider.files(&FileSelector::all()).unwrap();
        let first = files.first().unwrap();
        let text = provider.read(first).unwrap();

        assert_eq!(&*text, "const a = 1");
        assert_eq!(provider.bytes_read(), 11);
    }
}
