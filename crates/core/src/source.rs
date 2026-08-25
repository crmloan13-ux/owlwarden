//! The `SourceProvider` port: read-only, sandboxed access to project source.
//!
//! # Why there is no `ast()` here
//!
//! `ARCHITECTURE.md` §3 sketches `fn ast(&self, file) -> Result<Ast, ParseError>`
//! on this port. That signature cannot be implemented safely: oxc allocates the
//! AST in an arena, so a `Program` borrows the `Allocator` that produced it and
//! cannot be returned as an owned value without self-referential unsafe code —
//! which `#![forbid(unsafe_code)]` rules out, correctly.
//!
//! Parsing therefore lives in the static engine, which owns the arena, parses
//! each file **once**, and hands a borrowed view to every rule. That is also the
//! faster design: N rules over M files costs M parses, not N×M.
//! See `docs/adr/0004-source-provider-has-no-ast.md`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// A project-relative path, normalized to `/` separators.
///
/// Windows is a day-one target and reports must be comparable across machines:
/// a baseline recorded on macOS has to match the same finding on a Windows CI
/// runner, so the separator cannot be platform-dependent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelPath(String);

impl RelPath {
    /// Normalizes a project-relative path.
    ///
    /// # Errors
    /// Returns [`SourceError::PathEscapesRoot`] if the path is absolute or
    /// contains a `..` component. Callers pass paths that may originate in
    /// config or a plugin, so this is a boundary check, not a formality.
    pub fn new(path: &Path) -> Result<Self, SourceError> {
        use std::path::Component;

        let mut parts: Vec<String> = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => {
                    parts.push(part.to_string_lossy().into_owned());
                }
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(SourceError::PathEscapesRoot {
                        path: path.display().to_string(),
                    });
                }
            }
        }
        Ok(Self(parts.join("/")))
    }

    /// The normalized path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The file extension without the dot, lowercased.
    #[must_use]
    pub fn extension(&self) -> Option<String> {
        let name = self.file_name();
        let (_, ext) = name.rsplit_once('.')?;
        Some(ext.to_ascii_lowercase())
    }

    /// The final path segment.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A file the provider is willing to hand out, with its size already known so
/// callers can budget before reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// Project-relative path.
    pub path: RelPath,
    /// Size in bytes, as reported by the filesystem at walk time.
    pub size_bytes: u64,
}

/// Which files a caller wants.
///
/// Deliberately not a raw glob string on the port: the caller states intent and
/// the adapter compiles it, so no untrusted pattern reaches a glob engine
/// without passing through one validated place.
#[derive(Debug, Clone, Default)]
pub struct FileSelector {
    /// Glob patterns relative to the project root, e.g. `app/**/route.ts`.
    /// Empty means "everything the provider is willing to serve".
    pub include: Vec<String>,
    /// Patterns to exclude, applied after `include`.
    pub exclude: Vec<String>,
}

impl FileSelector {
    /// A selector matching everything the provider serves by default.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// A selector for the given glob patterns.
    #[must_use]
    pub fn include(patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            include: patterns.into_iter().map(Into::into).collect(),
            exclude: Vec::new(),
        }
    }
}

/// Read-only, sandboxed access to the files of one project.
///
/// Implementations must guarantee, and are tested for:
/// - every returned path stays inside the project root, symlinks included;
/// - `.gitignore` is respected by default (scanning `node_modules` is both
///   useless and slow);
/// - the caps in [`crate::limits::source`] are enforced.
pub trait SourceProvider: Send + Sync {
    /// The project root. Absolute and canonical.
    fn root(&self) -> &Path;

    /// Lists files matching `selector`, already filtered by the provider's own
    /// limits.
    ///
    /// # Errors
    /// [`SourceError`] if the tree cannot be walked or a pattern is invalid.
    fn files(&self, selector: &FileSelector) -> Result<Vec<SourceFile>, SourceError>;

    /// Reads a file's contents as UTF-8.
    ///
    /// Returns `Arc<str>` because the same file is handed to many rules and the
    /// text outlives any single borrow.
    ///
    /// # Errors
    /// [`SourceError`] if the file is missing, too large, outside the root, or
    /// not valid UTF-8.
    fn read(&self, file: &SourceFile) -> Result<Arc<str>, SourceError>;

    /// Lists agent-workspace configuration files matching `patterns`,
    /// **ignoring `.gitignore` and the built-in directory deny list**.
    ///
    /// This is the one deliberate hole in the walker's normal behaviour, and it
    /// exists for one reason: `.claude/settings.local.json` is conventionally
    /// gitignored and `.vscode/` and `.cursor/` are on the deny list, so the
    /// ordinary walk is silent on exactly the files the agent-surface rules are
    /// about ([ADR 0025](../../../docs/adr/0025-agent-surface-and-supply-chain.md) §3).
    ///
    /// Everything else still holds: results stay under the root, symlinks that
    /// leave it are refused at read time, the size caps apply, and dependency
    /// trees are still skipped.
    ///
    /// `patterns` is not a user-facing setting. The only caller passes the
    /// closed list in `owlwarden_static::agentws::paths`, which is data in
    /// source rather than a glob a repository can widen — pointing the scanner
    /// at a file it has no parser for would produce "we found nothing", which
    /// is the one answer this surface must never give by accident.
    ///
    /// # Errors
    /// [`SourceError`] if the tree cannot be walked or a pattern is invalid.
    fn agent_workspace_files(&self, patterns: &[&str]) -> Result<Vec<SourceFile>, SourceError>;
}

/// Failure reading project source.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The path pointed outside the project root. Always a hard failure: this
    /// is the sandbox boundary, not a heuristic.
    #[error("path {path} resolves outside the project root")]
    PathEscapesRoot {
        /// The offending path.
        path: String,
    },

    /// The file exceeded [`crate::limits::source::MAX_FILE_BYTES`].
    #[error("{path} is {size} bytes, over the {max}-byte per-file limit")]
    FileTooLarge {
        /// Offending path.
        path: String,
        /// Actual size.
        size: u64,
        /// Configured cap.
        max: u64,
    },

    /// The scan hit [`crate::limits::source::MAX_TOTAL_BYTES`].
    #[error("scan exceeded its {max}-byte total source budget")]
    BudgetExhausted {
        /// Configured cap.
        max: u64,
    },

    /// The file was not valid UTF-8. We do not guess encodings; a mis-decoded
    /// source file produces wrong columns and wrong code frames.
    #[error("{path} is not valid UTF-8")]
    NotUtf8 {
        /// Offending path.
        path: String,
    },

    /// A glob pattern from config could not be compiled.
    #[error("invalid glob pattern {pattern:?}: {reason}")]
    InvalidPattern {
        /// The pattern as written.
        pattern: String,
        /// Compiler message.
        reason: String,
    },

    /// Anything the operating system refused.
    #[error("io error on {path}: {source}")]
    Io {
        /// Path being accessed.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn rel_path_normalizes_separators() {
        let path = RelPath::new(Path::new("app").join("api").join("route.ts").as_path()).unwrap();
        assert_eq!(path.as_str(), "app/api/route.ts");
        assert_eq!(path.extension().as_deref(), Some("ts"));
        assert_eq!(path.file_name(), "route.ts");
    }

    #[test]
    fn rel_path_rejects_traversal_and_absolute_paths() {
        assert!(matches!(
            RelPath::new(Path::new("../../etc/passwd")),
            Err(SourceError::PathEscapesRoot { .. })
        ));
        assert!(matches!(
            RelPath::new(Path::new("/etc/passwd")),
            Err(SourceError::PathEscapesRoot { .. })
        ));
        assert!(matches!(
            RelPath::new(Path::new("app/../../../etc/passwd")),
            Err(SourceError::PathEscapesRoot { .. })
        ));
    }

    #[test]
    fn rel_path_drops_redundant_current_dir() {
        let path = RelPath::new(Path::new("./app/./route.ts")).unwrap();
        assert_eq!(path.as_str(), "app/route.ts");
    }
}
