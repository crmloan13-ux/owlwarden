//! `Project` — the whole codebase as a rule sees it.
//!
//! Built once per scan from a [`SourceProvider`], so the manifest is read once
//! and the file list is walked once. Project rules use this to answer questions
//! a single file cannot: what framework is this, and is a required
//! configuration file missing entirely?

use std::collections::BTreeMap;
use std::sync::Arc;

use owlwarden_core::finding::Framework;
use owlwarden_core::source::{FileSelector, SourceError, SourceFile, SourceProvider};

use crate::SUPPORTED_EXTENSIONS;
use crate::framework::{FrameworkRegistry, FrameworkSet};
use crate::parse::{ParseFailure, with_parsed};
use crate::unit::{FileUnit, UnitMeta};

/// The parts of `package.json` we read.
///
/// Deserialized into a narrow struct rather than a generic JSON value: a
/// `package.json` is user-controlled input, and only these three fields have
/// any business influencing a scan.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PackageManifest {
    /// Package name, used only in report headers.
    #[serde(default)]
    pub name: Option<String>,
    /// Merged `dependencies` and `devDependencies`.
    #[serde(default, rename = "dependencies")]
    pub dependencies: BTreeMap<String, String>,
    /// `scripts`, used to tell the user how to wire `security-check`.
    #[serde(default)]
    pub scripts: BTreeMap<String, String>,
}

impl PackageManifest {
    /// Parses a `package.json`, merging dev dependencies into `dependencies`.
    ///
    /// A malformed manifest yields the empty manifest rather than an error:
    /// framework detection degrades to generic advice, which is a far better
    /// outcome than refusing to scan the project at all.
    #[must_use]
    pub fn parse(json: &str) -> Self {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            dependencies: BTreeMap<String, String>,
            #[serde(default, rename = "devDependencies")]
            dev_dependencies: BTreeMap<String, String>,
            #[serde(default)]
            scripts: BTreeMap<String, String>,
        }

        let Ok(raw) = serde_json::from_str::<Raw>(json) else {
            return Self::default();
        };
        let mut dependencies = raw.dependencies;
        dependencies.extend(raw.dev_dependencies);
        Self {
            name: raw.name,
            dependencies,
            scripts: raw.scripts,
        }
    }

    /// Whether the package is declared as a dependency of any kind.
    #[must_use]
    pub fn depends_on(&self, package: &str) -> bool {
        self.dependencies.contains_key(package)
    }
}

/// One project, ready to analyse.
pub struct Project<'a> {
    source: &'a dyn SourceProvider,
    manifest: PackageManifest,
    frameworks: Arc<FrameworkSet>,
    files: Vec<SourceFile>,
}

impl<'a> Project<'a> {
    /// Walks the project and reads its manifest, detecting frameworks with the
    /// built-in registry.
    ///
    /// # Errors
    /// [`SourceError`] if the file tree cannot be walked. A missing or
    /// unreadable `package.json` is not an error — plenty of real projects have
    /// one that we cannot parse, and the scan is still useful.
    pub fn discover(source: &'a dyn SourceProvider) -> Result<Self, SourceError> {
        Self::discover_with(source, &FrameworkRegistry::builtin())
    }

    /// Walks the project using a caller-supplied registry.
    ///
    /// The seam a plugin host uses: it builds a registry with the first-party
    /// profiles plus whatever the loaded plugins registered, and the rest of
    /// the engine is unchanged.
    ///
    /// # Errors
    /// [`SourceError`] if the file tree cannot be walked.
    pub fn discover_with(
        source: &'a dyn SourceProvider,
        registry: &FrameworkRegistry,
    ) -> Result<Self, SourceError> {
        let include: Vec<String> = SUPPORTED_EXTENSIONS
            .iter()
            .map(|extension| format!("**/*.{extension}"))
            .collect();
        let files = source.files(&FileSelector::include(include))?;

        let manifest = read_manifest(source);
        let frameworks = Arc::new(registry.detect(&manifest));

        Ok(Self {
            source,
            manifest,
            frameworks,
            files,
        })
    }

    /// The framework remediation is written for.
    #[must_use]
    pub fn framework(&self) -> &Framework {
        self.frameworks.id()
    }

    /// Every framework detected in this project.
    #[must_use]
    pub fn frameworks(&self) -> &FrameworkSet {
        &self.frameworks
    }

    /// The parsed `package.json`.
    #[must_use]
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    /// Every source file the engine will consider, in a stable order.
    #[must_use]
    pub fn files(&self) -> &[SourceFile] {
        &self.files
    }

    /// The underlying provider, for rules that need to read a specific file.
    #[must_use]
    pub fn source(&self) -> &'a dyn SourceProvider {
        self.source
    }

    /// Finds the first file whose project-relative path equals one of
    /// `candidates`, in the order given.
    ///
    /// Used by project rules looking for a configuration file: the caller
    /// states the exact names it understands rather than pattern-matching, so
    /// "not found" is unambiguous.
    #[must_use]
    pub fn find_file(&self, candidates: &[impl AsRef<str>]) -> Option<&SourceFile> {
        candidates.iter().find_map(|candidate| {
            self.files
                .iter()
                .find(|file| file.path.as_str() == candidate.as_ref())
        })
    }

    /// Every file matching one of `candidates`, in the order given.
    ///
    /// A project can configure headers in more than one place — a
    /// `next.config.js` and a `middleware.ts` — and a rule that stopped at the
    /// first would report a gap the second had already closed.
    #[must_use]
    pub fn find_files(&self, candidates: &[impl AsRef<str>]) -> Vec<&SourceFile> {
        candidates
            .iter()
            .filter_map(|candidate| {
                self.files
                    .iter()
                    .find(|file| file.path.as_str() == candidate.as_ref())
            })
            .collect()
    }

    /// Reads and parses one file, handing the result to `f`.
    ///
    /// # Errors
    /// [`ProjectError`] if the file cannot be read or does not parse.
    pub fn with_parsed_file<T>(
        &self,
        file: &SourceFile,
        f: impl FnOnce(&FileUnit<'_>) -> T,
    ) -> Result<T, ProjectError> {
        let text = self.source.read(file)?;
        let meta = UnitMeta {
            frameworks: Arc::clone(&self.frameworks),
            route: self.frameworks.route(file.path.as_str()),
        };
        Ok(with_parsed(&file.path, &text, meta, f)?)
    }
}

/// Reading or parsing one file of a project failed.
#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    /// The file could not be read.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// The file could not be parsed.
    #[error(transparent)]
    Parse(#[from] ParseFailure),
}

impl From<ProjectError> for owlwarden_core::detector::DetectorError {
    fn from(error: ProjectError) -> Self {
        match error {
            ProjectError::Source(source) => Self::Source(source),
            ProjectError::Parse(parse) => parse.into(),
        }
    }
}

/// Reads `package.json` from the project root, tolerating its absence.
fn read_manifest(source: &dyn SourceProvider) -> PackageManifest {
    let Ok(files) = source.files(&FileSelector::include(["package.json"])) else {
        return PackageManifest::default();
    };
    let Some(file) = files
        .iter()
        .find(|file| file.path.as_str() == "package.json")
    else {
        return PackageManifest::default();
    };
    source.read(file).map_or_else(
        |_| PackageManifest::default(),
        |text| PackageManifest::parse(&text),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn dev_dependencies_count_as_dependencies() {
        let manifest = PackageManifest::parse(
            r#"{"name":"app","dependencies":{"next":"14.0.0"},"devDependencies":{"typescript":"5"}}"#,
        );
        assert!(manifest.depends_on("next"));
        assert!(manifest.depends_on("typescript"));
        assert!(!manifest.depends_on("express"));
        assert_eq!(manifest.name.as_deref(), Some("app"));
    }

    #[test]
    fn a_broken_manifest_degrades_instead_of_failing() {
        let manifest = PackageManifest::parse("{ this is not json");
        assert!(manifest.name.is_none());
        assert!(manifest.dependencies.is_empty());
    }

    #[test]
    fn a_manifest_with_hostile_shapes_is_ignored_not_trusted() {
        // `dependencies` as an array does not match the schema; serde rejects
        // the whole document and we fall back to the empty manifest.
        let manifest = PackageManifest::parse(r#"{"dependencies":["next"]}"#);
        assert!(manifest.dependencies.is_empty());
    }
}
