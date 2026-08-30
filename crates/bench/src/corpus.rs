//! The labelled corpus, and the discipline that makes it worth anything.
//!
//! A corpus is only worth what its discipline is worth, so the rules from
//! [ADR 0030](../../../docs/adr/0030-published-benchmark.md) §1 are enforced
//! here rather than written down and hoped for:
//!
//! - **Two reviewers per repository, named in the file.** A single-reviewer
//!   label is not a label, and [`GroundTruth::validate`] refuses one.
//! - **Disagreements are recorded, not resolved.** They go in `disagreements`
//!   and are excluded from both numerator and denominator. A corpus that
//!   quietly resolves its hard cases has optimised away exactly the cases that
//!   matter.
//! - **Repositories are pinned by commit SHA**, so a result is reproducible in
//!   five years and offline.
//! - **Each repository records its licence**, because vendoring somebody's code
//!   to measure ourselves against is a thing with terms.
//!
//! What cannot be enforced in code is the rule that matters most: *the corpus
//! is chosen before the rules are tuned against it, and additions are reviewed
//! in their own pull request*. Adding a repository in the same commit as a rule
//! fix is how a benchmark becomes a rubber stamp, and only a reviewer can catch
//! that.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Largest ground-truth file read. These are hand-written labels, not data.
pub const MAX_GROUND_TRUTH_BYTES: u64 = 4 * 1024 * 1024;

/// Most repositories in the corpus.
pub const MAX_ENTRIES: usize = 256;

/// What a reviewer decided about one reported finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// A real problem. Counts in the numerator of precision.
    TruePositive,
    /// Reported, and not a problem. The number this whole apparatus exists to
    /// publish.
    FalsePositive,
}

/// One labelled finding in one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelledFinding {
    /// The rule that reported it, or should have.
    pub rule: String,
    /// Repository-relative path.
    pub path: String,
    /// 1-based line.
    pub line: u32,
    /// What the reviewers decided.
    pub verdict: Verdict,
    /// The exposure the reviewers agreed on, when they judged it.
    ///
    /// Present only where they did. `authenticated` precision is tracked
    /// separately and is the metric most likely to be embarrassing, so a label
    /// nobody actually made must not be invented by defaulting this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<String>,
    /// Why, in the reviewers' own words. Mandatory: a label nobody can explain
    /// is a label nobody can check.
    pub note: String,
}

/// A case the reviewers did not agree on.
///
/// Excluded from both numerator and denominator, and counted in the published
/// output. A benchmark that hid its hard cases would be reporting on the easy
/// ones and calling it a rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Disagreement {
    /// Repository-relative path.
    pub path: String,
    /// 1-based line.
    pub line: u32,
    /// What the reviewers could not settle.
    pub note: String,
}

/// One repository's ground truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroundTruth {
    /// Where the source came from.
    pub repo: String,
    /// The exact commit. A moving target is not a benchmark.
    pub commit: String,
    /// The licence the source is under.
    pub licence: String,
    /// The framework, for grouping the published table.
    pub framework: String,
    /// The runtime, where the repository declares one.
    #[serde(default)]
    pub runtime: Option<String>,
    /// Who labelled it. Two or more, named.
    pub labelled_by: Vec<String>,
    /// When.
    pub labelled_at: String,
    /// Every labelled finding.
    #[serde(default)]
    pub findings: Vec<LabelledFinding>,
    /// Cases excluded from scoring.
    #[serde(default)]
    pub disagreements: Vec<Disagreement>,
}

impl GroundTruth {
    /// Whether this file meets the corpus discipline.
    ///
    /// # Errors
    /// [`CorpusError`] naming the rule that was broken. Refusing to score an
    /// under-reviewed repository is the point: a number computed from one
    /// person's opinion is not a measurement, and publishing it as one is worse
    /// than publishing nothing.
    pub fn validate(&self, path: &Path) -> Result<(), CorpusError> {
        let at = path.display().to_string();
        if self.commit.len() < 7 || !self.commit.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(CorpusError::NotPinned { path: at });
        }
        if self.licence.trim().is_empty() {
            return Err(CorpusError::NoLicence { path: at });
        }
        let reviewers: BTreeSet<&str> = self
            .labelled_by
            .iter()
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
            .collect();
        if reviewers.len() < 2 {
            return Err(CorpusError::OneReviewer {
                path: at,
                found: reviewers.len(),
            });
        }
        if let Some(finding) = self
            .findings
            .iter()
            .find(|finding| finding.note.trim().is_empty())
        {
            return Err(CorpusError::UnexplainedLabel {
                path: at,
                rule: finding.rule.clone(),
                line: finding.line,
            });
        }
        Ok(())
    }

    /// Whether a reported finding was excluded by a disagreement.
    #[must_use]
    pub fn is_disagreement(&self, path: &str, line: u32) -> bool {
        self.disagreements
            .iter()
            .any(|entry| entry.path == path && entry.line == line)
    }

    /// The label for a reported finding, if the reviewers made one.
    #[must_use]
    pub fn label_for(&self, rule: &str, path: &str, line: u32) -> Option<&LabelledFinding> {
        self.findings
            .iter()
            .find(|finding| finding.rule == rule && finding.path == path && finding.line == line)
    }
}

/// One repository in the corpus: its source tree and its labels.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    /// Directory name, used as the row label.
    pub name: String,
    /// The tree to scan.
    pub root: PathBuf,
    /// The labels.
    pub truth: GroundTruth,
}

/// Every repository the harness will score.
#[derive(Debug, Clone, Default)]
pub struct Corpus {
    /// Entries, in a stable order.
    pub entries: Vec<CorpusEntry>,
}

/// The corpus could not be loaded, or does not meet its own discipline.
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    /// The corpus directory is missing.
    #[error(
        "no corpus at {path}. `owlwarden bench` scores against labelled real repositories; \
         see docs/explanation/benchmark.md for how to add one."
    )]
    Missing {
        /// Where it was looked for.
        path: String,
    },
    /// A ground-truth file could not be read or parsed.
    #[error("{path}: {message}")]
    Malformed {
        /// The file.
        path: String,
        /// What went wrong.
        message: String,
    },
    /// The repository is not pinned to a commit.
    #[error("{path}: no commit SHA. A moving target is not a benchmark.")]
    NotPinned {
        /// The file.
        path: String,
    },
    /// No licence recorded.
    #[error("{path}: no licence recorded for the vendored source.")]
    NoLicence {
        /// The file.
        path: String,
    },
    /// Fewer than two reviewers.
    #[error(
        "{path}: {found} reviewer(s). A single-reviewer label is not a label — \
         ADR 0030 §1 requires two, named."
    )]
    OneReviewer {
        /// The file.
        path: String,
        /// How many were named.
        found: usize,
    },
    /// A label with no reasoning.
    #[error(
        "{path}: the {rule} label at line {line} has no note; a label nobody can explain is a label nobody can check"
    )]
    UnexplainedLabel {
        /// The file.
        path: String,
        /// The rule.
        rule: String,
        /// The line.
        line: u32,
    },
}

/// Loads every repository under a corpus directory.
///
/// # Errors
/// [`CorpusError`] when the directory is missing, a ground-truth file is
/// malformed, or an entry breaks the corpus discipline.
pub fn load(root: &Path) -> Result<Corpus, CorpusError> {
    if !root.is_dir() {
        return Err(CorpusError::Missing {
            path: root.display().to_string(),
        });
    }
    let mut entries = Vec::new();
    let listing = std::fs::read_dir(root).map_err(|error| CorpusError::Malformed {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;

    let mut directories: Vec<PathBuf> = listing
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .take(MAX_ENTRIES)
        .collect();
    // Sorted, because byte-identical output on three platforms is a hard
    // requirement and directory order is not stable across filesystems.
    directories.sort();

    for directory in directories {
        let manifest = directory.join("ground-truth.json");
        if !manifest.is_file() {
            continue;
        }
        let truth = read_ground_truth(&manifest)?;
        truth.validate(&manifest)?;
        entries.push(CorpusEntry {
            name: directory
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unnamed")
                .to_owned(),
            // The source sits beside its labels, fetched-and-checksummed or
            // vendored as a submodule.
            root: directory.join("source"),
            truth,
        });
    }
    Ok(Corpus { entries })
}

fn read_ground_truth(path: &Path) -> Result<GroundTruth, CorpusError> {
    let metadata = std::fs::metadata(path).map_err(|error| CorpusError::Malformed {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.len() > MAX_GROUND_TRUTH_BYTES {
        return Err(CorpusError::Malformed {
            path: path.display().to_string(),
            message: format!("larger than {MAX_GROUND_TRUTH_BYTES} bytes"),
        });
    }
    let bytes = std::fs::read(path).map_err(|error| CorpusError::Malformed {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    serde_json::from_slice(&bytes).map_err(|error| CorpusError::Malformed {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn truth() -> GroundTruth {
        GroundTruth {
            repo: "https://github.com/example/app".to_owned(),
            commit: "a1b2c3d4e5f6".to_owned(),
            licence: "MIT".to_owned(),
            framework: "fastify".to_owned(),
            runtime: Some("node".to_owned()),
            labelled_by: vec!["reviewer-one".to_owned(), "reviewer-two".to_owned()],
            labelled_at: "2026-08-27".to_owned(),
            findings: vec![LabelledFinding {
                rule: "insecure-cookie".to_owned(),
                path: "src/routes/session.ts".to_owned(),
                line: 44,
                verdict: Verdict::TruePositive,
                exposure: Some("internet".to_owned()),
                note: "session cookie, no httpOnly, unauthenticated login route".to_owned(),
            }],
            disagreements: Vec::new(),
        }
    }

    #[test]
    fn a_single_reviewer_label_is_refused() {
        // ADR 0030 §1. Not a style preference: a number computed from one
        // person's opinion is not a measurement, and publishing it as one is
        // worse than publishing nothing.
        let mut lonely = truth();
        lonely.labelled_by = vec!["reviewer-one".to_owned()];
        assert!(matches!(
            lonely.validate(Path::new("x")).unwrap_err(),
            CorpusError::OneReviewer { found: 1, .. }
        ));

        // …and the same name twice is one reviewer.
        let mut duplicated = truth();
        duplicated.labelled_by = vec!["reviewer-one".to_owned(), " reviewer-one ".to_owned()];
        assert!(matches!(
            duplicated.validate(Path::new("x")).unwrap_err(),
            CorpusError::OneReviewer { found: 1, .. }
        ));
    }

    #[test]
    fn an_unpinned_repository_is_refused() {
        let mut floating = truth();
        floating.commit = "main".to_owned();
        assert!(matches!(
            floating.validate(Path::new("x")).unwrap_err(),
            CorpusError::NotPinned { .. }
        ));
    }

    #[test]
    fn a_repository_with_no_recorded_licence_is_refused() {
        let mut unlicensed = truth();
        unlicensed.licence = "  ".to_owned();
        assert!(matches!(
            unlicensed.validate(Path::new("x")).unwrap_err(),
            CorpusError::NoLicence { .. }
        ));
    }

    #[test]
    fn a_label_with_no_note_is_refused() {
        let mut silent = truth();
        if let Some(finding) = silent.findings.first_mut() {
            finding.note = String::new();
        }
        assert!(matches!(
            silent.validate(Path::new("x")).unwrap_err(),
            CorpusError::UnexplainedLabel { .. }
        ));
    }

    #[test]
    fn a_well_formed_entry_validates() {
        assert!(truth().validate(Path::new("x")).is_ok());
    }

    #[test]
    fn a_missing_corpus_says_how_to_add_one() {
        let error = load(Path::new("/nonexistent/owlwarden/corpus")).unwrap_err();
        assert!(matches!(error, CorpusError::Missing { .. }));
        assert!(error.to_string().contains("benchmark.md"));
    }
}
