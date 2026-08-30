//! Running the corpus.
//!
//! The one part that touches a filesystem and an engine. Everything else in
//! this crate is arithmetic over data, which is what makes the arithmetic
//! testable without a corpus.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use owlwarden_core::context::ScanSettings;
use owlwarden_core::finding::{Confidence, Severity};
use owlwarden_core::suppression::SuppressionPolicy;

use crate::corpus::{Corpus, CorpusEntry};
use crate::report::{BenchReport, CorpusSize, RepositoryScore};
use crate::score::{Outcome, score_entry};

/// The preset the benchmark runs.
///
/// `deep`, not `quick`. The number published has to describe the whole
/// catalogue: measuring only the rules that are already the most precise would
/// be choosing the denominator to flatter the numerator.
pub const BENCH_PRESET: &str = "deep";

/// What a benchmark run needs.
pub struct BenchRequest<'a> {
    /// The loaded corpus.
    pub corpus: &'a Corpus,
    /// Score only this rule.
    pub rule: Option<&'a str>,
}

/// Scanning a corpus repository failed.
#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    /// The corpus is empty.
    #[error(
        "the corpus has no repositories. A precision figure over nothing is not a measurement; \
         see docs/explanation/benchmark.md for how to add one."
    )]
    Empty,
    /// One repository could not be scanned.
    #[error("{name}: {message}")]
    Scan {
        /// The corpus entry.
        name: String,
        /// What went wrong.
        message: String,
    },
    /// A repository's source is not present.
    #[error(
        "{name}: no source at {path}. The corpus is vendored or fetched-and-checksummed; \
         run `pnpm bench:fetch` first."
    )]
    NoSource {
        /// The corpus entry.
        name: String,
        /// Where it should have been.
        path: String,
    },
}

/// Scores the whole corpus.
///
/// `scan` is supplied by the caller so this crate does not acquire an async
/// runtime — the same seam `owlwarden-seal` uses, for the same reason.
///
/// # Errors
/// [`BenchError`] when the corpus is empty or a repository cannot be scanned.
/// A repository that fails is never scored as clean: a scanner that crashed on
/// the hard repository and published its precision over the easy ones would be
/// reporting the opposite of what happened.
pub fn run(
    request: &BenchRequest<'_>,
    scan: &dyn Fn(&Path, &ScanSettings) -> Result<owlwarden_core::report::Report, String>,
) -> Result<BenchReport, BenchError> {
    if request.corpus.entries.is_empty() {
        return Err(BenchError::Empty);
    }

    let started = Instant::now();
    let mut overall = Outcome::default();
    let mut per_rule: BTreeMap<String, Outcome> = BTreeMap::new();
    let mut repositories = Vec::new();
    let mut size = CorpusSize::default();

    for entry in &request.corpus.entries {
        let outcome = score_one(entry, request.rule, scan, &mut per_rule, &mut repositories)?;
        size.repositories = size.repositories.saturating_add(1);
        size.labels = size
            .labels
            .saturating_add(u32::try_from(entry.truth.findings.len()).unwrap_or(u32::MAX));
        size.disagreements = size
            .disagreements
            .saturating_add(u32::try_from(entry.truth.disagreements.len()).unwrap_or(u32::MAX));
        overall.merge(&outcome);
    }

    let duration = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(BenchReport::assemble(
        &overall,
        per_rule,
        repositories,
        size,
        duration,
    ))
}

fn score_one(
    entry: &CorpusEntry,
    rule: Option<&str>,
    scan: &dyn Fn(&Path, &ScanSettings) -> Result<owlwarden_core::report::Report, String>,
    per_rule: &mut BTreeMap<String, Outcome>,
    repositories: &mut Vec<RepositoryScore>,
) -> Result<Outcome, BenchError> {
    if !entry.root.is_dir() {
        return Err(BenchError::NoSource {
            name: entry.name.clone(),
            path: entry.root.display().to_string(),
        });
    }

    let started = Instant::now();
    let report = scan(&entry.root, &settings()).map_err(|message| BenchError::Scan {
        name: entry.name.clone(),
        message,
    })?;
    let duration = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let outcome = score_entry(&report.findings, &entry.truth, rule);

    // Per rule, so a regression can be attributed rather than merely noticed.
    let mut rules: Vec<String> = report
        .findings
        .iter()
        .map(|finding| finding.id.to_string())
        .collect();
    rules.extend(entry.truth.findings.iter().map(|label| label.rule.clone()));
    rules.sort();
    rules.dedup();
    for id in rules {
        if rule.is_some_and(|only| only != id) {
            continue;
        }
        let scoped = score_entry(&report.findings, &entry.truth, Some(&id));
        per_rule.entry(id).or_default().merge(&scoped);
    }

    repositories.push(RepositoryScore {
        name: entry.name.clone(),
        repo: entry.truth.repo.clone(),
        commit: entry.truth.commit.clone(),
        framework: entry.truth.framework.clone(),
        duration_ms: duration,
        precision: outcome.precision(),
        recall: outcome.recall(),
        disagreements: outcome.disagreements,
    });
    Ok(outcome)
}

/// The settings every corpus scan runs under.
///
/// Suppressions are **not** honoured and no baseline is applied. A corpus
/// repository is somebody else's code, and a scanner that let the measured
/// tree silence its own findings would be publishing a number about the
/// repository's comments rather than about the rules.
#[must_use]
pub fn settings() -> ScanSettings {
    ScanSettings {
        allow_active: false,
        min_confidence: Confidence::Possible,
        min_severity: Severity::Info,
        preset: BENCH_PRESET.to_owned(),
        dirty_paths: None,
        scoped_paths: None,
        include_user_config: false,
        home_override: None,
    }
}

/// The suppression posture a corpus scan runs under.
#[must_use]
pub fn suppression_policy() -> SuppressionPolicy {
    SuppressionPolicy::ReportOnly
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::corpus::{GroundTruth, LabelledFinding, Verdict};
    use owlwarden_core::finding::{Location, RuleId, SourceLocation};
    use owlwarden_core::report::{Report, ReportSummary, SCHEMA_VERSION, ScanTarget, ToolInfo};

    fn truth() -> GroundTruth {
        GroundTruth {
            repo: "https://github.com/example/app".to_owned(),
            commit: "a1b2c3d".to_owned(),
            licence: "MIT".to_owned(),
            framework: "express".to_owned(),
            runtime: None,
            labelled_by: vec!["a".to_owned(), "b".to_owned()],
            labelled_at: "2026-08-27".to_owned(),
            findings: vec![LabelledFinding {
                rule: "ssrf".to_owned(),
                path: "src/a.ts".to_owned(),
                line: 1,
                verdict: Verdict::TruePositive,
                exposure: None,
                note: "caller-controlled host".to_owned(),
            }],
            disagreements: Vec::new(),
        }
    }

    fn report_of(findings: Vec<owlwarden_core::finding::Finding>) -> Report {
        Report {
            schema_version: SCHEMA_VERSION.to_owned(),
            tool: ToolInfo::default(),
            scanned_at: "1970-01-01T00:00:00Z".to_owned(),
            duration_ms: 0,
            target: ScanTarget::default(),
            summary: ReportSummary::of(&findings),
            exposure_summary: owlwarden_core::report::ExposureSummary::of(&findings),
            findings,
            suppressed_count: 0,
            suppressions: Vec::new(),
            baseline_hidden_count: 0,
            truncated: false,
            errors: Vec::new(),
        }
    }

    #[test]
    fn an_empty_corpus_is_an_error_rather_than_a_perfect_score() {
        let error = run(
            &BenchRequest {
                corpus: &Corpus::default(),
                rule: None,
            },
            &|_, _| Ok(report_of(Vec::new())),
        )
        .unwrap_err();
        assert!(matches!(error, BenchError::Empty));
        assert!(error.to_string().contains("not a measurement"));
    }

    #[test]
    fn a_repository_with_no_source_is_named_rather_than_skipped() {
        let corpus = Corpus {
            entries: vec![CorpusEntry {
                name: "example-app".to_owned(),
                root: Path::new("/nonexistent/owlwarden/source").to_path_buf(),
                truth: truth(),
            }],
        };
        let error = run(
            &BenchRequest {
                corpus: &corpus,
                rule: None,
            },
            &|_, _| Ok(report_of(Vec::new())),
        )
        .unwrap_err();
        assert!(matches!(error, BenchError::NoSource { .. }));
    }

    #[test]
    fn a_scan_that_fails_is_never_scored_as_clean() {
        // A scanner that crashed on the hard repository and published its
        // precision over the easy ones would report the opposite of what
        // happened.
        let directory = tempfile::tempdir().unwrap();
        let corpus = Corpus {
            entries: vec![CorpusEntry {
                name: "example-app".to_owned(),
                root: directory.path().to_path_buf(),
                truth: truth(),
            }],
        };
        let error = run(
            &BenchRequest {
                corpus: &corpus,
                rule: None,
            },
            &|_, _| Err("the parser gave up".to_owned()),
        )
        .unwrap_err();
        assert!(matches!(error, BenchError::Scan { .. }));
        assert!(error.to_string().contains("the parser gave up"));
    }

    #[test]
    fn a_corpus_run_scores_and_carries_its_denominator() {
        let directory = tempfile::tempdir().unwrap();
        let corpus = Corpus {
            entries: vec![CorpusEntry {
                name: "example-app".to_owned(),
                root: directory.path().to_path_buf(),
                truth: truth(),
            }],
        };
        let report = run(
            &BenchRequest {
                corpus: &corpus,
                rule: None,
            },
            &|_, _| {
                Ok(report_of(vec![
                    owlwarden_core::finding::Finding::builder(
                        RuleId::new_static("ssrf"),
                        Severity::High,
                        "t",
                    )
                    .location(Location::Source(SourceLocation {
                        path: "src/a.ts".to_owned(),
                        line: 1,
                        col: 1,
                    }))
                    .build(),
                ]))
            },
        )
        .unwrap();

        assert_eq!(report.precision, Some(1.0));
        assert_eq!(report.corpus.repositories, 1);
        assert_eq!(report.corpus.labels, 1);
        assert_eq!(report.rules.len(), 1);
        assert!(report.summary().contains("1 repositories"));
    }

    #[test]
    fn a_corpus_scan_never_honours_the_repositorys_own_suppressions() {
        // The measured tree is somebody else's code. A scanner that let it
        // silence findings would publish a number about its comments.
        assert_eq!(suppression_policy(), SuppressionPolicy::ReportOnly);
        assert!(!settings().include_user_config);
        assert_eq!(settings().preset, "deep");
    }
}
