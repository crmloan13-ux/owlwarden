//! What one benchmark run publishes.
//!
//! # Determinism is a hard requirement
//!
//! Same corpus, same commit, byte-identical output on macOS, Linux, and
//! Windows. A benchmark that varies by platform is a benchmark people argue
//! with instead of act on, so every collection here is ordered by a total key
//! and every rate is rounded to a fixed number of places before it is
//! serialized — a float printed at full precision differs in its last digit
//! between platforms and would make the published artefact churn.
//!
//! # The denominator travels with the number
//!
//! Corpus size, repository count, label count, and disagreement count are on
//! the same object as the precision figure, because **a precision figure
//! without a denominator is marketing**
//! ([ADR 0030](../../../docs/adr/0030-published-benchmark.md) §4). The renderer
//! cannot show one without the other, because there is nowhere to get one
//! without the other.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::score::Outcome;

/// Decimal places every published rate is rounded to.
///
/// Four is more than anyone reads and few enough that the last digit is not a
/// platform's floating-point formatting showing through.
const RATE_PLACES: u32 = 4;

/// Rounds a rate for publication.
fn publishable(rate: Option<f64>) -> Option<f64> {
    let rate = rate?;
    let scale = f64::from(10_u32.pow(RATE_PLACES));
    Some((rate * scale).round() / scale)
}

/// One rule's score across the whole corpus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleScore {
    /// The rule.
    pub rule: String,
    /// Reported and real.
    pub true_positives: u32,
    /// Reported and noise.
    pub false_positives: u32,
    /// Labelled real and missed.
    pub false_negatives: u32,
    /// Reported and not yet reviewed.
    pub unlabelled: u32,
    /// `None` when nothing reviewed was reported.
    pub precision: Option<f64>,
    /// `None` when nothing labelled exists for this rule.
    pub recall: Option<f64>,
    /// Every false positive, with where. A number nobody can inspect is a
    /// number nobody trusts.
    pub false_positive_locations: Vec<String>,
}

/// One repository's row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryScore {
    /// Corpus directory name.
    pub name: String,
    /// Upstream URL.
    pub repo: String,
    /// The pinned commit.
    pub commit: String,
    /// Framework, for grouping.
    pub framework: String,
    /// Wall time for this repository, in milliseconds.
    pub duration_ms: u64,
    /// Its scores.
    pub precision: Option<f64>,
    /// Its recall.
    pub recall: Option<f64>,
    /// Findings excluded because the reviewers disagreed.
    pub disagreements: u32,
}

/// The corpus's own size, published beside every rate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusSize {
    /// Repositories scored.
    pub repositories: u32,
    /// Labels across them.
    pub labels: u32,
    /// Cases the reviewers did not agree on, and which are excluded.
    pub disagreements: u32,
}

/// One benchmark run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchReport {
    /// Engine version.
    pub version: String,
    /// The corpus's size, so a rate is never read without its denominator.
    pub corpus: CorpusSize,
    /// Overall precision.
    pub precision: Option<f64>,
    /// Overall recall.
    pub recall: Option<f64>,
    /// Precision restricted to findings called `authenticated`.
    ///
    /// Its own field, and published on its own, because a finding wrongly
    /// marked as behind auth is one somebody deprioritises. It is the number
    /// this project is most embarrassed to publish, which is why it is not
    /// folded into the headline.
    pub authenticated_precision: Option<f64>,
    /// Per rule, ordered by rule id.
    pub rules: Vec<RuleScore>,
    /// Per repository, ordered by name.
    pub repositories: Vec<RepositoryScore>,
    /// Total wall time in milliseconds.
    pub duration_ms: u64,
    /// The exact command that reproduces this run.
    pub reproduce: String,
}

impl BenchReport {
    /// Builds a report from per-repository outcomes.
    ///
    /// `per_rule` and `repositories` are sorted here rather than by the caller,
    /// because determinism is a property of the artefact and not of whoever
    /// happened to assemble it.
    #[must_use]
    pub fn assemble(
        overall: &Outcome,
        per_rule: BTreeMap<String, Outcome>,
        mut repositories: Vec<RepositoryScore>,
        corpus: CorpusSize,
        duration_ms: u64,
    ) -> Self {
        repositories.sort_by(|left, right| left.name.cmp(&right.name));
        let rules = per_rule
            .into_iter()
            .map(|(rule, outcome)| RuleScore {
                rule,
                true_positives: outcome.true_positives,
                false_positives: outcome.false_positives,
                false_negatives: outcome.false_negatives,
                unlabelled: outcome.unlabelled,
                precision: publishable(outcome.precision()),
                recall: publishable(outcome.recall()),
                false_positive_locations: outcome.false_positive_locations.clone(),
            })
            .collect();

        Self {
            version: owlwarden_core::ENGINE_VERSION.to_owned(),
            corpus,
            precision: publishable(overall.precision()),
            recall: publishable(overall.recall()),
            authenticated_precision: publishable(overall.authenticated_precision()),
            rules,
            repositories,
            duration_ms,
            reproduce: "npx owlwarden bench --format json".to_owned(),
        }
    }

    /// Whether this run clears its floors.
    ///
    /// Returns one line per breach, in a stable order. Empty means the build
    /// passes.
    #[must_use]
    pub fn breaches(&self, thresholds: &crate::thresholds::Thresholds) -> Vec<String> {
        let mut out = Vec::new();

        if let (Some(floor), Some(actual)) = (thresholds.overall, self.precision)
            && actual < floor
        {
            out.push(format!(
                "overall precision {actual:.4} is below the floor of {floor:.4}"
            ));
        }
        if let (Some(floor), Some(actual)) =
            (thresholds.authenticated, self.authenticated_precision)
            && actual < floor
        {
            out.push(format!(
                "`authenticated` precision {actual:.4} is below the floor of {floor:.4}"
            ));
        }
        for score in &self.rules {
            let (Some(floor), Some(actual)) = (thresholds.for_rule(&score.rule), score.precision)
            else {
                continue;
            };
            if actual < floor {
                out.push(format!(
                    "{}: precision {actual:.4} is below the floor of {floor:.4}",
                    score.rule
                ));
            }
        }
        out.sort();
        out
    }

    /// The one-paragraph summary a human reads.
    ///
    /// States the denominator in the same breath as the rate, every time.
    #[must_use]
    pub fn summary(&self) -> String {
        let rate = |value: Option<f64>| {
            value.map_or_else(
                || "n/a".to_owned(),
                |value| format!("{:.1}%", value * 100.0),
            )
        };
        format!(
            "precision {} · recall {} · `authenticated` precision {}\n\
             over {} repositories, {} labels, {} disagreement(s) excluded · {}.{:02}s",
            rate(self.precision),
            rate(self.recall),
            rate(self.authenticated_precision),
            self.corpus.repositories,
            self.corpus.labels,
            self.corpus.disagreements,
            self.duration_ms / 1000,
            (self.duration_ms % 1000) / 10,
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::thresholds::Thresholds;

    fn report(precision: Option<f64>, authenticated: Option<f64>) -> BenchReport {
        BenchReport {
            version: "1.2.0".to_owned(),
            corpus: CorpusSize {
                repositories: 4,
                labels: 120,
                disagreements: 3,
            },
            precision,
            recall: Some(0.7),
            authenticated_precision: authenticated,
            rules: Vec::new(),
            repositories: Vec::new(),
            duration_ms: 4_120,
            reproduce: "npx owlwarden bench --format json".to_owned(),
        }
    }

    #[test]
    fn the_summary_never_states_a_rate_without_its_denominator() {
        // ADR 0030 §4: a precision figure without a denominator is marketing.
        let summary = report(Some(0.93), Some(0.88)).summary();
        assert!(summary.contains("93.0%"));
        assert!(summary.contains("4 repositories"));
        assert!(summary.contains("120 labels"));
        assert!(summary.contains("3 disagreement(s) excluded"));
    }

    #[test]
    fn authenticated_precision_is_reported_separately_from_the_headline() {
        let summary = report(Some(0.93), Some(0.60)).summary();
        assert!(summary.contains("`authenticated` precision 60.0%"));
    }

    #[test]
    fn a_run_below_the_floor_breaches_and_says_by_how_much() {
        let thresholds = Thresholds {
            overall: Some(0.9),
            authenticated: Some(0.95),
            ..Thresholds::default()
        };
        let breaches = report(Some(0.85), Some(0.5)).breaches(&thresholds);
        assert_eq!(breaches.len(), 2);
        assert!(
            breaches
                .iter()
                .any(|line| line.contains("overall precision"))
        );
        assert!(
            breaches
                .iter()
                .any(|line| line.contains("`authenticated` precision"))
        );
    }

    #[test]
    fn a_run_with_no_measurement_does_not_breach() {
        // Precision over nothing is `None`, and `None` must not read as zero:
        // an empty corpus should fail loudly elsewhere, not silently here.
        let thresholds = Thresholds {
            overall: Some(0.9),
            ..Thresholds::default()
        };
        assert!(report(None, None).breaches(&thresholds).is_empty());
    }

    #[test]
    fn rates_are_rounded_so_two_platforms_publish_the_same_bytes() {
        let assembled = BenchReport::assemble(
            &Outcome {
                true_positives: 1,
                false_positives: 2,
                ..Outcome::default()
            },
            BTreeMap::new(),
            Vec::new(),
            CorpusSize::default(),
            0,
        );
        // 1/3 at full precision differs in its last digit between platforms.
        assert_eq!(assembled.precision, Some(0.3333));
    }
}
