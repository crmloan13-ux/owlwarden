//! Scoring one repository: what we reported against what the reviewers said.
//!
//! # The two mistakes this module exists to avoid
//!
//! **Counting a disagreement.** A case the reviewers split on is excluded from
//! both numerator and denominator, not resolved in whichever direction flatters
//! the number. A corpus that quietly settled its hard cases would have optimised
//! away exactly the cases that matter.
//!
//! **Counting an unlabelled finding as correct.** A finding nobody reviewed is
//! *unlabelled*, and it is counted as such and reported. Treating it as a true
//! positive would let precision rise by finding more things nobody checked,
//! which is the opposite of what the number is for.

use owlwarden_core::finding::Finding;

use crate::corpus::{GroundTruth, Verdict};

/// What one repository's scan scored against its labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Reported, and labelled as real.
    pub true_positives: u32,
    /// Reported, and labelled as noise. The number this exists to publish.
    pub false_positives: u32,
    /// Labelled as real, and not reported.
    pub false_negatives: u32,
    /// Reported, and nobody has reviewed it yet.
    ///
    /// Excluded from precision. Reported so the reader can see how much of the
    /// output the number does *not* describe — a precision figure over a
    /// tenth of the findings is a statistic about a tenth of the findings.
    pub unlabelled: u32,
    /// Reported, and excluded because the reviewers disagreed.
    pub disagreements: u32,
    /// Classified `authenticated` and labelled real.
    pub authenticated_true: u32,
    /// Classified `authenticated` and labelled noise.
    ///
    /// Tracked separately per [ADR 0029](../../../docs/adr/0029-exposure-model.md)
    /// §2, because a finding wrongly marked as behind auth is a finding somebody
    /// deprioritises. It is the metric most likely to be embarrassing, which is
    /// why it is the one published on its own.
    pub authenticated_false: u32,
    /// Every false positive, with where it was, because a number nobody can
    /// inspect is a number nobody trusts.
    pub false_positive_locations: Vec<String>,
}

impl Outcome {
    /// Of what we reported and that was reviewed, how much was real.
    ///
    /// `None` when nothing reviewed was reported: a precision of 1.0 over zero
    /// findings is not a measurement, and rendering it as one would be the most
    /// flattering possible lie.
    #[must_use]
    pub fn precision(&self) -> Option<f64> {
        let judged = self.true_positives.saturating_add(self.false_positives);
        (judged > 0).then(|| f64::from(self.true_positives) / f64::from(judged))
    }

    /// Of what is labelled real, how much we found.
    #[must_use]
    pub fn recall(&self) -> Option<f64> {
        let labelled = self.true_positives.saturating_add(self.false_negatives);
        (labelled > 0).then(|| f64::from(self.true_positives) / f64::from(labelled))
    }

    /// Precision restricted to findings we called `authenticated`.
    #[must_use]
    pub fn authenticated_precision(&self) -> Option<f64> {
        let judged = self
            .authenticated_true
            .saturating_add(self.authenticated_false);
        (judged > 0).then(|| f64::from(self.authenticated_true) / f64::from(judged))
    }

    /// Folds another repository's outcome into this one.
    pub fn merge(&mut self, other: &Self) {
        self.true_positives = self.true_positives.saturating_add(other.true_positives);
        self.false_positives = self.false_positives.saturating_add(other.false_positives);
        self.false_negatives = self.false_negatives.saturating_add(other.false_negatives);
        self.unlabelled = self.unlabelled.saturating_add(other.unlabelled);
        self.disagreements = self.disagreements.saturating_add(other.disagreements);
        self.authenticated_true = self
            .authenticated_true
            .saturating_add(other.authenticated_true);
        self.authenticated_false = self
            .authenticated_false
            .saturating_add(other.authenticated_false);
        self.false_positive_locations
            .extend(other.false_positive_locations.iter().cloned());
    }
}

/// Scores one scan against one ground-truth file.
///
/// `rule_filter` restricts scoring to one rule, for `bench --rule`.
#[must_use]
pub fn score_entry(
    findings: &[Finding],
    truth: &GroundTruth,
    rule_filter: Option<&str>,
) -> Outcome {
    let mut outcome = Outcome::default();
    let wanted = |rule: &str| rule_filter.is_none_or(|only| only == rule);

    for finding in findings {
        let rule = finding.id.to_string();
        if !wanted(&rule) {
            continue;
        }
        let Some(location) = finding.location.as_source() else {
            // A dynamic finding has no file to label against. Out of scope for
            // this corpus rather than silently scored.
            continue;
        };

        if truth.is_disagreement(&location.path, location.line) {
            outcome.disagreements = outcome.disagreements.saturating_add(1);
            continue;
        }

        match truth.label_for(&rule, &location.path, location.line) {
            None => outcome.unlabelled = outcome.unlabelled.saturating_add(1),
            Some(label) => {
                let authenticated =
                    finding.exposure == Some(owlwarden_core::finding::Exposure::Authenticated);
                match label.verdict {
                    Verdict::TruePositive => {
                        outcome.true_positives = outcome.true_positives.saturating_add(1);
                        if authenticated {
                            outcome.authenticated_true =
                                outcome.authenticated_true.saturating_add(1);
                        }
                    }
                    Verdict::FalsePositive => {
                        outcome.false_positives = outcome.false_positives.saturating_add(1);
                        outcome
                            .false_positive_locations
                            .push(format!("{rule} {}:{}", location.path, location.line));
                        if authenticated {
                            outcome.authenticated_false =
                                outcome.authenticated_false.saturating_add(1);
                        }
                    }
                }
            }
        }
    }

    // Anything labelled real that we did not report.
    for label in &truth.findings {
        if label.verdict != Verdict::TruePositive || !wanted(&label.rule) {
            continue;
        }
        let reported = findings.iter().any(|finding| {
            finding.id.as_str() == label.rule
                && finding.location.as_source().is_some_and(|location| {
                    location.path == label.path && location.line == label.line
                })
        });
        if !reported {
            outcome.false_negatives = outcome.false_negatives.saturating_add(1);
        }
    }

    // Sorted, because the published list must be byte-identical between runs
    // and between platforms.
    outcome.false_positive_locations.sort();
    outcome
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use owlwarden_core::finding::{
        Exposure, ExposureEvidence, Finding, Location, RuleId, Severity, SourceLocation,
    };

    use crate::corpus::{Disagreement, LabelledFinding};

    fn finding(rule: &'static str, path: &str, line: u32) -> Finding {
        Finding::builder(RuleId::new_static(rule), Severity::High, "t")
            .location(Location::Source(SourceLocation {
                path: path.to_owned(),
                line,
                col: 1,
            }))
            .build()
    }

    fn label(rule: &str, path: &str, line: u32, verdict: Verdict) -> LabelledFinding {
        LabelledFinding {
            rule: rule.to_owned(),
            path: path.to_owned(),
            line,
            verdict,
            exposure: None,
            note: "reviewed".to_owned(),
        }
    }

    fn truth(findings: Vec<LabelledFinding>, disagreements: Vec<Disagreement>) -> GroundTruth {
        GroundTruth {
            repo: "r".to_owned(),
            commit: "abcdef1".to_owned(),
            licence: "MIT".to_owned(),
            framework: "express".to_owned(),
            runtime: None,
            labelled_by: vec!["a".to_owned(), "b".to_owned()],
            labelled_at: "2026-08-27".to_owned(),
            findings,
            disagreements,
        }
    }

    #[test]
    fn precision_counts_only_what_was_reviewed() {
        let outcome = score_entry(
            &[
                finding("ssrf", "a.ts", 1),
                finding("ssrf", "b.ts", 2),
                finding("ssrf", "c.ts", 3),
            ],
            &truth(
                vec![
                    label("ssrf", "a.ts", 1, Verdict::TruePositive),
                    label("ssrf", "b.ts", 2, Verdict::FalsePositive),
                ],
                Vec::new(),
            ),
            None,
        );
        assert_eq!(outcome.true_positives, 1);
        assert_eq!(outcome.false_positives, 1);
        assert_eq!(outcome.unlabelled, 1, "c.ts was never reviewed");
        assert!((outcome.precision().unwrap() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn a_disagreement_is_excluded_from_both_sides() {
        // ADR 0030 §1. Resolving it either way would be optimising away the
        // case that most deserves to be counted as uncertain.
        let outcome = score_entry(
            &[finding("ssrf", "a.ts", 1), finding("ssrf", "b.ts", 9)],
            &truth(
                vec![label("ssrf", "a.ts", 1, Verdict::TruePositive)],
                vec![Disagreement {
                    path: "b.ts".to_owned(),
                    line: 9,
                    note: "reviewers split on whether the allowlist is sufficient".to_owned(),
                }],
            ),
            None,
        );
        assert_eq!(outcome.disagreements, 1);
        assert_eq!(outcome.true_positives, 1);
        assert_eq!(outcome.false_positives, 0);
        assert_eq!(outcome.unlabelled, 0, "a disagreement is not unlabelled");
        assert!((outcome.precision().unwrap() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_labelled_finding_we_missed_is_a_false_negative() {
        let outcome = score_entry(
            &[],
            &truth(
                vec![label("sql-injection", "a.ts", 1, Verdict::TruePositive)],
                Vec::new(),
            ),
            None,
        );
        assert_eq!(outcome.false_negatives, 1);
        assert_eq!(outcome.recall(), Some(0.0));
        assert_eq!(
            outcome.precision(),
            None,
            "nothing reported, nothing judged"
        );
    }

    #[test]
    fn precision_over_nothing_is_none_rather_than_one() {
        // The most flattering possible lie: a scanner that reported nothing
        // would otherwise publish 100% precision.
        let outcome = score_entry(&[], &truth(Vec::new(), Vec::new()), None);
        assert_eq!(outcome.precision(), None);
        assert_eq!(outcome.authenticated_precision(), None);
    }

    #[test]
    fn authenticated_precision_is_tracked_on_its_own() {
        let mut gated = finding("insecure-cookie", "a.ts", 1);
        gated.exposure = Some(Exposure::Authenticated);
        gated.exposure_evidence = Some(ExposureEvidence::default());
        let mut also_gated = finding("insecure-cookie", "b.ts", 2);
        also_gated.exposure = Some(Exposure::Authenticated);

        let outcome = score_entry(
            &[gated, also_gated],
            &truth(
                vec![
                    label("insecure-cookie", "a.ts", 1, Verdict::TruePositive),
                    label("insecure-cookie", "b.ts", 2, Verdict::FalsePositive),
                ],
                Vec::new(),
            ),
            None,
        );
        assert_eq!(outcome.authenticated_true, 1);
        assert_eq!(outcome.authenticated_false, 1);
        assert!((outcome.authenticated_precision().unwrap() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn a_rule_filter_scores_only_that_rule() {
        let outcome = score_entry(
            &[
                finding("ssrf", "a.ts", 1),
                finding("open-redirect", "b.ts", 2),
            ],
            &truth(
                vec![
                    label("ssrf", "a.ts", 1, Verdict::TruePositive),
                    label("open-redirect", "b.ts", 2, Verdict::FalsePositive),
                ],
                Vec::new(),
            ),
            Some("ssrf"),
        );
        assert_eq!(outcome.true_positives, 1);
        assert_eq!(outcome.false_positives, 0);
    }

    #[test]
    fn the_false_positive_list_is_sorted_for_reproducibility() {
        let outcome = score_entry(
            &[
                finding("ssrf", "z.ts", 1),
                finding("ssrf", "a.ts", 1),
                finding("ssrf", "m.ts", 1),
            ],
            &truth(
                vec![
                    label("ssrf", "z.ts", 1, Verdict::FalsePositive),
                    label("ssrf", "a.ts", 1, Verdict::FalsePositive),
                    label("ssrf", "m.ts", 1, Verdict::FalsePositive),
                ],
                Vec::new(),
            ),
            None,
        );
        let mut sorted = outcome.false_positive_locations.clone();
        sorted.sort();
        assert_eq!(outcome.false_positive_locations, sorted);
    }
}
