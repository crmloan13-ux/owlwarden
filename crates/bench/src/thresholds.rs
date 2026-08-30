//! `bench/thresholds.toml` — precision as a build invariant.
//!
//! A pull request that drops corpus precision below the threshold fails,
//! exactly as a rule shipping without a remediation cell fails today.
//!
//! # The asymmetry that makes the number mean something
//!
//! **Raising a threshold is a normal change. Lowering one requires a note in
//! the file explaining what was traded and why**, and this module refuses to
//! load a file where a threshold was lowered without one.
//!
//! That is the same pattern as suppressions requiring a mandatory reason,
//! applied to the project's own standards. Without it, precision is a statistic
//! that drifts down one acceptable increment at a time, and nobody is ever the
//! person who lowered it.
//!
//! # Why only precision gates the build
//!
//! Recall is bounded by what has been *labelled*, so a recall threshold mostly
//! measures corpus growth rather than the tool. Recall is published; only
//! precision gates ([ADR 0030](../../../docs/adr/0030-published-benchmark.md)).

use std::collections::BTreeMap;
use std::path::Path;

/// Largest thresholds file read.
pub const MAX_BYTES: u64 = 256 * 1024;

/// The floors a run must clear.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Thresholds {
    /// Overall corpus precision, 0.0 to 1.0.
    pub overall: Option<f64>,
    /// `authenticated` precision, floored separately because it is the metric
    /// most likely to be embarrassing.
    pub authenticated: Option<f64>,
    /// Per-rule floors.
    pub per_rule: BTreeMap<String, f64>,
    /// Notes recorded against a lowering, keyed the same way.
    ///
    /// `overall` and `authenticated` use those literal keys.
    pub notes: BTreeMap<String, String>,
}

/// The thresholds file could not be read, or breaks its own rule.
#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    /// The file could not be read.
    #[error("{path}: {message}")]
    Io {
        /// The file.
        path: String,
        /// What went wrong.
        message: String,
    },
    /// A line could not be parsed.
    #[error("{path}:{line}: {message}")]
    Malformed {
        /// The file.
        path: String,
        /// 1-based line.
        line: usize,
        /// What went wrong.
        message: String,
    },
    /// A threshold moved down with no explanation.
    #[error(
        "{path}: {key} was lowered to {value} with no `# note:` line above it. \
         Lowering a threshold is a decision; record what was traded and why, the same way a \
         suppression records its reason."
    )]
    UnexplainedLowering {
        /// The file.
        path: String,
        /// Which threshold.
        key: String,
        /// The new value.
        value: f64,
    },
}

impl Thresholds {
    /// The floor for one rule, or the overall floor.
    #[must_use]
    pub fn for_rule(&self, rule: &str) -> Option<f64> {
        self.per_rule.get(rule).copied().or(self.overall)
    }
}

/// Reads `bench/thresholds.toml`.
///
/// A deliberately small parser rather than a TOML dependency: the file is a
/// dozen `key = value` lines with `# note:` comments above them, and a security
/// tool's install footprint is part of its argument
/// ([ADR 0009](../../../docs/adr/0009-minimal-dependencies.md)). The note
/// association — a note applies to the key on the next non-blank line — is not
/// something a general TOML parser would give us anyway.
///
/// # Errors
/// [`ThresholdError`] when the file cannot be read, a line is malformed, or a
/// threshold was lowered without a note.
pub fn load(path: &Path, previous: Option<&Thresholds>) -> Result<Thresholds, ThresholdError> {
    let display = path.display().to_string();
    let metadata = std::fs::metadata(path).map_err(|error| ThresholdError::Io {
        path: display.clone(),
        message: error.to_string(),
    })?;
    if metadata.len() > MAX_BYTES {
        return Err(ThresholdError::Io {
            path: display,
            message: format!("larger than {MAX_BYTES} bytes"),
        });
    }
    let text = std::fs::read_to_string(path).map_err(|error| ThresholdError::Io {
        path: display.clone(),
        message: error.to_string(),
    })?;
    parse(&text, &display, previous)
}

/// [`load`] from text, so the rule can be tested without a filesystem.
///
/// # Errors
/// As [`load`].
pub fn parse(
    text: &str,
    display: &str,
    previous: Option<&Thresholds>,
) -> Result<Thresholds, ThresholdError> {
    let mut thresholds = Thresholds::default();
    let mut pending_note: Option<String> = None;

    for (index, raw) in text.lines().enumerate().take(4096) {
        let line = raw.trim();
        let number = index.saturating_add(1);

        if line.is_empty() {
            continue;
        }
        if let Some(note) = line.strip_prefix("# note:") {
            pending_note = Some(note.trim().to_owned());
            continue;
        }
        if line.starts_with('#') || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(ThresholdError::Malformed {
                path: display.to_owned(),
                line: number,
                message: "expected `key = value`".to_owned(),
            });
        };
        let key = key.trim().trim_matches('"').to_owned();
        let value: f64 = value
            .trim()
            .parse()
            .map_err(|_| ThresholdError::Malformed {
                path: display.to_owned(),
                line: number,
                message: "expected a number between 0 and 1".to_owned(),
            })?;
        if !(0.0..=1.0).contains(&value) {
            return Err(ThresholdError::Malformed {
                path: display.to_owned(),
                line: number,
                message: "a precision threshold is between 0 and 1".to_owned(),
            });
        }

        if let Some(note) = pending_note.take() {
            thresholds.notes.insert(key.clone(), note);
        }
        match key.as_str() {
            "overall" => thresholds.overall = Some(value),
            "authenticated" => thresholds.authenticated = Some(value),
            _ => {
                thresholds.per_rule.insert(key, value);
            }
        }
    }

    if let Some(previous) = previous {
        check_no_silent_lowering(&thresholds, previous, display)?;
    }
    Ok(thresholds)
}

/// Refuses any threshold that moved down without a note.
fn check_no_silent_lowering(
    current: &Thresholds,
    previous: &Thresholds,
    display: &str,
) -> Result<(), ThresholdError> {
    let mut pairs: Vec<(String, Option<f64>, Option<f64>)> = vec![
        ("overall".to_owned(), current.overall, previous.overall),
        (
            "authenticated".to_owned(),
            current.authenticated,
            previous.authenticated,
        ),
    ];
    for (rule, value) in &current.per_rule {
        pairs.push((
            rule.clone(),
            Some(*value),
            previous.per_rule.get(rule).copied(),
        ));
    }

    for (key, now, before) in pairs {
        let (Some(now), Some(before)) = (now, before) else {
            continue;
        };
        if now < before && !current.notes.contains_key(&key) {
            return Err(ThresholdError::UnexplainedLowering {
                path: display.to_owned(),
                key,
                value: now,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_note_attaches_to_the_key_below_it() {
        let parsed = parse(
            "# note: traded precision for the SvelteKit loader shape\noverall = 0.9\n",
            "t.toml",
            None,
        )
        .unwrap();
        assert_eq!(parsed.overall, Some(0.9));
        assert_eq!(
            parsed.notes.get("overall").map(String::as_str),
            Some("traded precision for the SvelteKit loader shape")
        );
    }

    #[test]
    fn lowering_without_a_note_is_refused() {
        // The whole reason this file is parsed rather than read: without it,
        // precision drifts down one acceptable increment at a time and nobody
        // is ever the person who lowered it.
        let before = parse("overall = 0.95\n", "t.toml", None).unwrap();
        let error = parse("overall = 0.80\n", "t.toml", Some(&before)).unwrap_err();
        assert!(matches!(error, ThresholdError::UnexplainedLowering { .. }));
        assert!(error.to_string().contains("what was traded"));
    }

    #[test]
    fn lowering_with_a_note_is_allowed() {
        let before = parse("overall = 0.95\n", "t.toml", None).unwrap();
        let after = parse(
            "# note: ssrf now covers `got`, which the corpus labels harshly\noverall = 0.80\n",
            "t.toml",
            Some(&before),
        );
        assert!(after.is_ok());
    }

    #[test]
    fn raising_a_threshold_needs_no_note() {
        let before = parse("overall = 0.80\n", "t.toml", None).unwrap();
        assert!(parse("overall = 0.95\n", "t.toml", Some(&before)).is_ok());
    }

    #[test]
    fn a_per_rule_floor_overrides_the_overall_one() {
        let parsed = parse("overall = 0.9\nssrf = 0.75\n", "t.toml", None).unwrap();
        assert_eq!(parsed.for_rule("ssrf"), Some(0.75));
        assert_eq!(parsed.for_rule("open-redirect"), Some(0.9));
    }

    #[test]
    fn a_threshold_outside_zero_to_one_is_refused() {
        for body in ["overall = 1.5\n", "overall = -0.2\n", "overall = high\n"] {
            assert!(parse(body, "t.toml", None).is_err(), "accepted {body:?}");
        }
    }

    #[test]
    fn section_headers_and_ordinary_comments_are_skipped() {
        let parsed = parse(
            "# owlwarden precision floors\n[rules]\nssrf = 0.8\n",
            "t.toml",
            None,
        )
        .unwrap();
        assert_eq!(parsed.per_rule.get("ssrf"), Some(&0.8));
    }
}
