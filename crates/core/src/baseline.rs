//! Baseline mode — adopt the tool on a legacy codebase without drowning.
//!
//! `--baseline .owlwarden-baseline.json` keeps only findings that are *new*
//! since the baseline was written. Entries key on a fingerprint of rule id,
//! normalised path, and a whitespace-collapsed hash of the evidence (or the
//! highlighted line). Line numbers are deliberately absent: reformatting that
//! shifts a finding down the file must not resurrect debt that was already
//! accepted.
//!
//! This module is pure. Loading and saving the file are the caller's job —
//! core does no I/O (`ARCHITECTURE.md` §3).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::finding::Finding;
use crate::report::now_rfc3339;

/// Wire format version for the baseline file. Bumped on incompatible changes.
pub const SCHEMA_VERSION: &str = "1.0";

/// Maximum entries accepted from a baseline file. Beyond this the load fails
/// rather than silently truncating — a truncated baseline would report
/// previously-accepted findings as new.
pub const MAX_ENTRIES: usize = 50_000;

/// Maximum baseline document size in bytes. Callers must refuse to buffer more
/// than this before calling [`BaselineFile::parse`].
pub const MAX_BASELINE_BYTES: usize = MAX_ENTRIES.saturating_mul(512);

/// Maximum length of a single string field inside a baseline entry.
const MAX_FIELD_BYTES: usize = 1_024;

/// One accepted finding, keyed by fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineEntry {
    /// Stable key. See [`fingerprint`].
    pub fingerprint: String,
    /// Rule id, for humans reading the file.
    pub id: String,
    /// Project-relative path with `/` separators.
    pub path: String,
    /// Finding title at the time it was baselined. Cosmetic.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
}

/// The on-disk baseline document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineFile {
    /// Format version.
    pub schema_version: String,
    /// When the file was written, RFC 3339 UTC.
    pub generated_at: String,
    /// Engine version that wrote it.
    pub tool_version: String,
    /// Accepted findings.
    pub entries: Vec<BaselineEntry>,
}

impl BaselineFile {
    /// Builds a baseline from the findings a user is willing to carry.
    #[must_use]
    pub fn from_findings(findings: &[Finding], tool_version: &str) -> Self {
        let capped: Vec<&Finding> = findings.iter().take(MAX_ENTRIES).collect();
        let mut entries: Vec<BaselineEntry> = with_occurrences(&capped)
            .into_iter()
            .filter_map(|(finding, occurrence)| {
                let path = finding.location.as_source()?.path.clone();
                Some(BaselineEntry {
                    fingerprint: fingerprint_at(finding, occurrence),
                    id: finding.id.to_string(),
                    path,
                    title: finding.title.clone(),
                })
            })
            .collect();
        // Stable order so two writes of the same set are byte-identical aside
        // from `generated_at`.
        entries.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
        entries.dedup_by(|left, right| left.fingerprint == right.fingerprint);

        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            generated_at: now_rfc3339(),
            tool_version: tool_version.to_owned(),
            entries,
        }
    }

    /// Parses a baseline document, enforcing size and shape bounds.
    ///
    /// # Errors
    /// [`BaselineError`] when the JSON is malformed, the schema is unknown, or
    /// the entry count exceeds [`MAX_ENTRIES`].
    pub fn parse(json: &str) -> Result<Self, BaselineError> {
        if json.len() > MAX_BASELINE_BYTES {
            return Err(BaselineError::TooLarge { len: json.len() });
        }
        let file: Self = serde_json::from_str(json).map_err(|source| BaselineError::Parse {
            message: source.to_string(),
        })?;
        if file.schema_version != SCHEMA_VERSION {
            return Err(BaselineError::UnsupportedSchema {
                version: file.schema_version,
            });
        }
        if file.entries.len() > MAX_ENTRIES {
            return Err(BaselineError::TooManyEntries {
                count: file.entries.len(),
            });
        }
        for entry in &file.entries {
            if entry.fingerprint.is_empty() || entry.fingerprint.len() > 64 {
                return Err(BaselineError::InvalidFingerprint {
                    fingerprint: entry.fingerprint.clone(),
                });
            }
            if entry.path.len() > MAX_FIELD_BYTES || entry.title.len() > MAX_FIELD_BYTES {
                return Err(BaselineError::FieldTooLong {
                    path: entry.path.clone(),
                });
            }
            if entry.id.len() > 128 {
                return Err(BaselineError::FieldTooLong {
                    path: entry.path.clone(),
                });
            }
        }
        Ok(file)
    }

    /// Serialises the baseline as indented JSON.
    ///
    /// # Errors
    /// [`BaselineError::Encode`] if serialisation fails (it should not for our
    /// own types).
    pub fn to_json(&self) -> Result<String, BaselineError> {
        serde_json::to_string_pretty(self).map_err(|source| BaselineError::Encode {
            message: source.to_string(),
        })
    }

    /// The set of fingerprints this baseline accepts.
    #[must_use]
    pub fn fingerprint_set(&self) -> BTreeSet<&str> {
        self.entries
            .iter()
            .map(|entry| entry.fingerprint.as_str())
            .collect()
    }
}

/// Why a baseline file could not be used.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BaselineError {
    /// JSON did not match the expected shape.
    #[error("baseline file could not be parsed: {message}")]
    Parse {
        /// Underlying serde message.
        message: String,
    },
    /// Schema version we do not understand.
    #[error("baseline schema {version:?} is not supported (need {need})", need = SCHEMA_VERSION)]
    UnsupportedSchema {
        /// Version found in the file.
        version: String,
    },
    /// Entry count above [`MAX_ENTRIES`].
    #[error("baseline has {count} entries; maximum is {max}", max = MAX_ENTRIES)]
    TooManyEntries {
        /// How many were present.
        count: usize,
    },
    /// Raw file larger than we are willing to buffer.
    #[error("baseline file is {len} bytes; refusing to load")]
    TooLarge {
        /// Byte length.
        len: usize,
    },
    /// A fingerprint failed basic validation.
    #[error("baseline entry has an invalid fingerprint: {fingerprint:?}")]
    InvalidFingerprint {
        /// The offending value.
        fingerprint: String,
    },
    /// A string field in an entry exceeded the per-field cap.
    #[error("baseline entry field too long near path {path:?}")]
    FieldTooLong {
        /// Path of the offending entry (best-effort locator).
        path: String,
    },
    /// Serialisation failed.
    #[error("could not encode baseline: {message}")]
    Encode {
        /// Underlying message.
        message: String,
    },
}

/// Result of filtering a report against a baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineFilter {
    /// Findings whose fingerprint is not in the baseline.
    pub findings: Vec<Finding>,
    /// How many findings the baseline hid.
    pub hidden_count: u32,
}

/// Keeps only findings absent from the baseline.
#[must_use]
pub fn filter(findings: Vec<Finding>, baseline: &BaselineFile) -> BaselineFilter {
    let known = baseline.fingerprint_set();
    let refs: Vec<&Finding> = findings.iter().collect();
    let occurrences: Vec<u32> = with_occurrences(&refs)
        .into_iter()
        .map(|(_, occurrence)| occurrence)
        .collect();
    let mut kept = Vec::with_capacity(findings.len());
    let mut hidden_count = 0u32;
    // `with_occurrences` walks in the same order as `findings`, so zip is safe.
    for (finding, occurrence) in findings.into_iter().zip(occurrences) {
        let key = fingerprint_at(&finding, occurrence);
        if known.contains(key.as_str()) {
            hidden_count = hidden_count.saturating_add(1);
        } else {
            kept.push(finding);
        }
    }
    BaselineFilter {
        findings: kept,
        hidden_count,
    }
}

/// Fingerprint of one finding for baseline matching (first occurrence).
///
/// Prefer [`fingerprint_at`] when more than one finding shares the same
/// material — see [`with_occurrences`].
#[must_use]
pub fn fingerprint(finding: &Finding) -> String {
    fingerprint_at(finding, 0)
}

/// Fingerprint with an occurrence index among findings that share the same
/// material key.
///
/// Composition: hash of `rule id | normalised path | collapsed code |
/// occurrence`. Line numbers stay out so reformatting does not reopen debt;
/// the occurrence index stops two identical `err.stack` findings in one file
/// from collapsing into a single baseline entry.
#[must_use]
pub fn fingerprint_at(finding: &Finding, occurrence: u32) -> String {
    let material = format!("{}|{occurrence}", material_key(finding));
    format!("{:016x}", fnv1a64(material.as_bytes()))
}

/// Stable key shared by findings that would otherwise collide after line
/// numbers are dropped.
fn material_key(finding: &Finding) -> String {
    let path = finding
        .location
        .as_source()
        .map_or("", |location| location.path.as_str());
    let code = normalize_code(&code_material(finding));
    format!("{}|{path}|{code}", finding.id.as_str())
}

/// Assigns a 0-based occurrence index to each finding among peers that share
/// the same [`material_key`], in the order given (report order).
fn with_occurrences<'a>(findings: &[&'a Finding]) -> Vec<(&'a Finding, u32)> {
    let mut counts = std::collections::BTreeMap::<String, u32>::new();
    let mut out = Vec::with_capacity(findings.len());
    for finding in findings {
        let key = material_key(finding);
        let occurrence = counts.get(&key).copied().unwrap_or(0);
        counts.insert(key, occurrence.saturating_add(1));
        out.push((*finding, occurrence));
    }
    out
}

fn code_material(finding: &Finding) -> String {
    if let Some(evidence) = finding.context.evidence.as_deref()
        && !evidence.is_empty()
    {
        return evidence.to_owned();
    }
    if let Some(snippet) = &finding.snippet {
        let highlight_line = snippet.highlight.line;
        if let Some(offset) = highlight_line.checked_sub(snippet.start_line)
            && let Some(line) = snippet.lines.get(offset as usize)
        {
            return line.clone();
        }
    }
    finding.title.clone()
}

/// Collapse runs of whitespace so a reformat that only changes spaces/tabs
/// yields the same hash.
fn normalize_code(code: &str) -> String {
    code.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// FNV-1a 64-bit. Stable across platforms and Rust releases; not cryptographic,
/// which is fine — this is a fingerprint for matching, not a security boundary.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in bytes.iter().take(8 * 1024) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cloned_ref_to_slice_refs
    )]

    use super::*;
    use crate::finding::{
        CodeFrame, Confidence, Highlight, Location, RuleId, Severity, SourceLocation,
    };

    fn finding(rule: &'static str, path: &str, line: u32, evidence: &str) -> Finding {
        Finding::builder(RuleId::new_static(rule), Severity::High, "title")
            .confidence(Confidence::Likely)
            .location(Location::Source(SourceLocation {
                path: path.to_owned(),
                line,
                col: 1,
            }))
            .context(crate::finding::FindingContext {
                evidence: Some(evidence.to_owned()),
                ..crate::finding::FindingContext::default()
            })
            .build()
    }

    #[test]
    fn fingerprint_ignores_line_number() {
        let a = finding("stack-trace-leak", "a.ts", 10, "err.stack");
        let b = finding("stack-trace-leak", "a.ts", 40, "err.stack");
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_survives_whitespace_reformatting() {
        let a = finding("stack-trace-leak", "a.ts", 10, "err.stack");
        let b = finding("stack-trace-leak", "a.ts", 10, "err.stack  ");
        let c = finding("stack-trace-leak", "a.ts", 10, "err.\tstack");
        // evidence is the short form; normalize collapses internal whitespace too
        let spaced = Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t")
            .location(Location::Source(SourceLocation {
                path: "a.ts".to_owned(),
                line: 1,
                col: 1,
            }))
            .snippet(CodeFrame {
                path: "a.ts".to_owned(),
                start_line: 1,
                lines: vec!["  { error:   err.stack },".to_owned()],
                highlight: Highlight {
                    line: 1,
                    start_col: 1,
                    end_col: 10,
                    label: None,
                },
            })
            .build();
        let tight = Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t")
            .location(Location::Source(SourceLocation {
                path: "a.ts".to_owned(),
                line: 1,
                col: 1,
            }))
            .snippet(CodeFrame {
                path: "a.ts".to_owned(),
                start_line: 1,
                lines: vec!["{ error: err.stack },".to_owned()],
                highlight: Highlight {
                    line: 1,
                    start_col: 1,
                    end_col: 10,
                    label: None,
                },
            })
            .build();
        assert_eq!(fingerprint(&a), fingerprint(&b));
        assert_ne!(
            fingerprint(&a),
            fingerprint(&c),
            "dot vs tab-dot is different evidence on purpose"
        );
        assert_eq!(fingerprint(&spaced), fingerprint(&tight));
    }

    #[test]
    fn filter_keeps_only_new_findings() {
        let known = finding("stack-trace-leak", "a.ts", 10, "err.stack");
        let fresh = finding("cors-permissive", "b.ts", 3, "origin: '*'");
        let baseline = BaselineFile::from_findings(&[known.clone()], "0.0.2");
        let result = filter(vec![known, fresh.clone()], &baseline);
        assert_eq!(result.hidden_count, 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].id, fresh.id);
    }

    #[test]
    fn two_identical_findings_in_one_file_get_distinct_fingerprints() {
        let first = finding("stack-trace-leak", "a.ts", 10, "err.stack");
        let second = finding("stack-trace-leak", "a.ts", 40, "err.stack");
        // Same material key (line is ignored) — without an occurrence index
        // baselining one would hide both.
        assert_eq!(material_key(&first), material_key(&second));
        let baseline = BaselineFile::from_findings(std::slice::from_ref(&first), "0.0.2");
        let result = filter(vec![first, second.clone()], &baseline);
        assert_eq!(result.hidden_count, 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].location.as_source().unwrap().line, 40);
    }

    #[test]
    fn round_trips_json() {
        let baseline = BaselineFile::from_findings(
            &[finding("stack-trace-leak", "a.ts", 10, "err.stack")],
            "0.0.2",
        );
        let json = baseline.to_json().unwrap();
        let parsed = BaselineFile::parse(&json).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn rejects_unknown_schema() {
        let json = r#"{"schemaVersion":"9.9","generatedAt":"x","toolVersion":"x","entries":[]}"#;
        assert!(matches!(
            BaselineFile::parse(json),
            Err(BaselineError::UnsupportedSchema { .. })
        ));
    }
}
