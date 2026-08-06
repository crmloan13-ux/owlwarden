//! `ci-unpinned-action` — a GitHub Action referenced by a moving tag.
//!
//! # Why this belongs under A08
//!
//! Software and Data Integrity Failures covers supply-chain trust in the build.
//! `uses: actions/checkout@v4` (or `@main`) resolves to whatever that tag points
//! at on the day the workflow runs. An attacker who moves the tag, or a
//! compromised maintainer who pushes a new one, runs code in your CI with your
//! secrets. Pinning the 40-character commit SHA makes the reference immutable.
//!
//! Parsed with a line scanner rather than a YAML library on purpose: we only
//! need `uses:` lines, and a full YAML dependency is not worth the install
//! footprint for one pattern (`ARCHITECTURE.md` § dependency posture).

use owlwarden_core::detector::{DetectorError, DetectorMeta};
use owlwarden_core::finding::{
    Confidence, Finding, FindingContext, Framework, Location, OwaspRef, Reference, RuleId,
    Severity, SourceLocation,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::FileSelector;
use owlwarden_static::project::Project;
use owlwarden_static::rule::{FindingSink, ProjectRule, RuleInfo};

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "ci-unpinned-action";

/// Workflows scanned per project.
const MAX_WORKFLOW_FILES: usize = 64;
/// Findings per scan.
const MAX_FINDINGS: usize = 64;
/// Cap on action name / ref length kept in evidence. A hostile workflow line can
/// be almost `MAX_FILE_BYTES` long; without this the report itself becomes a
/// memory exhaustion gadget.
const MAX_REF_CHARS: usize = 128;

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct CiUnpinnedAction;

impl CiUnpinnedAction {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "GitHub Action is not pinned to a commit SHA",
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A08:2021")),
            cwe: Some(829),
            category: "ci",
            description: "A workflow references a GitHub Action by a branch or version tag. Tags \
                          move; a compromised or hijacked tag runs attacker-controlled code in CI \
                          with repository secrets. Pin the full commit SHA.",
        }
    }
}

impl RuleInfo for CiUnpinnedAction {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl ProjectRule for CiUnpinnedAction {
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink) -> Result<(), DetectorError> {
        let selector = FileSelector::include([
            ".github/workflows/*.yml".to_owned(),
            ".github/workflows/*.yaml".to_owned(),
        ]);
        let Ok(files) = project.source().files(&selector) else {
            return Ok(());
        };

        let mut emitted = 0usize;
        for file in files.iter().take(MAX_WORKFLOW_FILES) {
            if emitted >= MAX_FINDINGS {
                break;
            }
            let Ok(text) = project.source().read(file) else {
                continue;
            };
            for hit in scan_workflow(file.path.as_str(), &text)
                .into_iter()
                .take(MAX_FINDINGS.saturating_sub(emitted))
            {
                if !sink.push(build_finding(project.framework(), &hit)) {
                    return Ok(());
                }
                emitted = emitted.saturating_add(1);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Hit {
    path: String,
    line: u32,
    action: String,
    reference: String,
}

fn scan_workflow(path: &str, source: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (index, raw) in source.lines().enumerate() {
        if hits.len() >= MAX_FINDINGS {
            break;
        }
        let Some((action, reference)) = parse_uses_line(raw) else {
            continue;
        };
        if is_commit_sha(&reference) {
            continue;
        }
        // Local actions (`./.github/actions/foo`) have no @ref.
        if reference.is_empty() {
            continue;
        }
        hits.push(Hit {
            path: path.to_owned(),
            line: u32::try_from(index + 1).unwrap_or(1),
            action: truncate_chars(&action, MAX_REF_CHARS),
            reference: truncate_chars(&reference, MAX_REF_CHARS),
        });
    }
    hits
}

fn truncate_chars(value: &str, max: usize) -> String {
    let mut out = String::new();
    for (count, ch) in value.chars().enumerate() {
        if count >= max {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

/// Pulls `owner/name` and `ref` out of a `uses:` line.
fn parse_uses_line(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    // Ignore comments.
    if trimmed.starts_with('#') {
        return None;
    }
    let without_dash = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim_start();
    let value = without_dash.strip_prefix("uses:")?.trim();
    // Drop a trailing `# comment` before looking at quotes — pinning a SHA and
    // keeping the human tag in a comment is the recommended form.
    let value = value
        .split_once('#')
        .map_or(value, |(value, _)| value)
        .trim();
    let value = value.trim_matches(|ch| ch == '"' || ch == '\'');
    // Docker and local actions are out of scope for this rule.
    if value.starts_with("docker://") || value.starts_with("./") || value.starts_with("../") {
        return None;
    }
    let (action, reference) = value.split_once('@')?;
    let reference = reference.trim();
    if action.is_empty() || !action.contains('/') {
        return None;
    }
    Some((action.to_owned(), reference.to_owned()))
}

fn is_commit_sha(reference: &str) -> bool {
    reference.len() == 40 && reference.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn build_finding(framework: &Framework, hit: &Hit) -> Finding {
    let meta = CiUnpinnedAction::meta();
    finding_builder(&meta)
        .confidence(Confidence::Likely)
        .why(
            "A moving tag can be retargeted to a different commit. Anyone who can push that tag \
             — or who compromises the action's repository — runs code in your CI with access to \
             repository secrets.",
        )
        .location(Location::Source(SourceLocation {
            path: hit.path.clone(),
            line: hit.line,
            col: 1,
        }))
        .context(FindingContext {
            framework: Some(framework.clone()),
            route: None,
            method: None,
            evidence: Some(format!("{}@{}", hit.action, hit.reference)),
        })
        .fixes(remediation().select(framework))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

fn remediation() -> Remediation {
    // The fix is the same for every framework: pin the SHA. The table still
    // needs one entry per supported framework so the coverage test stays honest.
    let patch = "uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1";
    let summary = "Pin the action to a full commit SHA (keep the tag in a comment for humans).";
    Remediation::new(summary)
        .manual(Framework::NEXT, summary, patch)
        .manual(Framework::NUXT, summary, patch)
        .manual(Framework::NEST, summary, patch)
        .manual(Framework::EXPRESS, summary, patch)
        .manual(Framework::FASTIFY, summary, patch)
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn pins_and_tags_are_classified() {
        assert!(is_commit_sha("b4ffde65f46336ab88eb53be808477a3936bae11"));
        assert!(!is_commit_sha("v4"));
        assert!(!is_commit_sha("main"));
        assert!(!is_commit_sha("b4ffde65")); // short SHA — still movable enough
    }

    #[test]
    fn parses_common_uses_spellings() {
        let (action, reference) = parse_uses_line("      - uses: actions/checkout@v4").unwrap();
        assert_eq!(action, "actions/checkout");
        assert_eq!(reference, "v4");

        let (action, reference) = parse_uses_line("uses: \"actions/setup-node@main\"").unwrap();
        assert_eq!(action, "actions/setup-node");
        assert_eq!(reference, "main");

        assert!(parse_uses_line("      - uses: ./local-action").is_none());
    }

    #[test]
    fn sha_with_human_tag_comment_is_pinned() {
        let hits = scan_workflow(
            "ci.yml",
            "uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1\n",
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn short_sha_still_fires() {
        let hits = scan_workflow("ci.yml", "uses: actions/checkout@b4ffde65\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].reference, "b4ffde65");
    }

    #[test]
    fn evidence_from_a_huge_uses_line_is_truncated() {
        let huge_ref = "a".repeat(10_000);
        let line = format!("uses: evil/action@{huge_ref}\n");
        let hits = scan_workflow("ci.yml", &line);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].reference.chars().count() <= MAX_REF_CHARS + 1); // + ellipsis
        assert!(hits[0].reference.ends_with('…'));
    }
}
