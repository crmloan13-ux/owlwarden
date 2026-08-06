//! Post-scan passes: inline suppressions and baseline filtering.
//!
//! Rules produce every finding they see. These passes decide what the user (or
//! an agent) actually gets. Keeping that decision out of the rules means a
//! rule cannot accidentally bypass a suppression, and the same fingerprint
//! logic applies whether the finding came from a file rule or a project rule.

use owlwarden_core::baseline::{self, BaselineFile};
use owlwarden_core::report::Report;
use owlwarden_core::source::{FileSelector, SourceProvider};
use owlwarden_core::suppression::{self, Directive};

use crate::SUPPORTED_EXTENSIONS;

/// Files considered when collecting suppression comments, beyond the JS/TS
/// tree the engine already walked. Workflow YAML is included so
/// `ci-unpinned-action` can be silenced the same way as a TypeScript finding.
const EXTRA_SUPPRESSION_GLOBS: &[&str] = &[".github/workflows/*.yml", ".github/workflows/*.yaml"];

/// Applies inline suppressions to a finished report.
pub fn apply_suppressions(report: &mut Report, source: &dyn SourceProvider) {
    let directives = collect_directives(source);
    let outcome = suppression::apply(std::mem::take(&mut report.findings), &directives);
    report.findings = outcome.findings;
    report.suppressed_count = outcome.suppressed_count;
    report.suppressions = outcome.records;
    report.summary = owlwarden_core::report::ReportSummary::of(&report.findings);
}

/// Drops findings present in the baseline. Call after [`apply_suppressions`].
pub fn apply_baseline(report: &mut Report, baseline: &BaselineFile) {
    let filtered = baseline::filter(std::mem::take(&mut report.findings), baseline);
    report.findings = filtered.findings;
    report.baseline_hidden_count = filtered.hidden_count;
    report.summary = owlwarden_core::report::ReportSummary::of(&report.findings);
}

/// Applies suppressions (always) and an optional baseline to a finished report.
pub fn apply_trust_filters(
    report: &mut Report,
    source: &dyn SourceProvider,
    baseline: Option<&BaselineFile>,
) {
    apply_suppressions(report, source);
    if let Some(baseline) = baseline {
        apply_baseline(report, baseline);
    }
}

fn collect_directives(source: &dyn SourceProvider) -> Vec<Directive> {
    let mut globs: Vec<String> = SUPPORTED_EXTENSIONS
        .iter()
        .map(|extension| format!("**/*.{extension}"))
        .collect();
    for pattern in EXTRA_SUPPRESSION_GLOBS {
        globs.push((*pattern).to_owned());
    }

    let Ok(files) = source.files(&FileSelector::include(globs)) else {
        return Vec::new();
    };

    let mut directives = Vec::new();
    for file in files.iter().take(owlwarden_core::limits::source::MAX_FILES) {
        if directives.len() >= owlwarden_core::limits::source::MAX_SUPPRESSIONS {
            break;
        }
        let Ok(text) = source.read(file) else {
            continue;
        };
        for directive in suppression::parse_directives(file.path.as_str(), &text) {
            if directives.len() >= owlwarden_core::limits::source::MAX_SUPPRESSIONS {
                break;
            }
            directives.push(directive);
        }
    }
    directives
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use owlwarden_core::finding::{
        Confidence, Finding, Location, RuleId, Severity, SourceLocation,
    };
    use owlwarden_core::report::{Report, ReportSummary, SCHEMA_VERSION, ScanTarget, ToolInfo};
    use owlwarden_core::source::{FileSelector, RelPath, SourceError, SourceFile, SourceProvider};

    use super::*;

    struct MemorySource {
        root: PathBuf,
        files: Vec<(String, String)>,
    }

    impl SourceProvider for MemorySource {
        fn root(&self) -> &Path {
            &self.root
        }

        fn files(&self, selector: &FileSelector) -> Result<Vec<SourceFile>, SourceError> {
            let _ = selector;
            Ok(self
                .files
                .iter()
                .map(|(path, body)| SourceFile {
                    path: RelPath::new(Path::new(path)).unwrap(),
                    size_bytes: body.len() as u64,
                })
                .collect())
        }

        fn read(&self, file: &SourceFile) -> Result<Arc<str>, SourceError> {
            self.files
                .iter()
                .find(|(path, _)| path == file.path.as_str())
                .map(|(_, body)| Arc::<str>::from(body.as_str()))
                .ok_or_else(|| SourceError::PathEscapesRoot {
                    path: file.path.to_string(),
                })
        }
    }

    fn report_with(findings: Vec<Finding>) -> Report {
        Report {
            schema_version: SCHEMA_VERSION.to_owned(),
            tool: ToolInfo::default(),
            scanned_at: "1970-01-01T00:00:00Z".to_owned(),
            duration_ms: 0,
            target: ScanTarget::default(),
            summary: ReportSummary::of(&findings),
            findings,
            suppressed_count: 0,
            suppressions: Vec::new(),
            baseline_hidden_count: 0,
            truncated: false,
            errors: Vec::new(),
        }
    }

    #[test]
    fn suppression_hides_finding_and_records_it() {
        let source = MemorySource {
            root: PathBuf::from("/tmp"),
            files: vec![(
                "a.ts".to_owned(),
                "// owlwarden-disable-next-line stack-trace-leak -- test\nerr.stack\n".to_owned(),
            )],
        };
        let mut report = report_with(vec![
            Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t")
                .confidence(Confidence::Likely)
                .location(Location::Source(SourceLocation {
                    path: "a.ts".to_owned(),
                    line: 2,
                    col: 1,
                }))
                .build(),
        ]);

        apply_suppressions(&mut report, &source);
        assert!(report.findings.is_empty());
        assert_eq!(report.suppressed_count, 1);
        assert_eq!(report.suppressions.len(), 1);
        assert!(!report.suppressions[0].stale);
    }
}
