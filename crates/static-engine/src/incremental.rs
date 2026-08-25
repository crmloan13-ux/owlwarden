//! Incremental watch: dirty-path validation and finding merge ([ADR 0023]).

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use owlwarden_core::finding::Finding;
use owlwarden_core::limits;
use owlwarden_core::report::{Report, ReportSummary};
use owlwarden_core::source::RelPath;

use crate::RunError;
use crate::rule::ProjectRule;

/// Whether a dirty path forces a full tree rescan.
#[must_use]
pub fn forces_full_rescan(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or(normalized.as_str());

    if base == "package.json" {
        return true;
    }
    if base.starts_with("tsconfig") {
        return true;
    }
    if Path::new(base)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"))
        || base.eq_ignore_ascii_case("Cargo.lock")
        || base == "package-lock.json"
        || base == "pnpm-lock.yaml"
        || base == "bun.lockb"
        || base == "yarn.lock"
    {
        return true;
    }
    normalized.starts_with(".owlwarden/") || normalized == ".owlwarden"
}

/// True when any path in the set requires abandoning incremental mode.
#[must_use]
pub fn any_forces_full_rescan(paths: &[String]) -> bool {
    paths
        .iter()
        .take(limits::incremental::MAX_DIRTY_PATHS)
        .any(|path| forces_full_rescan(path))
}

/// Validates and normalizes dirty paths against `root`.
///
/// Paths may refer to deleted files (canonicalization fails) as long as they
/// cannot escape the project root.
///
/// # Errors
/// [`RunError::InvalidDirtyPaths`] when the list is too long or a path escapes.
pub fn validate_dirty_paths(root: &Path, paths: &[String]) -> Result<Vec<String>, RunError> {
    if paths.len() > limits::incremental::MAX_DIRTY_PATHS {
        return Err(RunError::InvalidDirtyPaths {
            message: format!(
                "too many dirty paths ({}); maximum is {}",
                paths.len(),
                limits::incremental::MAX_DIRTY_PATHS
            ),
        });
    }

    let root = root
        .canonicalize()
        .map_err(|error| RunError::InvalidDirtyPaths {
            message: format!("could not resolve project root: {error}"),
        })?;

    let mut validated = Vec::with_capacity(paths.len().min(limits::incremental::MAX_DIRTY_PATHS));
    let mut seen = HashSet::new();

    for raw in paths.iter().take(limits::incremental::MAX_DIRTY_PATHS) {
        let rel = RelPath::new(Path::new(raw)).map_err(|error| RunError::InvalidDirtyPaths {
            message: format!("{raw}: {error}"),
        })?;
        let key = rel.as_str().to_owned();
        if !seen.insert(key.clone()) {
            continue;
        }

        let joined = root.join(rel.as_str());
        match joined.canonicalize() {
            Ok(canonical) if !canonical.starts_with(&root) => {
                return Err(RunError::InvalidDirtyPaths {
                    message: format!("{raw}: path escapes project root"),
                });
            }
            Ok(_) | Err(_) => validated.push(key),
        }
    }

    Ok(validated)
}

/// Merges cached file-rule findings with a fresh incremental scan.
///
/// Findings from project rules and any path in `dirty_paths` come only from
/// `new_findings`; everything else is retained from `previous`.
#[must_use]
pub fn merge_incremental_findings<S: ::std::hash::BuildHasher>(
    previous: &Report,
    new_findings: Vec<Finding>,
    dirty_paths: &HashSet<String, S>,
    project_rules: &[Arc<dyn ProjectRule>],
) -> Vec<Finding> {
    let project_rule_ids: HashSet<String> = project_rules
        .iter()
        .map(|rule| rule.meta().id.as_str().to_owned())
        .collect();

    let mut merged = Vec::with_capacity(previous.findings.len() + new_findings.len());

    for finding in &previous.findings {
        if project_rule_ids.contains(finding.id.as_str()) {
            continue;
        }
        let Some(location) = finding.location.as_source() else {
            continue;
        };
        if dirty_paths.contains(&location.path) {
            continue;
        }
        merged.push(finding.clone());
    }

    merged.extend(new_findings);

    if merged.len() > limits::scan::MAX_FINDINGS {
        merged.truncate(limits::scan::MAX_FINDINGS);
    }
    merged
}

/// Applies incremental merge to `report` when `previous` and `dirty` are set.
pub fn merge_into_report(
    report: &mut Report,
    previous: &Report,
    dirty_paths: &[String],
    project_rules: &[Arc<dyn ProjectRule>],
) {
    let dirty_set: HashSet<String> = dirty_paths.iter().cloned().collect();
    report.findings = merge_incremental_findings(
        previous,
        std::mem::take(&mut report.findings),
        &dirty_set,
        project_rules,
    );
    report.summary = ReportSummary::of(&report.findings);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::borrow::Cow;

    use owlwarden_core::finding::{
        Confidence, Finding, Location, RuleId, Severity, SourceLocation,
    };
    use owlwarden_core::report::{Report, ReportSummary, SCHEMA_VERSION, ScanTarget, ToolInfo};
    use tempfile::TempDir;

    use super::*;
    use crate::rule::RuleInfo;
    use owlwarden_core::surface::Surface;

    fn source_finding(rule: &'static str, path: &str) -> Finding {
        Finding::builder(RuleId::new_static(rule), Severity::Low, "test")
            .location(Location::Source(SourceLocation {
                path: path.into(),
                line: 1,
                col: 1,
            }))
            .build()
    }

    fn empty_report(findings: Vec<Finding>) -> Report {
        Report {
            schema_version: SCHEMA_VERSION.to_owned(),
            tool: ToolInfo::default(),
            scanned_at: String::new(),
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

    struct DummyProjectRule;
    impl RuleInfo for DummyProjectRule {
        fn meta(&self) -> owlwarden_core::detector::DetectorMeta {
            owlwarden_core::detector::DetectorMeta {
                id: RuleId::new_static("project-rule"),
                title: "project".into(),
                severity: Severity::Info,
                max_confidence: Confidence::Likely,
                owasp: None,
                asi: None,
                cwe: None,
                surface: Surface::WebApp,
                category: "test".into(),
                description: Cow::Borrowed(""),
            }
        }

        fn remediation(&self) -> owlwarden_core::remediation::Remediation {
            owlwarden_core::remediation::Remediation::new(String::new())
        }
    }
    impl ProjectRule for DummyProjectRule {
        fn check(
            &self,
            _project: &crate::Project<'_>,
            _sink: &mut crate::FindingSink,
        ) -> Result<(), owlwarden_core::detector::DetectorError> {
            Ok(())
        }
    }

    #[test]
    fn forces_full_on_manifest_and_config_paths() {
        assert!(forces_full_rescan("package.json"));
        assert!(forces_full_rescan("apps/web/package.json"));
        assert!(forces_full_rescan("pnpm-lock.yaml"));
        assert!(forces_full_rescan("yarn.lock"));
        assert!(forces_full_rescan("tsconfig.json"));
        assert!(forces_full_rescan("tsconfig.build.json"));
        assert!(forces_full_rescan(".owlwarden/config.json"));
        assert!(!forces_full_rescan("src/app.ts"));
    }

    #[test]
    fn escape_in_dirty_paths_is_refused() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        std::fs::write(root.join("app.ts"), "export {}").unwrap();

        let err = validate_dirty_paths(root, &["../../etc/passwd".to_owned()]).unwrap_err();
        assert!(matches!(err, RunError::InvalidDirtyPaths { .. }));
    }

    #[test]
    fn deleted_dirty_path_is_accepted() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let paths = validate_dirty_paths(root, &["gone.ts".to_owned()]).unwrap();
        assert_eq!(paths, vec!["gone.ts"]);
    }

    #[test]
    fn merge_drops_dirty_paths_and_project_rules() {
        let previous = empty_report(vec![
            source_finding("file-rule", "clean.ts"),
            source_finding("file-rule", "dirty.ts"),
            source_finding("project-rule", "package.json"),
        ]);
        let new_findings = vec![
            source_finding("file-rule", "dirty.ts"),
            source_finding("project-rule", "package.json"),
        ];
        let dirty: HashSet<String> = ["dirty.ts".to_owned()].into_iter().collect();
        let project_rules: Vec<Arc<dyn ProjectRule>> = vec![Arc::new(DummyProjectRule)];
        let merged = merge_incremental_findings(&previous, new_findings, &dirty, &project_rules);
        let paths: Vec<&str> = merged
            .iter()
            .filter_map(|finding| finding.location.as_source().map(|loc| loc.path.as_str()))
            .collect();
        assert_eq!(paths, vec!["clean.ts", "dirty.ts", "package.json"]);
    }

    #[test]
    fn any_forces_full_rescan_detects_lockfile() {
        assert!(any_forces_full_rescan(&[
            "src/a.ts".to_owned(),
            "pnpm-lock.yaml".to_owned()
        ]));
        assert!(!any_forces_full_rescan(&["src/a.ts".to_owned()]));
    }

    #[test]
    fn merge_clears_finding_when_dirty_rescan_is_clean() {
        // Wrong-cache / false-negative guard: a finding on a dirty path must
        // disappear when the new scan does not re-emit it.
        let previous = empty_report(vec![
            source_finding("file-rule", "clean.ts"),
            source_finding("file-rule", "fixed.ts"),
        ]);
        let dirty: HashSet<String> = ["fixed.ts".to_owned()].into_iter().collect();
        let project_rules: Vec<Arc<dyn ProjectRule>> = vec![Arc::new(DummyProjectRule)];
        let merged = merge_incremental_findings(&previous, Vec::new(), &dirty, &project_rules);
        let paths: Vec<&str> = merged
            .iter()
            .filter_map(|finding| finding.location.as_source().map(|loc| loc.path.as_str()))
            .collect();
        assert_eq!(paths, vec!["clean.ts"]);
    }

    #[test]
    fn merge_drops_findings_for_deleted_dirty_paths() {
        let previous = empty_report(vec![
            source_finding("file-rule", "keep.ts"),
            source_finding("file-rule", "gone.ts"),
        ]);
        let dirty: HashSet<String> = ["gone.ts".to_owned()].into_iter().collect();
        let project_rules: Vec<Arc<dyn ProjectRule>> = vec![Arc::new(DummyProjectRule)];
        let merged = merge_incremental_findings(&previous, Vec::new(), &dirty, &project_rules);
        let path = merged
            .first()
            .and_then(|finding| finding.location.as_source())
            .map(|loc| loc.path.as_str());
        assert_eq!(path, Some("keep.ts"));
    }
}
