//! `known-vulnerable-dependency` — lockfile package with a known OSV advisory.
//!
//! Opt-in only (`--osv`). Without an [`AdvisoryClient`](owlwarden_core::AdvisoryClient)
//! the scheduler skips this detector; catalogue / `explain` / coverage still
//! see it through [`KnownVulnerableDependency`] as a [`RuleInfo`].
//!
//! A06 stays `Partial`: we report what Google OSV returns for resolved
//! versions, not a full offline component inventory (ADR 0016).

use std::sync::Arc;

use async_trait::async_trait;
use owlwarden_core::advisory::{AdvisoryHit, PackageQuery};
use owlwarden_core::context::ScanContext;
use owlwarden_core::detector::{Capabilities, Detector, DetectorError, DetectorKind, DetectorMeta};
use owlwarden_core::finding::{
    Confidence, Finding, FindingContext, Framework, Location, OwaspRef, Reference, RuleId,
    Severity, SourceLocation,
};
use owlwarden_core::limits;
use owlwarden_core::remediation::Remediation;
use owlwarden_static::rule::RuleInfo;

use crate::SUPPORTED_FRAMEWORKS;
use crate::build::finding_builder;
use crate::lockfile::{self, LockfilePackage};

/// The rule id. Permanent public API.
pub const ID: &str = "known-vulnerable-dependency";

/// Catalogue / explain / coverage entry. Findings come only from
/// [`OsvAdvisoryDetector`] when `--osv` wires an advisory client.
#[derive(Debug, Default, Clone, Copy)]
pub struct KnownVulnerableDependency;

impl KnownVulnerableDependency {
    /// Metadata shared with the runtime detector.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Dependency has a known vulnerability".into(),
            severity: Severity::High,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A06:2021")),
            cwe: Some(1395),
            category: "dependencies".into(),
            description: "A lockfile pins a package version that Google OSV reports as \
                          vulnerable. Requires `--osv` (sends package name and version to \
                          api.osv.dev — never source). Upgrade to a fixed release, or accept \
                          the risk with an inline suppression and a reason."
                .into(),
        }
    }
}

impl RuleInfo for KnownVulnerableDependency {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

/// Runtime detector: reads lockfiles, queries OSV, emits findings.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsvAdvisoryDetector;

/// Builds the opt-in detector for `--osv`.
#[must_use]
pub fn osv_detector() -> Arc<dyn Detector> {
    Arc::new(OsvAdvisoryDetector)
}

#[async_trait]
impl Detector for OsvAdvisoryDetector {
    fn meta(&self) -> DetectorMeta {
        KnownVulnerableDependency::meta()
    }

    fn kind(&self) -> DetectorKind {
        DetectorKind::Static
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::source_and_advisory()
    }

    async fn run(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Some(client) = ctx.advisory() else {
            return Err(DetectorError::MissingCapability {
                id: RuleId::new_static(ID),
                capability: "advisory",
            });
        };

        let packages = lockfile::collect_packages(ctx.source());
        if packages.is_empty() {
            return Ok(Vec::new());
        }

        // Deduplicate queries while keeping the first lockfile location.
        let mut seen = std::collections::HashSet::new();
        let mut unique: Vec<LockfilePackage> = Vec::new();
        for package in packages {
            let key = (
                package.query.ecosystem.clone(),
                package.query.name.clone(),
                package.query.version.clone(),
            );
            if !seen.insert(key) {
                continue;
            }
            unique.push(package);
            if unique.len() >= limits::advisory::MAX_PACKAGES {
                break;
            }
        }

        let queries: Vec<PackageQuery> = unique.iter().map(|p| p.query.clone()).collect();
        let hits = client
            .query(&queries)
            .await
            .map_err(|error| DetectorError::Other(format!("advisory lookup failed: {error}")))?;

        let location_by_query: std::collections::HashMap<
            (String, String, String),
            &LockfilePackage,
        > = unique
            .iter()
            .map(|p| {
                (
                    (
                        p.query.ecosystem.clone(),
                        p.query.name.clone(),
                        p.query.version.clone(),
                    ),
                    p,
                )
            })
            .collect();

        let mut findings = Vec::new();
        for hit in hits.into_iter().take(limits::advisory::MAX_FINDINGS) {
            let key = (
                hit.package.ecosystem.clone(),
                hit.package.name.clone(),
                hit.package.version.clone(),
            );
            let loc = location_by_query.get(&key).copied();
            findings.push(build_finding(&hit, loc));
        }
        Ok(findings)
    }
}

fn build_finding(hit: &AdvisoryHit, loc: Option<&LockfilePackage>) -> Finding {
    let meta = KnownVulnerableDependency::meta();
    let path = loc.map_or("package-lock.json", |l| l.path.as_str());
    let line = loc.map_or(1, |l| l.line);
    let id_label = hit
        .cve
        .as_deref()
        .map_or_else(|| hit.id.clone(), |cve| format!("{} ({cve})", hit.id));
    let evidence = truncate(
        &format!(
            "{}@{} — {id_label}: {}",
            hit.package.name, hit.package.version, hit.summary
        ),
        240,
    );

    finding_builder(&meta)
        .confidence(Confidence::Likely)
        .why(format!(
            "OSV reports {id_label} against {}@{} resolved in the lockfile. \
             Upgrade the dependency (and regenerate the lockfile) to a version \
             that does not match this advisory.",
            hit.package.name, hit.package.version
        ))
        .location(Location::Source(SourceLocation {
            path: path.to_owned(),
            line,
            col: 1,
        }))
        .context(FindingContext {
            framework: None,
            route: None,
            method: None,
            evidence: Some(evidence),
        })
        .fixes(remediation().select(&Framework::GENERIC))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, ch) in value.chars().enumerate() {
        if count >= max_chars {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

fn remediation() -> Remediation {
    Remediation::new(
        "Upgrade the package to a version that OSV (or the advisory) marks as fixed, \
         then regenerate the lockfile. Confirm the new version still satisfies your \
         app's API requirements before deploying.",
    )
    .manual_each(
        SUPPORTED_FRAMEWORKS,
        "Bump the dependency in package.json (or override it), reinstall, and \
         re-run `owlwarden scan --osv` to confirm the advisory is gone.",
        "{\n  \"dependencies\": {\n    \"vulnerable-package\": \"^FIXED.VERSION\"\n  }\n}",
    )
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use async_trait::async_trait;
    use owlwarden_core::advisory::{AdvisoryClient, AdvisoryError, AdvisoryHit, PackageQuery};
    use owlwarden_core::budget::Budget;
    use owlwarden_core::context::{ScanContext, ScanSettings};
    use owlwarden_core::scope::DenyAllScope;
    use owlwarden_core::source::{FileSelector, SourceError, SourceFile, SourceProvider};

    use super::*;

    struct MockAdvisoryClient {
        hits: Vec<AdvisoryHit>,
    }

    #[async_trait]
    impl AdvisoryClient for MockAdvisoryClient {
        async fn query(
            &self,
            _queries: &[PackageQuery],
        ) -> Result<Vec<AdvisoryHit>, AdvisoryError> {
            Ok(self.hits.clone())
        }
    }

    struct FixtureSource {
        root: PathBuf,
        files: Vec<(String, String)>,
    }

    impl SourceProvider for FixtureSource {
        fn root(&self) -> &Path {
            &self.root
        }

        fn files(&self, selector: &FileSelector) -> Result<Vec<SourceFile>, SourceError> {
            let mut out = Vec::new();
            for (path, text) in &self.files {
                let name = path.rsplit('/').next().unwrap_or(path);
                let wanted = selector.include.is_empty()
                    || selector
                        .include
                        .iter()
                        .any(|pat| pat == path || pat == name || pat.ends_with(name));
                if wanted {
                    out.push(SourceFile {
                        path: owlwarden_core::source::RelPath::new(Path::new(path))?,
                        size_bytes: text.len() as u64,
                    });
                }
            }
            Ok(out)
        }

        fn read(&self, file: &SourceFile) -> Result<Arc<str>, SourceError> {
            self.files
                .iter()
                .find(|(path, _)| path == file.path.as_str())
                .map(|(_, text)| Arc::<str>::from(text.as_str()))
                .ok_or_else(|| SourceError::PathEscapesRoot {
                    path: file.path.to_string(),
                })
        }
    }

    #[tokio::test]
    async fn mock_client_hit_becomes_a_finding() {
        let lock = r#"{
  "name": "osv-demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "osv-demo", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.19" }
  }
}"#;
        let source = FixtureSource {
            root: PathBuf::from("/tmp/osv-demo"),
            files: vec![("package-lock.json".to_owned(), lock.to_owned())],
        };
        let client = MockAdvisoryClient {
            hits: vec![AdvisoryHit {
                id: "GHSA-test".to_owned(),
                cve: Some("CVE-2021-23337".to_owned()),
                summary: "Command injection in lodash".to_owned(),
                package: PackageQuery {
                    ecosystem: "npm".to_owned(),
                    name: "lodash".to_owned(),
                    version: "4.17.19".to_owned(),
                },
            }],
        };
        let scope = DenyAllScope;
        let budget = Budget::passive();
        let settings = ScanSettings {
            preset: "deep".to_owned(),
            ..ScanSettings::default()
        };
        let ctx =
            ScanContext::with_advisory(&source, None, Some(&client), &scope, &settings, &budget);
        let findings = OsvAdvisoryDetector.run(&ctx).await.unwrap();
        assert_eq!(findings.len(), 1);
        let finding = findings.first().unwrap();
        assert_eq!(finding.id.as_str(), ID);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Likely);
        let Location::Source(loc) = &finding.location else {
            panic!("expected source location");
        };
        assert_eq!(loc.path, "package-lock.json");
        assert!(
            finding
                .context
                .evidence
                .as_deref()
                .is_some_and(|e| e.contains("lodash@4.17.19"))
        );
    }

    #[tokio::test]
    async fn without_advisory_client_reports_missing_capability() {
        let source = FixtureSource {
            root: PathBuf::from("/tmp/empty"),
            files: Vec::new(),
        };
        let scope = DenyAllScope;
        let budget = Budget::passive();
        let settings = ScanSettings::default();
        let ctx = ScanContext::new(&source, None, &scope, &settings, &budget);
        let error = OsvAdvisoryDetector.run(&ctx).await.unwrap_err();
        assert!(matches!(
            error,
            DetectorError::MissingCapability {
                capability: "advisory",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn disk_osv_demo_fixture_fires_with_mock_client() {
        let lock = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/vulnerable/osv-demo/package-lock.json"
        ))
        .expect("osv-demo lockfile");
        let source = FixtureSource {
            root: PathBuf::from("/tmp/osv-demo"),
            files: vec![("package-lock.json".to_owned(), lock)],
        };
        let client = MockAdvisoryClient {
            hits: vec![AdvisoryHit {
                id: "GHSA-demo".to_owned(),
                cve: None,
                summary: "fixture advisory".to_owned(),
                package: PackageQuery {
                    ecosystem: "npm".to_owned(),
                    name: "lodash".to_owned(),
                    version: "4.17.19".to_owned(),
                },
            }],
        };
        let scope = DenyAllScope;
        let budget = Budget::passive();
        let settings = ScanSettings {
            preset: "deep".to_owned(),
            ..ScanSettings::default()
        };
        let ctx =
            ScanContext::with_advisory(&source, None, Some(&client), &scope, &settings, &budget);
        let findings = OsvAdvisoryDetector.run(&ctx).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings.first().unwrap().id.as_str(), ID);
    }

    #[tokio::test]
    async fn disk_osv_demo_clean_is_silent_when_mock_returns_nothing() {
        let lock = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/should-not-fire/osv-demo-clean/package-lock.json"
        ))
        .expect("osv-demo-clean lockfile");
        let source = FixtureSource {
            root: PathBuf::from("/tmp/osv-demo-clean"),
            files: vec![("package-lock.json".to_owned(), lock)],
        };
        let client = MockAdvisoryClient { hits: Vec::new() };
        let scope = DenyAllScope;
        let budget = Budget::passive();
        let settings = ScanSettings::default();
        let ctx =
            ScanContext::with_advisory(&source, None, Some(&client), &scope, &settings, &budget);
        let findings = OsvAdvisoryDetector.run(&ctx).await.unwrap();
        assert!(findings.is_empty());
    }
}
