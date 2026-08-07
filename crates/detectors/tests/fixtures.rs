//! End-to-end rule behaviour against the fixture projects.
//!
//! Two halves, and the second is the one that matters more:
//!
//! - `fixtures/vulnerable/` must produce exactly the findings we claim.
//! - `fixtures/should-not-fire/` must produce **nothing**. Any finding here
//!   fails the build, because precision is a tested property of this project,
//!   not an aspiration (`ARCHITECTURE.md` §10).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use owlwarden_core::context::ScanSettings;
use owlwarden_core::finding::{Confidence, Location, Severity};
use owlwarden_core::report::Report;

/// Resolves a path under `fixtures/`, from the workspace root.
fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

/// Scans a fixture with every built-in rule enabled.
async fn scan(relative: &str) -> Report {
    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset("deep");
    owlwarden_static::scan_project(
        fixture(relative),
        file_rules,
        project_rules,
        ScanSettings {
            preset: "deep".to_owned(),
            ..ScanSettings::default()
        },
    )
    .await
    .expect("fixture scan should complete")
}

/// The findings of one rule, in report order.
fn of_rule<'a>(report: &'a Report, rule: &str) -> Vec<&'a owlwarden_core::finding::Finding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.id.as_str() == rule)
        .collect()
}

#[tokio::test]
async fn next_fixture_reports_the_stack_trace_leak_with_a_code_frame() {
    let report = scan("vulnerable/next-api").await;
    let leaks = of_rule(&report, "stack-trace-leak");
    assert_eq!(leaks.len(), 1, "expected exactly one leak, got {leaks:?}");

    let leak = leaks.first().unwrap();
    assert_eq!(leak.severity, Severity::High);
    assert_eq!(
        leak.confidence,
        Confidence::Likely,
        "the binding comes from a catch clause, so this is not a guess"
    );

    let Location::Source(location) = &leak.location else {
        panic!("a static finding must have a source location");
    };
    assert_eq!(location.path, "app/api/users/route.ts");
    assert_eq!(location.line, 20, "the line holding `err.stack`");

    let frame = leak.snippet.as_ref().expect("a code frame is the whole DX");
    assert!(
        frame.lines.iter().any(|line| line.contains("err.stack")),
        "the frame must contain the offending line: {:?}",
        frame.lines
    );
    assert_eq!(frame.highlight.line, 20);
    assert_eq!(
        frame.highlight.label.as_deref(),
        Some("leaks internal stack trace to the client")
    );

    assert_eq!(leak.context.route.as_deref(), Some("/api/users"));
    assert_eq!(leak.context.method.as_deref(), Some("GET"));
    assert_eq!(leak.cwe, Some(209));
    assert_eq!(leak.owasp.as_ref().map(|c| c.as_str()), Some("A05:2021"));
}

#[tokio::test]
async fn next_fixture_reports_missing_headers_at_low_confidence() {
    let report = scan("vulnerable/next-api").await;
    let headers = of_rule(&report, "security-headers-missing");
    assert_eq!(headers.len(), 1);

    let finding = headers.first().unwrap();
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(
        finding.confidence,
        Confidence::Possible,
        "with no header configuration at all, a CDN may be setting them — say so"
    );

    let fix = finding.primary_fix().expect("a fix for the detected stack");
    assert!(
        fix.patch
            .as_deref()
            .is_some_and(|patch| patch.contains("async headers()")),
        "the Next.js fix must be copy-pasteable"
    );
}

/// One fixture project and the rules it must produce.
///
/// The point of a table rather than a test per framework: adding a framework is
/// a row, and a rule that quietly stops working on one framework while still
/// passing on another fails here. Support for every framework in
/// `SUPPORTED_FRAMEWORKS` is a property CI enforces, not a sentence in the README.
struct Expectation {
    framework: &'static str,
    vulnerable: &'static str,
    clean: &'static str,
    /// Rule ids that must fire in `vulnerable`, with how many times.
    ///
    /// The count is part of the expectation. A rule that starts firing twice on
    /// the same line is as broken as one that stops firing, and only the count
    /// catches it.
    fires: &'static [(&'static str, usize)],
}

/// Every catalogue rule × every supported framework — same counts, no kitchen
/// sink. `weak-crypto` is three shapes (MD5-password, Math.random session,
/// AES-ECB) on each twin so the grid is not "one shape here, three there".
/// Counts are part of the contract. Two shapes per injection-adjacent rule
/// (fetch + axios, redirect + Location header, password + accessToken) keep
/// the corpus honest about real codebases rather than one-liner demos.
const SHARED_FIRES: &[(&str, usize)] = &[
    ("stack-trace-leak", 1),
    ("sql-injection", 1),
    ("cors-permissive", 1),
    ("insecure-cookie", 1),
    ("hardcoded-secret", 1),
    ("security-headers-missing", 1),
    ("ssrf", 2),
    ("open-redirect", 2),
    ("weak-crypto", 3),
    ("unpinned-dependency", 1),
    ("ci-unpinned-action", 1),
    ("sensitive-data-logged", 2),
];

const MATRIX: &[Expectation] = &[
    Expectation {
        framework: "next",
        vulnerable: "vulnerable/next-api",
        clean: "should-not-fire/next-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "nuxt",
        vulnerable: "vulnerable/nuxt-api",
        clean: "should-not-fire/nuxt-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "nest",
        vulnerable: "vulnerable/nest-api",
        clean: "should-not-fire/nest-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "express",
        vulnerable: "vulnerable/express-api",
        clean: "should-not-fire/express-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "fastify",
        vulnerable: "vulnerable/fastify-api",
        clean: "should-not-fire/fastify-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "hono",
        vulnerable: "vulnerable/hono-api",
        clean: "should-not-fire/hono-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "koa",
        vulnerable: "vulnerable/koa-api",
        clean: "should-not-fire/koa-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "hapi",
        vulnerable: "vulnerable/hapi-api",
        clean: "should-not-fire/hapi-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "sails",
        vulnerable: "vulnerable/sails-api",
        clean: "should-not-fire/sails-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "astro",
        vulnerable: "vulnerable/astro-api",
        clean: "should-not-fire/astro-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "remix",
        vulnerable: "vulnerable/remix-api",
        clean: "should-not-fire/remix-api-clean",
        fires: SHARED_FIRES,
    },
    Expectation {
        framework: "gatsby",
        vulnerable: "vulnerable/gatsby-api",
        clean: "should-not-fire/gatsby-api-clean",
        fires: SHARED_FIRES,
    },
];

#[tokio::test]
async fn the_matrix_covers_every_supported_framework() {
    // If someone adds a framework profile without fixtures, the tool claims
    // support it has never demonstrated. Fail here instead.
    for framework in owlwarden_detectors::SUPPORTED_FRAMEWORKS {
        assert!(
            MATRIX.iter().any(|row| row.framework == framework.as_str()),
            "{} is advertised as supported but has no fixture row",
            framework.as_str()
        );
    }
}

#[test]
fn every_catalogue_rule_is_exercised_on_every_framework() {
    let catalogue: Vec<_> = owlwarden_detectors::all_rule_metas()
        .into_iter()
        .map(|meta| meta.id.to_string())
        .collect();
    assert_eq!(
        catalogue.len(),
        SHARED_FIRES.len(),
        "SHARED_FIRES and the catalogue drifted apart"
    );
    for rule in &catalogue {
        assert!(
            SHARED_FIRES.iter().any(|(id, _)| id == rule),
            "{rule} is in the catalogue but missing from SHARED_FIRES"
        );
        for row in MATRIX {
            assert!(
                row.fires.iter().any(|(id, _)| id == rule),
                "{rule} has no expected fire on {}",
                row.framework
            );
            // Same expected counts on every framework — no kitchen-sink row.
            assert_eq!(
                row.fires, SHARED_FIRES,
                "{} must use SHARED_FIRES so the grid stays square",
                row.framework
            );
        }
    }
    // 12 rules × 12 frameworks = 144 cells. If this number moves, update the
    // table in fixtures/should-not-fire/README.md in the same PR.
    assert_eq!(
        SHARED_FIRES.len() * MATRIX.len(),
        owlwarden_detectors::SUPPORTED_FRAMEWORKS.len() * catalogue.len()
    );
    assert_eq!(SHARED_FIRES.len() * MATRIX.len(), 144);
}

#[tokio::test]
async fn every_framework_reports_its_expected_rules() {
    for row in MATRIX {
        let report = scan(row.vulnerable).await;
        let found: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.id.as_str())
            .collect();

        for (rule, times) in row.fires {
            let hits = of_rule(&report, rule);
            assert_eq!(
                hits.len(),
                *times,
                "{}: expected {rule} {times} time(s), got {}; all findings: {found:?}",
                row.framework,
                hits.len()
            );
        }

        let expected: usize = row.fires.iter().map(|(_, times)| times).sum();
        assert_eq!(
            found.len(),
            expected,
            "{}: unexpected extra findings; got {found:?}, expected {:?}",
            row.framework,
            row.fires
        );

        // The framework has to be recognised, or every fix is the generic one.
        for finding in &report.findings {
            assert_eq!(
                finding
                    .context
                    .framework
                    .as_ref()
                    .map(owlwarden_core::finding::Framework::as_str),
                Some(row.framework),
                "{}: {} was attributed to the wrong framework",
                row.framework,
                finding.id.as_str()
            );
        }
    }
}

#[tokio::test]
async fn every_framework_has_a_clean_counterpart_that_stays_silent() {
    // The corrected version of each vulnerable fixture, plus code written to
    // resemble each rule without being it. This is the only evidence that the
    // rules are precise rather than merely loud.
    for row in MATRIX {
        let report = scan(row.clean).await;
        assert!(
            report.findings.is_empty(),
            "{}: the corrected project produced {} finding(s): {:#?}",
            row.framework,
            report.findings.len(),
            report
                .findings
                .iter()
                .map(|finding| (finding.id.as_str(), &finding.location))
                .collect::<Vec<_>>()
        );
        assert!(
            report.errors.is_empty(),
            "{}: scan errors {:?}",
            row.framework,
            report.errors
        );
    }
}

#[tokio::test]
async fn nest_fixture_reports_both_rules() {
    let report = scan("vulnerable/nest-api").await;

    let leaks = of_rule(&report, "stack-trace-leak");
    assert_eq!(leaks.len(), 1, "the exception body carries the stack");
    let leak = leaks.first().unwrap();
    let Location::Source(location) = &leak.location else {
        panic!("expected a source location");
    };
    assert_eq!(location.path, "src/users/users.controller.ts");

    let headers = of_rule(&report, "security-headers-missing");
    assert_eq!(headers.len(), 1, "the bootstrap never registers helmet");
    let finding = headers.first().unwrap();
    let Location::Source(location) = &finding.location else {
        panic!("expected a source location");
    };
    assert_eq!(
        location.path, "src/main.ts",
        "point at the bootstrap, not at package.json, when we can see it"
    );
    let fix = finding.primary_fix().unwrap();
    assert!(fix.patch.as_deref().is_some_and(|p| p.contains("helmet")));
}

#[tokio::test]
async fn a_scan_is_deterministic() {
    // Two runs must produce byte-identical findings, or snapshot tests and CI
    // diffs are worthless.
    let first = scan("vulnerable/next-api").await;
    let second = scan("vulnerable/next-api").await;
    assert_eq!(first.findings, second.findings);
}

#[tokio::test]
async fn the_false_positive_corpus_is_silent() {
    for project in ["tempting"] {
        let report = scan(&format!("should-not-fire/{project}")).await;
        assert!(
            report.findings.is_empty(),
            "{project} is correct code but produced {} finding(s): {:#?}",
            report.findings.len(),
            report
                .findings
                .iter()
                .map(|f| (f.id.as_str(), &f.location))
                .collect::<Vec<_>>()
        );
        assert!(
            report.errors.is_empty(),
            "{project} produced scan errors: {:?}",
            report.errors
        );
    }
}

#[tokio::test]
async fn every_finding_carries_what_a_reader_needs() {
    // The definition of done for a rule: a fix, a why, and one to three curated
    // references. Asserting it here means a new rule cannot ship without them.
    for row in MATRIX {
        let project = row.vulnerable;
        let report = scan(project).await;
        assert!(!report.findings.is_empty(), "{project} found nothing");

        for finding in &report.findings {
            let id = finding.id.as_str();
            assert!(!finding.why.is_empty(), "{id} has no `why`");
            assert!(!finding.remediation.is_empty(), "{id} has no fix");
            assert!(
                finding.primary_fix().is_some(),
                "{id} has no fix for the detected framework"
            );
            let references = finding.references.len();
            assert!(
                (1..=3).contains(&references),
                "{id} has {references} references; curate 1-3, do not dump a reading list"
            );
            assert!(
                finding.context.framework.is_some(),
                "{id} did not record the framework"
            );
        }
    }
}

#[tokio::test]
async fn scanning_an_empty_directory_is_not_an_error() {
    let empty = tempfile::tempdir().unwrap();
    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset("deep");
    let report = owlwarden_static::scan_project(
        empty.path(),
        file_rules,
        project_rules,
        ScanSettings::default(),
    )
    .await
    .expect("an empty project is a valid, clean project");

    assert!(report.findings.is_empty());
    assert_eq!(report.target.files_scanned, 0);
    assert_eq!(report.suppressed_count, 0);
}
