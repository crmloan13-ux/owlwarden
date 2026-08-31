//! Golden artefacts shared with the TypeScript side.
//!
//! `packages/sdk` declares the report format a second time, in zod. Two
//! declarations of one format drift unless something forces them together, and
//! this is that something: these tests write what the engine actually produces
//! into `fixtures/golden/`, and the vitest in `packages/sdk/test` parses those
//! files with the zod schemas.
//!
//! So: rename a field in Rust and this test fails (the golden is stale).
//! Regenerate, and the TypeScript test fails until the schema is updated. There
//! is no path where the two quietly disagree.
//!
//! Regenerate with `OWLWARDEN_UPDATE_GOLDEN=1 cargo test -p owlwarden-reporters`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use owlwarden_core::context::ScanSettings;
use owlwarden_core::finding::{Confidence, Severity};
use owlwarden_core::report::Report;

/// Where the golden files live, relative to this crate.
fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/golden")
}

/// Compares `actual` against the checked-in golden, or rewrites it on request.
fn assert_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);

    if std::env::var_os("OWLWARDEN_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(golden_dir()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read {}: {error}\nRegenerate with OWLWARDEN_UPDATE_GOLDEN=1 cargo test",
            path.display()
        )
    });

    // Compare with normalised line endings: git on Windows may check the file
    // out with CRLF, and that is not a contract change.
    assert_eq!(
        expected.replace("\r\n", "\n"),
        actual.replace("\r\n", "\n"),
        "{} is out of date.\nIf the change is intended, regenerate with:\n  \
         OWLWARDEN_UPDATE_GOLDEN=1 cargo test -p owlwarden-reporters\n\
         then run the TypeScript tests — the zod schema in packages/sdk may need the same change.",
        path.display()
    );
}

/// A report with everything that varies between runs pinned.
async fn frozen_report() -> Report {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vulnerable/next-api");

    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset("deep");
    let mut report = owlwarden_static::scan_project(
        root,
        file_rules,
        project_rules,
        ScanSettings {
            preset: "deep".to_owned(),
            ..ScanSettings::default()
        },
    )
    .await
    .expect("fixture scan should complete");

    report.scanned_at = "2026-01-01T00:00:00Z".to_owned();
    report.duration_ms = 120;
    report.tool.version = "0.0.0-test".to_owned();
    report.target.project = "fixtures/vulnerable/next-api".to_owned();
    report
}

#[tokio::test]
async fn report_golden_is_current() {
    let report = frozen_report().await;
    let encoded = serde_json::to_string_pretty(&report).unwrap();
    assert_golden("report.json", &format!("{encoded}\n"));
}

#[tokio::test]
async fn rules_golden_is_current() {
    let encoded = serde_json::to_string_pretty(&owlwarden_detectors::all_rule_metas()).unwrap();
    assert_golden("rules.json", &format!("{encoded}\n"));
}

#[tokio::test]
async fn coverage_golden_is_current() {
    // Pinned for the same reason as the rule catalogue, plus one of its own: the
    // coverage numbers are a public claim about what the tool does. Checking the
    // table into the repository means a change to it shows up in a diff and gets
    // read, rather than moving quietly with a refactor.
    let mut report = owlwarden_detectors::coverage_report();
    report.version = "0.0.0-test".to_owned();
    let encoded = serde_json::to_string_pretty(&report).unwrap();
    assert_golden("coverage.json", &format!("{encoded}\n"));
}

/// The full `should_fail` truth table for the golden report.
///
/// The CLI computes the exit code in TypeScript, the engine computes it in Rust,
/// and a disagreement means CI passes when it should fail. Pinning the whole
/// matrix is cheap; discovering the disagreement in someone's pipeline is not.
#[tokio::test]
async fn should_fail_matrix_is_current() {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Row {
        fail_on: Severity,
        min_confidence: Confidence,
        fails: bool,
    }

    let report = frozen_report().await;
    let rows: Vec<Row> = [
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .flat_map(|fail_on| {
        [
            Confidence::Confirmed,
            Confidence::Likely,
            Confidence::Possible,
        ]
        .into_iter()
        .map(move |min_confidence| (fail_on, min_confidence))
    })
    .map(|(fail_on, min_confidence)| Row {
        fail_on,
        min_confidence,
        fails: report.should_fail(fail_on, min_confidence),
    })
    .collect();

    let encoded = serde_json::to_string_pretty(&rows).unwrap();
    assert_golden("should-fail.json", &format!("{encoded}\n"));
}

/// A turn record with everything that varies between runs pinned.
///
/// Built by scanning the same fixture twice — once whole, once with one rule's
/// findings withheld — so the record carries at least one finding in each of
/// the three states. A golden that only ever exercised `introduced` would let
/// the `carried` and `fixed` shapes drift without failing anything.
async fn frozen_turn() -> owlwarden_core::turn::TurnReport {
    let report = frozen_report().await;

    // `after` is the whole report. `before` holds every finding except one
    // rule's — those read as introduced — plus one finding on a path that no
    // longer exists, which reads as fixed. Everything else is carried.
    let mut before: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.id.as_str() != "stack-trace-leak")
        .cloned()
        .collect();

    if let Some(first) = report.findings.first() {
        let mut deleted = first.clone();
        if let owlwarden_core::finding::Location::Source(location) = &mut deleted.location {
            location.path = format!("deleted/{}", location.path);
        }
        before.push(deleted);
    }

    let diff = owlwarden_core::turn::TurnDiff::between(&before, &report.findings);
    let mut record = owlwarden_core::turn::TurnReport::new(
        &diff,
        owlwarden_core::turn::TurnBase {
            reference: "HEAD".to_owned(),
            commit: Some("0000000000000000000000000000000000000000".to_owned()),
        },
        3,
        120,
        owlwarden_core::turn::TurnGate {
            fail_on: Severity::Medium,
            min_confidence: Confidence::Possible,
            fail_on_exposure: None,
        },
    );
    record.recorded_at = "2026-01-01T00:00:00Z".to_owned();
    record.tool.version = "0.0.0-test".to_owned();
    record.surface = Some(owlwarden_core::turn::TurnSurface {
        state: "unchanged".to_owned(),
        files: 2,
        hooks: 1,
        mcp_servers: 0,
        changes: Vec::new(),
    });
    record
}

#[tokio::test]
async fn turn_golden_is_current() {
    let record = frozen_turn().await;
    assert!(
        record.counts.introduced > 0 && record.counts.carried > 0 && record.counts.fixed > 0,
        "the golden must exercise all three states, or two of them can drift silently"
    );
    let encoded = serde_json::to_string_pretty(&record).unwrap();
    assert_golden("turn.json", &format!("{encoded}\n"));
}
