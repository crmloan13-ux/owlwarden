//! Golden output for every reporter.
//!
//! Output format is a contract. The JSON is parsed by CI pipelines and agents;
//! the terminal layout is what users learn to read. Both change on purpose or
//! not at all, and a diff in these snapshots is the reviewer's prompt to decide
//! which one it was.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use owlwarden_core::context::ScanSettings;
use owlwarden_core::report::Report;
use owlwarden_reporters::{
    JsonReporter, JunitReporter, MdReporter, PrettyOptions, SarifReporter, render_to_string,
};

/// Scans a fixture and freezes everything that varies between runs.
///
/// Timestamps, durations, and the absolute project path are real in production
/// and useless in a snapshot; pinning them keeps the diff about the output
/// format rather than about the clock.
async fn stable_report(fixture: &str) -> Report {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(fixture);

    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset("owasp-top10");
    let mut report = owlwarden_static::scan_project(
        root,
        file_rules,
        project_rules,
        ScanSettings {
            preset: "owasp-top10".to_owned(),
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
async fn pretty_output_for_a_next_project() {
    let report = stable_report("vulnerable/next-api").await;
    let rendered = render_to_string(
        &report,
        PrettyOptions {
            color: false,
            unicode: true,
            hyperlinks: false,
        },
    )
    .unwrap();

    insta::assert_snapshot!("pretty_next", rendered);
}

#[tokio::test]
async fn pretty_output_falls_back_to_ascii() {
    // Windows consoles and non-UTF locales get this variant. It must stay
    // readable, not merely different.
    let report = stable_report("vulnerable/nest-api").await;
    let rendered = render_to_string(
        &report,
        PrettyOptions {
            color: false,
            unicode: false,
            hyperlinks: false,
        },
    )
    .unwrap();

    assert!(rendered.is_ascii() || rendered.contains("NestJS"));
    insta::assert_snapshot!("pretty_nest_ascii", rendered);
}

#[tokio::test]
async fn pretty_output_when_there_is_nothing_to_report() {
    let report = stable_report("should-not-fire/next-api-clean").await;
    let rendered = render_to_string(&report, PrettyOptions::default()).unwrap();

    assert!(rendered.contains("No findings."));
    assert!(
        !rendered.contains("explain"),
        "do not offer next steps when there is nothing to explain"
    );
}

#[tokio::test]
async fn json_output_is_the_documented_shape() {
    let report = stable_report("vulnerable/next-api").await;
    let encoded = JsonReporter::to_string(&report, true).unwrap();

    // Parse it back: the contract is the parsed shape, not the byte layout.
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(value["schemaVersion"], "1.0");
    assert_eq!(value["tool"]["name"], "owlwarden");
    assert!(value["findings"].is_array());
    assert!(
        value["suppressedCount"].is_number(),
        "'0 findings' must never be mistaken for '0 problems'"
    );

    insta::assert_snapshot!("json_next", encoded);
}

#[tokio::test]
async fn json_output_is_a_single_line_by_default() {
    // `owlwarden scan --format json | jq` depends on this.
    let report = stable_report("vulnerable/next-api").await;
    let encoded = JsonReporter::to_string(&report, false).unwrap();
    assert!(!encoded.contains('\n'), "compact JSON must be one line");
}

#[tokio::test]
async fn sarif_output_is_version_2_1_0() {
    let report = stable_report("vulnerable/next-api").await;
    let encoded = SarifReporter::to_string_pretty(&report).unwrap();
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(value["version"], "2.1.0");
    assert!(!value["runs"][0]["results"].as_array().unwrap().is_empty());
    assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "owlwarden");
    insta::assert_snapshot!("sarif_next", encoded);
}

#[tokio::test]
async fn junit_output_has_one_failure_per_finding() {
    let report = stable_report("vulnerable/next-api").await;
    let encoded = JunitReporter::to_string(&report).unwrap();
    assert!(encoded.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
    let failures = report.findings.len();
    assert_eq!(
        encoded.matches("<failure ").count(),
        failures,
        "each finding is one JUnit failure"
    );
    insta::assert_snapshot!("junit_next", encoded);
}

#[tokio::test]
async fn md_output_groups_by_exposure_and_carries_the_fix() {
    let report = stable_report("vulnerable/next-api").await;
    let encoded = MdReporter::to_string(&report).unwrap();
    assert!(encoded.starts_with("# owlwarden report —"));
    // Grouped by exposure since 1.2: a pull-request comment is read top-down,
    // and the top is where the reachable findings belong (ADR 0029 §5).
    assert!(encoded.contains("## Internet-reachable"));
    assert!(
        encoded.find("## Internet-reachable") < encoded.find("## Unclassified")
            || !encoded.contains("## Unclassified"),
        "the reachable group must come first"
    );
    assert!(encoded.contains("**Fix"));
    assert!(encoded.contains("**Exposure:**"));
    assert!(encoded.contains("stack-trace-leak") || encoded.contains("Stack trace"));
    insta::assert_snapshot!("md_next", encoded);
}

#[tokio::test]
async fn md_falls_back_to_severity_headings_when_nothing_is_classified() {
    // `vet` over agent configuration classifies nothing, and a report whose
    // only heading was "Unclassified" would be worse than the 1.1 shape.
    let mut report = stable_report("vulnerable/next-api").await;
    for finding in &mut report.findings {
        finding.exposure = None;
        finding.exposure_evidence = None;
    }
    report.recount();
    let encoded = MdReporter::to_string(&report).unwrap();
    assert!(encoded.contains("## High"));
    assert!(!encoded.contains("## Unclassified"));
}

#[tokio::test]
async fn md_clean_scan_says_no_findings() {
    let report = stable_report("should-not-fire/next-api-clean").await;
    let encoded = MdReporter::to_string(&report).unwrap();
    assert!(encoded.contains("No findings."));
    assert!(encoded.contains("0 findings"));
}

#[tokio::test]
async fn junit_clean_scan_is_a_passing_suite() {
    let report = stable_report("should-not-fire/next-api-clean").await;
    let encoded = JunitReporter::to_string(&report).unwrap();
    assert!(encoded.contains(r#"failures="0""#));
    assert!(encoded.contains("no findings"));
    assert!(!encoded.contains("<failure"));
}
