//! Cold-scan performance baseline (v0.4).
//!
//! Architecture budgets a 1k-file Next.js project under 5 s cold. This harness
//! times a real fixture scan so a regression is measurable. It is **ignored**
//! by default — wall-clock numbers vary by host — and is not a hard CI gate
//! yet (ADR 0018).
//!
//! ```text
//! cargo test -p owlwarden-detectors --test perf_baseline -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::time::Instant;

use owlwarden_core::context::ScanSettings;

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

#[tokio::test]
#[ignore = "manual cold-scan baseline; host-dependent"]
async fn cold_scan_next_fixture_reports_duration() {
    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset("deep");
    let root = fixture("vulnerable/next-api");

    // Warm once so the timed run is not dominated by process startup alone.
    let _ = owlwarden_static::scan_project(
        root.clone(),
        file_rules.clone(),
        project_rules.clone(),
        ScanSettings::default(),
    )
    .await
    .expect("warm scan");

    let started = Instant::now();
    let report =
        owlwarden_static::scan_project(root, file_rules, project_rules, ScanSettings::default())
            .await
            .expect("timed scan");
    let elapsed = started.elapsed();

    eprintln!(
        "cold-scan baseline: {} files, {} findings, {:.2} ms (budget reference: 5000 ms for ~1k files)",
        report.target.files_scanned,
        report.findings.len(),
        elapsed.as_secs_f64() * 1000.0
    );

    // Sanity only — not the Architecture 5 s / 1k-file budget (fixture is small).
    assert!(
        elapsed.as_secs() < 30,
        "fixture cold scan took {:?}; something is badly wrong",
        elapsed
    );
    assert!(report.target.files_scanned > 0);
}
