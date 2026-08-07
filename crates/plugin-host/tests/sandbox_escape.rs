//! Sandbox-escape suite: adversarial WASM modules, assembled at test time
//! with `wat` so nothing in this repository ships a binary `.wasm` blob, run
//! through the real [`WasmDetector`] and checked for containment.
//!
//! Each test is one claim about the sandbox. Together they are the exit
//! criteria for `plugin-host` v0.2: a plugin that misbehaves in any of these
//! ways must be contained, not merely slowed down.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use owlwarden_core::budget::Budget;
use owlwarden_core::context::{ScanContext, ScanSettings};
use owlwarden_core::detector::Detector;
use owlwarden_core::finding::Finding;
use owlwarden_core::limits::plugin as limits;
use owlwarden_core::scope::DenyAllScope;
use owlwarden_core::source::{FileSelector, SourceError, SourceFile, SourceProvider};
use owlwarden_plugin_host::{PluginManifest, WasmDetector};

/// A source provider with no files. Every escape test's guest ignores the
/// snapshot it is handed, so what matters here is only that building one
/// does not fail.
struct EmptySource;

impl SourceProvider for EmptySource {
    fn root(&self) -> &std::path::Path {
        std::path::Path::new("/")
    }

    fn files(&self, _selector: &FileSelector) -> Result<Vec<SourceFile>, SourceError> {
        Ok(Vec::new())
    }

    fn read(&self, _file: &SourceFile) -> Result<std::sync::Arc<str>, SourceError> {
        unreachable!("EmptySource never lists a file, so this is never called")
    }
}

/// Runs `detector` against an empty, passive [`ScanContext`] and returns
/// whatever [`Detector::run`] returns, alongside how long it took — every
/// escape test cares as much about *how fast* containment kicked in as about
/// the outcome.
async fn run(detector: &WasmDetector) -> (Result<Vec<Finding>, String>, Duration) {
    let source = EmptySource;
    let scope = DenyAllScope;
    let settings = ScanSettings::default();
    let budget = Budget::passive();
    let ctx = ScanContext::new(&source, None, &scope, &settings, &budget);

    let started = Instant::now();
    let result = detector.run(&ctx).await.map_err(|error| error.to_string());
    (result, started.elapsed())
}

/// A manifest declaring namespaced rules under `escape-test-plugin-`.
fn manifest() -> PluginManifest {
    let json = r#"{
        "schemaVersion": 1,
        "id": "escape-test-plugin",
        "version": "0.1.0",
        "rules": [
            {
                "id": "escape-test-plugin-demo",
                "title": "Demo finding",
                "severity": "medium",
                "maxConfidence": "likely",
                "category": "demo",
                "description": "A demonstration rule used by the sandbox-escape suite."
            },
            {
                "id": "escape-test-plugin-grow",
                "title": "Memory-grow probe",
                "severity": "info",
                "maxConfidence": "possible",
                "category": "demo",
                "description": "Reports whether an oversized memory.grow or table.grow succeeded."
            }
        ]
    }"#;
    PluginManifest::parse(json, "test-manifest").expect("the fixture manifest must parse")
}

fn load(wat_source: &str) -> WasmDetector {
    let wasm = wat::parse_str(wat_source).expect("the fixture wat must assemble");
    WasmDetector::load(&manifest(), &wasm).expect("the fixture module must satisfy the guest ABI")
}

/// Escapes the JSON payload as a WAT byte-string of `\xx` hex escapes so the
/// literal quotes and braces in a finding's JSON never have to be
/// hand-escaped for the text format — every byte is unambiguous.
fn wat_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:02x}")).collect()
}

const NOOP_IMPORT: &str =
    r#"(import "owlwarden" "emit_finding" (func $emit (param i32 i32) (result i32)))"#;

// 1. busy_loop: fuel runs out; the store traps rather than spinning forever.
#[tokio::test]
async fn busy_loop_exhausts_fuel_instead_of_hanging() {
    let detector = load(&format!(
        r#"(module
            {NOOP_IMPORT}
            (memory (export "memory") 1)
            (func (export "alloc") (param i32) (result i32) i32.const 0)
            (func (export "detect") (param i32 i32) (result i32)
                (loop $forever (br $forever))
                i32.const 0))"#,
    ));

    let (result, elapsed) = run(&detector).await;

    assert!(
        result.is_err(),
        "an infinite loop must not be allowed to succeed"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "fuel exhaustion must be near-instant, not wait for the {}s wall-clock backstop; took {elapsed:?}",
        limits::MAX_INVOCATION_TIME.as_secs(),
    );
}

// 2. grow_memory: an oversized `memory.grow` is refused by StoreLimits, not
// granted at the cost of the host's own address space.
#[tokio::test]
async fn grow_memory_past_the_limit_is_refused_not_granted() {
    let blocked = br#"{"ruleId":"escape-test-plugin-grow","path":"grow-blocked"}"#;
    let granted = br#"{"ruleId":"escape-test-plugin-grow","path":"grow-granted"}"#;

    let detector = load(&format!(
        r#"(module
            {NOOP_IMPORT}
            (memory (export "memory") 1)
            (data (i32.const 0) "{blocked_bytes}")
            (data (i32.const 512) "{granted_bytes}")
            (func (export "alloc") (param i32) (result i32) i32.const 4096)
            (func (export "detect") (param i32 i32) (result i32)
                (local $grew i32)
                ;; 200,000 pages is ~12.5 GiB — far past the 64 MiB store limit.
                (local.set $grew (memory.grow (i32.const 200000)))
                (if (i32.eq (local.get $grew) (i32.const -1))
                    (then (drop (call $emit (i32.const 0) (i32.const {blocked_len}))))
                    (else (drop (call $emit (i32.const 512) (i32.const {granted_len})))))
                i32.const 0))"#,
        blocked_bytes = wat_bytes(blocked),
        granted_bytes = wat_bytes(granted),
        blocked_len = blocked.len(),
        granted_len = granted.len(),
    ));

    let (result, _elapsed) = run(&detector).await;
    let findings = result.expect("a refused grow is not itself a runtime error");

    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0]
            .location
            .as_source()
            .map(|loc| loc.path.as_str()),
        Some("grow-blocked"),
        "memory.grow past the store limit must return -1 (failure) to the guest, \
         not actually grow the host's allocation",
    );
}

// 2b. table.grow: same containment for funcref tables — wasmtime's default
// StoreLimits leave tables unbounded, which would be a RAM escape beside
// linear memory.
#[tokio::test]
async fn grow_table_past_the_limit_is_refused_not_granted() {
    let blocked = br#"{"ruleId":"escape-test-plugin-grow","path":"table-blocked"}"#;
    let granted = br#"{"ruleId":"escape-test-plugin-grow","path":"table-granted"}"#;
    // Grow far past MAX_TABLE_ELEMENTS in one step.
    let grow_by = limits::MAX_TABLE_ELEMENTS as i32 * 100;

    let detector = load(&format!(
        r#"(module
            {NOOP_IMPORT}
            (memory (export "memory") 1)
            (table 0 funcref)
            (data (i32.const 0) "{blocked_bytes}")
            (data (i32.const 512) "{granted_bytes}")
            (func (export "alloc") (param i32) (result i32) i32.const 4096)
            (func (export "detect") (param i32 i32) (result i32)
                (local $grew i32)
                (local.set $grew (table.grow 0 (ref.null func) (i32.const {grow_by})))
                (if (i32.eq (local.get $grew) (i32.const -1))
                    (then (drop (call $emit (i32.const 0) (i32.const {blocked_len}))))
                    (else (drop (call $emit (i32.const 512) (i32.const {granted_len})))))
                i32.const 0))"#,
        blocked_bytes = wat_bytes(blocked),
        granted_bytes = wat_bytes(granted),
        blocked_len = blocked.len(),
        granted_len = granted.len(),
    ));

    let (result, _elapsed) = run(&detector).await;
    let findings = result.expect("a refused table.grow is not itself a runtime error");

    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0]
            .location
            .as_source()
            .map(|loc| loc.path.as_str()),
        Some("table-blocked"),
        "table.grow past StoreLimits::table_elements must return -1",
    );
}

// 3. flood_findings: a guest calling `emit_finding` far more than the cap
// only ever contributes MAX_FINDINGS_PER_INVOCATION findings.
#[tokio::test]
async fn flood_of_findings_is_capped_at_the_per_invocation_limit() {
    let payload = br#"{"ruleId":"escape-test-plugin-demo","path":"flood.ts"}"#;
    let flood_calls = limits::MAX_FINDINGS_PER_INVOCATION * 4;

    let detector = load(&format!(
        r#"(module
            {NOOP_IMPORT}
            (memory (export "memory") 1)
            (data (i32.const 0) "{bytes}")
            (func (export "alloc") (param i32) (result i32) i32.const 4096)
            (func (export "detect") (param i32 i32) (result i32)
                (local $i i32)
                (block $exit
                    (loop $again
                        (br_if $exit (i32.ge_s (local.get $i) (i32.const {flood_calls})))
                        (drop (call $emit (i32.const 0) (i32.const {len})))
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br $again)))
                i32.const 0))"#,
        bytes = wat_bytes(payload),
        len = payload.len(),
    ));

    let (result, _elapsed) = run(&detector).await;
    let findings = result.expect("a flood of valid findings must not itself be a runtime error");

    assert_eq!(
        findings.len(),
        limits::MAX_FINDINGS_PER_INVOCATION,
        "the host must stop accepting findings at the cap, no matter how many the guest sends",
    );
}

// 4. emit_bad_rule_id: a claim for a rule id the plugin never declared is
// dropped, not smuggled into the report under a manifest it doesn't own.
#[tokio::test]
async fn a_claim_for_an_undeclared_rule_id_is_dropped() {
    let payload = br#"{"ruleId":"not-mine","path":"a.ts"}"#;

    let detector = load(&format!(
        r#"(module
            {NOOP_IMPORT}
            (memory (export "memory") 1)
            (data (i32.const 0) "{bytes}")
            (func (export "alloc") (param i32) (result i32) i32.const 4096)
            (func (export "detect") (param i32 i32) (result i32)
                (drop (call $emit (i32.const 0) (i32.const {len})))
                i32.const 0))"#,
        bytes = wat_bytes(payload),
        len = payload.len(),
    ));

    let (result, _elapsed) = run(&detector).await;
    let findings = result.expect("an invalid claim is a silent no, not a trap");

    assert!(
        findings.is_empty(),
        "a rule id absent from the plugin's own manifest must never reach a Finding",
    );
}

// 5. benign_emit: the positive control. A well-formed claim for a rule the
// plugin actually declared is accepted end to end.
#[tokio::test]
async fn a_benign_well_formed_claim_is_accepted() {
    let payload = br#"{"ruleId":"escape-test-plugin-demo","path":"src/index.ts","line":3,"col":5,"why":"benign positive control"}"#;

    let detector = load(&format!(
        r#"(module
            {NOOP_IMPORT}
            (memory (export "memory") 1)
            (data (i32.const 0) "{bytes}")
            (func (export "alloc") (param i32) (result i32) i32.const 4096)
            (func (export "detect") (param i32 i32) (result i32)
                (drop (call $emit (i32.const 0) (i32.const {len})))
                i32.const 0))"#,
        bytes = wat_bytes(payload),
        len = payload.len(),
    ));

    let (result, _elapsed) = run(&detector).await;
    let findings = result.expect("a benign, well-formed claim must succeed");

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.id.as_str(), "escape-test-plugin-demo");
    assert_eq!(finding.why, "benign positive control");
    assert_eq!(
        finding
            .location
            .as_source()
            .map(|loc| (loc.path.as_str(), loc.line, loc.col)),
        Some(("src/index.ts", 3, 5)),
    );
}

// 6. oversized why: dropped so the report cannot become an exfil channel.
#[tokio::test]
async fn an_oversized_why_is_dropped() {
    let why = "x".repeat(limits::MAX_WHY_BYTES + 1);
    let payload = format!(r#"{{"ruleId":"escape-test-plugin-demo","path":"a.ts","why":"{why}"}}"#);

    let detector = load(&format!(
        r#"(module
            {NOOP_IMPORT}
            (memory (export "memory") 1)
            (data (i32.const 0) "{bytes}")
            (func (export "alloc") (param i32) (result i32) i32.const 4096)
            (func (export "detect") (param i32 i32) (result i32)
                (drop (call $emit (i32.const 0) (i32.const {len})))
                i32.const 0))"#,
        bytes = wat_bytes(payload.as_bytes()),
        len = payload.len(),
    ));

    let (result, _elapsed) = run(&detector).await;
    let findings = result.expect("an oversized why is a silent no, not a trap");
    assert!(findings.is_empty());
}
