//! Golden pairs: one host event in, one host decision out.
//!
//! ADR 0026 exit criterion 1 asks for a fixture pair per adapter, and this is
//! it. The value is not that the snapshots are correct today — it is that when
//! a host changes its schema, or when someone edits an adapter, the diff is
//! visible in a file rather than discovered by a developer whose gate quietly
//! stopped firing.
//!
//! Regenerate with `INSTA_UPDATE=always cargo test -p owlwarden-gate`, and read
//! the diff before accepting it: an adapter change that alters these files is
//! a change to what a host receives.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use owlwarden_core::finding::{
    Confidence, Finding, Fix, FixSafety, Location, RuleId, RuntimeScope, Severity, SourceLocation,
};
use owlwarden_core::report::{ExposureSummary, Report, ReportSummary, ScanTarget, ToolInfo};
use owlwarden_gate::{GateOutcome, GatePolicy, adapter_for, decide};

/// A report with everything that varies between runs pinned.
fn report(findings: Vec<Finding>) -> Box<Report> {
    Box::new(Report {
        schema_version: "1.0".into(),
        tool: ToolInfo {
            name: "owlwarden".into(),
            version: "0.0.0-test".into(),
        },
        scanned_at: "2026-01-01T00:00:00Z".into(),
        duration_ms: 12,
        target: ScanTarget {
            project: "fixtures/agent/claude-code/vulnerable".into(),
            preset: "quick".into(),
            files_scanned: 3,
            diff_scope: Some("since HEAD".into()),
            ..ScanTarget::default()
        },
        summary: ReportSummary::of(&findings),
        exposure_summary: ExposureSummary::default(),
        findings,
        suppressed_count: 0,
        suppressions: Vec::new(),
        baseline_hidden_count: 0,
        truncated: false,
        errors: Vec::new(),
    })
}

fn stack_trace_leak() -> Finding {
    Finding::builder(
        RuleId::new_static("stack-trace-leak"),
        Severity::High,
        "Stack trace leaked in error response",
    )
    .confidence(Confidence::Likely)
    .why("Stack traces expose absolute file paths and dependency versions.")
    .location(Location::Source(SourceLocation {
        path: "app/api/users/route.ts".into(),
        line: 13,
        col: 16,
    }))
    .fix(Fix {
        framework: Some(owlwarden_core::finding::Framework::NEXT),
        host: None,
        runtime: None,
        summary: "Return a generic message; log the error server-side.".into(),
        patch: Some(
            "console.error(err)\nreturn NextResponse.json({ error: 'Internal Server Error' }, { status: 500 })"
                .into(),
        ),
        safety: FixSafety::Manual,
    })
    .build()
}

fn hostile_hook() -> Finding {
    Finding::builder(
        RuleId::new_static("agent-hook-autoexec"),
        Severity::High,
        "Repository config executes a command when the workspace is opened",
    )
    .confidence(Confidence::Likely)
    .runtime_scope(RuntimeScope::Active)
    .why("Anyone who clones this repository and opens it runs `node .claude/setup.mjs`.")
    .location(Location::Source(SourceLocation {
        path: ".claude/settings.json".into(),
        line: 4,
        col: 24,
    }))
    .fix(Fix {
        framework: None,
        host: Some(owlwarden_core::finding::AgentHost::CLAUDE_CODE),
        runtime: None,
        summary: "Remove the SessionStart entry from .claude/settings.json.".into(),
        patch: Some("// .claude/settings.json\n{ \"hooks\": {} }".into()),
        safety: FixSafety::Manual,
    })
    .build()
}

/// Runs one adapter end to end: event JSON in, host response out.
fn round_trip(host: &str, payload: &str, outcome: GateOutcome) -> String {
    let adapter = adapter_for(host).expect("a shipped adapter");
    let event = adapter.parse(payload).expect("a known event");
    let decision = decide(&event, outcome, &GatePolicy::default());
    let encoded = adapter.encode(&event, &decision);
    format!(
        "event: {}\nkind: {}\nverdict: {}\nexit: {}\nstdout: {}\nstderr: {}\n",
        event.host_event.as_deref().unwrap_or("-"),
        event.kind.as_str(),
        decision.verdict.as_str(),
        encoded.exit_code,
        encoded.stdout,
        encoded.stderr.as_deref().unwrap_or("-")
    )
}

#[test]
fn claude_code_denies_an_edit_that_leaked_a_stack_trace() {
    insta::assert_snapshot!(round_trip(
        "claude-code",
        r#"{"hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"app/api/users/route.ts"}}"#,
        GateOutcome::Scanned(report(vec![stack_trace_leak()])),
    ));
}

#[test]
fn claude_code_denies_a_config_change_that_planted_a_hook() {
    insta::assert_snapshot!(round_trip(
        "claude-code",
        r#"{"hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}"#,
        GateOutcome::Scanned(report(vec![hostile_hook()])),
    ));
}

#[test]
fn claude_code_allows_a_clean_edit() {
    insta::assert_snapshot!(round_trip(
        "claude-code",
        r#"{"hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"app/page.tsx"}}"#,
        GateOutcome::Scanned(report(Vec::new())),
    ));
}

#[test]
fn claude_code_asks_when_it_cannot_check_a_command() {
    insta::assert_snapshot!(round_trip(
        "claude-code",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"pnpm add left-pad"}}"#,
        GateOutcome::Failed("engine timed out after 400ms".into()),
    ));
}

#[test]
fn claude_code_injects_a_digest_at_session_start() {
    insta::assert_snapshot!(round_trip(
        "claude-code",
        r#"{"hook_event_name":"SessionStart","source":"startup"}"#,
        GateOutcome::Scanned(report(vec![stack_trace_leak()])),
    ));
}

#[test]
fn cursor_denies_at_the_turn_boundary() {
    insta::assert_snapshot!(round_trip(
        "cursor",
        r#"{"hook_event_name":"stop"}"#,
        GateOutcome::Scanned(report(vec![stack_trace_leak(), hostile_hook()])),
    ));
}

#[test]
fn cursor_allows_a_clean_edit() {
    insta::assert_snapshot!(round_trip(
        "cursor",
        r#"{"hook_event_name":"afterFileEdit","file_path":"app/route.ts"}"#,
        GateOutcome::Scanned(report(Vec::new())),
    ));
}

#[test]
fn generic_denies_with_the_documented_exit_code() {
    insta::assert_snapshot!(round_trip(
        "generic",
        r#"{"event":"turn-boundary"}"#,
        GateOutcome::Scanned(report(vec![stack_trace_leak()])),
    ));
}

#[test]
fn generic_allows_a_clean_turn() {
    insta::assert_snapshot!(round_trip(
        "generic",
        r#"{"event":"turn-boundary"}"#,
        GateOutcome::Scanned(report(Vec::new())),
    ));
}

#[test]
fn the_loop_closes_agent_writes_gate_denies_agent_rewrites_gate_allows() {
    // ADR 0026 exit criterion 2, as one test rather than a paragraph.
    let adapter = adapter_for("claude-code").expect("shipped");
    let payload = r#"{"hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"app/api/users/route.ts"}}"#;
    let event = adapter.parse(payload).expect("a known event");

    // 1. The agent writes a vulnerable file. The gate denies, and the reason
    //    carries the rule, the line, and the patch — everything needed to fix
    //    it without another tool call.
    let denied = decide(
        &event,
        GateOutcome::Scanned(report(vec![stack_trace_leak()])),
        &GatePolicy::default(),
    );
    assert_eq!(denied.verdict, owlwarden_gate::Verdict::Deny);
    assert!(denied.reason.contains("stack-trace-leak"));
    assert!(denied.reason.contains("app/api/users/route.ts:13:16"));
    assert!(denied.reason.contains("NextResponse.json"));

    // 2. The agent rewrites. The next scan is clean, and the gate allows.
    let allowed = decide(
        &event,
        GateOutcome::Scanned(report(Vec::new())),
        &GatePolicy::default(),
    );
    assert_eq!(allowed.verdict, owlwarden_gate::Verdict::Allow);
    assert_eq!(
        adapter.encode(&event, &allowed).stdout,
        "{}",
        "a clean gate costs the model nothing"
    );
}
