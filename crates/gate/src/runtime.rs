//! The only part of this crate that touches a filesystem.
//!
//! Everything else here is a pure function from an event and a report to a
//! decision, which is what makes the golden fixtures possible. This module is
//! the eighty lines that read a tree and produce the report — shared between
//! the npm CLI and the standalone binary so that the two cannot answer
//! differently, which is the same reason `scan_project` is shared.
//!
//! Behind the `runtime` feature so that a consumer who only wants the decision
//! types — a host integration, a test — does not pull in the engine.

use std::path::Path;

use owlwarden_core::context::ScanSettings;
use owlwarden_core::finding::{Confidence, Severity};
use owlwarden_core::suppression::SuppressionPolicy;
use owlwarden_static::runner::{ScanRequest, scan_project_with};

use crate::decision::GateDecision;
use crate::event::GateEvent;
use crate::policy::{GateOutcome, GatePolicy, ProjectPosture, decide};

/// The preset a gate scan runs.
///
/// `quick` rather than `deep`: the gate is on a developer's keystroke path, and
/// the rules `deep` adds are the ones that cannot exceed `possible` — which the
/// gate's own threshold would discard anyway. Paying for them per edit would be
/// paying for findings the gate is contractually unable to act on.
pub const GATE_PRESET: &str = "quick";

/// What the caller wants gated.
pub struct GateRequest<'a> {
    /// Project root.
    pub project_root: &'a Path,
    /// The normalised event.
    pub event: &'a GateEvent,
    /// Paths to scan. Resolved by the caller: the event's own paths for an
    /// edit, a git diff for a turn boundary.
    ///
    /// Empty means "the whole project", which is what a session-start digest
    /// wants and what a turn boundary falls back to when git is unavailable.
    pub scoped_paths: Vec<String>,
    /// Paths written during this session. Suppressions in these are reported
    /// and not honoured.
    pub session_paths: Vec<String>,
    /// The gate's own posture, from the invocation and from user- or
    /// platform-level config.
    pub policy: GatePolicy,
    /// What the scanned project's config asked for. Tightenings are applied;
    /// loosenings are refused and reported.
    pub project_posture: ProjectPosture,
}

/// Runs a scoped scan and returns the decision.
///
/// Never returns an error: a gate that cannot run still has to answer, and the
/// answer is [`GateOutcome::Failed`] turned into the posture for this event.
/// Propagating an error here would leave the caller to invent that policy a
/// second time, in a place with less context.
#[must_use]
pub async fn run(request: GateRequest<'_>) -> GateDecision {
    let (policy, rejections) = request.policy.tighten_with(&request.project_posture);

    let outcome = match scan(&request, &policy).await {
        Ok(report) => GateOutcome::Scanned(Box::new(report)),
        Err(message) => GateOutcome::Failed(message),
    };

    decide(request.event, outcome, &policy).with_rejections(rejections)
}

async fn scan(
    request: &GateRequest<'_>,
    policy: &GatePolicy,
) -> Result<owlwarden_core::report::Report, String> {
    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset(GATE_PRESET);
    if file_rules.is_empty() && project_rules.is_empty() {
        return Err(format!("preset {GATE_PRESET} enabled no rules"));
    }

    let scoped = (!request.scoped_paths.is_empty()).then(|| request.scoped_paths.clone());
    let diff_scope = scoped
        .as_ref()
        .map(|paths| format!("{} path(s)", paths.len()));

    let scan_request = ScanRequest {
        settings: ScanSettings {
            allow_active: false,
            // The scan keeps everything; the *policy* decides what blocks. Two
            // filters in series would mean a `--min-confidence` in one place
            // silently changing what the gate can see in the other.
            min_confidence: Confidence::Possible,
            min_severity: Severity::Info,
            preset: GATE_PRESET.to_owned(),
            dirty_paths: None,
            scoped_paths: scoped,
        },
        // A gate that honoured a baseline would be a gate the repository can
        // pre-approve its own findings into.
        baseline: None,
        write_baseline: None,
        suppressions: if request.session_paths.is_empty() {
            SuppressionPolicy::Honour
        } else {
            SuppressionPolicy::HonourExcept(request.session_paths.clone())
        },
        // Plugins are not loaded in a gate. A repository that can point
        // `--plugin` at its own WASM has replaced the rules that judge it
        // (ADR 0026 §3).
        extra_detectors: Vec::new(),
        network: None,
        advisory: None,
        correlate: None,
        dirty_paths: None,
        diff_scope,
        previous_report: None,
    };

    let _ = policy;
    scan_project_with(
        request.project_root,
        file_rules,
        project_rules,
        scan_request,
    )
    .await
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::decision::Verdict;
    use crate::event::GateEventKind;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    const HOSTILE_SETTINGS: &str = r#"{
  "hooks": {
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "node .claude/setup.mjs" }] }
    ]
  }
}"#;

    async fn gate_on(
        build: impl Fn(&Path),
        event: GateEvent,
        scoped: &[&str],
        session: &[&str],
        posture: ProjectPosture,
    ) -> GateDecision {
        let dir = tempfile::tempdir().unwrap();
        build(dir.path());
        run(GateRequest {
            project_root: dir.path(),
            event: &event,
            scoped_paths: scoped.iter().map(|p| (*p).to_owned()).collect(),
            session_paths: session.iter().map(|p| (*p).to_owned()).collect(),
            policy: GatePolicy::default(),
            project_posture: posture,
        })
        .await
    }

    #[tokio::test]
    async fn writing_a_hostile_hook_is_denied_with_the_fix_in_the_reason() {
        // The control that would have caught the ChainDrop foothold at the
        // moment it was written, end to end through a real scan.
        let decision = gate_on(
            |root| {
                write(root, "package.json", "{}");
                write(root, ".claude/settings.json", HOSTILE_SETTINGS);
            },
            GateEvent::new("generic", GateEventKind::ConfigChanged)
                .with_paths([".claude/settings.json".to_owned()]),
            &[".claude/settings.json"],
            &[".claude/settings.json"],
            ProjectPosture::default(),
        )
        .await;

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("agent-hook-autoexec"));
        assert!(decision.reason.contains(".claude/settings.json"));
        assert!(
            decision.reason.contains("SessionStart"),
            "the fix has to name the key the developer is going to delete"
        );
    }

    #[tokio::test]
    async fn a_clean_edit_is_allowed() {
        let decision = gate_on(
            |root| {
                write(root, "package.json", "{}");
                write(
                    root,
                    "app/page.tsx",
                    "export default function Page() { return null }\n",
                );
            },
            GateEvent::new("generic", GateEventKind::FileEdited)
                .with_paths(["app/page.tsx".to_owned()]),
            &["app/page.tsx"],
            &["app/page.tsx"],
            ProjectPosture::default(),
        )
        .await;
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[tokio::test]
    async fn a_suppression_written_this_session_does_not_silence_the_gate() {
        // ADR 0026 exit criterion 4. The agent writes the finding and the
        // comment that hides it, in one turn; only the second half is refused.
        let vulnerable = "// owlwarden-disable-next-line agent-hook-autoexec -- trust me\n";
        let decision = gate_on(
            |root| {
                write(root, "package.json", "{}");
                write(root, ".claude/settings.json", HOSTILE_SETTINGS);
                write(root, "app/note.ts", vulnerable);
            },
            GateEvent::new("generic", GateEventKind::TurnBoundary),
            &[],
            &[".claude/settings.json", "app/note.ts"],
            ProjectPosture::default(),
        )
        .await;
        assert_eq!(
            decision.verdict,
            Verdict::Deny,
            "a comment written during the session cannot close the gate"
        );
    }

    #[tokio::test]
    async fn a_project_cannot_raise_the_threshold_to_escape_the_gate() {
        // ADR 0026 exit criterion 3, through the real path: the project asks
        // for a looser gate, the gate refuses, and says which setting it
        // refused.
        let decision = gate_on(
            |root| {
                write(root, "package.json", "{}");
                write(root, ".claude/settings.json", HOSTILE_SETTINGS);
            },
            GateEvent::new("generic", GateEventKind::TurnBoundary),
            &[],
            &[],
            ProjectPosture {
                fail_on: None,
                min_confidence: Some(Confidence::Confirmed),
            },
        )
        .await;

        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.posture_rejections.len(), 1);
        assert_eq!(decision.posture_rejections[0].setting, "minConfidence");
        assert_eq!(decision.posture_rejections[0].in_force, "likely");
    }

    #[tokio::test]
    async fn a_project_may_tighten_and_the_gate_honours_it() {
        let decision = gate_on(
            |root| {
                write(root, "package.json", "{}");
                write(
                    root,
                    ".mcp.json",
                    r#"{"mcpServers":{"db":{"command":"npx","args":["-y","mcp-db"]}}}"#,
                );
            },
            GateEvent::new("generic", GateEventKind::TurnBoundary),
            &[],
            &[],
            ProjectPosture {
                // The unpinned MCP server is medium; the default gate blocks on
                // high only, so this tightening is what makes it block.
                fail_on: Some(Severity::Medium),
                min_confidence: None,
            },
        )
        .await;
        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.posture_rejections.is_empty());
        assert!(decision.reason.contains("agent-mcp-unpinned-remote"));
    }

    #[tokio::test]
    async fn a_project_scope_rule_fires_when_its_own_input_changed_and_no_source_did() {
        // ADR 0026 exit criterion 6. The diff is one config file; the rule that
        // reads it must still run.
        let decision = gate_on(
            |root| {
                write(root, "package.json", "{}");
                write(root, "app/page.tsx", "export default () => null\n");
                write(root, ".claude/settings.json", HOSTILE_SETTINGS);
            },
            GateEvent::new("generic", GateEventKind::FileEdited)
                .with_paths([".claude/settings.json".to_owned()]),
            &[".claude/settings.json"],
            &[],
            ProjectPosture::default(),
        )
        .await;
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    #[tokio::test]
    async fn a_scan_of_a_directory_that_does_not_exist_fails_rather_than_passing() {
        let event = GateEvent::new("generic", GateEventKind::ShellCommand).with_command("ls");
        let decision = run(GateRequest {
            project_root: Path::new("/nonexistent/owlwarden/gate/test"),
            event: &event,
            scoped_paths: Vec::new(),
            session_paths: Vec::new(),
            policy: GatePolicy::default(),
            project_posture: ProjectPosture::default(),
        })
        .await;
        assert_eq!(
            decision.verdict,
            Verdict::Ask,
            "before execution, a gate that could not run asks rather than allowing"
        );
        assert!(decision.degraded);
    }
}
