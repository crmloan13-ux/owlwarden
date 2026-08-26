//! The agent-workspace rule family.
//!
//! Eleven rules that read the configuration an agent or editor loads out of the
//! working tree, rather than the application source next to it. The surface,
//! the path allowlist, and the parser live in
//! [`owlwarden_static::agentws`]; this module is the rules themselves and the
//! one model they all read.
//!
//! # Why there is a shared hook model
//!
//! Four hosts express "run this command" four different ways —
//! `hooks.SessionStart[].hooks[].command`, `tasks[].command` with
//! `runOptions.runOn`, `postCreateCommand`, `hooks.beforeShellExecution`. Three
//! rules need to ask questions about all of them. Written per rule, that is
//! twelve places for a host's schema to be half-supported, and the failure mode
//! is silence.
//!
//! So [`collect_hooks`] extracts one [`HookEntry`] shape from every host, once,
//! and the rules judge the entries. Adding a host is an arm in one function and
//! a fixture pair — the same shape as adding a `FrameworkProfile`.
//!
//! # What every rule in the family has in common
//!
//! - Caps at `Likely`. `Confirmed` means corroborated against a running target
//!   and there is none here ([ADR 0025](../../../docs/adr/0025-agent-surface-and-supply-chain.md) §6).
//! - Carries a [`RuntimeScope`], applied as a confidence ceiling by
//!   [`agent_finding`], so a hook in a tutorial is not reported like a hook in
//!   your settings.
//! - States the *specific fact that fired it* — which key, which trigger, which
//!   token — so a false positive is a one-line bug report rather than an
//!   argument.

pub mod config;
pub mod hooks;
pub mod instructions;
pub mod permissions;
pub mod supply_chain;

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    AgentHost, Confidence, Finding, FindingBuilder, FindingContext, Reference, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_static::agentws::jsonc::{JsonMember, JsonNode, Span};
use owlwarden_static::agentws::paths::WorkspaceFileKind;
use owlwarden_static::agentws::workspace::WorkspaceFile;

use crate::build::{finding_builder, finding_builder_with};

/// Findings one agent rule will emit per scan.
///
/// A repository of templates can hold hundreds of configs. Past this the report
/// is telling the reader about someone else's examples, and the engine's own
/// truncation flag is a better signal than three hundred rows.
pub const MAX_FINDINGS_PER_RULE: usize = 64;

/// Longest evidence string echoed from a config file.
pub const MAX_EVIDENCE_CHARS: usize = 120;

/// Starts a finding on the agent surface, pre-filled from the file it was found
/// in.
///
/// Every rule in the family goes through here, which is what makes the
/// `runtime_scope` ceiling structural rather than something eleven rules have
/// to remember. A rule that forgot would report a fenced example in a tutorial
/// at the same weight as a live `settings.json`, and that is the failure mode
/// that gets a rule family switched off.
#[must_use]
pub fn agent_finding(
    meta: &DetectorMeta,
    file: &WorkspaceFile,
    span: Span,
    label: impl Into<String>,
    why: impl Into<String>,
) -> FindingBuilder {
    agent_finding_with(meta, meta.severity, file, span, label, why)
}

/// [`agent_finding`] with a severity that depends on what was found.
#[must_use]
pub fn agent_finding_with(
    meta: &DetectorMeta,
    severity: Severity,
    file: &WorkspaceFile,
    span: Span,
    label: impl Into<String>,
    why: impl Into<String>,
) -> FindingBuilder {
    let scope = file.scope_at(span.0);
    let confidence = min_confidence(meta.max_confidence, scope.confidence_ceiling());

    finding_builder_with(meta, severity)
        .confidence(confidence)
        .runtime_scope(scope)
        .why(why)
        .location(file.location(span))
        .snippet(file.code_frame(span, label))
        .context(FindingContext {
            framework: None,
            host: Some(file.host.clone()),
            route: None,
            method: None,
            evidence: None,
        })
        .fixes(remediation_for(meta, &file.host))
        .reference(Reference::rule_page(&meta.id))
}

/// The lower of two confidences.
fn min_confidence(left: Confidence, right: Confidence) -> Confidence {
    if left <= right { left } else { right }
}

/// The fixes for one rule and one host.
///
/// Indirect through the catalogue rather than taking a [`Remediation`] so a
/// rule cannot attach a table that differs from the one `explain` prints.
fn remediation_for(meta: &DetectorMeta, host: &AgentHost) -> Vec<owlwarden_core::finding::Fix> {
    crate::all_rules()
        .into_iter()
        .find(|rule| rule.meta().id == meta.id)
        .map_or_else(Vec::new, |rule| rule.remediation().select_for_host(host))
}

/// Truncates an evidence string and escapes anything invisible in it.
///
/// Evidence comes out of an attacker-controlled file and lands in a terminal, a
/// Markdown report, and a PR comment. A raw bidi override here would reorder
/// the report itself.
#[must_use]
pub fn evidence(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .take(MAX_EVIDENCE_CHARS)
        .map(|ch| {
            if owlwarden_static::agentws::text::hidden_kind(ch).is_some() || ch.is_control() {
                '\u{FFFD}'
            } else {
                ch
            }
        })
        .collect();
    if text.chars().count() > MAX_EVIDENCE_CHARS {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

/// One "run this command" declaration, whatever host wrote it.
#[derive(Debug, Clone)]
pub struct HookEntry<'a> {
    /// The file it came from.
    pub file: &'a WorkspaceFile,
    /// The host's own name for the trigger: `SessionStart`, `folderOpen`,
    /// `postCreateCommand`. Printed verbatim, because the reader is going to go
    /// and look for exactly this word.
    pub trigger: String,
    /// Where the trigger is declared.
    pub trigger_span: Span,
    /// The command, when the declaration carries one.
    pub command: Option<String>,
    /// Where the command string is.
    pub command_span: Option<Span>,
    /// Whether it runs with no further action from the developer beyond opening
    /// the folder or starting a session.
    ///
    /// This is the single most load-bearing bit in the family. `true` is
    /// "cloning this repository is enough"; `false` is "the developer asked for
    /// something first".
    pub automatic: bool,
}

impl HookEntry<'_> {
    /// The span a finding about this entry should point at: the command when
    /// there is one, else the trigger.
    #[must_use]
    pub fn span(&self) -> Span {
        self.command_span.unwrap_or(self.trigger_span)
    }
}

/// Claude Code hook events that fire without a further user action.
const CLAUDE_AUTOMATIC_EVENTS: &[&str] = &["sessionstart", "sessionend"];

/// Dev container lifecycle keys that run on open or create.
const DEVCONTAINER_AUTOMATIC: &[&str] = &[
    "initializecommand",
    "oncreatecommand",
    "updatecontentcommand",
    "postcreatecommand",
    "poststartcommand",
    "postattachcommand",
];

/// Every hook, task, and lifecycle command declared anywhere in the workspace.
#[must_use]
pub fn collect_hooks(workspace: &owlwarden_static::agentws::AgentWorkspace) -> Vec<HookEntry<'_>> {
    let mut entries = Vec::new();
    for (file, doc) in workspace.json_files() {
        match file.kind {
            WorkspaceFileKind::Tasks => collect_vscode_tasks(file, doc, &mut entries),
            WorkspaceFileKind::DevContainer => collect_devcontainer(file, doc, &mut entries),
            WorkspaceFileKind::Settings | WorkspaceFileKind::Hooks => {
                collect_hook_blocks(file, doc, &mut entries);
            }
            _ => {}
        }
    }
    entries
}

/// `hooks` blocks, as Claude Code, Cursor, Gemini, and Codex spell them.
///
/// One walker for all four because the shape is the same in each: an object
/// keyed by event name, holding entries that eventually carry a `command`
/// string. Where they differ is only in nesting depth, and walking to the
/// `command` regardless of depth is what keeps a schema tweak from making this
/// silently blind.
fn collect_hook_blocks<'a>(
    file: &'a WorkspaceFile,
    doc: &'a JsonNode,
    entries: &mut Vec<HookEntry<'a>>,
) {
    // `members`, not `get`. A config can declare `hooks` twice — an empty block
    // first, a hostile one second — and a reviewer reading top-down sees the
    // empty one while the host, whose parser is last-wins, loads the other.
    // Reading only the first would have been a two-line bypass of this entire
    // rule family; reading all of them costs nothing and cannot be wrong in
    // that direction.
    let blocks: Vec<&JsonMember> = doc
        .members("hooks")
        .filter(|member| member.value.as_object().is_some())
        .collect();
    for block in blocks {
        collect_hook_events(file, &block.value, entries);
    }
}

/// One `hooks` object's events.
fn collect_hook_events<'a>(
    file: &'a WorkspaceFile,
    node: &'a JsonNode,
    entries: &mut Vec<HookEntry<'a>>,
) {
    let Some(hooks) = node.as_object() else {
        return;
    };
    for event in hooks {
        let normalised = event.key.to_ascii_lowercase().replace(['-', '_'], "");
        let automatic = CLAUDE_AUTOMATIC_EVENTS.contains(&normalised.as_str())
            || normalised.starts_with("onopen")
            // `startup`, `onStartup`, `on_startup` — four hosts, four spellings
            // of the same event, and the one we fail to match is the one that
            // ships.
            || normalised.contains("startup");

        let commands = commands_under(&event.value);
        if commands.is_empty() {
            entries.push(HookEntry {
                file,
                trigger: event.key.clone(),
                trigger_span: event.key_span,
                command: None,
                command_span: None,
                automatic,
            });
            continue;
        }
        for (command, span) in commands {
            entries.push(HookEntry {
                file,
                trigger: event.key.clone(),
                trigger_span: event.key_span,
                command: Some(command),
                command_span: Some(span),
                automatic,
            });
        }
    }
}

/// Every `command` string at any depth below `node`.
fn commands_under(node: &JsonNode) -> Vec<(String, Span)> {
    node.strings()
        .into_iter()
        .filter(|hit| hit.path.last().is_some_and(|key| is_command_key(key)))
        .map(|hit| (hit.value.to_owned(), hit.span))
        .collect()
}

/// Keys whose value is a command line.
///
/// Closed list rather than "any string": a hook block also holds matchers,
/// globs, and descriptions, and judging those as commands would fire on
/// `"description": "runs curl in CI"`.
#[must_use]
pub fn is_command_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().replace(['-', '_'], "").as_str(),
        "command" | "cmd" | "run" | "script" | "shellcommand" | "exec" | "entrypoint"
    )
}

fn collect_vscode_tasks<'a>(
    file: &'a WorkspaceFile,
    doc: &'a JsonNode,
    entries: &mut Vec<HookEntry<'a>>,
) {
    let Some(tasks) = doc.get("tasks").and_then(JsonNode::as_array) else {
        return;
    };
    for task in tasks {
        let run_on = task
            .pointer(&["runOptions", "runOn"])
            .and_then(JsonNode::as_str)
            .unwrap_or("default");
        let automatic = run_on.eq_ignore_ascii_case("folderOpen");

        let label_span = task
            .as_object()
            .and_then(|members| members.first())
            .map_or(task.span, |member| member.key_span);
        let trigger_span = task
            .pointer(&["runOptions", "runOn"])
            .map_or(label_span, |node| node.span);

        let command = task.get("command").and_then(JsonNode::as_str);
        let arguments = task
            .get("args")
            .and_then(JsonNode::as_array)
            .map(|args| {
                args.iter()
                    .filter_map(JsonNode::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        entries.push(HookEntry {
            file,
            trigger: format!("runOn: {run_on}"),
            trigger_span,
            command: command.map(|text| {
                if arguments.is_empty() {
                    text.to_owned()
                } else {
                    format!("{text} {arguments}")
                }
            }),
            command_span: task.get("command").map(|node| node.span),
            automatic,
        });
    }
}

fn collect_devcontainer<'a>(
    file: &'a WorkspaceFile,
    doc: &'a JsonNode,
    entries: &mut Vec<HookEntry<'a>>,
) {
    let Some(members) = doc.as_object() else {
        return;
    };
    for member in members {
        let normalised = member.key.to_ascii_lowercase();
        if !DEVCONTAINER_AUTOMATIC.contains(&normalised.as_str()) {
            continue;
        }
        // The value may be a string, an array of argv, or an object of named
        // commands. All three are documented forms; treating only the string
        // form as a command is how a rule ends up blind to the other two.
        let commands: Vec<(String, Span)> = match &member.value.value {
            owlwarden_static::agentws::jsonc::JsonValue::String(text) => {
                vec![(text.clone(), member.value.span)]
            }
            _ => member
                .value
                .strings()
                .into_iter()
                .map(|hit| (hit.value.to_owned(), hit.span))
                .collect(),
        };
        for (command, span) in commands {
            entries.push(HookEntry {
                file,
                trigger: member.key.clone(),
                trigger_span: member.key_span,
                command: Some(command),
                command_span: Some(span),
                automatic: true,
            });
        }
    }
}

/// Builds a remediation table that already covers every supported host.
///
/// The generic entry is mandatory (as everywhere), and `host_each` fills the
/// hosts a rule has nothing host-specific to say to. Rules that *can* name the
/// host's own file and key do so instead — which is most of them, and is the
/// difference between a fix a reader can paste and a paragraph.
#[must_use]
pub fn host_table(generic: &str) -> Remediation {
    Remediation::new(generic)
}

/// Attaches `finding` to `sink`, respecting the per-rule cap.
///
/// Returns `false` once the rule should stop building findings it will throw
/// away.
pub fn push(
    sink: &mut owlwarden_static::rule::FindingSink,
    emitted: &mut usize,
    finding: Finding,
) -> bool {
    if *emitted >= MAX_FINDINGS_PER_RULE {
        return false;
    }
    *emitted = emitted.saturating_add(1);
    sink.push(finding)
}

/// A builder seeded from metadata, for rules that build their own location.
#[must_use]
pub fn plain_builder(meta: &DetectorMeta) -> FindingBuilder {
    finding_builder(meta)
}

#[cfg(test)]
pub(crate) mod testing {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::Path;

    use owlwarden_core::finding::Finding;
    use owlwarden_static::agentws::AgentWorkspace;
    use owlwarden_static::fs_source::FsSourceProvider;
    use owlwarden_static::project::Project;
    use owlwarden_static::rule::{FindingSink, ProjectRule};

    /// Writes a tree, scans it with one rule, and returns the findings.
    ///
    /// Goes through `Project` and the real `FsSourceProvider` rather than a
    /// double: the allowlist, the `.gitignore` override, and the scope
    /// classification are all part of what the rule is being tested for, and a
    /// double would test none of them.
    pub fn run_rule(rule: &dyn ProjectRule, files: &[(&str, &str)]) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let full = dir.path().join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full, contents).unwrap();
        }
        let provider = FsSourceProvider::new(dir.path()).unwrap();
        let project = Project::discover(&provider).unwrap();
        let mut sink = FindingSink::new();
        rule.check(&project, &mut sink).expect("the rule completed");
        sink.drain()
    }

    /// Loads just the workspace, for tests about the shared model.
    pub fn workspace_of(files: &[(&str, &str)]) -> (tempfile::TempDir, AgentWorkspace) {
        let dir = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let full = dir.path().join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full, contents).unwrap();
        }
        let provider = FsSourceProvider::new(dir.path()).unwrap();
        let workspace = AgentWorkspace::load(&provider).unwrap();
        (dir, workspace)
    }

    /// Asserts a rule is silent on a tree.
    pub fn assert_silent(rule: &dyn ProjectRule, files: &[(&str, &str)], why: &str) {
        let findings = run_rule(rule, files);
        assert!(
            findings.is_empty(),
            "{why}: expected silence, got {:?}",
            findings.iter().map(|f| f.title.clone()).collect::<Vec<_>>()
        );
    }

    /// Ignores the `Path` import lint when a test does not need it.
    #[allow(dead_code)]
    pub fn touch(_path: &Path) {}
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
    use testing::workspace_of;

    #[test]
    fn claude_session_start_is_automatic_and_post_tool_use_is_not() {
        let (_dir, workspace) = workspace_of(&[(
            ".claude/settings.json",
            r#"{
  "hooks": {
    "SessionStart": [{ "hooks": [{ "type": "command", "command": "node .claude/setup.mjs" }] }],
    "PostToolUse": [{ "hooks": [{ "type": "command", "command": "pnpm exec prettier --write" }] }]
  }
}"#,
        )]);
        let hooks = collect_hooks(&workspace);
        assert_eq!(hooks.len(), 2);
        let session = hooks.iter().find(|h| h.trigger == "SessionStart").unwrap();
        assert!(session.automatic);
        assert_eq!(session.command.as_deref(), Some("node .claude/setup.mjs"));
        let post = hooks.iter().find(|h| h.trigger == "PostToolUse").unwrap();
        assert!(
            !post.automatic,
            "an edit hook needs the developer to edit something first"
        );
    }

    #[test]
    fn a_vscode_task_is_automatic_only_with_run_on_folder_open() {
        let (_dir, workspace) = workspace_of(&[(
            ".vscode/tasks.json",
            r#"{
  "version": "2.0.0",
  "tasks": [
    { "label": "evil", "command": "node", "args": [".vscode/setup.mjs"],
      "runOptions": { "runOn": "folderOpen" } },
    { "label": "build", "command": "pnpm", "args": ["build"] }
  ]
}"#,
        )]);
        let hooks = collect_hooks(&workspace);
        assert_eq!(hooks.len(), 2);
        assert!(hooks[0].automatic);
        assert_eq!(hooks[0].command.as_deref(), Some("node .vscode/setup.mjs"));
        assert!(!hooks[1].automatic, "a task with no runOn waits to be run");
        assert_eq!(hooks[1].trigger, "runOn: default");
    }

    #[test]
    fn every_devcontainer_lifecycle_form_is_seen() {
        let (_dir, workspace) = workspace_of(&[(
            ".devcontainer/devcontainer.json",
            r#"{
  "postCreateCommand": "pnpm install",
  "postStartCommand": ["node", "scripts/start.mjs"],
  "updateContentCommand": { "deps": "pnpm install", "build": "pnpm build" },
  "customizations": { "vscode": { "settings": {} } }
}"#,
        )]);
        let hooks = collect_hooks(&workspace);
        assert_eq!(
            hooks.len(),
            5,
            "string, argv array, and named-object forms all count"
        );
        assert!(hooks.iter().all(|hook| hook.automatic));
    }

    #[test]
    fn a_description_is_not_mistaken_for_a_command() {
        let (_dir, workspace) = workspace_of(&[(
            ".claude/settings.json",
            r#"{"hooks": {"Stop": [{"description": "we used to curl https://x.example | sh here"}]}}"#,
        )]);
        let hooks = collect_hooks(&workspace);
        assert_eq!(hooks.len(), 1);
        assert!(
            hooks[0].command.is_none(),
            "only command-shaped keys are commands"
        );
    }

    #[test]
    fn evidence_never_carries_an_invisible_character_through() {
        let rendered = evidence("run \u{202E}evil\u{202C} now");
        assert!(!rendered.contains('\u{202E}'));
        assert!(rendered.contains('\u{FFFD}'));
        assert!(evidence(&"a".repeat(500)).ends_with('…'));
    }
}
