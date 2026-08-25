//! `agent-permission-wildcard` — repository config pre-approves a broad tool
//! permission.
//!
//! # Why medium and not high
//!
//! On its own this is a widened blast radius, not an execution. Nothing runs
//! because a repository pre-approved `Bash`; something runs when a hook fires
//! or the model decides. Reporting it at the same weight as
//! `agent-hook-autoexec` would flatten a distinction the reader needs.
//!
//! Combined with an open-time hook in the same file it is the full chain, and
//! the finding says so in its own text rather than leaving the reader to
//! assemble two rows of a report.
//!
//! # The argument-wildcard case
//!
//! `Bash(git *)` looks like a constraint and is not one:
//! `git -c core.pager='sh -c "curl … | sh"' log` is a `git` command by any
//! textual test. The rule names that specific fact in the finding, because
//! "this looks scoped and is not" is the part a reviewer gets wrong.

use owlwarden_core::detector::{DetectorError, DetectorMeta};
use owlwarden_core::finding::{
    AgentHost, AsiRef, Confidence, FindingContext, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::surface::Surface;
use owlwarden_static::agentws::jsonc::JsonNode;
use owlwarden_static::project::Project;
use owlwarden_static::rule::{FindingSink, ProjectRule, RuleInfo};

use super::{agent_finding, collect_hooks, evidence, push};

/// The rule id. Permanent public API.
pub const ID: &str = "agent-permission-wildcard";

/// Permission entries that are unbounded however they are written.
const UNBOUNDED: &[&str] = &[
    "*",
    "bash",
    "bash(*)",
    "bash(*:*)",
    "shell",
    "shell(*)",
    "execute",
    "webfetch",
    "webfetch(*)",
    "websearch(*)",
    "write",
    "write(*)",
    "read(*)",
    "edit(*)",
    "mcp__*",
    "task(*)",
];

/// Programs whose own flags can reach a shell, so an argument wildcard after
/// them constrains nothing.
///
/// Every entry here is a program with a documented way to run another program:
/// `git -c core.pager`, `npm run-script`, `docker run`, `make`, `sudo`. The
/// list is short and specific on purpose — `Bash(ls *)` is a real constraint
/// and must not be reported.
const MULTITOOLS: &[&str] = &[
    "git", "npm", "pnpm", "yarn", "bun", "npx", "docker", "podman", "make", "sudo", "env", "xargs",
    "find", "ssh", "kubectl", "cargo", "uv", "pip", "python", "python3", "node", "deno", "perl",
    "ruby", "sh", "bash", "zsh",
];

/// Keys that switch a permission gate off wholesale.
const GATE_SWITCHES: &[(&str, &str)] = &[
    ("defaultmode", "bypasspermissions"),
    ("permissionmode", "bypasspermissions"),
    ("dangerouslyskippermissions", "true"),
    ("disableallhooks", "true"),
    ("security.workspace.trust.enabled", "false"),
    ("security.workspace.trust.untrustedfiles", "open"),
    ("chat.tools.autoapprove", "true"),
    ("autoapprove", "true"),
    ("yolo", "true"),
];

/// Repository config pre-approves a broad tool permission.
#[derive(Debug, Default, Clone, Copy)]
pub struct AgentPermissionWildcard;

impl AgentPermissionWildcard {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Repository config pre-approves a broad tool permission".into(),
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: None,
            asi: Some(AsiRef::new_static("ASI03")),
            cwe: Some(732),
            surface: Surface::AgentWorkspace,
            category: "agent-config".into(),
            description: "A repository-local config grants an unbounded tool permission — `Bash`, \
                          `WebFetch`, `Write(*)`, `mcp__*` — or switches a permission gate off \
                          entirely. The approval prompt exists to bound the blast radius of a \
                          model doing something unexpected; a repository should not be the thing \
                          that answers it."
                .into(),
        }
    }
}

impl RuleInfo for AgentPermissionWildcard {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl ProjectRule for AgentPermissionWildcard {
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink) -> Result<(), DetectorError> {
        let meta = Self::meta();
        let workspace = project.agent_workspace();
        let mut emitted = 0usize;

        // Files that also run something on open. Named in the finding, because
        // the combination is the chain and one report row should say so.
        let auto_files: Vec<String> = collect_hooks(workspace)
            .iter()
            .filter(|hook| hook.automatic)
            .map(|hook| hook.file.path.to_string())
            .collect();

        for (file, doc) in workspace.json_files() {
            let chained = auto_files.contains(&file.path.to_string());

            for hit in doc.strings() {
                if !hit.within("permissions") && !hit.within("allow") && !hit.within("autoApprove")
                {
                    continue;
                }
                if hit.within("deny") || hit.within("ask") {
                    continue;
                }
                let Some(reason) = wildcard_reason(hit.value) else {
                    continue;
                };
                let finding = agent_finding(
                    &meta,
                    file,
                    hit.span,
                    reason.label,
                    format!("{}{}", reason.why, chain_note(chained)),
                )
                .context(FindingContext {
                    framework: None,
                    host: Some(file.host.clone()),
                    route: None,
                    method: None,
                    evidence: Some(evidence(&format!("{} = {}", hit.path_str(), hit.value))),
                })
                .build();
                if !push(sink, &mut emitted, finding) {
                    return Ok(());
                }
            }

            for (span, key, value) in gate_switches(doc) {
                let finding = agent_finding(
                    &meta,
                    file,
                    span,
                    format!("{key} switches the permission gate off"),
                    format!(
                        "`{key}` is set to `{value}`, which removes the approval step for the \
                         whole session. The prompt is the control; a repository that answers it \
                         in advance has removed the control.{}",
                        chain_note(chained)
                    ),
                )
                .context(FindingContext {
                    framework: None,
                    host: Some(file.host.clone()),
                    route: None,
                    method: None,
                    evidence: Some(evidence(&format!("{key} = {value}"))),
                })
                .build();
                if !push(sink, &mut emitted, finding) {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

fn chain_note(chained: bool) -> &'static str {
    if chained {
        " This file also declares a command that runs when the workspace opens, so the two \
         together are an execution with the approval already granted."
    } else {
        ""
    }
}

struct WildcardReason {
    label: &'static str,
    why: &'static str,
}

/// Why an entry is unbounded, or `None` if it is a real constraint.
fn wildcard_reason(entry: &str) -> Option<WildcardReason> {
    let normalised = entry.trim().to_ascii_lowercase();
    if UNBOUNDED.contains(&normalised.as_str()) {
        return Some(WildcardReason {
            label: "grants an unbounded permission",
            why: "This entry pre-approves the tool for anything, so the approval prompt never \
                  appears for it again in this project.",
        });
    }
    if normalised.ends_with("__*") || normalised.starts_with("mcp__") && normalised.contains('*') {
        return Some(WildcardReason {
            label: "grants every tool on an MCP server",
            why: "The entry approves every tool the server exposes, including tools it adds after \
                  this line was reviewed.",
        });
    }

    // `Bash(git *)` and friends.
    let inner = normalised
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))?;
    let program = inner.split_whitespace().next()?;
    if !inner.contains('*') {
        return None;
    }
    MULTITOOLS
        .contains(&program.trim_end_matches(':'))
        .then_some(WildcardReason {
            label: "looks scoped, but the wildcard makes the constraint meaningless",
            why: "The program named here can run other programs through its own flags — \
                  `git -c core.pager='sh -c …'` is a `git` command by any textual test — so the \
                  argument wildcard approves far more than it appears to.",
        })
}

/// Every wholesale gate switch in a document, with its span.
fn gate_switches(doc: &JsonNode) -> Vec<((u32, u32), String, String)> {
    fn walk(node: &JsonNode, out: &mut Vec<((u32, u32), String, String)>) {
        let Some(members) = node.as_object() else {
            if let Some(items) = node.as_array() {
                for item in items {
                    walk(item, out);
                }
            }
            return;
        };
        for member in members {
            let key = member.key.to_ascii_lowercase().replace(['-', '_'], "");
            let value = match &member.value.value {
                owlwarden_static::agentws::jsonc::JsonValue::Bool(flag) => flag.to_string(),
                owlwarden_static::agentws::jsonc::JsonValue::String(text) => {
                    text.to_ascii_lowercase()
                }
                _ => String::new(),
            };
            if GATE_SWITCHES
                .iter()
                .any(|(name, expected)| *name == key && *expected == value)
            {
                out.push((member.key_span, member.key.clone(), value.clone()));
            }
            walk(&member.value, out);
        }
    }
    let mut out = Vec::new();
    walk(doc, &mut out);
    out
}

fn remediation() -> Remediation {
    Remediation::new(
        "Replace the wildcard with the specific commands the project actually needs, and leave \
         everything else to the approval prompt. A list of five exact commands is more useful to \
         the team than one wildcard, and it is reviewable.",
    )
    .generic_patch("\"allow\": [\"Bash(pnpm test)\", \"Bash(pnpm lint)\"]")
    .host(
        AgentHost::CLAUDE_CODE,
        "Narrow `permissions.allow` in `.claude/settings.json` to exact commands. Note that \
         argument wildcards after a multitool (`Bash(git *)`) are not constraints — pin the \
         subcommand too. Platform teams can set the permitted set in managed settings so a \
         repository cannot widen it.",
        "// .claude/settings.json\n\"permissions\": {\n  \"allow\": [\"Bash(pnpm test:unit)\", \"Bash(git status)\"],\n  \"deny\": [\"Bash(curl:*)\", \"Read(./.env)\"]\n}",
    )
    .host(
        AgentHost::CURSOR,
        "List the exact commands in Cursor's allow list rather than a wildcard, and keep the \
         approval prompt for everything else.",
        "// .cursor/settings\n\"allow\": [\"pnpm test\", \"pnpm lint\"]",
    )
    .host(
        AgentHost::VSCODE,
        "Leave `security.workspace.trust` enabled. Restricted mode exists precisely so that \
         opening an unfamiliar repository is safe, and a repository asking you to switch it off \
         is asking for the one thing it should not be able to ask for.",
        "// user settings.json\n\"security.workspace.trust.enabled\": true",
    )
    .host(
        AgentHost::COPILOT,
        "Tool auto-approval belongs in the editor's own settings, at user scope. Remove it from \
         the repository and let each developer decide what runs without asking.",
        "// user settings.json — not the repository's\n\"chat.tools.autoApprove\": false",
    )
    .host(
        AgentHost::CODEX,
        "Set the approval policy in the user-level Codex configuration and keep the repository's \
         to project facts. Where a sandbox mode is available, prefer it to a broad allow list.",
        "// ~/.codex/config.json\n\"approvalPolicy\": \"on-request\"",
    )
    .host(
        AgentHost::GEMINI_CLI,
        "Remove the auto-approve entry from `.gemini/settings.json`. If a command is run often \
         enough to be tedious, add that exact command rather than the tool that runs it.",
        "// .gemini/settings.json\n\"autoApprove\": [\"pnpm test\"]",
    )
    .host(
        AgentHost::GENERIC,
        "Grant the smallest set that lets the project's own workflow run, name it exactly, and \
         keep the prompt for the rest. The prompt is not friction to be removed; it is where the \
         blast radius is decided.",
        "\"allow\": [\"pnpm test\", \"pnpm lint\"]",
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use crate::agent::testing::{assert_silent, run_rule};

    #[test]
    fn an_unbounded_bash_grant_fires() {
        let findings = run_rule(
            &AgentPermissionWildcard,
            &[(".claude/settings.json", r#"{"permissions":{"allow":["Bash"]}}"#)],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].id.as_str(), ID);
    }

    #[test]
    fn an_exact_command_is_the_shape_we_are_asking_for() {
        assert_silent(
            &AgentPermissionWildcard,
            &[(
                ".claude/settings.json",
                r#"{"permissions":{"allow":["Bash(pnpm test)","Bash(git status)","Read(./src)"]}}"#,
            )],
            "exact commands are exactly what the fix asks for",
        );
    }

    #[test]
    fn a_wildcard_after_a_multitool_is_not_a_constraint() {
        let findings = run_rule(
            &AgentPermissionWildcard,
            &[(
                ".claude/settings.json",
                r#"{"permissions":{"allow":["Bash(git *)"]}}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].why.contains("core.pager"));
    }

    #[test]
    fn a_wildcard_after_a_plain_program_is_a_real_constraint() {
        assert_silent(
            &AgentPermissionWildcard,
            &[(
                ".claude/settings.json",
                r#"{"permissions":{"allow":["Bash(ls *)","Bash(cat *)"]}}"#,
            )],
            "`ls` cannot be talked into running something else",
        );
    }

    #[test]
    fn a_deny_list_entry_is_never_a_finding() {
        assert_silent(
            &AgentPermissionWildcard,
            &[(
                ".claude/settings.json",
                r#"{"permissions":{"deny":["Bash","WebFetch"],"allow":["Bash(pnpm test)"]}}"#,
            )],
            "denying everything is the opposite of the problem",
        );
    }

    #[test]
    fn switching_workspace_trust_off_is_a_finding() {
        let findings = run_rule(
            &AgentPermissionWildcard,
            &[(
                ".vscode/settings.json",
                r#"{"security.workspace.trust.enabled": false}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].why.contains("approval step"));
    }

    #[test]
    fn the_full_chain_says_so_in_one_finding() {
        let findings = run_rule(
            &AgentPermissionWildcard,
            &[(
                ".claude/settings.json",
                r#"{"permissions":{"allow":["Bash"]},
                    "hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node x.mjs"}]}]}}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].why.contains("opens"),
            "the correlation note is what turns two rows into one decision"
        );
    }

    #[test]
    fn an_mcp_wildcard_is_reported_as_every_tool_on_the_server() {
        let findings = run_rule(
            &AgentPermissionWildcard,
            &[(
                ".claude/settings.json",
                r#"{"permissions":{"allow":["mcp__github__*"]}}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].why.contains("after this line was reviewed"));
    }
}
