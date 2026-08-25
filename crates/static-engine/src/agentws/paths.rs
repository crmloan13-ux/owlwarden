//! The closed path allowlist for the agent workspace surface.
//!
//! # Why a closed list, and why it overrides `.gitignore`
//!
//! [`FsSourceProvider`](crate::fs_source::FsSourceProvider) respects
//! `.gitignore`, skips `node_modules`, refuses outbound symlinks, and caps file
//! size. Two of those four are wrong for this surface.
//!
//! `.claude/settings.local.json` is conventionally gitignored. It is also where
//! a workspace-scoped hook configuration vulnerability lived. Respecting
//! `.gitignore` here would make the rule silent on exactly the file the CVE was
//! about — and `.vscode/` and `.cursor/` are on the provider's own exclusion
//! list, for reasons that made sense when the only question was "is this
//! application source?".
//!
//! So this surface reads from an explicit list that overrides both. Everything
//! else stays: paths remain under the scan root, symlinks that leave it are
//! refused, size caps apply, and nothing is ever executed
//! ([ADR 0025](../../../../docs/adr/0025-agent-surface-and-supply-chain.md) §3).
//!
//! The list is **data, not a glob the user can widen**. A user-extensible
//! pattern would let a repository point owlwarden at a file the engine has no
//! parser for, and "we found nothing in a file we do not understand" is not an
//! answer worth giving.
//!
//! It is two entries longer than the list in ADR 0025 §3. `.cursor/hooks/**`
//! and `.cursor/*.{js,mjs,cjs,ts,sh,py}` are the Cursor equivalents of the
//! `.claude/` entries the ADR does list, and leaving them out would have made
//! `agent-config-loader-script` structurally blind to the `ChainDrop` shape one
//! host over — which is the shape the rule exists for. Extending a closed list
//! is a reviewed change, and this comment plus the test below are the review
//! record.
//!
//! # Why the patterns also match under a prefix
//!
//! A `.claude/settings.json` at the root is the live configuration. The same
//! file under `examples/` is documentation, and reporting the two at equal
//! weight is how a rule family gets switched off in week two (§5). Matching
//! under a prefix is what lets the second be *found and marked*, rather than
//! either missed or reported as live. The prefix decides
//! [`RuntimeScope`](owlwarden_core::finding::RuntimeScope); it never decides
//! whether we look.

use owlwarden_core::finding::{AgentHost, RuntimeScope};
use owlwarden_core::source::RelPath;

/// What kind of artefact a workspace file is, which decides how it is parsed
/// and which rules look at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkspaceFileKind {
    /// Host settings: hooks, permissions, env. JSON.
    Settings,
    /// A dedicated hooks file. JSON.
    Hooks,
    /// An editor task file. JSON.
    Tasks,
    /// An MCP server declaration. JSON.
    Mcp,
    /// A dev container definition. JSON.
    DevContainer,
    /// A recommended-extensions list. JSON.
    Extensions,
    /// A plugin or marketplace manifest. JSON.
    PluginManifest,
    /// Free-text instructions the model reads: `CLAUDE.md`, `.cursorrules`,
    /// rules files, `copilot-instructions.md`.
    Instructions,
    /// A subagent or skill definition — Markdown with YAML frontmatter.
    AgentDefinition,
    /// An executable script sitting inside a config directory.
    Script,
}

impl WorkspaceFileKind {
    /// Whether the file is parsed as JSONC.
    #[must_use]
    pub const fn is_json(self) -> bool {
        matches!(
            self,
            Self::Settings
                | Self::Hooks
                | Self::Tasks
                | Self::Mcp
                | Self::DevContainer
                | Self::Extensions
                | Self::PluginManifest
        )
    }

    /// Whether the file is read as prose the model will follow.
    #[must_use]
    pub const fn is_instructions(self) -> bool {
        matches!(self, Self::Instructions | Self::AgentDefinition)
    }

    /// Short label for evidence lines.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Settings => "settings",
            Self::Hooks => "hooks",
            Self::Tasks => "tasks",
            Self::Mcp => "mcp",
            Self::DevContainer => "devcontainer",
            Self::Extensions => "extensions",
            Self::PluginManifest => "plugin manifest",
            Self::Instructions => "instructions",
            Self::AgentDefinition => "agent definition",
            Self::Script => "script",
        }
    }
}

/// How a pattern matches a path.
///
/// An enum of four concrete shapes rather than a glob engine: the list is
/// closed and small, the semantics of each entry are then obvious at the call
/// site, and there is no pattern compiler between an attacker-controlled path
/// and the decision to read a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Exactly this path.
    Exact(&'static str),
    /// Anything at any depth under this directory.
    Under(&'static str),
    /// An immediate child of this directory with one of these extensions.
    DirWithExt(&'static str, &'static [&'static str]),
    /// A file with this name at any depth under this directory.
    UnderNamed(&'static str, &'static str),
}

/// Extensions that make a file inside a config directory executable.
const SCRIPT_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "ts", "sh", "py"];

/// One entry of the allowlist.
#[derive(Debug, Clone)]
pub struct WorkspacePattern {
    /// The pattern as ADR 0025 §3 writes it. Kept verbatim so the document and
    /// the code can be diffed by eye, and asserted by a test.
    pub glob: &'static str,
    shape: Shape,
    /// The host that reads this path.
    pub host: AgentHost,
    /// How the file is parsed.
    pub kind: WorkspaceFileKind,
    /// The scope a match at the repository root gets. A match under a prefix is
    /// downgraded by [`classify`].
    pub root_scope: RuntimeScope,
}

/// The allowlist, in full.
///
/// `node_modules` stays excluded on this surface too. An agent config *inside*
/// a dependency is a real vector and a very large scan; it is named as
/// out-of-scope in ADR 0025 rather than left unsaid.
pub const ALLOWLIST: &[WorkspacePattern] = &[
    WorkspacePattern {
        glob: ".claude/settings.json",
        shape: Shape::Exact(".claude/settings.json"),
        host: AgentHost::CLAUDE_CODE,
        kind: WorkspaceFileKind::Settings,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".claude/settings.local.json",
        shape: Shape::Exact(".claude/settings.local.json"),
        host: AgentHost::CLAUDE_CODE,
        kind: WorkspaceFileKind::Settings,
        // Gitignored by convention, loaded by the host all the same. This entry
        // is the whole reason the allowlist overrides `.gitignore`.
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".claude/hooks/**",
        shape: Shape::Under(".claude/hooks"),
        host: AgentHost::CLAUDE_CODE,
        kind: WorkspaceFileKind::Script,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".claude/agents/**",
        shape: Shape::Under(".claude/agents"),
        host: AgentHost::CLAUDE_CODE,
        kind: WorkspaceFileKind::AgentDefinition,
        root_scope: RuntimeScope::ProjectOptional,
    },
    WorkspacePattern {
        glob: ".claude/skills/**",
        shape: Shape::Under(".claude/skills"),
        host: AgentHost::CLAUDE_CODE,
        kind: WorkspaceFileKind::AgentDefinition,
        root_scope: RuntimeScope::ProjectOptional,
    },
    WorkspacePattern {
        glob: ".claude/*.{js,mjs,cjs,ts,sh,py}",
        shape: Shape::DirWithExt(".claude", SCRIPT_EXTENSIONS),
        host: AgentHost::CLAUDE_CODE,
        kind: WorkspaceFileKind::Script,
        // A loose script is only executed if something references it. The rule
        // that finds the reference is what raises this to `active`.
        root_scope: RuntimeScope::ProjectOptional,
    },
    WorkspacePattern {
        glob: ".claude-plugin/**",
        shape: Shape::Under(".claude-plugin"),
        host: AgentHost::CLAUDE_CODE,
        kind: WorkspaceFileKind::PluginManifest,
        root_scope: RuntimeScope::ProjectOptional,
    },
    WorkspacePattern {
        glob: ".cursor/mcp.json",
        shape: Shape::Exact(".cursor/mcp.json"),
        host: AgentHost::CURSOR,
        kind: WorkspaceFileKind::Mcp,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".cursor/hooks.json",
        shape: Shape::Exact(".cursor/hooks.json"),
        host: AgentHost::CURSOR,
        kind: WorkspaceFileKind::Hooks,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".cursor/hooks/**",
        shape: Shape::Under(".cursor/hooks"),
        host: AgentHost::CURSOR,
        kind: WorkspaceFileKind::Script,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".cursor/*.{js,mjs,cjs,ts,sh,py}",
        shape: Shape::DirWithExt(".cursor", SCRIPT_EXTENSIONS),
        host: AgentHost::CURSOR,
        kind: WorkspaceFileKind::Script,
        root_scope: RuntimeScope::ProjectOptional,
    },
    WorkspacePattern {
        glob: ".cursor/rules/**",
        shape: Shape::Under(".cursor/rules"),
        host: AgentHost::CURSOR,
        kind: WorkspaceFileKind::Instructions,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".cursorrules",
        shape: Shape::Exact(".cursorrules"),
        host: AgentHost::CURSOR,
        kind: WorkspaceFileKind::Instructions,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".vscode/tasks.json",
        shape: Shape::Exact(".vscode/tasks.json"),
        host: AgentHost::VSCODE,
        kind: WorkspaceFileKind::Tasks,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".vscode/settings.json",
        shape: Shape::Exact(".vscode/settings.json"),
        host: AgentHost::VSCODE,
        kind: WorkspaceFileKind::Settings,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".vscode/extensions.json",
        shape: Shape::Exact(".vscode/extensions.json"),
        host: AgentHost::VSCODE,
        kind: WorkspaceFileKind::Extensions,
        root_scope: RuntimeScope::ProjectOptional,
    },
    WorkspacePattern {
        glob: ".vscode/*.{js,mjs,cjs,ts,sh,py}",
        shape: Shape::DirWithExt(".vscode", SCRIPT_EXTENSIONS),
        host: AgentHost::VSCODE,
        kind: WorkspaceFileKind::Script,
        root_scope: RuntimeScope::ProjectOptional,
    },
    WorkspacePattern {
        glob: ".devcontainer/devcontainer.json",
        shape: Shape::Exact(".devcontainer/devcontainer.json"),
        host: AgentHost::VSCODE,
        kind: WorkspaceFileKind::DevContainer,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".devcontainer/**/devcontainer.json",
        shape: Shape::UnderNamed(".devcontainer", "devcontainer.json"),
        host: AgentHost::VSCODE,
        kind: WorkspaceFileKind::DevContainer,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".github/copilot-instructions.md",
        shape: Shape::Exact(".github/copilot-instructions.md"),
        host: AgentHost::COPILOT,
        kind: WorkspaceFileKind::Instructions,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".gemini/**",
        shape: Shape::Under(".gemini"),
        host: AgentHost::GEMINI_CLI,
        kind: WorkspaceFileKind::Settings,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".codex/**",
        shape: Shape::Under(".codex"),
        host: AgentHost::CODEX,
        kind: WorkspaceFileKind::Settings,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: ".mcp.json",
        shape: Shape::Exact(".mcp.json"),
        host: AgentHost::GENERIC,
        kind: WorkspaceFileKind::Mcp,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: "mcp.json",
        shape: Shape::Exact("mcp.json"),
        host: AgentHost::GENERIC,
        kind: WorkspaceFileKind::Mcp,
        // Not on any host's default resolution path by itself; a host has to be
        // pointed at it.
        root_scope: RuntimeScope::ProjectOptional,
    },
    WorkspacePattern {
        glob: "CLAUDE.md",
        shape: Shape::Exact("CLAUDE.md"),
        host: AgentHost::CLAUDE_CODE,
        kind: WorkspaceFileKind::Instructions,
        root_scope: RuntimeScope::Active,
    },
    WorkspacePattern {
        glob: "AGENTS.md",
        shape: Shape::Exact("AGENTS.md"),
        host: AgentHost::GENERIC,
        kind: WorkspaceFileKind::Instructions,
        root_scope: RuntimeScope::Active,
    },
];

/// Directory names that mean "this is an example, not the configuration".
///
/// Deliberately conservative. A false `template` classification caps a real
/// finding's confidence, so this list contains only names whose meaning is not
/// in dispute — no `demo`, no `sandbox`, no `playground`, all of which are also
/// used for code that genuinely runs.
const TEMPLATE_DIRS: &[&str] = &[
    "doc",
    "docs",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "sample",
    "samples",
    "template",
    "templates",
    "test",
    "tests",
    "__tests__",
    "testdata",
    "__fixtures__",
];

/// What the allowlist says about one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// The host that reads it.
    pub host: AgentHost,
    /// How to parse it.
    pub kind: WorkspaceFileKind,
    /// How much of the host's real configuration it is.
    pub runtime_scope: RuntimeScope,
    /// The allowlist pattern that matched, for evidence and for tests.
    pub matched: &'static str,
}

/// Classifies a project-relative path, or `None` if it is not on the list.
///
/// The first matching pattern wins, so order in [`ALLOWLIST`] is significant
/// where two patterns could both match — `.claude/hooks/x.mjs` is a hook script
/// and not a loose `.claude` script, because the more specific entry is first.
#[must_use]
pub fn classify(path: &RelPath) -> Option<Classification> {
    let full = path.as_str();
    for (prefix_len, candidate) in suffixes(full) {
        for pattern in ALLOWLIST {
            if !pattern.shape.matches(candidate) {
                continue;
            }
            let runtime_scope = if prefix_len == 0 {
                pattern.root_scope
            } else {
                scope_for_prefix(full.get(..prefix_len).unwrap_or_default())
            };
            return Some(Classification {
                host: pattern.host.clone(),
                kind: refine_kind(pattern.kind, candidate),
                runtime_scope,
                matched: pattern.glob,
            });
        }
    }
    None
}

/// `.gemini/**` and `.codex/**` are whole directories holding both settings and
/// instructions. The pattern cannot say which, so the extension does.
fn refine_kind(kind: WorkspaceFileKind, path: &str) -> WorkspaceFileKind {
    let extension = path
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase());
    match extension.as_deref() {
        Some("md" | "markdown" | "txt") if kind.is_json() => WorkspaceFileKind::Instructions,
        Some("js" | "mjs" | "cjs" | "ts" | "sh" | "py") if kind.is_json() => {
            WorkspaceFileKind::Script
        }
        Some("md" | "markdown") if kind == WorkspaceFileKind::Script => {
            // A Markdown file under `.claude/hooks/` is a note, not a hook.
            WorkspaceFileKind::Instructions
        }
        Some("json" | "jsonc") if kind == WorkspaceFileKind::AgentDefinition => {
            WorkspaceFileKind::Settings
        }
        _ => kind,
    }
}

/// `(prefix_len, suffix)` for the whole path and then for each directory
/// boundary, so a pattern can be tried at the root first and under a prefix
/// after.
fn suffixes(path: &str) -> Vec<(usize, &str)> {
    let mut out = vec![(0usize, path)];
    let mut index = 0usize;
    for (position, byte) in path.char_indices() {
        if byte == '/' {
            index = position.saturating_add(1);
            if let Some(rest) = path.get(index..) {
                out.push((index, rest));
            }
        }
    }
    let _ = index;
    out
}

/// The scope a nested match gets, from the directories above it.
fn scope_for_prefix(prefix: &str) -> RuntimeScope {
    let is_template = prefix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .any(|segment| TEMPLATE_DIRS.contains(&segment.to_ascii_lowercase().as_str()));
    if is_template {
        RuntimeScope::Template
    } else {
        // A `.claude/settings.json` inside a monorepo package is real
        // configuration for whoever opens that package, and not what the host
        // loads for the repository root. `project-optional` is exactly that.
        RuntimeScope::ProjectOptional
    }
}

impl Shape {
    fn matches(self, path: &str) -> bool {
        match self {
            Self::Exact(expected) => path == expected,
            Self::Under(dir) => path
                .strip_prefix(dir)
                .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1),
            Self::DirWithExt(dir, extensions) => {
                let Some(rest) = path.strip_prefix(dir).and_then(|r| r.strip_prefix('/')) else {
                    return false;
                };
                if rest.contains('/') {
                    return false;
                }
                rest.rsplit_once('.').is_some_and(|(stem, extension)| {
                    !stem.is_empty()
                        && extensions.contains(&extension.to_ascii_lowercase().as_str())
                })
            }
            Self::UnderNamed(dir, name) => {
                let Some(rest) = path.strip_prefix(dir).and_then(|r| r.strip_prefix('/')) else {
                    return false;
                };
                rest.contains('/') && rest.rsplit('/').next() == Some(name)
            }
        }
    }
}

/// Every glob in the allowlist, for the documentation test and for
/// `owlwarden coverage`.
#[must_use]
pub fn allowlist_globs() -> Vec<&'static str> {
    ALLOWLIST.iter().map(|pattern| pattern.glob).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::path::Path;

    fn classify_str(path: &str) -> Option<Classification> {
        classify(&RelPath::new(Path::new(path)).expect("a relative path"))
    }

    #[test]
    fn the_gitignored_file_the_cve_was_about_is_on_the_list() {
        let found = classify_str(".claude/settings.local.json").expect("allowlisted");
        assert_eq!(found.host, AgentHost::CLAUDE_CODE);
        assert_eq!(found.runtime_scope, RuntimeScope::Active);
    }

    #[test]
    fn every_host_and_kind_is_reachable_from_some_pattern() {
        for host in owlwarden_core::surface::SUPPORTED_AGENT_HOSTS {
            assert!(
                ALLOWLIST.iter().any(|pattern| &pattern.host == host),
                "{host} has no path on the allowlist, so its rules can never fire"
            );
        }
    }

    #[test]
    fn the_list_matches_the_adr_verbatim() {
        // If this fails, the document and the code have diverged, and the
        // document is what a reviewer reads.
        let expected = [
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".claude/hooks/**",
            ".claude/agents/**",
            ".claude/skills/**",
            ".claude/*.{js,mjs,cjs,ts,sh,py}",
            ".claude-plugin/**",
            ".cursor/mcp.json",
            ".cursor/hooks.json",
            ".cursor/hooks/**",
            ".cursor/*.{js,mjs,cjs,ts,sh,py}",
            ".cursor/rules/**",
            ".cursorrules",
            ".vscode/tasks.json",
            ".vscode/settings.json",
            ".vscode/extensions.json",
            ".vscode/*.{js,mjs,cjs,ts,sh,py}",
            ".devcontainer/devcontainer.json",
            ".devcontainer/**/devcontainer.json",
            ".github/copilot-instructions.md",
            ".gemini/**",
            ".codex/**",
            ".mcp.json",
            "mcp.json",
            "CLAUDE.md",
            "AGENTS.md",
        ];
        assert_eq!(allowlist_globs(), expected);
    }

    #[test]
    fn ordinary_source_is_not_on_the_surface() {
        for path in [
            "app/api/users/route.ts",
            "package.json",
            "README.md",
            ".github/workflows/ci.yml",
            "src/claude.md",
            "claude.md",
            ".claudeignore",
            ".vscode/launch.json",
        ] {
            assert!(
                classify_str(path).is_none(),
                "{path} must not be scanned here"
            );
        }
    }

    #[test]
    fn the_extension_patterns_only_take_immediate_children() {
        assert!(classify_str(".claude/setup.mjs").is_some());
        assert!(classify_str(".vscode/setup.mjs").is_some());
        // A nested script is reached by `.claude/hooks/**`, not by the loose
        // pattern, and anything else nested is not on the list at all.
        assert_eq!(
            classify_str(".claude/nested/deep/setup.mjs").map(|c| c.matched),
            None
        );
        assert_eq!(
            classify_str(".claude/hooks/pre.mjs").map(|c| c.matched),
            Some(".claude/hooks/**")
        );
    }

    #[test]
    fn a_template_copy_is_found_and_marked_rather_than_missed() {
        let template = classify_str("examples/starter/.claude/settings.json").expect("found");
        assert_eq!(template.runtime_scope, RuntimeScope::Template);
        assert_eq!(
            template.runtime_scope.confidence_ceiling(),
            owlwarden_core::finding::Confidence::Possible
        );

        let nested = classify_str("packages/api/.claude/settings.json").expect("found");
        assert_eq!(nested.runtime_scope, RuntimeScope::ProjectOptional);

        let root = classify_str(".claude/settings.json").expect("found");
        assert_eq!(root.runtime_scope, RuntimeScope::Active);
    }

    #[test]
    fn nested_devcontainers_are_matched_at_any_depth() {
        assert!(classify_str(".devcontainer/devcontainer.json").is_some());
        assert!(classify_str(".devcontainer/api/devcontainer.json").is_some());
        assert!(classify_str(".devcontainer/api/Dockerfile").is_none());
    }

    #[test]
    fn a_gemini_markdown_file_is_instructions_not_settings() {
        assert_eq!(
            classify_str(".gemini/GEMINI.md").map(|c| c.kind),
            Some(WorkspaceFileKind::Instructions)
        );
        assert_eq!(
            classify_str(".gemini/settings.json").map(|c| c.kind),
            Some(WorkspaceFileKind::Settings)
        );
        assert_eq!(
            classify_str(".codex/hook.sh").map(|c| c.kind),
            Some(WorkspaceFileKind::Script)
        );
    }

    #[test]
    fn a_directory_itself_is_not_a_file() {
        assert!(classify_str(".claude/hooks").is_none());
        assert!(classify_str(".gemini").is_none());
    }
}
