//! `agent-mcp-unpinned-remote` and `agent-marketplace-untrusted`.
//!
//! Both rules ask the same question in two places: *where does the code the
//! agent will run come from, and is that decision written down?* An MCP server
//! resolved with `npx -y` and a marketplace added by a repository are the same
//! delegation of trust, made on the developer's behalf, by a file in a pull
//! request.

use owlwarden_core::detector::{DetectorError, DetectorMeta};
use owlwarden_core::finding::{AgentHost, AsiRef, Confidence, FindingContext, RuleId, Severity};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::surface::Surface;
use owlwarden_static::agentws::jsonc::{JsonMember, JsonNode};
use owlwarden_static::project::Project;
use owlwarden_static::rule::{FindingSink, ProjectRule, RuleInfo};

use super::{agent_finding, evidence, push};

/// `agent-mcp-unpinned-remote` — permanent public API.
pub const MCP_ID: &str = "agent-mcp-unpinned-remote";
/// `agent-marketplace-untrusted` — permanent public API.
pub const MARKETPLACE_ID: &str = "agent-marketplace-untrusted";

/// Keys that hold a map of MCP server declarations.
const SERVER_MAP_KEYS: &[&str] = &["mcpservers", "servers", "mcp"];

/// Runners that resolve a package when the server starts.
const RESOLVERS: &[&str] = &["npx", "bunx", "uvx", "pnpx", "dlx", "pipx"];

/// MCP server declaration resolves code at run time.
#[derive(Debug, Default, Clone, Copy)]
pub struct AgentMcpUnpinnedRemote;

impl AgentMcpUnpinnedRemote {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(MCP_ID),
            title: "MCP server declaration resolves code at run time".into(),
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: None,
            asi: Some(AsiRef::new_static("ASI04")),
            cwe: Some(1357),
            surface: Surface::AgentWorkspace,
            category: "agent-supply-chain".into(),
            description: "An MCP server is launched with `npx -y`, `uvx`, `bunx`, or a container \
                          image with no digest, or is reached over a remote transport. The code \
                          that gets a tool call today is not necessarily the code that got one \
                          yesterday, and there is no version in the repository to review."
                .into(),
        }
    }
}

impl RuleInfo for AgentMcpUnpinnedRemote {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        mcp_remediation()
    }
}

impl ProjectRule for AgentMcpUnpinnedRemote {
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink) -> Result<(), DetectorError> {
        let meta = Self::meta();
        let mut emitted = 0usize;

        for (file, doc) in project.agent_workspace().json_files() {
            for server in servers(doc) {
                let Some(problem) = server_problem(&server.value) else {
                    continue;
                };
                let finding = agent_finding(
                    &meta,
                    file,
                    problem.span,
                    problem.label,
                    format!(
                        "`{}` {} Whoever controls what that name resolves to controls a process \
                         holding tool access to this workspace.",
                        server.key, problem.why
                    ),
                )
                .context(FindingContext {
                    framework: None,
                    host: Some(file.host.clone()),
                    route: None,
                    method: None,
                    evidence: Some(evidence(&format!("{}: {}", server.key, problem.evidence))),
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

struct ServerProblem {
    span: (u32, u32),
    label: &'static str,
    why: &'static str,
    evidence: String,
}

/// Every MCP server declaration in a document.
fn servers(doc: &JsonNode) -> Vec<&JsonMember> {
    let mut out = Vec::new();
    let Some(members) = doc.as_object() else {
        return out;
    };
    for member in members {
        let key = member.key.to_ascii_lowercase().replace(['-', '_'], "");
        if SERVER_MAP_KEYS.contains(&key.as_str())
            && let Some(servers) = member.value.as_object()
        {
            out.extend(servers.iter());
        }
        // `.vscode/settings.json` nests the same map one level down under
        // `mcp`; walking one extra level costs nothing and covers it.
        if let Some(nested) = member.value.as_object() {
            for inner in nested {
                let inner_key = inner.key.to_ascii_lowercase().replace(['-', '_'], "");
                if SERVER_MAP_KEYS.contains(&inner_key.as_str())
                    && let Some(servers) = inner.value.as_object()
                {
                    out.extend(servers.iter());
                }
            }
        }
    }
    out
}

/// What is wrong with one server declaration, if anything.
fn server_problem(server: &JsonNode) -> Option<ServerProblem> {
    // A remote transport: the code is not on this machine at all.
    if let Some(url) = server.get("url").or_else(|| server.get("endpoint"))
        && let Some(text) = url.as_str()
        && !is_loopback(text)
    {
        return Some(ServerProblem {
            span: url.span,
            label: "remote transport — the tool runs on someone else's machine",
            why: "is reached over a remote transport, so its behaviour can change without any \
                  change to this repository.",
            evidence: text.to_owned(),
        });
    }

    let command_node = server.get("command")?;
    let command = command_node.as_str()?;
    let args: Vec<&str> = server
        .get("args")
        .and_then(JsonNode::as_array)
        .map(|items| items.iter().filter_map(JsonNode::as_str).collect())
        .unwrap_or_default();
    let program = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let full = format!("{command} {}", args.join(" "));

    if RESOLVERS.contains(&program) || args.first().is_some_and(|arg| *arg == "dlx") {
        let specifier = args
            .iter()
            .find(|arg| !arg.starts_with('-') && **arg != "dlx")
            .copied()
            .unwrap_or_default();
        if !is_pinned_specifier(specifier) {
            return Some(ServerProblem {
                span: command_node.span,
                label: "resolves the package when the server starts",
                why: "resolves its package at run time with no version pinned, so today's code is \
                      whatever the registry serves.",
                evidence: full,
            });
        }
        return None;
    }

    if program == "docker" || program == "podman" {
        let image = args
            .iter()
            .rev()
            .find(|arg| !arg.starts_with('-'))
            .copied()
            .unwrap_or_default();
        if !image.contains("@sha256:") {
            return Some(ServerProblem {
                span: command_node.span,
                label: "container image is not pinned to a digest",
                why: "runs a container image with no digest, so the tag can be repointed at a \
                      different image.",
                evidence: full,
            });
        }
    }
    None
}

/// Whether a package specifier names an exact version.
///
/// `pkg@1.2.3` yes; `pkg`, `pkg@latest`, `pkg@^1` no. Scoped names keep their
/// leading `@`, which is why the search starts after the first character.
fn is_pinned_specifier(specifier: &str) -> bool {
    let Some((_, version)) = specifier.get(1..).and_then(|rest| rest.split_once('@')) else {
        return false;
    };
    !version.is_empty()
        && version.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        && !version.contains(['^', '~', '*', 'x'])
}

fn is_loopback(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let after = lower
        .split_once("://")
        .map_or(lower.as_str(), |(_, rest)| rest);
    let host = after.split(['/', ':']).next().unwrap_or_default();
    matches!(host, "localhost" | "127.0.0.1" | "::1") || host.ends_with(".localhost")
}

fn mcp_remediation() -> Remediation {
    Remediation::new(
        "Pin the version or the digest, and prefer a dependency in `devDependencies` over a \
         run-time resolve. For a remote transport, state the trust decision in the config — a \
         comment naming who runs the endpoint — rather than leaving it implicit.",
    )
    .generic_patch("\"args\": [\"-y\", \"@scope/mcp-server@1.4.2\"]")
    .host(
        AgentHost::CLAUDE_CODE,
        "Pin the exact version in `.mcp.json` or `.claude/settings.json`. Better: add the server \
         to `devDependencies` and launch it with `pnpm exec`, so the lockfile is the record of \
         what runs.",
        "// .mcp.json\n{\n  \"mcpServers\": {\n    \"db\": { \"command\": \"pnpm\", \"args\": [\"exec\", \"mcp-db\"] }\n  }\n}",
    )
    .host(
        AgentHost::CURSOR,
        "Pin the version in `.cursor/mcp.json`, or point the entry at a binary from \
         `devDependencies`. An unpinned entry means every teammate may be running a different \
         server.",
        "// .cursor/mcp.json\n\"args\": [\"-y\", \"@scope/mcp-server@1.4.2\"]",
    )
    .host(
        AgentHost::VSCODE,
        "Pin the version in the `mcp` block of `.vscode/settings.json`, or use a container image \
         by digest. `latest` in a workspace file is a moving target every contributor inherits.",
        "// .vscode/settings.json\n\"mcp\": { \"servers\": { \"db\": { \"command\": \"npx\", \"args\": [\"-y\", \"mcp-db@1.4.2\"] } } }",
    )
    .host(
        AgentHost::COPILOT,
        "Declare the server in the editor's MCP configuration with an exact version, and keep \
         `.github/copilot-instructions.md` free of tool wiring.",
        "\"args\": [\"-y\", \"mcp-db@1.4.2\"]",
    )
    .host(
        AgentHost::CODEX,
        "Pin the package version in the Codex tool configuration under `.codex/`, or install the \
         server as a project dependency and invoke it by path.",
        "// .codex/config.json\n\"args\": [\"-y\", \"mcp-db@1.4.2\"]",
    )
    .host(
        AgentHost::GEMINI_CLI,
        "Pin the version in `.gemini/settings.json`. Gemini CLI will happily start whatever the \
         registry returns; the pin is the only thing that makes the run reproducible.",
        "// .gemini/settings.json\n\"args\": [\"-y\", \"mcp-db@1.4.2\"]",
    )
    .host(
        AgentHost::GENERIC,
        "Name an exact version or an image digest. The test is whether two developers cloning the \
         repository on different days get the same server; `latest` fails it.",
        "\"args\": [\"-y\", \"mcp-db@1.4.2\"]",
    )
}

// ---------------------------------------------------------------------------
// agent-marketplace-untrusted
// ---------------------------------------------------------------------------

/// Keys through which a repository adds a source of plugins, skills, or
/// extensions.
///
/// `.vscode/extensions.json` `recommendations` is deliberately absent: it
/// suggests, it does not install, and the developer sees a prompt. Firing on it
/// would be the loudest false positive this rule could have.
const SOURCE_KEYS: &[&str] = &[
    "extraknownmarketplaces",
    "knownmarketplaces",
    "marketplaces",
    "marketplace",
    "pluginsources",
    "pluginrepositories",
    "skillsources",
    "skilldirectories",
    "extensionsources",
    "registries",
];

/// Keys that install from a source rather than merely naming one.
const AUTOINSTALL_KEYS: &[&str] = &["autoinstallplugins", "autoinstall", "installonstartup"];

/// Repository config adds a third-party plugin or skill source.
#[derive(Debug, Default, Clone, Copy)]
pub struct AgentMarketplaceUntrusted;

impl AgentMarketplaceUntrusted {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(MARKETPLACE_ID),
            title: "Repository config adds a third-party plugin or skill source".into(),
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: None,
            asi: Some(AsiRef::new_static("ASI04")),
            cwe: Some(1357),
            surface: Surface::AgentWorkspace,
            category: "agent-supply-chain".into(),
            description: "Repository-local configuration registers an extra plugin marketplace, \
                          skill directory, or extension source, or installs from one \
                          automatically. A marketplace reference is a delegation of trust the \
                          repository is making on the developer's behalf."
                .into(),
        }
    }
}

impl RuleInfo for AgentMarketplaceUntrusted {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        marketplace_remediation()
    }
}

impl ProjectRule for AgentMarketplaceUntrusted {
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink) -> Result<(), DetectorError> {
        let meta = Self::meta();
        let mut emitted = 0usize;

        for (file, doc) in project.agent_workspace().json_files() {
            for hit in doc.strings() {
                let under_source = hit
                    .path
                    .iter()
                    .any(|key| SOURCE_KEYS.contains(&normalise(key).as_str()));
                if !under_source {
                    continue;
                }
                let finding = agent_finding(
                    &meta,
                    file,
                    hit.span,
                    "adds a plugin source the developer did not choose",
                    format!(
                        "This repository registers `{}` as a source of plugins or skills. Anything \
                         that source serves runs with the same access as the agent, and the \
                         decision to trust it was made by whoever opened the pull request.",
                        evidence(hit.value)
                    ),
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

            if let Some((span, key)) = autoinstall(doc) {
                let finding = agent_finding(
                    &meta,
                    file,
                    span,
                    "installs plugins automatically",
                    format!(
                        "`{key}` installs from a plugin source without asking. Opening the \
                         repository is then enough to add code to the agent's own toolchain."
                    ),
                )
                .context(FindingContext {
                    framework: None,
                    host: Some(file.host.clone()),
                    route: None,
                    method: None,
                    evidence: Some(evidence(&key)),
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

fn normalise(key: &str) -> String {
    key.to_ascii_lowercase().replace(['-', '_', '.'], "")
}

fn autoinstall(doc: &JsonNode) -> Option<((u32, u32), String)> {
    fn walk(node: &JsonNode) -> Option<((u32, u32), String)> {
        let members = node.as_object()?;
        for member in members {
            if AUTOINSTALL_KEYS.contains(&normalise(&member.key).as_str())
                && member.value.as_bool() == Some(true)
            {
                return Some((member.key_span, member.key.clone()));
            }
            if let Some(found) = walk(&member.value) {
                return Some(found);
            }
        }
        None
    }
    walk(doc)
}

fn marketplace_remediation() -> Remediation {
    Remediation::new(
        "Take the source out of the repository. If the team wants it, each developer adds it once, \
         deliberately, at user level — the difference being that they chose to.",
    )
    .generic_patch("// remove the extra plugin source from repository config")
    .host(
        AgentHost::CLAUDE_CODE,
        "Remove `extraKnownMarketplaces` from `.claude/settings.json`. Ask developers to run \
         `/plugin marketplace add` themselves, so the trust decision is theirs and is visible when \
         they make it.",
        "// .claude/settings.json — no marketplace entries\n{ \"permissions\": { \"allow\": [] } }",
    )
    .host(
        AgentHost::CURSOR,
        "Remove the extra source from `.cursor/`. Cursor's extension and MCP sources belong in the \
         developer's own settings.",
        "// .cursor/settings — no extra sources",
    )
    .host(
        AgentHost::VSCODE,
        "Recommendations in `.vscode/extensions.json` are fine — they prompt. An extra gallery or \
         registry URL is not: remove it and let the marketplace the editor ships with be the one \
         that serves code.",
        "// .vscode/extensions.json\n{ \"recommendations\": [\"dbaeumer.vscode-eslint\"] }",
    )
    .host(
        AgentHost::COPILOT,
        "Extension sources come from the editor and from organisation policy. Remove the entry \
         from the repository and configure it centrally if it is genuinely needed.",
        "// organisation policy, not the repository",
    )
    .host(
        AgentHost::CODEX,
        "Remove the extra tool or plugin source from `.codex/` and let each developer add it at \
         user level.",
        "// ~/.codex/config.json",
    )
    .host(
        AgentHost::GEMINI_CLI,
        "Remove the extension source from `.gemini/settings.json`; Gemini CLI reads user-level \
         settings for exactly this.",
        "// ~/.gemini/settings.json",
    )
    .host(
        AgentHost::GENERIC,
        "A repository should not be able to decide where the developer's tools come from. Move \
         the source to the tier the developer controls.",
        "// user-level configuration, not the repository's",
    )
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
    use crate::agent::testing::{assert_silent, run_rule};

    #[test]
    fn an_unpinned_npx_server_fires() {
        let findings = run_rule(
            &AgentMcpUnpinnedRemote,
            &[(
                ".mcp.json",
                r#"{"mcpServers":{"db":{"command":"npx","args":["-y","mcp-db"]}}}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(
            findings[0]
                .context
                .evidence
                .as_deref()
                .unwrap()
                .contains("mcp-db")
        );
    }

    #[test]
    fn an_exactly_pinned_server_is_the_tempting_twin_and_stays_silent() {
        assert_silent(
            &AgentMcpUnpinnedRemote,
            &[(
                ".mcp.json",
                r#"{"mcpServers":{"db":{"command":"npx","args":["-y","@scope/mcp-db@1.4.2"]}}}"#,
            )],
            "an exact version is exactly what the fix asks for",
        );
        assert_silent(
            &AgentMcpUnpinnedRemote,
            &[(
                ".mcp.json",
                r#"{"mcpServers":{"db":{"command":"pnpm","args":["exec","mcp-db"]}}}"#,
            )],
            "a lockfile-backed launch is pinned by the lockfile",
        );
    }

    #[test]
    fn a_range_is_not_a_pin() {
        for specifier in ["mcp-db@latest", "mcp-db@^1.0.0", "mcp-db@1.x", "mcp-db"] {
            let json = format!(
                r#"{{"mcpServers":{{"db":{{"command":"npx","args":["-y","{specifier}"]}}}}}}"#
            );
            let findings = run_rule(&AgentMcpUnpinnedRemote, &[(".mcp.json", json.as_str())]);
            assert_eq!(findings.len(), 1, "{specifier} is not a pin");
        }
    }

    #[test]
    fn a_container_needs_a_digest_and_a_digest_is_enough() {
        let findings = run_rule(
            &AgentMcpUnpinnedRemote,
            &[(
                ".mcp.json",
                r#"{"mcpServers":{"x":{"command":"docker","args":["run","-i","ghcr.io/x/y:1.2"]}}}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
        assert_silent(
            &AgentMcpUnpinnedRemote,
            &[(
                ".mcp.json",
                r#"{"mcpServers":{"x":{"command":"docker","args":["run","-i","ghcr.io/x/y@sha256:abc"]}}}"#,
            )],
            "a digest is immutable, which is the whole ask",
        );
    }

    #[test]
    fn a_loopback_transport_is_the_developers_own_server() {
        assert_silent(
            &AgentMcpUnpinnedRemote,
            &[(
                ".cursor/mcp.json",
                r#"{"mcpServers":{"local":{"url":"http://localhost:7331/sse"}}}"#,
            )],
            "a server on the developer's own machine is not a supply chain",
        );
        let findings = run_rule(
            &AgentMcpUnpinnedRemote,
            &[(
                ".cursor/mcp.json",
                r#"{"mcpServers":{"remote":{"url":"https://tools.evil.example/sse"}}}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn an_extra_marketplace_fires() {
        let findings = run_rule(
            &AgentMarketplaceUntrusted,
            &[(
                ".claude/settings.json",
                r#"{"extraKnownMarketplaces":{"x":{"source":{"source":"github","repo":"evil/plugins"}}}}"#,
            )],
        );
        assert!(!findings.is_empty());
        assert_eq!(findings[0].id.as_str(), MARKETPLACE_ID);
    }

    #[test]
    fn extension_recommendations_are_not_a_marketplace() {
        assert_silent(
            &AgentMarketplaceUntrusted,
            &[(
                ".vscode/extensions.json",
                r#"{"recommendations":["dbaeumer.vscode-eslint","esbenp.prettier-vscode"]}"#,
            )],
            "recommendations prompt the developer; they do not install",
        );
    }

    #[test]
    fn auto_install_is_reported_even_with_no_source_named() {
        let findings = run_rule(
            &AgentMarketplaceUntrusted,
            &[(".claude/settings.json", r#"{"autoInstallPlugins": true}"#)],
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].why.contains("without asking"));
    }
}
