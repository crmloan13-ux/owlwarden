//! Reading the current surface out of the working tree.
//!
//! Everything here is derived from [`AgentWorkspace`], which is the same closed
//! allowlist, the same bounded JSONC parser, and the same size caps the rules
//! read through. The seal is not a second way into the surface — a second
//! reader would eventually disagree with the first, and the disagreement would
//! be silent.

use std::collections::BTreeSet;

use owlwarden_detectors::agent::{HookEntry, collect_hooks};
use owlwarden_static::agentws::AgentWorkspace;
use owlwarden_static::agentws::jsonc::{JsonNode, JsonValue};
use owlwarden_static::agentws::paths::WorkspaceFileKind;
use owlwarden_static::agentws::workspace::WorkspaceFile;

use crate::model::{
    EngineStamp, SealedFile, SealedHook, SealedMcpServer, SealedPermissions, SurfaceRecord, digest,
};

/// Longest command prefix echoed into the lockfile.
///
/// The lockfile is committed and read in a pull request. A hostile config can
/// hold a megabyte on one line, and the whole value of the diff is that a human
/// reads it.
const MAX_TARGET_CHARS: usize = 120;

/// Most entries of any one list. The surface is already capped by
/// [`AgentWorkspace`]; this bounds the derived lists so a file of ten thousand
/// hooks produces a lockfile somebody can still open.
const MAX_ENTRIES: usize = 512;

/// Extraction failed in a way that must not be reported as a clean surface.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// The tree could not be walked.
    #[error("could not read the agent workspace: {0}")]
    Workspace(#[from] owlwarden_core::source::SourceError),
}

/// Reads the whole protected surface.
///
/// Deterministic: every list is sorted by a total key, so two runs over the
/// same tree write byte-identical files. A lockfile that churns is a lockfile
/// nobody reads.
#[must_use]
pub fn extract(workspace: &AgentWorkspace) -> SurfaceRecord {
    let mut record = SurfaceRecord {
        files: sealed_files(workspace),
        hooks: sealed_hooks(workspace),
        mcp_servers: sealed_mcp_servers(workspace),
        permissions: sealed_permissions(workspace),
        marketplaces: marketplaces(workspace),
        instruction_files: instruction_files(workspace),
    };
    record
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    record.hooks.sort_by(|left, right| {
        left.key().cmp(&right.key()).then_with(|| {
            left.command_digest
                .cmp(&right.command_digest)
                .then_with(|| left.declared_at.cmp(&right.declared_at))
        })
    });
    record.mcp_servers.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.host.cmp(&right.host))
    });
    record.marketplaces.sort_unstable();
    record.marketplaces.dedup();
    record.instruction_files.sort_unstable();
    record
}

/// The engine stamp for this build.
#[must_use]
pub fn engine_stamp() -> EngineStamp {
    let mut ids: Vec<String> = owlwarden_detectors::all_rules()
        .into_iter()
        .map(|rule| rule.meta().id.to_string())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    EngineStamp {
        version: owlwarden_core::ENGINE_VERSION.to_owned(),
        catalogue_digest: digest(ids.join("\n").as_bytes()),
    }
}

fn sealed_files(workspace: &AgentWorkspace) -> Vec<SealedFile> {
    workspace
        .files()
        .iter()
        // The lockfile and its signature are on the protected surface — writing
        // one is a tracked event — but they are not *in* the record. Sealing a
        // file whose contents are the seal is a fixed point that does not
        // exist: every write would change the digest it just recorded.
        .filter(|file| file.kind != WorkspaceFileKind::SurfaceLock)
        .take(MAX_ENTRIES)
        .map(|file| SealedFile {
            path: file.path.to_string(),
            sha256: digest(file.text.as_bytes()),
            semantic: semantic_digest(file),
            tier: file.runtime_scope.as_str().to_owned(),
        })
        .collect()
}

/// The digest comparison actually uses.
///
/// For a JSON file it is over the canonicalised structure, so reformatting does
/// not break the seal and one changed character of a hook command does. For an
/// instruction file it is the byte digest, because whitespace in a file whose
/// purpose is to be read by a model is content: a reordered paragraph in
/// `CLAUDE.md` is a different instruction, and a seal that shrugged at it would
/// be sealing the wrong thing.
fn semantic_digest(file: &WorkspaceFile) -> String {
    match file.doc() {
        Some(doc) => {
            let mut canonical = String::new();
            canonicalise(doc, &mut canonical, 0);
            digest(canonical.as_bytes())
        }
        None => digest(file.text.as_bytes()),
    }
}

/// Writes a value in a canonical form: keys sorted, whitespace fixed, numbers
/// as written.
///
/// Duplicate keys are kept and sorted alongside each other rather than
/// collapsed. The parser keeps them deliberately — a config can declare `hooks`
/// twice, and a host whose parser is last-wins loads the second — so a
/// canonicaliser that dropped one would erase exactly the shape this surface
/// exists to notice.
///
/// Bounded by depth, because the input is a file nobody vetted and the parser's
/// own depth cap is the only thing between this and a stack.
fn canonicalise(node: &JsonNode, out: &mut String, depth: usize) {
    if depth > owlwarden_static::agentws::jsonc::MAX_DEPTH {
        out.push('…');
        return;
    }
    match &node.value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        JsonValue::Number(text) => out.push_str(text),
        JsonValue::String(text) => {
            out.push('"');
            for ch in text.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    other => out.push(other),
                }
            }
            out.push('"');
        }
        JsonValue::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonicalise(item, out, depth.saturating_add(1));
            }
            out.push(']');
        }
        JsonValue::Object(members) => {
            let mut rendered: Vec<String> = members
                .iter()
                .map(|member| {
                    let mut entry = String::new();
                    canonicalise(
                        &JsonNode {
                            value: JsonValue::String(member.key.clone()),
                            span: member.key_span,
                        },
                        &mut entry,
                        depth.saturating_add(1),
                    );
                    entry.push(':');
                    canonicalise(&member.value, &mut entry, depth.saturating_add(1));
                    entry
                })
                .collect();
            rendered.sort_unstable();
            out.push('{');
            out.push_str(&rendered.join(","));
            out.push('}');
        }
    }
}

fn sealed_hooks(workspace: &AgentWorkspace) -> Vec<SealedHook> {
    collect_hooks(workspace)
        .into_iter()
        .take(MAX_ENTRIES)
        .map(|entry| sealed_hook(&entry))
        .collect()
}

fn sealed_hook(entry: &HookEntry<'_>) -> SealedHook {
    let command = entry.command.clone().unwrap_or_default();
    let (line, _) = entry.file.lines.position(&entry.file.text, entry.span().0);
    SealedHook {
        host: entry.file.host.as_str().to_owned(),
        event: clamp(&entry.trigger),
        matcher: entry.matcher.as_deref().map(clamp),
        command_digest: digest(command.as_bytes()),
        target: clamp(&command),
        declared_at: format!("{}:{line}", entry.file.path.as_str()),
        automatic: entry.automatic,
    }
}

fn sealed_mcp_servers(workspace: &AgentWorkspace) -> Vec<SealedMcpServer> {
    let mut out = Vec::new();
    for (file, doc) in workspace.json_files() {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        // `members`, not `get`, for the reason the hook walker uses it: a
        // config can declare the key twice, and the host's parser is last-wins.
        for block in doc.members("mcpServers").chain(doc.members("servers")) {
            let Some(members) = block.value.as_object() else {
                continue;
            };
            for member in members.iter().take(MAX_ENTRIES) {
                if out.len() >= MAX_ENTRIES {
                    break;
                }
                let (line, _) = file.lines.position(&file.text, member.key_span.0);
                let command = server_command(&member.value);
                out.push(SealedMcpServer {
                    name: clamp(&member.key),
                    host: file.host.as_str().to_owned(),
                    pin: pin_of(&command, &member.value).to_owned(),
                    command: clamp(&command),
                    declared_at: format!("{}:{line}", file.path.as_str()),
                });
            }
        }
    }
    out
}

/// The command line or URL a server entry resolves to.
fn server_command(node: &JsonNode) -> String {
    if let Some(url) = node.get("url").and_then(JsonNode::as_str) {
        return url.to_owned();
    }
    let command = node.get("command").and_then(JsonNode::as_str).unwrap_or("");
    let arguments = node
        .get("args")
        .and_then(JsonNode::as_array)
        .map(|args| {
            args.iter()
                .filter_map(JsonNode::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    if arguments.is_empty() {
        command.to_owned()
    } else {
        format!("{command} {arguments}")
    }
}

/// How tightly a server is pinned.
///
/// The field a reviewer reads. `exact` and `unpinned` are the two that matter:
/// a server moving from `some-mcp@2.4.1` to `npx -y some-mcp` is the whole
/// finding, and a file digest would only have said `settings.json` changed.
fn pin_of(command: &str, node: &JsonNode) -> &'static str {
    if command.is_empty() {
        return "unknown";
    }
    if command.starts_with("http://") || command.starts_with("https://") {
        return "remote";
    }
    if command.contains("node_modules/.bin/") || command.starts_with("./") {
        return "workspace";
    }
    let version = command
        .split_whitespace()
        .find_map(|word| word.rsplit_once('@'))
        .map(|(_, version)| version);
    match version {
        Some(version)
            if !version.is_empty()
                && version.chars().next().is_some_and(|ch| ch.is_ascii_digit()) =>
        {
            "exact"
        }
        Some(_) => "range",
        None => {
            // `npx -y whatever` resolves to whatever is latest today.
            if node
                .get("command")
                .and_then(JsonNode::as_str)
                .is_some_and(|value| value.ends_with("npx") || value.ends_with("bunx"))
            {
                "unpinned"
            } else {
                "unversioned"
            }
        }
    }
}

fn sealed_permissions(workspace: &AgentWorkspace) -> SealedPermissions {
    let mut allow: Vec<String> = Vec::new();
    let mut deny: Vec<String> = Vec::new();
    for (_, doc) in workspace.json_files() {
        for block in doc.members("permissions") {
            collect_list(&block.value, "allow", &mut allow);
            collect_list(&block.value, "deny", &mut deny);
        }
    }
    allow.sort_unstable();
    allow.dedup();
    deny.sort_unstable();
    deny.dedup();
    SealedPermissions {
        allow_digest: (!allow.is_empty()).then(|| digest(allow.join("\n").as_bytes())),
        deny_digest: (!deny.is_empty()).then(|| digest(deny.join("\n").as_bytes())),
        allow_count: allow.len(),
        deny_count: deny.len(),
    }
}

fn collect_list(node: &JsonNode, key: &str, out: &mut Vec<String>) {
    for member in node.members(key) {
        let Some(items) = member.value.as_array() else {
            continue;
        };
        for item in items.iter().take(MAX_ENTRIES) {
            if out.len() >= MAX_ENTRIES {
                return;
            }
            if let Some(text) = item.as_str() {
                out.push(text.to_owned());
            }
        }
    }
}

/// Plugin marketplace and extension sources.
///
/// Both belong here for the same reason: each is a place the host will fetch
/// executable configuration from, named by the repository rather than by the
/// developer, and neither is recorded anywhere else.
fn marketplaces(workspace: &AgentWorkspace) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for (file, doc) in workspace.json_files() {
        for key in ["marketplaces", "marketplace", "sources", "recommendations"] {
            for member in doc.members(key) {
                match &member.value.value {
                    JsonValue::String(text) => {
                        out.insert(clamp(text));
                    }
                    JsonValue::Array(items) => {
                        for item in items.iter().take(MAX_ENTRIES) {
                            if let Some(text) = item.as_str() {
                                out.insert(clamp(text));
                            } else if let Some(source) =
                                item.get("source").and_then(JsonNode::as_str)
                            {
                                out.insert(clamp(source));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // A marketplace manifest is itself a source.
        if file.kind == WorkspaceFileKind::PluginManifest {
            out.insert(file.path.to_string());
        }
    }
    out.into_iter().take(MAX_ENTRIES).collect()
}

fn instruction_files(workspace: &AgentWorkspace) -> Vec<String> {
    workspace
        .instruction_files()
        .take(MAX_ENTRIES)
        .map(|file| file.path.to_string())
        .collect()
}

/// Truncates and neutralises a string bound for a committed file.
///
/// Reuses the engine's own untrusted-text handling rather than a second
/// implementation: this text comes out of a repository nobody vetted and lands
/// in a lockfile that is read in a pull request, where a bidi override would
/// reorder the diff itself.
fn clamp(text: &str) -> String {
    owlwarden_core::untrusted_text::one_line(text, MAX_TARGET_CHARS)
}
