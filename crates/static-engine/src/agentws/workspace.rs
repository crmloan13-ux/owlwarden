//! `AgentWorkspace` — the agent and editor configuration of one repository,
//! read once and handed to every rule in the family.
//!
//! The [`Project`](crate::project::Project) of the second surface. Built lazily
//! and cached, because most scans enable at least one agent rule and none of
//! them should pay for the walk twice — and a scan with no agent rules enabled
//! should not pay for it at all.
//!
//! Nothing here executes, imports, resolves, or fetches. A `$schema` URL is a
//! string; a `command` is a string; a script file is bytes we count characters
//! in. That is the whole safety story for `owlwarden vet` pointed at a
//! repository nobody has read yet.

use std::sync::Arc;

use owlwarden_core::finding::{AgentHost, CodeFrame, Location, RuntimeScope, SourceLocation};
use owlwarden_core::source::{RelPath, SourceError, SourceFile, SourceProvider};

use super::jsonc::{self, JsonNode, JsonParseError};
use super::paths::{self, WorkspaceFileKind};
use crate::line_index::LineIndex;

/// Most configuration files one repository can contribute to this surface.
///
/// A repository of templates can legitimately hold hundreds; beyond this the
/// scan is telling the reader about someone else's examples rather than about
/// their project, and the cap is reported rather than hidden.
pub const MAX_WORKSPACE_FILES: usize = 512;

/// Total bytes read from this surface in one scan.
pub const MAX_WORKSPACE_BYTES: usize = 8 * 1024 * 1024;

/// One configuration file, read and (when it is JSON) parsed.
#[derive(Debug)]
pub struct WorkspaceFile {
    /// Project-relative path.
    pub path: RelPath,
    /// The host that reads it.
    pub host: AgentHost,
    /// How it was parsed.
    pub kind: WorkspaceFileKind,
    /// How much of the host's real configuration it is.
    pub runtime_scope: RuntimeScope,
    /// The allowlist pattern that matched, for evidence.
    pub matched: &'static str,
    /// The file, verbatim. Rules match on a normalised copy and report from
    /// this one, so a homoglyph cannot both evade the match and hide from the
    /// code frame.
    pub text: Arc<str>,
    /// Line starts, for code frames.
    pub lines: LineIndex,
    doc: Option<JsonNode>,
    fences: Vec<(u32, u32)>,
}

impl WorkspaceFile {
    /// The parsed document, for JSON kinds that parsed.
    #[must_use]
    pub fn doc(&self) -> Option<&JsonNode> {
        self.doc.as_ref()
    }

    /// A [`Location`] for a byte span.
    #[must_use]
    pub fn location(&self, span: (u32, u32)) -> Location {
        let (line, col) = self.lines.position(&self.text, span.0);
        Location::Source(SourceLocation {
            path: self.path.to_string(),
            line,
            col,
        })
    }

    /// A code frame for a byte span.
    #[must_use]
    pub fn code_frame(&self, span: (u32, u32), label: impl Into<String>) -> CodeFrame {
        self.lines
            .code_frame(&self.text, self.path.as_str(), span, Some(label.into()))
    }

    /// The scope a finding at `offset` carries.
    ///
    /// The file's own scope, except inside a fenced code block in an
    /// instruction file: a hook shown in a tutorial is documentation, and
    /// reporting it at the weight of a live config is the fastest way to have
    /// this rule family switched off
    /// ([ADR 0025](../../../../docs/adr/0025-agent-surface-and-supply-chain.md) §5).
    #[must_use]
    pub fn scope_at(&self, offset: u32) -> RuntimeScope {
        if self
            .fences
            .iter()
            .any(|(start, end)| offset >= *start && offset < *end)
        {
            return RuntimeScope::Documentation;
        }
        self.runtime_scope
    }

    /// Whether this file is inside a fenced block anywhere (i.e. is prose).
    #[must_use]
    pub fn has_fenced_blocks(&self) -> bool {
        !self.fences.is_empty()
    }
}

/// A file on the allowlist that could not be read or parsed.
///
/// Carried rather than dropped. "We could not read your agent configuration" is
/// actionable; reporting it as clean is a lie, and on this surface a malformed
/// file is also a plausible evasion.
#[derive(Debug, Clone)]
pub struct UnreadableFile {
    /// Project-relative path.
    pub path: String,
    /// Why, in one clause safe to show a user.
    pub reason: String,
    /// Byte offset the failure is anchored at.
    pub offset: u32,
    /// The host that would have read it.
    pub host: AgentHost,
    /// How much of the host's configuration it would have been.
    pub runtime_scope: RuntimeScope,
}

/// Every agent-workspace file in one repository.
#[derive(Debug, Default)]
pub struct AgentWorkspace {
    files: Vec<WorkspaceFile>,
    unreadable: Vec<UnreadableFile>,
    truncated: bool,
}

impl AgentWorkspace {
    /// Walks the allowlist and reads what it finds.
    ///
    /// # Errors
    /// [`SourceError`] only when the tree itself cannot be walked. An
    /// individual file that cannot be read or parsed becomes an
    /// [`UnreadableFile`], not a failed scan: one broken config must not hide
    /// the other nine.
    pub fn load(source: &dyn SourceProvider) -> Result<Self, SourceError> {
        let globs = paths::allowlist_globs();
        let listed = source.agent_workspace_files(&globs)?;

        let mut workspace = Self::default();
        let mut bytes = 0usize;

        for file in listed {
            if workspace.files.len() >= MAX_WORKSPACE_FILES || bytes >= MAX_WORKSPACE_BYTES {
                workspace.truncated = true;
                break;
            }
            let Some(class) = paths::classify(&file.path) else {
                // The walker matched a glob the classifier does not recognise.
                // That is a bug in one of the two, not a file to guess about.
                continue;
            };
            workspace.ingest(source, &file, class, &mut bytes);
        }

        workspace
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        Ok(workspace)
    }

    fn ingest(
        &mut self,
        source: &dyn SourceProvider,
        file: &SourceFile,
        class: paths::Classification,
        bytes: &mut usize,
    ) {
        let text = match source.read(file) {
            Ok(text) => text,
            Err(error) => {
                self.unreadable.push(UnreadableFile {
                    path: file.path.to_string(),
                    reason: error.to_string(),
                    offset: 0,
                    host: class.host,
                    runtime_scope: class.runtime_scope,
                });
                return;
            }
        };
        *bytes = bytes.saturating_add(text.len());

        let doc = if class.kind.is_json() {
            match jsonc::parse(&text) {
                Ok(node) => Some(node),
                Err(error) => {
                    self.unreadable.push(UnreadableFile {
                        path: file.path.to_string(),
                        reason: parse_reason(&error),
                        offset: error.offset(),
                        host: class.host.clone(),
                        runtime_scope: class.runtime_scope,
                    });
                    None
                }
            }
        } else {
            None
        };

        let fences = if class.kind.is_instructions() {
            fenced_spans(&text)
        } else {
            Vec::new()
        };

        self.files.push(WorkspaceFile {
            path: file.path.clone(),
            host: class.host,
            kind: class.kind,
            runtime_scope: class.runtime_scope,
            matched: class.matched,
            lines: LineIndex::new(&text),
            text,
            doc,
            fences,
        });
    }

    /// The workspace for a tree that could not be walked at all.
    ///
    /// One [`UnreadableFile`] rather than zero files: silence here would be
    /// indistinguishable from "this repository has no agent configuration",
    /// which is the one wrong answer.
    #[must_use]
    pub fn unwalkable(error: &SourceError) -> Self {
        Self {
            files: Vec::new(),
            unreadable: vec![UnreadableFile {
                path: ".".to_owned(),
                reason: format!("could not walk the project for agent configuration: {error}"),
                offset: 0,
                host: AgentHost::GENERIC,
                runtime_scope: RuntimeScope::Active,
            }],
            truncated: true,
        }
    }

    /// Every file, in path order.
    #[must_use]
    pub fn files(&self) -> &[WorkspaceFile] {
        &self.files
    }

    /// Files of one kind.
    pub fn of_kind(&self, kind: WorkspaceFileKind) -> impl Iterator<Item = &WorkspaceFile> {
        self.files.iter().filter(move |file| file.kind == kind)
    }

    /// Files that parsed as JSON.
    pub fn json_files(&self) -> impl Iterator<Item = (&WorkspaceFile, &JsonNode)> {
        self.files
            .iter()
            .filter_map(|file| file.doc.as_ref().map(|doc| (file, doc)))
    }

    /// Files read as prose the model will follow.
    pub fn instruction_files(&self) -> impl Iterator<Item = &WorkspaceFile> {
        self.files.iter().filter(|file| file.kind.is_instructions())
    }

    /// Files on the allowlist we could not read or parse.
    #[must_use]
    pub fn unreadable(&self) -> &[UnreadableFile] {
        &self.unreadable
    }

    /// Whether a cap stopped the walk. A truncated workspace is not a clean
    /// workspace, and the engine says so.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether there is anything on this surface at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.unreadable.is_empty()
    }

    /// The file at exactly this project-relative path, if it is on the surface.
    #[must_use]
    pub fn find(&self, path: &str) -> Option<&WorkspaceFile> {
        self.files.iter().find(|file| file.path.as_str() == path)
    }
}

fn parse_reason(error: &JsonParseError) -> String {
    format!("could not parse: {error}")
}

/// Byte spans of fenced code blocks in a Markdown document.
///
/// Deliberately simple — matching a triple-backtick or triple-tilde fence at a
/// line start, with the
/// closing fence at least as long as the opening one. It is not a Markdown
/// parser and does not need to be: the question is "would a reader see this as
/// an example?", and everything this misses is reported at *higher* weight, not
/// lower, which is the safe direction to be wrong in.
fn fenced_spans(text: &str) -> Vec<(u32, u32)> {
    let mut spans = Vec::new();
    let mut open: Option<(u32, usize, char)> = None;
    let mut offset = 0usize;

    for line in text.split_inclusive('\n') {
        let start = u32::try_from(offset).unwrap_or(u32::MAX);
        let trimmed = line.trim_start();
        let indent = line.len().saturating_sub(trimmed.len());
        let marker = trimmed.chars().next();
        let run = marker
            .filter(|ch| *ch == '`' || *ch == '~')
            .map_or(0, |ch| trimmed.chars().take_while(|c| *c == ch).count());

        match (&open, marker) {
            (None, Some(ch)) if run >= 3 && indent <= 3 => {
                open = Some((start, run, ch));
            }
            (Some((open_start, open_run, open_ch)), Some(ch))
                if ch == *open_ch && run >= *open_run && indent <= 3 =>
            {
                let end = u32::try_from(offset.saturating_add(line.len())).unwrap_or(u32::MAX);
                spans.push((*open_start, end));
                open = None;
            }
            _ => {}
        }
        offset = offset.saturating_add(line.len());
    }

    // An unclosed fence runs to the end of the file. A truncated example is
    // still an example.
    if let Some((open_start, _, _)) = open {
        spans.push((open_start, u32::try_from(text.len()).unwrap_or(u32::MAX)));
    }
    spans
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
    use crate::fs_source::FsSourceProvider;
    use std::path::Path;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn workspace_of(build: impl Fn(&Path)) -> (tempfile::TempDir, AgentWorkspace) {
        let dir = tempfile::tempdir().unwrap();
        build(dir.path());
        let provider = FsSourceProvider::new(dir.path()).unwrap();
        let workspace = AgentWorkspace::load(&provider).unwrap();
        (dir, workspace)
    }

    #[test]
    fn a_gitignored_settings_file_is_still_read() {
        // The whole reason this surface has its own walker.
        let (_dir, workspace) = workspace_of(|root| {
            write(
                root,
                ".gitignore",
                ".claude/settings.local.json\n.vscode/\n",
            );
            write(root, ".claude/settings.local.json", r#"{"hooks":{}}"#);
            write(root, ".vscode/tasks.json", r#"{"version":"2.0.0"}"#);
        });
        assert!(workspace.find(".claude/settings.local.json").is_some());
        assert!(
            workspace.find(".vscode/tasks.json").is_some(),
            ".vscode is on the application-scan deny list and must still be read here"
        );
    }

    #[test]
    fn application_source_is_not_pulled_in() {
        let (_dir, workspace) = workspace_of(|root| {
            write(root, "app/route.ts", "export const GET = () => {}");
            write(root, "package.json", "{}");
            write(root, ".claude/settings.json", "{}");
        });
        let listed: Vec<&str> = workspace.files().iter().map(|f| f.path.as_str()).collect();
        assert_eq!(listed, [".claude/settings.json"]);
    }

    #[test]
    fn node_modules_is_still_out_of_bounds() {
        let (_dir, workspace) = workspace_of(|root| {
            write(root, "node_modules/evil/.claude/settings.json", "{}");
            write(root, ".claude/settings.json", "{}");
        });
        assert_eq!(workspace.files().len(), 1);
    }

    #[test]
    fn a_malformed_config_is_reported_and_never_called_clean() {
        let (_dir, workspace) = workspace_of(|root| {
            write(root, ".claude/settings.json", "{ this is not json");
        });
        assert!(workspace.files().iter().all(|file| file.doc().is_none()));
        assert_eq!(workspace.unreadable().len(), 1);
        assert!(workspace.unreadable()[0].reason.contains("could not parse"));
    }

    #[test]
    fn json_with_comments_and_trailing_commas_parses() {
        let (_dir, workspace) = workspace_of(|root| {
            write(
                root,
                ".vscode/tasks.json",
                "{\n // comment\n \"version\": \"2.0.0\",\n}",
            );
        });
        assert!(workspace.unreadable().is_empty());
        let file = workspace.find(".vscode/tasks.json").unwrap();
        assert_eq!(
            file.doc()
                .and_then(|doc| doc.get("version"))
                .and_then(jsonc::JsonNode::as_str),
            Some("2.0.0")
        );
    }

    #[test]
    fn a_template_copy_is_capped_and_a_root_copy_is_not() {
        let (_dir, workspace) = workspace_of(|root| {
            write(root, ".claude/settings.json", "{}");
            write(root, "examples/basic/.claude/settings.json", "{}");
        });
        assert_eq!(
            workspace
                .find(".claude/settings.json")
                .map(|f| f.runtime_scope),
            Some(RuntimeScope::Active)
        );
        assert_eq!(
            workspace
                .find("examples/basic/.claude/settings.json")
                .map(|f| f.runtime_scope),
            Some(RuntimeScope::Template)
        );
    }

    #[test]
    fn a_hook_inside_a_fenced_block_is_documentation() {
        let (_dir, workspace) = workspace_of(|root| {
            write(
                root,
                "CLAUDE.md",
                "# Rules\n\nDo not do this:\n\n```json\n{\"hooks\": {\"SessionStart\": []}}\n```\n\nProse after.\n",
            );
        });
        let file = workspace.find("CLAUDE.md").unwrap();
        let inside = file.text.find("SessionStart").unwrap();
        let outside = file.text.find("Prose after").unwrap();
        assert_eq!(
            file.scope_at(u32::try_from(inside).unwrap()),
            RuntimeScope::Documentation
        );
        assert_eq!(
            file.scope_at(u32::try_from(outside).unwrap()),
            RuntimeScope::Active
        );
    }

    #[test]
    fn an_unclosed_fence_swallows_the_rest_of_the_file() {
        // Being wrong towards `documentation` here would let an attacker hide a
        // directive behind an unclosed fence, so this is asserted deliberately:
        // the *content after an opening fence* is an example either way, and the
        // rules that matter on instruction files (hidden text) do not consult
        // the fence map at all.
        let spans = fenced_spans("intro\n```\nstill inside\n");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].1 as usize, "intro\n```\nstill inside\n".len());
    }

    #[test]
    fn tilde_fences_and_long_fences_close_correctly() {
        let text = "~~~\na\n~~~\n```\nb\n`````\n";
        let spans = fenced_spans(text);
        assert_eq!(spans.len(), 2, "both blocks close");
        let first = &text[spans[0].0 as usize..spans[0].1 as usize];
        assert!(first.contains('a') && !first.contains('b'));
    }

    #[test]
    fn an_empty_repository_produces_an_empty_workspace_rather_than_an_error() {
        let (_dir, workspace) = workspace_of(|_| {});
        assert!(workspace.is_empty());
        assert!(!workspace.truncated());
    }
}
