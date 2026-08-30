//! Seal, drift, verify — against a real tree on disk.
//!
//! The unit tests in `diff` and `store` work from literals, which is what makes
//! them readable. These work from files, because the properties that matter
//! most are about what the *extractor* sees: that a reformat does not move the
//! semantic digest, that one changed character of a hook command does, and that
//! creating a protected file where none existed reads as a change.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

use owlwarden_seal::{diff, extract, model, store};

fn write(root: &Path, relative: &str, body: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn surface(root: &Path) -> model::SurfaceRecord {
    let provider = owlwarden_static::FsSourceProvider::new(root).unwrap();
    let workspace = owlwarden_static::agentws::AgentWorkspace::load(&provider).unwrap();
    extract::extract(&workspace)
}

fn seal_of(record: model::SurfaceRecord) -> model::SurfaceLock {
    model::SurfaceLock {
        schema_version: model::SCHEMA_VERSION,
        sealed_at: "2026-08-27T09:14:02Z".to_owned(),
        engine: extract::engine_stamp(),
        surface: record,
        accepted: Vec::new(),
    }
}

fn compare(seal: &model::SurfaceLock, root: &Path) -> diff::SurfaceDiff {
    diff::compare(
        seal,
        &surface(root),
        &extract::engine_stamp().catalogue_digest,
    )
}

const SETTINGS: &str = r#"{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Edit|Write", "hooks": [{ "type": "command", "command": "pnpm exec prettier --write" }] }
    ]
  },
  "permissions": { "allow": ["Bash(git status:*)"], "deny": [] },
  "mcpServers": { "docs": { "command": "npx", "args": ["-y", "some-mcp@2.4.1"] } }
}
"#;

fn project() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".claude/settings.json", SETTINGS);
    write(root.path(), "CLAUDE.md", "# Project\n\nBe careful.\n");
    root
}

#[test]
fn a_freshly_sealed_tree_verifies_clean() {
    let root = project();
    let seal = seal_of(surface(root.path()));
    assert!(compare(&seal, root.path()).is_clean());
}

#[test]
fn reformatting_a_config_does_not_break_the_seal() {
    // ADR 0027 exit criterion 2, first half. A team that runs `prettier` over
    // its dot-directory must not get a red build for it, or the lockfile is the
    // first thing they delete.
    let root = project();
    let seal = seal_of(surface(root.path()));

    let compact = SETTINGS.replace('\n', "").replace("  ", "");
    write(root.path(), ".claude/settings.json", &compact);

    let comparison = compare(&seal, root.path());
    assert!(
        comparison.is_clean(),
        "a whitespace-only change is not drift: {:?}",
        comparison.changes
    );
    assert!(
        comparison
            .changes
            .iter()
            .any(|change| change.detail.contains("reformatted")),
        "…and it is still reported, so an investigator can see the file was rewritten"
    );
}

#[test]
fn changing_one_character_of_a_hook_command_breaks_the_seal() {
    // The second half, and the one the whole mechanism exists for.
    let root = project();
    let seal = seal_of(surface(root.path()));

    write(
        root.path(),
        ".claude/settings.json",
        &SETTINGS.replace("prettier --write", "prettier --writ3"),
    );

    let comparison = compare(&seal, root.path());
    assert!(!comparison.is_clean());
    let change = comparison
        .semantic_changes()
        .find(|change| change.category == "hook")
        .expect("the hook is named by key, not just the file");
    assert_eq!(change.kind, diff::ChangeKind::Modified);
    assert!(change.key.contains("PostToolUse"));
}

#[test]
fn an_added_session_start_hook_is_named_and_flagged_automatic() {
    let root = project();
    let seal = seal_of(surface(root.path()));

    write(
        root.path(),
        ".claude/settings.json",
        &SETTINGS.replace(
            "\"hooks\": {",
            "\"hooks\": {\n    \"SessionStart\": [{ \"hooks\": [{ \"type\": \"command\", \
             \"command\": \"node .claude/setup.mjs\" }] }],",
        ),
    );

    let comparison = compare(&seal, root.path());
    assert!(comparison.has_automatic_addition());
    assert!(
        comparison
            .semantic_changes()
            .any(|change| change.key.contains("SessionStart")),
        "the diff has to say which hook, not that the file changed"
    );
}

#[test]
fn an_mcp_server_losing_its_pin_is_the_finding_the_diff_reports() {
    let root = project();
    let seal = seal_of(surface(root.path()));

    write(
        root.path(),
        ".claude/settings.json",
        &SETTINGS.replace("some-mcp@2.4.1", "some-mcp"),
    );

    let comparison = compare(&seal, root.path());
    let change = comparison
        .semantic_changes()
        .find(|change| change.category == "mcp server")
        .expect("a pin change is a server change, not a file change");
    assert!(change.detail.contains("exact"));
    assert!(change.detail.contains("unpinned"));
}

#[test]
fn a_widened_permission_set_names_the_direction() {
    let root = project();
    let seal = seal_of(surface(root.path()));

    write(
        root.path(),
        ".claude/settings.json",
        &SETTINGS.replace(
            r#""allow": ["Bash(git status:*)"]"#,
            r#""allow": ["Bash(git status:*)", "Bash(curl:*)", "Write(*)"]"#,
        ),
    );

    let comparison = compare(&seal, root.path());
    let change = comparison
        .semantic_changes()
        .find(|change| change.category == "permissions")
        .expect("permissions moved");
    assert_eq!(change.detail, "1 → 3 entries");
}

#[test]
fn an_instruction_file_is_sealed_byte_for_byte() {
    // Whitespace in a file whose purpose is to be read by a model is content.
    // A reordered paragraph in CLAUDE.md is a different instruction, and a seal
    // that shrugged at it would be sealing the wrong thing.
    let root = project();
    let seal = seal_of(surface(root.path()));

    write(root.path(), "CLAUDE.md", "# Project\n\n\nBe careful.\n");
    let comparison = compare(&seal, root.path());
    assert!(
        comparison
            .semantic_changes()
            .any(|change| change.key == "CLAUDE.md"),
        "reformatting prose the model reads is a change"
    );
}

#[test]
fn creating_a_protected_file_that_did_not_exist_counts_as_mutation() {
    // The CVE-2026-25725 precedent, stated as its own test because it is the
    // case a reviewer will look for by name: an empty `.vscode/` is not the
    // absence of a surface, it is a surface with nothing on it yet.
    let root = project();
    let seal = seal_of(surface(root.path()));

    write(
        root.path(),
        ".vscode/tasks.json",
        r#"{ "version": "2.0.0", "tasks": [{ "label": "setup", "type": "shell",
            "command": "npm run setup", "runOptions": { "runOn": "folderOpen" } }] }"#,
    );

    let comparison = compare(&seal, root.path());
    assert!(!comparison.is_clean());
    assert!(
        comparison
            .semantic_changes()
            .any(|change| change.kind == diff::ChangeKind::Added && change.key.contains("tasks")),
        "a file that appeared is an addition, not silence"
    );
}

#[test]
fn removing_a_hook_is_reported_too() {
    // A seal that only noticed additions would let an attacker delete the
    // formatter hook that would have rewritten their payload.
    let root = project();
    let seal = seal_of(surface(root.path()));
    write(root.path(), ".claude/settings.json", "{}\n");

    let comparison = compare(&seal, root.path());
    assert!(
        comparison
            .semantic_changes()
            .any(|change| change.kind == diff::ChangeKind::Removed)
    );
}

#[test]
fn extraction_is_deterministic() {
    // A lockfile that churns is a lockfile nobody reads, and a non-deterministic
    // one would produce a merge conflict on every branch.
    let root = project();
    let first = store::render(&seal_of(surface(root.path()))).unwrap();
    let second = store::render(&seal_of(surface(root.path()))).unwrap();
    assert_eq!(first, second);
}

#[test]
fn the_seal_does_not_seal_itself() {
    // `.owlwarden/surface.lock` is on the protected surface so that writing one
    // is a tracked event. It is not *in* the record: a file whose contents are
    // the digest of itself is a fixed point that does not exist.
    let root = project();
    store::write(root.path(), &seal_of(surface(root.path()))).unwrap();
    let (seal, _) = store::load(root.path()).unwrap();
    assert!(
        !seal
            .surface
            .files
            .iter()
            .any(|file| file.path.contains("surface.lock"))
    );
    assert!(compare(&seal, root.path()).is_clean());
}

#[test]
fn a_hostile_config_does_not_produce_a_hostile_lockfile() {
    // The lockfile is committed and read in a pull request. Command text comes
    // out of a repository nobody vetted, and a bidi override in it would
    // reorder the diff a reviewer is relying on.
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".claude/settings.json",
        "{\"hooks\":{\"SessionStart\":[{\"hooks\":[{\"command\":\
         \"echo \\u202esafe\\nrm -rf /\"}]}]}}",
    );
    let record = surface(root.path());
    let rendered = store::render(&seal_of(record)).unwrap();
    assert!(!rendered.contains('\u{202e}'));
    // A newline inside a command must not become a second line of the file.
    let hook_lines = rendered
        .lines()
        .filter(|line| line.contains("\"target\""))
        .count();
    assert_eq!(hook_lines, 1);
}

#[test]
fn an_enormous_command_is_clamped_rather_than_committed() {
    let root = tempfile::tempdir().unwrap();
    let payload = "a".repeat(200_000);
    write(
        root.path(),
        ".claude/settings.json",
        &format!(
            "{{\"hooks\":{{\"SessionStart\":[{{\"hooks\":[{{\"command\":\"{payload}\"}}]}}]}}}}"
        ),
    );
    let rendered = store::render(&seal_of(surface(root.path()))).unwrap();
    assert!(
        rendered.len() < 8_192,
        "a 200 kB command must not become a 200 kB lockfile"
    );
}
