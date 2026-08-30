//! Attacking the one thing 1.2 added that reads outside the project root.
//!
//! `--include-user-config` narrows an invariant the project sells. Every other
//! surface is bounded by "results stay under the scan root"; this one is
//! bounded by a closed allowlist, a bounded reader, and a rule that the
//! contents never reach any output.
//!
//! Three attackers are in scope, and they are not the same:
//!
//! 1. **The scanned repository.** It cannot reach the user tier at all — the
//!    paths are compile-time constants — but it *can* try to make the resolver
//!    do work, or to make a shadowed classification hide a real finding.
//! 2. **Whoever can write the home directory.** `~/.claude/settings.json` is a
//!    path an attacker who reached `$HOME` also controls, so it is untrusted
//!    input like any other: bounded, symlink-refusing, never executed.
//! 3. **Whoever reads the report.** They must not learn anything about the
//!    developer's own configuration from it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

use owlwarden_core::finding::AgentHost;
use owlwarden_static::agentws::tiers::{self, TierPolicy};

fn write(root: &Path, relative: &str, body: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

// ── the repository cannot reach the user tier ───────────────────────────────

#[test]
fn a_declared_tier_path_can_never_escape_where_it_is_anchored() {
    // The allowlist is compile-time data, so this guards a future edit rather
    // than today's input. It is still the check worth having: the day someone
    // makes a tier path configurable, this is what refuses.
    let root = Path::new("/project");
    for hostile in [
        "../../etc/passwd",
        "~/../../etc/passwd",
        "%HOME%/../../../etc/shadow",
        "./../../secrets",
        "a/../../../b",
    ] {
        assert_eq!(
            tiers::expand(root, hostile),
            None,
            "{hostile} was expanded rather than refused"
        );
    }
}

#[test]
fn a_project_relative_tier_path_stays_under_the_root() {
    let root = Path::new("/project");
    for profile in tiers::profiles() {
        for tier in profile.readable_tiers(TierPolicy::ProjectOnly) {
            for declared in tier.paths {
                let expanded = tiers::expand(root, declared).expect("a project path expands");
                assert!(
                    expanded.starts_with(root),
                    "{declared} resolved outside the scan root"
                );
            }
        }
    }
}

#[test]
fn project_only_opens_nothing_above_the_root_even_with_a_home_present() {
    let home = tempfile::tempdir().unwrap();
    write(home.path(), ".claude/settings.json", "{\"hooks\":{}}");
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".claude/settings.json",
        "{\"hooks\":{\"a\":[]}}",
    );

    let config = tiers::resolve_with_home(
        root.path(),
        Some(home.path()),
        &AgentHost::CLAUDE_CODE,
        TierPolicy::ProjectOnly,
    );
    assert!(config.shadowed_keys().is_empty());
    assert!(
        config
            .tiers_read
            .iter()
            .all(|(kind, _)| !kind.is_outside_root()),
        "a tier above the root was opened without the flag"
    );
}

// ── the home directory is untrusted input ───────────────────────────────────

#[test]
fn a_symlinked_user_tier_file_is_refused_rather_than_followed() {
    // `~/.claude/settings.json` pointing at `/etc/shadow` must not become a
    // read of `/etc/shadow`. The bounded reader refuses a final-component
    // symlink; this asserts the tier resolver uses it.
    let secret = tempfile::NamedTempFile::new().unwrap();
    fs::write(secret.path(), "{\"hooks\":{\"stolen\":[]}}").unwrap();

    let home = tempfile::tempdir().unwrap();
    fs::create_dir_all(home.path().join(".claude")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(secret.path(), home.path().join(".claude/settings.json"))
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        write(root.path(), ".claude/settings.json", "{\"hooks\":{}}");
        let config = tiers::resolve_with_home(
            root.path(),
            Some(home.path()),
            &AgentHost::CLAUDE_CODE,
            TierPolicy::IncludeUserConfig,
        );
        assert!(
            !config.keys.iter().any(|key| key.key == "stolen"),
            "a symlinked tier file was followed"
        );
    }
    let _ = home;
}

#[test]
fn an_oversized_user_tier_file_is_refused_rather_than_read() {
    let home = tempfile::tempdir().unwrap();
    let size = usize::try_from(tiers::MAX_TIER_BYTES).unwrap() + 1024;
    write(
        home.path(),
        ".claude/settings.json",
        &format!("{{\"pad\":\"{}\"}}", "x".repeat(size)),
    );
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".claude/settings.json", "{\"hooks\":{}}");

    let config = tiers::resolve_with_home(
        root.path(),
        Some(home.path()),
        &AgentHost::CLAUDE_CODE,
        TierPolicy::IncludeUserConfig,
    );
    assert!(!config.keys.iter().any(|key| key.key == "pad"));
}

#[test]
fn hostile_user_tier_content_never_panics_and_never_shadows() {
    // A file we could not read must leave the project tier winning. Claiming a
    // key is shadowed on the strength of a file we failed to parse would
    // quietly downgrade a real finding, which is the reassuring direction.
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".claude/settings.json",
        "{\"hooks\":{\"a\":[]}}",
    );

    for body in [
        String::new(),
        "[".repeat(200_000),
        "null".to_owned(),
        "[]".to_owned(),
        "\u{0}\u{0}\u{0}".to_owned(),
        "{\"hooks\":".to_owned(),
        format!("{{{}}}", "\"a\":1,".repeat(100_000).trim_end_matches(',')),
    ] {
        let home = tempfile::tempdir().unwrap();
        write(home.path(), ".claude/settings.json", &body);
        let config = tiers::resolve_with_home(
            root.path(),
            Some(home.path()),
            &AgentHost::CLAUDE_CODE,
            TierPolicy::IncludeUserConfig,
        );
        assert!(
            config.shadowed_keys().is_empty(),
            "an unreadable tier file shadowed a project key: {body:.40?}"
        );
    }
}

#[test]
fn a_home_directory_with_no_settings_at_all_resolves_cleanly() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".claude/settings.json",
        "{\"hooks\":{\"a\":[]}}",
    );
    let config = tiers::resolve_with_home(
        root.path(),
        Some(home.path()),
        &AgentHost::CLAUDE_CODE,
        TierPolicy::IncludeUserConfig,
    );
    assert!(config.get("hooks").is_some());
    assert!(config.shadowed_keys().is_empty());
}

// ── nothing about the developer escapes ─────────────────────────────────────

#[test]
fn no_user_tier_key_value_or_path_appears_in_the_resolution() {
    // The rule, at the resolver rather than at a reporter: a leak here would
    // reach every format at once.
    const SENTINEL: &str = "OWLWARDEN-HOME-SENTINEL-4a91";
    let home = tempfile::tempdir().unwrap();
    write(
        home.path(),
        ".claude/settings.json",
        &format!(
            "{{\"hooks\":{{}},\"{SENTINEL}-key\":\"{SENTINEL}-value\",\
             \"env\":{{\"TOKEN\":\"{SENTINEL}-token\"}}}}"
        ),
    );
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".claude/settings.json",
        "{\"hooks\":{\"a\":[]}}",
    );

    let config = tiers::resolve_with_home(
        root.path(),
        Some(home.path()),
        &AgentHost::CLAUDE_CODE,
        TierPolicy::IncludeUserConfig,
    );

    let rendered = format!(
        "{:?}{:?}{:?}",
        config
            .keys
            .iter()
            .map(|key| (
                key.key.clone(),
                key.rendered_value(),
                key.winner_source.clone()
            ))
            .collect::<Vec<_>>(),
        config.tiers_read,
        config.tiers_skipped
    );
    assert!(!rendered.contains(SENTINEL), "user-tier content escaped");
    assert!(
        config.keys_only_above_root > 0,
        "the key set only above the root must be counted, not silently dropped"
    );
}

#[test]
fn the_home_directory_path_itself_never_appears() {
    // A home directory layout names a person. `/Users/alice/...` in a report
    // pasted into a shared ticket is a disclosure even when the file's contents
    // are not.
    let home = tempfile::tempdir().unwrap();
    write(home.path(), ".claude/settings.json", "{\"hooks\":{}}");
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".claude/settings.json",
        "{\"hooks\":{\"a\":[]}}",
    );

    let config = tiers::resolve_with_home(
        root.path(),
        Some(home.path()),
        &AgentHost::CLAUDE_CODE,
        TierPolicy::IncludeUserConfig,
    );
    let home_text = home.path().display().to_string();
    for (_, source) in &config.tiers_read {
        assert!(
            !source.contains(&home_text),
            "a home path reached the output"
        );
    }
    for key in &config.keys {
        assert!(!key.winner_source.contains(&home_text));
        for (_, source) in &key.losers {
            assert!(!source.contains(&home_text));
        }
    }
}

// ── bounded work ────────────────────────────────────────────────────────────

#[test]
fn a_pathological_home_directory_does_not_make_resolution_unbounded() {
    // Whoever can write `$HOME` chooses how much there is to read. The cap on
    // opened files is what stops that being a stall on the developer's machine.
    let home = tempfile::tempdir().unwrap();
    for index in 0..500 {
        write(
            home.path(),
            ".claude/settings.json",
            &format!("{{\"k{index}\":1}}"),
        );
    }
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".claude/settings.json", "{\"hooks\":{}}");

    let started = std::time::Instant::now();
    for host in [
        AgentHost::CLAUDE_CODE,
        AgentHost::CURSOR,
        AgentHost::VSCODE,
        AgentHost::CODEX,
        AgentHost::GEMINI_CLI,
        AgentHost::COPILOT,
        AgentHost::GENERIC,
    ] {
        let _ = tiers::resolve_with_home(
            root.path(),
            Some(home.path()),
            &host,
            TierPolicy::IncludeUserConfig,
        );
    }
    assert!(
        started.elapsed().as_secs() < 10,
        "resolving every host's tiers should be bounded"
    );
}
