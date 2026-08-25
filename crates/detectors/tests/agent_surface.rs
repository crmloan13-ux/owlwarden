//! The agent-surface grid: every rule, every host, three kinds of fixture.
//!
//! The framework matrix in `fixtures.rs` asks "does every rule work on every
//! framework?". This asks the same question one surface over, and adds a third
//! column the first one does not have.
//!
//! - **vulnerable** — fires, at the declared severity and confidence.
//! - **clean twin** — the same configuration, benign. Silent.
//! - **tempting** — a *legitimate* configuration that shares surface features
//!   with the vulnerable one. A `PostToolUse` hook running `pnpm exec
//!   prettier`. A `tasks.json` build task with no `runOn`. An MCP server pinned
//!   to an exact version. A dev container whose `postCreateCommand` is `pnpm
//!   install`. **Its silence is the assertion**, and it is the column that
//!   decides whether this rule family survives contact with real repositories
//!   ([ADR 0025](../../../docs/adr/0025-agent-surface-and-supply-chain.md),
//!   *False positives*).
//!
//! Plus a standing corpus of the configurations real repositories ship, which
//! must be silent in `quick`, and a hostile-input suite that must terminate
//! within budget and execute nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use owlwarden_core::context::ScanSettings;
use owlwarden_core::finding::{Confidence, RuntimeScope, Severity};
use owlwarden_core::report::Report;
use owlwarden_core::surface::Surface;

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/agent")
        .join(relative)
}

async fn scan_preset(root: PathBuf, preset: &str) -> Report {
    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset(preset);
    owlwarden_static::scan_project(
        root,
        file_rules,
        project_rules,
        ScanSettings {
            preset: preset.to_owned(),
            ..ScanSettings::default()
        },
    )
    .await
    .expect("the scan completed")
}

async fn scan(relative: &str) -> Report {
    scan_preset(fixture(relative), "deep").await
}

/// Rule ids present in a report, deduplicated and sorted.
fn rule_ids(report: &Report) -> Vec<String> {
    let unique: BTreeSet<String> = report
        .findings
        .iter()
        .map(|finding| finding.id.to_string())
        .collect();
    unique.into_iter().collect()
}

/// One host's three fixtures and what the vulnerable one must produce.
struct HostGrid {
    host: &'static str,
    /// Rule ids that must fire in `<host>/vulnerable`, exactly this set.
    ///
    /// A set rather than counts: unlike the framework grid, the same rule
    /// legitimately fires a different number of times per host — Claude Code
    /// expresses three permission problems in one file where Codex expresses
    /// one — and pinning counts here would make the table a transcription of
    /// the fixtures rather than a statement about the rules.
    fires: &'static [&'static str],
}

const GRID: &[HostGrid] = &[
    HostGrid {
        host: "claude-code",
        fires: &[
            "agent-config-env-redirect",
            "agent-config-loader-script",
            "agent-config-secret-reachable",
            "agent-hook-autoexec",
            "agent-hook-untrusted-command",
            "agent-instructions-directive",
            "agent-instructions-hidden-text",
            "agent-marketplace-untrusted",
            "agent-mcp-unpinned-remote",
            "agent-permission-wildcard",
        ],
    },
    HostGrid {
        host: "cursor",
        fires: &[
            "agent-config-env-redirect",
            "agent-config-loader-script",
            "agent-config-secret-reachable",
            "agent-hook-autoexec",
            "agent-hook-untrusted-command",
            "agent-instructions-directive",
            "agent-marketplace-untrusted",
            "agent-mcp-unpinned-remote",
            "agent-permission-wildcard",
        ],
    },
    HostGrid {
        host: "vscode",
        fires: &[
            "agent-config-env-redirect",
            "agent-config-loader-script",
            "agent-config-secret-reachable",
            "agent-hook-autoexec",
            "agent-hook-untrusted-command",
            "agent-mcp-unpinned-remote",
            "agent-permission-wildcard",
        ],
    },
    HostGrid {
        // VS Code has no repository-level instruction file of its own, and
        // Copilot has nothing *but* one. Between them the pair covers the
        // instruction rules and the configuration rules; neither covers both,
        // and pretending otherwise would mean inventing a file the host does
        // not read.
        host: "copilot",
        fires: &[
            "agent-instructions-directive",
            "agent-instructions-hidden-text",
        ],
    },
    HostGrid {
        host: "codex",
        fires: &[
            "agent-config-env-redirect",
            "agent-config-loader-script",
            "agent-hook-autoexec",
            "agent-hook-untrusted-command",
            "agent-permission-wildcard",
        ],
    },
    HostGrid {
        host: "gemini-cli",
        fires: &[
            "agent-config-env-redirect",
            "agent-hook-autoexec",
            "agent-hook-untrusted-command",
            "agent-permission-wildcard",
        ],
    },
    HostGrid {
        host: "generic",
        fires: &[
            "agent-config-secret-reachable",
            "agent-instructions-directive",
            "agent-mcp-unpinned-remote",
        ],
    },
];

#[tokio::test]
async fn every_hosts_vulnerable_fixture_fires_exactly_what_it_claims() {
    for row in GRID {
        let report = scan(&format!("{}/vulnerable", row.host)).await;
        assert_eq!(
            rule_ids(&report),
            row.fires,
            "{} fired the wrong set",
            row.host
        );
    }
}

#[tokio::test]
async fn every_clean_twin_is_silent() {
    for row in GRID {
        let report = scan(&format!("{}/clean", row.host)).await;
        assert!(
            report.findings.is_empty(),
            "{} clean twin produced {:?}",
            row.host,
            rule_ids(&report)
        );
    }
}

#[tokio::test]
async fn every_tempting_fixture_can_never_fail_a_build() {
    // The bar, stated precisely. A tempting fixture is silent in `quick` — the
    // zero-config default, which is what a developer actually runs — and in
    // `deep` it may only produce findings that cannot fail CI on their own.
    //
    // Why not "silent in deep" as well: `generic/tempting` quotes a prompt
    // injection inside a fenced block, in a file explaining the threat. That is
    // reported, at `documentation` scope and `possible` confidence, and it
    // should be: a security team's own write-up is the one place the string
    // legitimately appears, and the honest answer is "we saw it, here is the
    // scope", not silence.
    for row in GRID {
        let quick = scan_preset(fixture(&format!("{}/tempting", row.host)), "quick").await;
        assert!(
            quick.findings.is_empty(),
            "{} tempting fixture fired in the default preset: {:?}",
            row.host,
            rule_ids(&quick)
        );

        let deep = scan(&format!("{}/tempting", row.host)).await;
        for finding in &deep.findings {
            assert_eq!(
                finding.confidence,
                Confidence::Possible,
                "{} tempting fixture produced a build-failing {}",
                row.host,
                finding.id
            );
        }
        assert!(
            !deep.should_fail(Severity::Info, Confidence::Possible),
            "{} tempting fixture would fail a build",
            row.host
        );
    }
}

#[tokio::test]
async fn every_agent_rule_is_exercised_by_at_least_one_host() {
    // The catalogue-coverage half of the grid: a rule that no fixture fires is
    // a rule nothing proves works.
    let catalogue: BTreeSet<String> = owlwarden_detectors::all_rule_metas()
        .into_iter()
        .filter(|meta| meta.surface == Surface::AgentWorkspace)
        .map(|meta| meta.id.to_string())
        .collect();

    let mut exercised: BTreeSet<String> = BTreeSet::new();
    for row in GRID {
        exercised.extend(row.fires.iter().map(|id| (*id).to_owned()));
    }

    let missing: Vec<&String> = catalogue.difference(&exercised).collect();
    assert!(
        missing.is_empty(),
        "these agent rules have no vulnerable fixture: {missing:?}"
    );
    let unknown: Vec<&String> = exercised.difference(&catalogue).collect();
    assert!(
        unknown.is_empty(),
        "the grid names rules that do not exist: {unknown:?}"
    );
}

#[tokio::test]
async fn every_host_in_the_profile_set_has_a_grid_row() {
    // A host advertised in `SUPPORTED_AGENT_HOSTS` — and therefore owed a fix
    // by every rule — but with no fixtures is support we have never
    // demonstrated.
    for host in owlwarden_detectors::SUPPORTED_AGENT_HOSTS {
        assert!(
            GRID.iter().any(|row| row.host == host.as_str()),
            "{host} is a supported profile with no fixture row"
        );
    }
    assert_eq!(GRID.len(), owlwarden_detectors::SUPPORTED_AGENT_HOSTS.len());
}

#[tokio::test]
async fn nothing_on_this_surface_is_ever_confirmed() {
    // ADR 0025 §6 and its exit criterion 5. `Confirmed` means corroborated
    // against a running target; there is none for a config file, and a second
    // meaning for the word would break the property the project sells.
    for row in GRID {
        let report = scan(&format!("{}/vulnerable", row.host)).await;
        for finding in &report.findings {
            assert!(
                finding.confidence < Confidence::Confirmed,
                "{} reached Confirmed on the agent surface",
                finding.id
            );
        }
    }
}

#[tokio::test]
async fn a_template_copy_is_capped_at_possible() {
    // ADR 0025 exit criterion 4, end to end rather than in a unit test: the
    // same hostile config, moved under a template path, must not be able to
    // fail a build.
    let dir = tempfile::tempdir().unwrap();
    let settings =
        std::fs::read_to_string(fixture("claude-code/vulnerable/.claude/settings.json")).unwrap();
    let nested = dir.path().join("examples/starter/.claude");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("settings.json"), &settings).unwrap();
    std::fs::write(dir.path().join("package.json"), "{}").unwrap();

    let report = scan_preset(dir.path().to_path_buf(), "deep").await;
    assert!(!report.findings.is_empty(), "a template is still reported");
    for finding in &report.findings {
        assert_eq!(finding.runtime_scope, Some(RuntimeScope::Template));
        assert_eq!(finding.confidence, Confidence::Possible);
    }
    assert!(
        !report.should_fail(Severity::Info, Confidence::Possible),
        "a repository full of examples must stay adoptable"
    );
}

#[tokio::test]
async fn the_standing_corpus_is_silent_in_the_default_preset() {
    // ADR 0025 exit criterion 3. These are the configurations real repositories
    // ship: a monorepo with a formatter hook, a dev container, pinned MCP
    // servers, Cursor rules, Copilot instructions. When one of them starts
    // firing, either the rule is wrong or the corpus is, and finding out which
    // is the work.
    for case in [
        "corpus/monorepo-with-formatter",
        "corpus/devcontainer-node",
        "corpus/mcp-pinned",
        "corpus/cursor-rules",
        "corpus/copilot-instructions",
    ] {
        let report = scan_preset(fixture(case), "quick").await;
        assert!(
            report.findings.is_empty(),
            "{case} is a configuration a real team ships, and it fired {:?}",
            rule_ids(&report)
        );
    }
}

#[tokio::test]
async fn malformed_configuration_is_reported_and_never_read_as_clean() {
    // ADR 0025 §4. Three files that do not parse, and the scan must say so
    // rather than returning a clean report about files it could not read.
    let report = scan("hostile/malformed").await;
    let complaints = report
        .errors
        .iter()
        .filter(|failure| failure.message.contains("could not parse"))
        .count();
    assert!(
        complaints >= 2,
        "expected the unreadable configs to be surfaced, got {:?}",
        report.errors
    );
    assert!(
        report
            .errors
            .iter()
            .any(|failure| failure.message.contains(".claude/settings.json")),
        "the file that failed must be named"
    );
}

#[tokio::test]
async fn hidden_text_is_reported_without_reproducing_it() {
    let report = scan("hostile/bidi").await;
    let hidden: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.id.as_str() == "agent-instructions-hidden-text")
        .collect();
    assert!(
        !hidden.is_empty(),
        "the bidi override and the tag characters"
    );

    for finding in &hidden {
        let evidence = finding.context.evidence.as_deref().unwrap_or_default();
        assert!(
            evidence.starts_with("U+"),
            "evidence must be escaped: {evidence:?}"
        );
        for forbidden in ['\u{202E}', '\u{202C}', '\u{E0041}'] {
            assert!(
                !evidence.contains(forbidden),
                "the report reproduced the payload it is reporting"
            );
        }
    }
}

#[tokio::test]
async fn hostile_input_terminates_within_budget_and_executes_nothing() {
    // ADR 0025 exit criterion 7. Generated rather than committed: a 12 MB file
    // and a 20 000-deep one are a problem for the repository, not evidence for
    // the reader.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("package.json"), "{}").unwrap();
    std::fs::create_dir_all(root.join(".claude")).unwrap();
    std::fs::create_dir_all(root.join(".vscode")).unwrap();

    // 12 MB, over the per-file read cap.
    std::fs::write(
        root.join(".claude/settings.json"),
        format!("{{\"a\":\"{}\"}}", "x".repeat(12 * 1024 * 1024)),
    )
    .unwrap();
    // 20 000 levels of nesting.
    std::fs::write(
        root.join(".vscode/tasks.json"),
        "[".repeat(20_000) + &"]".repeat(20_000),
    )
    .unwrap();
    // A flood of hook entries, to exercise the per-rule finding cap.
    let flood: Vec<String> = (0..40_000)
        .map(|index| format!("{{\"command\":\"echo {index}\"}}"))
        .collect();
    std::fs::write(
        root.join(".cursor/hooks.json"),
        format!("{{\"hooks\":{{\"sessionStart\":[{}]}}}}", flood.join(",")),
    )
    .or_else(|_| {
        std::fs::create_dir_all(root.join(".cursor"))?;
        std::fs::write(
            root.join(".cursor/hooks.json"),
            format!("{{\"hooks\":{{\"sessionStart\":[{}]}}}}", flood.join(",")),
        )
    })
    .unwrap();

    let started = Instant::now();
    let report = scan_preset(root.to_path_buf(), "deep").await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(30),
        "hostile input took {elapsed:?}; the caps are not holding"
    );
    // The finding cap held: a flood produces a bounded report, not 40 000 rows.
    assert!(
        report.findings.len() <= 200,
        "a flood produced {} findings",
        report.findings.len()
    );
    // And the files that could not be read are named rather than passed over.
    assert!(
        !report.errors.is_empty(),
        "an oversized and an over-nested config must both be reported"
    );
}

#[tokio::test]
async fn a_symlink_out_of_the_project_is_refused() {
    // The sandbox boundary, on the surface that deliberately relaxes
    // `.gitignore`. Relaxing one guarantee must not relax the others.
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("secret.json"),
            r#"{"token":"real-secret"}"#,
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.json"),
            dir.path().join(".claude/settings.json"),
        )
        .unwrap();

        let report = scan_preset(dir.path().to_path_buf(), "deep").await;
        for finding in &report.findings {
            assert!(
                !format!("{finding:?}").contains("real-secret"),
                "a symlink out of the project was followed"
            );
        }
    }
}

#[tokio::test]
async fn the_agent_surface_costs_nothing_when_no_agent_rule_is_enabled() {
    // The workspace walk is lazy. A `--preset owasp-top10` run has no business
    // reading `.cursor/hooks.json`, and no business reporting on one it cannot
    // parse.
    let report = scan_preset(fixture("hostile/malformed"), "owasp-top10").await;
    assert!(
        report
            .errors
            .iter()
            .all(|failure| !failure.message.contains("could not parse")),
        "a preset with no agent rules reported on agent configuration: {:?}",
        report.errors
    );
}
