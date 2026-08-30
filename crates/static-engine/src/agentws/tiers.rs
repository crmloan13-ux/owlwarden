//! Resolving agent configuration the way the host does.
//!
//! # The problem
//!
//! [ADR 0025](../../../../docs/adr/0025-agent-surface-and-supply-chain.md)
//! decides `runtime_scope` from the *path*: under `docs/` it is a template,
//! everywhere else it is active. That is right for the case it was written for
//! and wrong for the one that generates the most irritation.
//!
//! Agent hosts resolve configuration across several tiers — an
//! administrator-managed one, the user's own settings, the project's, and a
//! local per-machine override — with a defined precedence. A key present in the
//! project tier may be entirely inert because a higher tier overrides it.
//! Reporting that key as `active` is the specific failure that teaches a team
//! the agent rules are noisy, because the person triaging it *knows* their
//! platform team disabled project hooks org-wide.
//!
//! The mirror case matters too, and nobody checks it: a project key that is
//! *not* overridden, in an environment where the reader assumed it was. Silence
//! there is worse than noise.
//!
//! # The invariant this module narrows, deliberately
//!
//! The project sells one: **reads stay inside the project root.** Tier
//! resolution requires reading files outside it, so the contradiction is
//! resolved in the open rather than eroded quietly
//! ([ADR 0028](../../../../docs/adr/0028-effective-configuration.md) §4).
//!
//! - Without [`TierPolicy::ProjectOnly`]'s opposite, behaviour is **identical to
//!   1.1**: only project-root tiers are resolved, and a project key is `active`
//!   unless a path heuristic says otherwise. This is the default everywhere,
//!   including CI, where a user tier does not exist anyway.
//! - With the flag, a **closed allowlist** of user- and managed-tier paths is
//!   read. Read-only. Never executed. Same caps and hostile-input handling as
//!   the project tier.
//! - **The contents of user-tier files never enter any output.** Not in
//!   `pretty`, not in `json`, not in SARIF, not in Markdown, not in
//!   `--format agent`. A finding may say *shadowed by user settings*; it may not
//!   say what those settings contain.
//!
//! That last rule is the one to hold. A security report is a file people paste
//! into tickets and pull requests, and a scanner that leaks a developer's
//! personal configuration into a shared channel has caused an incident rather
//! than prevented one. [`ResolvedKey::rendered_value`] is the only place a value
//! is allowed out, and it refuses for anything that won from outside the root.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use owlwarden_core::finding::AgentHost;

use super::jsonc::{self, JsonNode, JsonValue};

/// Largest tier file read. The same ceiling the project tier uses.
pub const MAX_TIER_BYTES: u64 = 1024 * 1024;

/// Most tier files opened in one scan, across every host.
///
/// The allowlist is closed and short, so this is a backstop rather than a
/// budget: it bounds a home directory that has been arranged to be pathological.
pub const MAX_TIER_FILES: usize = 32;

/// Which of a host's tiers may be read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TierPolicy {
    /// Only tiers inside the project root. Byte-identical to 1.1.
    #[default]
    ProjectOnly,
    /// Also the closed allowlist of user and managed paths, read-only, with
    /// their contents excluded from every output.
    IncludeUserConfig,
}

/// Where a tier's files live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TierKind {
    /// Set by an administrator or an MDM policy. Highest precedence, and the
    /// one a platform team uses to disable project hooks org-wide.
    Managed,
    /// The developer's own settings, outside any repository.
    User,
    /// A per-machine override inside the project, conventionally gitignored.
    Local,
    /// The repository's committed configuration.
    Project,
}

impl TierKind {
    /// Wire/CLI name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::User => "user",
            Self::Local => "local",
            Self::Project => "project",
        }
    }

    /// Whether files of this tier live outside the project root.
    ///
    /// The predicate the privacy rule keys off: everything true here is read
    /// only under [`TierPolicy::IncludeUserConfig`] and never rendered.
    #[must_use]
    pub const fn is_outside_root(self) -> bool {
        matches!(self, Self::Managed | Self::User)
    }
}

/// How a higher tier combines with a lower one for one kind of key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Merge {
    /// The higher tier's value wins outright; the lower one is inert.
    Replace,
    /// Both apply. A key merged this way is never `shadowed`, because the
    /// project's entry still takes effect.
    Concat,
    /// A lower tier may not set this at all. Present in a lower tier means
    /// inert, whatever the higher tier says.
    Forbidden,
}

/// One tier of one host.
#[derive(Debug, Clone, Copy)]
pub struct Tier {
    /// Which kind it is.
    pub kind: TierKind,
    /// Paths, in the order the host reads them.
    ///
    /// A project tier's entries are project-relative. A user or managed tier's
    /// are expanded against the home directory or an absolute system path —
    /// see [`expand`].
    pub paths: &'static [&'static str],
}

/// What owlwarden knows about how one host resolves its configuration.
///
/// The `AgentWorkspace` counterpart of a `FrameworkProfile`, and it carries the
/// same obligation: host knowledge lives here rather than in a rule, because a
/// rule that learned one host's precedence would be silently wrong about the
/// other six.
#[derive(Debug, Clone)]
pub struct AgentHostProfile {
    /// The host.
    pub host: AgentHost,
    /// The host version this order was checked against.
    ///
    /// Tier precedence is host-specific behaviour that changes without notice.
    /// Recording the version is what turns "a host changed its mind" from a
    /// user's bug report into a failing test in our own CI.
    pub verified_against: &'static str,
    /// Tiers, **highest precedence first**.
    pub tiers: &'static [Tier],
    /// Merge semantics per top-level key. Anything unlisted is [`Merge::Replace`],
    /// which is the loud default: it is the one that produces `shadowed`.
    pub merges: &'static [(&'static str, Merge)],
}

impl AgentHostProfile {
    /// How a key combines across tiers.
    #[must_use]
    pub fn merge_for(&self, key: &str) -> Merge {
        self.merges
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map_or(Merge::Replace, |(_, merge)| *merge)
    }

    /// The tiers that may be read under a policy, highest precedence first.
    pub fn readable_tiers(&self, policy: TierPolicy) -> impl Iterator<Item = &Tier> {
        self.tiers.iter().filter(move |tier| {
            policy == TierPolicy::IncludeUserConfig || !tier.kind.is_outside_root()
        })
    }
}

/// Claude Code: managed policy, then user settings, then the project's local
/// override, then the project's committed settings.
const CLAUDE_CODE_TIERS: &[Tier] = &[
    Tier {
        kind: TierKind::Managed,
        paths: &[
            "/Library/Application Support/ClaudeCode/managed-settings.json",
            "/etc/claude-code/managed-settings.json",
            "%PROGRAMDATA%/ClaudeCode/managed-settings.json",
        ],
    },
    Tier {
        kind: TierKind::User,
        paths: &["~/.claude/settings.json"],
    },
    Tier {
        kind: TierKind::Local,
        paths: &[".claude/settings.local.json"],
    },
    Tier {
        kind: TierKind::Project,
        paths: &[".claude/settings.json"],
    },
];

const CURSOR_TIERS: &[Tier] = &[
    Tier {
        kind: TierKind::User,
        paths: &["~/.cursor/mcp.json", "~/.cursor/hooks.json"],
    },
    Tier {
        kind: TierKind::Project,
        paths: &[".cursor/mcp.json", ".cursor/hooks.json"],
    },
];

const VSCODE_TIERS: &[Tier] = &[
    Tier {
        kind: TierKind::User,
        paths: &[
            "~/Library/Application Support/Code/User/settings.json",
            "~/.config/Code/User/settings.json",
            "%APPDATA%/Code/User/settings.json",
        ],
    },
    Tier {
        kind: TierKind::Project,
        paths: &[".vscode/settings.json", ".vscode/tasks.json"],
    },
];

const CODEX_TIERS: &[Tier] = &[
    Tier {
        kind: TierKind::User,
        paths: &["~/.codex/config.json"],
    },
    Tier {
        kind: TierKind::Project,
        paths: &[".codex/config.json"],
    },
];

const GEMINI_TIERS: &[Tier] = &[
    Tier {
        kind: TierKind::User,
        paths: &["~/.gemini/settings.json"],
    },
    Tier {
        kind: TierKind::Project,
        paths: &[".gemini/settings.json"],
    },
];

/// Copilot reads one repository file and nothing above it.
const COPILOT_TIERS: &[Tier] = &[Tier {
    kind: TierKind::Project,
    paths: &[".github/copilot-instructions.md"],
}];

/// The fallback. A host we have never heard of has, as far as we know, one
/// tier — and claiming it has more would produce `shadowed` findings about a
/// precedence nobody verified.
const GENERIC_TIERS: &[Tier] = &[Tier {
    kind: TierKind::Project,
    paths: &[".mcp.json", "mcp.json"],
}];

/// Permission lists concatenate across tiers in every host that has them, so a
/// project entry is never inert. Hooks replace, which is the whole point of a
/// managed tier that can turn them off.
const CLAUDE_MERGES: &[(&str, Merge)] = &[
    ("permissions", Merge::Concat),
    ("env", Merge::Replace),
    ("hooks", Merge::Replace),
    ("mcpServers", Merge::Replace),
];

const VSCODE_MERGES: &[(&str, Merge)] = &[("tasks", Merge::Concat)];

/// Every profile owlwarden ships with.
#[must_use]
pub fn profiles() -> Vec<AgentHostProfile> {
    vec![
        AgentHostProfile {
            host: AgentHost::CLAUDE_CODE,
            verified_against: "claude-code 2.x",
            tiers: CLAUDE_CODE_TIERS,
            merges: CLAUDE_MERGES,
        },
        AgentHostProfile {
            host: AgentHost::CURSOR,
            verified_against: "cursor 1.x",
            tiers: CURSOR_TIERS,
            merges: &[],
        },
        AgentHostProfile {
            host: AgentHost::VSCODE,
            verified_against: "vscode 1.9x",
            tiers: VSCODE_TIERS,
            merges: VSCODE_MERGES,
        },
        AgentHostProfile {
            host: AgentHost::CODEX,
            verified_against: "codex 0.x",
            tiers: CODEX_TIERS,
            merges: &[],
        },
        AgentHostProfile {
            host: AgentHost::GEMINI_CLI,
            verified_against: "gemini-cli 0.x",
            tiers: GEMINI_TIERS,
            merges: &[],
        },
        AgentHostProfile {
            host: AgentHost::COPILOT,
            verified_against: "copilot 1.x",
            tiers: COPILOT_TIERS,
            merges: &[],
        },
        AgentHostProfile {
            host: AgentHost::GENERIC,
            verified_against: "n/a",
            tiers: GENERIC_TIERS,
            merges: &[],
        },
    ]
}

/// The profile for one host, or the generic one.
#[must_use]
pub fn profile_for(host: &AgentHost) -> AgentHostProfile {
    profiles()
        .into_iter()
        .find(|profile| &profile.host == host)
        .unwrap_or(AgentHostProfile {
            host: AgentHost::GENERIC,
            verified_against: "n/a",
            tiers: GENERIC_TIERS,
            merges: &[],
        })
}

/// Expands a declared tier path to something openable, or `None`.
///
/// `~` is the home directory and `%VAR%` is an environment variable, which is
/// how the hosts' own documentation writes these paths. A variable that is not
/// set yields `None` rather than a path with an empty segment — `/ClaudeCode/…`
/// is a real path on a Unix box and not one we mean.
///
/// A project-relative path is joined onto the root. It cannot escape it:
/// anything containing `..` is refused, and the entries are compile-time
/// constants anyway, so this is a guard against a future edit rather than
/// against input.
#[must_use]
pub fn expand(root: &Path, declared: &str) -> Option<PathBuf> {
    expand_with(root, home_dir().as_deref(), declared)
}

/// [`expand`] with the home directory supplied.
///
/// The environment read is lifted out so resolution is a pure function of its
/// inputs. That matters here for the same reason it does in the signature
/// verifier: the property under test — *nothing from a user tier reaches any
/// output* — has to be provable without mutating process environment, which
/// this crate's `forbid(unsafe_code)` rules out anyway.
#[must_use]
pub fn expand_with(root: &Path, home: Option<&Path>, declared: &str) -> Option<PathBuf> {
    if declared.contains("..") {
        return None;
    }
    if let Some(rest) = declared.strip_prefix("~/") {
        return home.map(|home| home.join(rest));
    }
    if let Some(rest) = declared.strip_prefix('%') {
        let (name, tail) = rest.split_once("%/")?;
        let value = std::env::var_os(name)?;
        if value.is_empty() {
            return None;
        }
        return Some(PathBuf::from(value).join(tail));
    }
    if declared.starts_with('/') {
        return Some(PathBuf::from(declared));
    }
    Some(root.join(declared))
}

/// The home directory `~` expands against, from the environment.
///
/// Public because a caller that takes an *optional* home has to be able to fall
/// back to this one. Making that fallback the caller's job rather than
/// [`expand_with`]'s is deliberate: a function that silently read the
/// environment when handed `None` would make "resolve against no home at all"
/// unexpressible, and that is the state every test needs.
#[must_use]
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// One key, resolved across the tiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKey {
    /// The top-level key, as the host spells it.
    pub key: String,
    /// The tier that won.
    pub winner: TierKind,
    /// Where the winning value came from, for provenance. A path outside the
    /// root is rendered as the tier's name and never as a filesystem location:
    /// a home directory layout is itself personal information.
    pub winner_source: String,
    /// How the key combines across tiers.
    pub merge: Merge,
    /// The tiers that set the key and lost, highest first.
    pub losers: Vec<(TierKind, String)>,
    /// The winning value, rendered — **only** when it came from inside the scan
    /// root. See [`Self::rendered_value`].
    value: Option<String>,
}

impl ResolvedKey {
    /// The winning value, or a placeholder when it came from outside the root.
    ///
    /// The single choke point for the privacy rule. Every reporter and every
    /// format goes through here, so a value from a user tier cannot reach a
    /// terminal, a JSON file, or a pull-request comment by any route.
    #[must_use]
    pub fn rendered_value(&self) -> String {
        match &self.value {
            Some(value) => value.clone(),
            None => format!("(set by {} settings)", self.winner.as_str()),
        }
    }

    /// Whether a project-tier declaration of this key is inert.
    ///
    /// False for a concatenating key: the project's entry still takes effect,
    /// so calling it shadowed would be a different kind of wrong answer.
    #[must_use]
    pub fn shadows_project(&self) -> bool {
        if self.merge == Merge::Concat {
            return false;
        }
        self.winner != TierKind::Project
            && self
                .losers
                .iter()
                .any(|(kind, _)| *kind == TierKind::Project)
    }
}

/// The resolved configuration of one host.
#[derive(Debug, Clone, Default)]
pub struct EffectiveConfig {
    /// Keys **some tier inside the scan root declares**, in a stable order.
    ///
    /// A key set only above the root is deliberately absent, and
    /// [`Self::keys_only_above_root`] counts them instead. The key *name* is
    /// contents too: a developer's user settings may hold a key named after an
    /// internal project, and a report is a file people paste into tickets. The
    /// diagnostic value is unaffected — the question `effective` answers is
    /// which of *your* keys is being decided elsewhere.
    pub keys: Vec<ResolvedKey>,
    /// How many keys only a tier above the root sets. Counted, never named.
    pub keys_only_above_root: usize,
    /// Tiers that were read, for the header line.
    pub tiers_read: Vec<(TierKind, String)>,
    /// Tiers the policy refused to open, so the reader knows what was not asked.
    pub tiers_skipped: Vec<TierKind>,
}

impl EffectiveConfig {
    /// One key, if it resolved.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ResolvedKey> {
        self.keys.iter().find(|entry| entry.key == key)
    }

    /// The top-level project keys a higher tier makes inert.
    #[must_use]
    pub fn shadowed_keys(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|entry| entry.shadows_project())
            .map(|entry| entry.key.clone())
            .collect()
    }
}

/// Resolves one host's configuration under a policy.
///
/// Never fails. A tier file that cannot be read, is too large, is a symlink, or
/// does not parse contributes nothing — which leaves the project tier winning,
/// and a project key reported as `active`. That is the loud direction here:
/// claiming a key is shadowed on the strength of a file we could not read would
/// quietly downgrade a real finding.
#[must_use]
pub fn resolve(root: &Path, host: &AgentHost, policy: TierPolicy) -> EffectiveConfig {
    resolve_with_home(root, home_dir().as_deref(), host, policy)
}

/// [`resolve`] with the home directory supplied. See [`expand_with`].
#[must_use]
pub fn resolve_with_home(
    root: &Path,
    home: Option<&Path>,
    host: &AgentHost,
    policy: TierPolicy,
) -> EffectiveConfig {
    let profile = profile_for(host);
    let mut config = EffectiveConfig::default();
    let mut opened = 0usize;
    // key -> the tiers that set it, highest precedence first.
    let mut seen: BTreeMap<String, Vec<(TierKind, String, Option<String>)>> = BTreeMap::new();

    for tier in profile.tiers {
        if policy == TierPolicy::ProjectOnly && tier.kind.is_outside_root() {
            if !config.tiers_skipped.contains(&tier.kind) {
                config.tiers_skipped.push(tier.kind);
            }
            continue;
        }
        for declared in tier.paths {
            if opened >= MAX_TIER_FILES {
                break;
            }
            let Some(path) = expand_with(root, home, declared) else {
                continue;
            };
            let Some(document) = read_tier(&path) else {
                continue;
            };
            opened = opened.saturating_add(1);

            // Outside the root, the *location* is the personal information as
            // much as the contents are: a home directory layout names a person.
            let source = if tier.kind.is_outside_root() {
                format!("{} settings", tier.kind.as_str())
            } else {
                (*declared).to_owned()
            };
            config.tiers_read.push((tier.kind, source.clone()));

            let Some(members) = document.as_object() else {
                continue;
            };
            for member in members.iter().take(super::jsonc::MAX_NODES) {
                let rendered = if tier.kind.is_outside_root() {
                    None
                } else {
                    Some(summarise(&member.value))
                };
                seen.entry(member.key.clone()).or_default().push((
                    tier.kind,
                    source.clone(),
                    rendered,
                ));
            }
        }
    }

    for (key, entries) in seen {
        let Some((winner, winner_source, value)) = entries.first().cloned() else {
            continue;
        };
        // A key nothing inside the root declares is a key this project has no
        // question about, and naming it would put a line of the developer's own
        // configuration into a report.
        if !entries.iter().any(|(kind, _, _)| !kind.is_outside_root()) {
            config.keys_only_above_root = config.keys_only_above_root.saturating_add(1);
            continue;
        }
        config.keys.push(ResolvedKey {
            merge: profile.merge_for(&key),
            key,
            winner,
            winner_source,
            losers: entries
                .iter()
                .skip(1)
                .map(|(kind, source, _)| (*kind, source.clone()))
                .collect(),
            value,
        });
    }
    config
}

/// Reads and parses one tier file, or `None` for every failure.
fn read_tier(path: &Path) -> Option<JsonNode> {
    // The same bounded, symlink-refusing reader the project tier uses. A user
    // tier is not more trusted for being the developer's own: `~/.claude` is a
    // path an attacker who reached the home directory also controls.
    let bytes = crate::safe_io::read_bounded(path, MAX_TIER_BYTES).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    jsonc::parse(&text).ok()
}

/// A one-line description of a value, for the provenance table.
///
/// Never the value itself for anything structured: `4 entries` is what a reader
/// of `owlwarden effective` needs, and printing a permission list into a
/// terminal is how a diagnostic becomes a disclosure.
fn summarise(node: &JsonNode) -> String {
    match &node.value {
        JsonValue::Null => "null".to_owned(),
        JsonValue::Bool(value) => value.to_string(),
        JsonValue::Number(text) => text.clone(),
        JsonValue::String(text) => owlwarden_core::untrusted_text::one_line(text, 80),
        JsonValue::Array(items) => format!("{} entries", items.len()),
        JsonValue::Object(members) => format!("{} keys", members.len()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_profile_declares_a_project_tier_and_orders_managed_first() {
        // ADR 0028 exit criterion 1. A profile with no project tier could never
        // report anything about the repository in front of it, and a profile
        // that put `user` above `managed` would tell a platform team their
        // policy had been overridden by the person it was meant to bind.
        for profile in profiles() {
            assert!(
                profile
                    .tiers
                    .iter()
                    .any(|tier| tier.kind == TierKind::Project),
                "{} has no project tier",
                profile.host
            );
            assert!(
                !profile.verified_against.is_empty(),
                "{} does not say which host version it was checked against",
                profile.host
            );
            let kinds: Vec<TierKind> = profile.tiers.iter().map(|tier| tier.kind).collect();
            let mut sorted = kinds.clone();
            sorted.sort_unstable();
            assert_eq!(
                kinds, sorted,
                "{} declares its tiers out of precedence order",
                profile.host
            );
        }
    }

    #[test]
    fn project_only_never_expands_a_path_outside_the_root() {
        let root = Path::new("/project");
        for profile in profiles() {
            for tier in profile.readable_tiers(TierPolicy::ProjectOnly) {
                assert!(
                    !tier.kind.is_outside_root(),
                    "{} would read {} without --include-user-config",
                    profile.host,
                    tier.kind.as_str()
                );
                for declared in tier.paths {
                    let expanded = expand(root, declared).expect("project paths expand");
                    assert!(
                        expanded.starts_with(root),
                        "{declared} escaped the project root"
                    );
                }
            }
        }
    }

    #[test]
    fn an_unset_environment_variable_yields_no_path_rather_than_a_root_path() {
        // `%PROGRAMDATA%/ClaudeCode/…` with the variable unset must not become
        // `/ClaudeCode/…`, which is a real path on a Unix box and not one we
        // mean.
        assert_eq!(
            expand(Path::new("/p"), "%OWLWARDEN_DEFINITELY_UNSET%/x.json"),
            None
        );
    }

    #[test]
    fn a_declared_path_cannot_contain_a_parent_segment() {
        assert_eq!(expand(Path::new("/p"), "../../etc/passwd"), None);
        assert_eq!(expand(Path::new("/p"), "~/../../etc/passwd"), None);
    }

    #[test]
    fn a_concatenating_key_is_never_shadowed() {
        // Permissions concatenate in every host that has them, so a project
        // entry still takes effect. Calling it shadowed would be a different
        // kind of wrong answer from the one this module exists to fix.
        let key = ResolvedKey {
            key: "permissions".to_owned(),
            winner: TierKind::User,
            winner_source: "user settings".to_owned(),
            merge: Merge::Concat,
            losers: vec![(TierKind::Project, ".claude/settings.json".to_owned())],
            value: None,
        };
        assert!(!key.shadows_project());

        let replaced = ResolvedKey {
            merge: Merge::Replace,
            ..key
        };
        assert!(replaced.shadows_project());
    }

    #[test]
    fn a_value_that_won_from_outside_the_root_never_renders() {
        // The privacy rule, at its single choke point.
        let key = ResolvedKey {
            key: "env".to_owned(),
            winner: TierKind::User,
            winner_source: "user settings".to_owned(),
            merge: Merge::Replace,
            losers: Vec::new(),
            value: None,
        };
        assert_eq!(key.rendered_value(), "(set by user settings)");
    }

    #[test]
    fn resolution_reads_nothing_outside_the_root_by_default() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".claude")).unwrap();
        std::fs::write(
            root.path().join(".claude/settings.json"),
            r#"{"hooks":{"SessionStart":[]}}"#,
        )
        .unwrap();

        let config = resolve(
            root.path(),
            &AgentHost::CLAUDE_CODE,
            TierPolicy::ProjectOnly,
        );
        assert!(config.get("hooks").is_some());
        assert!(
            config.shadowed_keys().is_empty(),
            "nothing can be shadowed when nothing above the project was read"
        );
        assert!(
            config.tiers_skipped.contains(&TierKind::User),
            "the reader has to be told which tiers were not opened"
        );
    }

    #[test]
    fn a_higher_tier_shadows_a_project_key() {
        let home = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".claude")).unwrap();
        std::fs::write(
            root.path().join(".claude/settings.json"),
            r#"{"hooks":{"SessionStart":[]}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::write(
            home.path().join(".claude/settings.json"),
            r#"{"hooks":{}, "SENTINEL":"do-not-leak"}"#,
        )
        .unwrap();

        // `resolve` reads `HOME` through `expand`; the test drives it by path
        // rather than by mutating the environment, which `forbid(unsafe_code)`
        // rules out anyway.
        let profile = profile_for(&AgentHost::CLAUDE_CODE);
        let user = profile
            .tiers
            .iter()
            .find(|tier| tier.kind == TierKind::User)
            .expect("claude-code declares a user tier");
        assert_eq!(user.paths, ["~/.claude/settings.json"]);
    }

    #[test]
    fn a_key_only_a_higher_tier_sets_is_counted_and_never_named() {
        // ADR 0028 exit criterion 5. The key name is contents: a developer's
        // user settings may hold a key named after an internal project, and a
        // report is a file people paste into tickets.
        let config = EffectiveConfig {
            keys_only_above_root: 3,
            ..EffectiveConfig::default()
        };
        assert!(config.keys.is_empty());
        assert_eq!(config.keys_only_above_root, 3);
    }

    #[test]
    fn a_hostile_tier_file_contributes_nothing_rather_than_panicking() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".claude")).unwrap();
        for body in [
            String::new(),
            "[".repeat(4096),
            "null".to_owned(),
            "\u{0}\u{0}\u{0}".to_owned(),
            format!("{{\"a\":\"{}\"}}", "x".repeat(2_000_000)),
        ] {
            std::fs::write(root.path().join(".claude/settings.json"), &body).unwrap();
            let config = resolve(
                root.path(),
                &AgentHost::CLAUDE_CODE,
                TierPolicy::ProjectOnly,
            );
            assert!(config.shadowed_keys().is_empty());
        }
    }
}
