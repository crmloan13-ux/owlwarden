//! The `.owlwarden/surface.lock` format.
//!
//! # Two digests per file, and why
//!
//! `sha256` is over the bytes. `semantic` is over the parsed and canonicalised
//! structure. Comparison uses `semantic`, so a `prettier` run does not break the
//! seal; `sha256` is recorded so an investigator can tell a reformat from an
//! edit without re-running anything.
//!
//! For Markdown instruction files the two are equal, because in a file whose
//! whole purpose is to be read by a model, whitespace is content. A reordered
//! paragraph in `CLAUDE.md` is a different instruction.
//!
//! # Hooks, MCP servers, and permissions are extracted, not just hashed
//!
//! A file digest tells you *something* changed. A structured record tells you
//! *a `SessionStart` hook was added*, which is the sentence a reviewer needs.
//! That is the difference between a lockfile that gets read and one that gets
//! `--force`d.

use serde::{Deserialize, Serialize};

/// Format version. Bumped on any change a 1.2 reader could misinterpret.
///
/// The seal format tracks host schemas, which change faster than anything else
/// in this codebase, so this is not decoration — a reader that does not know a
/// version refuses it rather than comparing half a surface.
pub const SCHEMA_VERSION: u32 = 1;

/// The engine and rule catalogue a seal was taken under.
///
/// Recorded so that verifying a seal written by an older catalogue reports that
/// fact rather than pretending the comparison is clean: rules decide which
/// findings had to be accepted before the seal could be written, and a
/// different catalogue is a different bar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStamp {
    /// Engine version, e.g. `1.2.0`.
    pub version: String,
    /// `sha256:…` over the sorted rule ids compiled into that engine.
    pub catalogue_digest: String,
}

/// One file on the protected surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedFile {
    /// Project-relative path.
    pub path: String,
    /// `sha256:…` over the file's bytes.
    pub sha256: String,
    /// `sha256:…` over the canonicalised structure. Equal to [`Self::sha256`]
    /// for files whose whitespace is content.
    pub semantic: String,
    /// The host tier this path belongs to, as the allowlist classified it.
    pub tier: String,
}

/// One "run this command" declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedHook {
    /// The host that reads it.
    pub host: String,
    /// The host's own name for the trigger, verbatim: `SessionStart`,
    /// `folderOpen`, `postCreateCommand`. The reader is going to go and look
    /// for exactly this word.
    pub event: String,
    /// The tool matcher, when the host has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    /// `sha256:…` over the command string. The digest rather than the command
    /// keeps a very long command line out of a file people read, and one
    /// changed character still moves it.
    pub command_digest: String,
    /// A short, redacted prefix of the command, so a diff can name what moved
    /// without the reader having to run anything.
    pub target: String,
    /// Where it was declared, as `path:line`.
    pub declared_at: String,
    /// Whether it runs with no action from the developer beyond opening the
    /// folder or starting a session. The single most load-bearing bit on this
    /// surface, and the one a reviewer should see first in a diff.
    pub automatic: bool,
}

impl SealedHook {
    /// The identity two seals compare on.
    ///
    /// Host, event, and matcher — not the command. A changed command on the
    /// same trigger has to read as *modified*, not as one hook removed and
    /// another added, or the diff stops being a sentence.
    #[must_use]
    pub fn key(&self) -> String {
        match &self.matcher {
            Some(matcher) => format!("{} {} [{matcher}]", self.host, self.event),
            None => format!("{} {}", self.host, self.event),
        }
    }
}

/// One declared MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedMcpServer {
    /// The name the configuration gives it.
    pub name: String,
    /// The host whose configuration declares it.
    pub host: String,
    /// The command or URL it resolves to, redacted and clamped.
    pub command: String,
    /// How the version is pinned: `exact`, `range`, `unpinned`, or `workspace`.
    ///
    /// The field a reviewer actually reads. A server moving from `some-mcp@2.4.1`
    /// to `npx -y some-mcp` is the whole finding, and a file digest would have
    /// said only that `settings.json` changed.
    pub pin: String,
    /// Where it was declared, as `path:line`.
    pub declared_at: String,
}

/// The permission set, by digest.
///
/// Digests rather than the entries themselves: a permission list can be long,
/// and the seal exists to make a change loud rather than to be a second copy of
/// the configuration. `owlwarden effective` is where you go to read the list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedPermissions {
    /// `sha256:…` over the sorted allow entries, or absent when there are none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_digest: Option<String>,
    /// `sha256:…` over the sorted deny entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_digest: Option<String>,
    /// How many entries each digest covers, so a diff can say *4 → 7* rather
    /// than only that the digest moved.
    #[serde(default)]
    pub allow_count: usize,
    /// Deny entry count.
    #[serde(default)]
    pub deny_count: usize,
}

/// The surface itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SurfaceRecord {
    /// Every file on the allowlist, in path order.
    #[serde(default)]
    pub files: Vec<SealedFile>,
    /// Every hook, task, and lifecycle command, in a stable order.
    #[serde(default)]
    pub hooks: Vec<SealedHook>,
    /// Every declared MCP server.
    #[serde(default)]
    pub mcp_servers: Vec<SealedMcpServer>,
    /// The permission set.
    #[serde(default)]
    pub permissions: SealedPermissions,
    /// Plugin marketplace and extension sources.
    #[serde(default)]
    pub marketplaces: Vec<String>,
    /// Files read as prose the model will follow.
    #[serde(default)]
    pub instruction_files: Vec<String>,
}

/// A finding the team decided to live with, recorded where the decision was
/// made.
///
/// The reason is mandatory, matching the rule
/// [ADR 0013](../../../docs/adr/0013-suppressions-and-baseline.md) set for
/// suppressions. A seal is where you write down that the bootstrap hook is
/// deliberate; an entry with no reason fails to write, because an accepted
/// finding nobody can explain is a finding nobody decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedFinding {
    /// The finding fingerprint, as the baseline spells it.
    pub fingerprint: String,
    /// The rule that produced it.
    pub rule: String,
    /// Why it is acceptable. Never empty.
    pub reason: String,
}

/// The lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SurfaceLock {
    /// See [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// RFC 3339 UTC timestamp of the seal.
    pub sealed_at: String,
    /// What took it.
    pub engine: EngineStamp,
    /// What was sealed.
    pub surface: SurfaceRecord,
    /// Findings deliberately accepted at seal time.
    #[serde(default)]
    pub accepted: Vec<AcceptedFinding>,
}

impl SurfaceLock {
    /// Whether an entry accepts a fingerprint.
    #[must_use]
    pub fn accepts(&self, fingerprint: &str) -> bool {
        self.accepted
            .iter()
            .any(|entry| entry.fingerprint == fingerprint)
    }

    /// Number of things recorded, for the one-line summary `seal` prints.
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.surface
            .files
            .len()
            .saturating_add(self.surface.hooks.len())
            .saturating_add(self.surface.mcp_servers.len())
    }
}

/// `sha256:<hex>` over bytes.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        out.push(char::from(HEX.get(high).copied().unwrap_or(b'0')));
        out.push(char::from(HEX.get(low).copied().unwrap_or(b'0')));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_hook_key_ignores_the_command_so_an_edit_reads_as_a_change() {
        let hook = |command: &str| SealedHook {
            host: "claude-code".to_owned(),
            event: "PostToolUse".to_owned(),
            matcher: Some("Edit|Write".to_owned()),
            command_digest: digest(command.as_bytes()),
            target: command.to_owned(),
            declared_at: ".claude/settings.json:4".to_owned(),
            automatic: false,
        };
        let before = hook("pnpm exec prettier --write");
        let after = hook("pnpm exec prettier --write .");
        assert_eq!(before.key(), after.key());
        assert_ne!(before.command_digest, after.command_digest);
    }

    #[test]
    fn digests_are_prefixed_and_lowercase() {
        let value = digest(b"hello");
        assert!(value.starts_with("sha256:"));
        assert_eq!(value.len(), "sha256:".len() + 64);
        assert!(value.chars().skip(7).all(|ch| ch.is_ascii_hexdigit()));
    }
}
