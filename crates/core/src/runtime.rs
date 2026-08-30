//! `Runtime` — where the code runs, as distinct from what it is written in.
//!
//! # Why this is an overlay and not a dimension
//!
//! `weak-crypto` tells a Hono user to `import { randomBytes } from
//! 'node:crypto'`. On Cloudflare Workers there is no `node:crypto` import to
//! make. The advice is not merely less good on that runtime; **it does not
//! run**, and a fix that throws at import time is not a fix — it is a cell that
//! satisfies a test.
//!
//! The obvious answer is a second profile dimension, and it is wrong. The
//! remediation matrix goes from 25 × 16 to 25 × 16 × 4 — about 1 600 cells,
//! most of them identical, because `sql-injection` does not care whether the
//! process is Bun or Node. Filling 1 600 cells where 400 carry information is
//! the padding [ADR 0018](../../../docs/adr/0018-corpus-depth-bar.md) rejected
//! for fixtures, and it makes adding a runtime a 400-cell change, which means
//! no runtime ever gets added.
//!
//! So remediation stays keyed by framework and runtimes are **deltas**: a rule
//! declares one only where the base fix genuinely does not run
//! ([ADR 0031](../../../docs/adr/0031-runtime-overlay.md)). Five rules carry
//! deltas. Twenty carry none, and the build asserts that their un-deltaed fix
//! executes on every declared runtime — which is what makes the *absence* of a
//! delta a positive assertion rather than an oversight.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Where the code runs.
///
/// Four values, not one per vendor. `WebWorker` covers Cloudflare Workers,
/// Vercel Edge, Deno Deploy's fetch handler, and every other host whose API is
/// the fetch API and whose `node:` builtins are absent or partial — because
/// what a fix needs to know is *which APIs exist*, and on that question they
/// are one runtime.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Runtime {
    /// Node.js. The default nearly everywhere, and the one every base fix is
    /// written for.
    #[default]
    Node,
    /// Bun. Node-compatible enough that most fixes carry over, and not
    /// compatible enough to assume it.
    Bun,
    /// Deno.
    Deno,
    /// Workers, edge functions, and anything else whose API is the fetch API.
    WebWorker,
}

impl Runtime {
    /// Wire/CLI name (`"node"`, `"bun"`, `"deno"`, `"webWorker"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
            Self::Deno => "deno",
            Self::WebWorker => "webWorker",
        }
    }

    /// The name a human reads on a summary line.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
            Self::Deno => "deno",
            Self::WebWorker => "edge",
        }
    }

    /// Parses a wire/CLI value. Tolerant of the names the ecosystem actually
    /// uses for the fetch-API tier, which is the one with four spellings.
    #[must_use]
    pub fn from_str_opt(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "node" | "nodejs" => Some(Self::Node),
            "bun" => Some(Self::Bun),
            "deno" => Some(Self::Deno),
            "webworker" | "worker" | "workers" | "edge" | "cloudflare" | "cloudflarepages"
            | "verceledge" | "edgelight" => Some(Self::WebWorker),
            _ => None,
        }
    }

    /// Every runtime, in a stable order.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Node, Self::Bun, Self::Deno, Self::WebWorker]
    }

    /// Whether `node:` builtins are available.
    ///
    /// The single question most deltas turn on. Bun implements them; Deno
    /// implements most under `node:` specifiers; a fetch-API host does not.
    #[must_use]
    pub const fn has_node_builtins(self) -> bool {
        !matches!(self, Self::WebWorker)
    }

    /// The command that runs a script on this runtime, for the execution smoke
    /// test. `None` where there is no single obvious one.
    #[must_use]
    pub const fn probe_command(self) -> Option<&'static str> {
        match self {
            Self::Node => Some("node"),
            Self::Bun => Some("bun"),
            Self::Deno => Some("deno"),
            // A Workers script needs a host to run in. The fixture suite runs
            // it under `workerd` when present; there is no bare interpreter.
            Self::WebWorker => Some("workerd"),
        }
    }
}

impl fmt::Display for Runtime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How a runtime was arrived at.
///
/// Carried on the finding because a fix chosen from an *inferred* runtime
/// should say what it inferred. A finding whose fix depends on the runtime and
/// whose runtime came from a framework default is a finding the reader should
/// check, and one word is what tells them to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeSource {
    /// An explicit declaration: `wrangler.toml`, `deno.json`, a `runtime`
    /// export, a Nitro preset, an adapter in the framework config.
    Declared,
    /// The lockfile or `engines`.
    Lockfile,
    /// The framework's default. An inference, and the report says so.
    Default,
}

impl RuntimeSource {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Lockfile => "lockfile",
            Self::Default => "default",
        }
    }

    /// The word the summary line uses.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Declared | Self::Lockfile => "detected",
            Self::Default => "defaulted",
        }
    }

    /// Whether this was inferred rather than read.
    #[must_use]
    pub const fn is_inferred(self) -> bool {
        matches!(self, Self::Default)
    }
}

impl fmt::Display for RuntimeSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_fetch_api_tier_parses_under_every_name_the_ecosystem_uses() {
        // Four vendors, one runtime as far as a fix is concerned. Missing a
        // spelling means silently handing a Workers user a `node:crypto` import.
        for text in [
            "webWorker",
            "web-worker",
            "worker",
            "workers",
            "edge",
            "cloudflare",
            "vercel-edge",
        ] {
            assert_eq!(
                Runtime::from_str_opt(text),
                Some(Runtime::WebWorker),
                "{text} should be the fetch-API tier"
            );
        }
    }

    #[test]
    fn only_the_fetch_api_tier_lacks_node_builtins() {
        assert!(Runtime::Node.has_node_builtins());
        assert!(Runtime::Bun.has_node_builtins());
        assert!(Runtime::Deno.has_node_builtins());
        assert!(!Runtime::WebWorker.has_node_builtins());
    }

    #[test]
    fn a_defaulted_runtime_reads_as_inferred_and_a_declared_one_does_not() {
        assert!(RuntimeSource::Default.is_inferred());
        assert_eq!(RuntimeSource::Default.label(), "defaulted");
        assert!(!RuntimeSource::Declared.is_inferred());
        assert_eq!(RuntimeSource::Declared.label(), "detected");
        // A lockfile is evidence, not a guess: it reads as detected.
        assert!(!RuntimeSource::Lockfile.is_inferred());
    }

    #[test]
    fn an_unknown_runtime_is_none_rather_than_node() {
        // Defaulting an unrecognised value to Node would hand a Workers user a
        // `node:crypto` import on the strength of a typo.
        assert_eq!(Runtime::from_str_opt("wasmer"), None);
        assert_eq!(Runtime::from_str_opt(""), None);
    }
}
