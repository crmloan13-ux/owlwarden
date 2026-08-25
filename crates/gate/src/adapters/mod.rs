//! Host adapters: pure translation, in and out.
//!
//! An adapter knows two things and nothing else: how to read one host's event
//! JSON into a [`GateEvent`], and how to write one [`GateDecision`] back in the
//! shape that host expects. It never decides anything — [`crate::decide`] does
//! that, once, for every host.
//!
//! # Vendor coupling, and the mitigation
//!
//! Every host we adapt to is a schema we do not control, and hosts churn faster
//! than web frameworks do. That cost is real and stated in
//! [ADR 0026](../../../../docs/adr/0026-deterministic-agent-gate.md)'s
//! consequences rather than hidden.
//!
//! Two things contain it. Each adapter is about a hundred lines with a golden
//! fixture pair, so a schema change is a small, visible diff. And [`generic`]
//! is **first-class, not a fallback**: it emits owlwarden's own JSON and the
//! [ADR 0017](../../../../docs/adr/0017-ci-reporting-surface.md) exit codes, so
//! a host we have never heard of can be wired up with three lines of shell and
//! no adapter at all.
//!
//! # Reading these adapters
//!
//! Each one documents the host schema it was written against. When a host
//! changes, the golden fixture is what fails, and the fixture is the record of
//! what the shape used to be.

pub mod claude_code;
pub mod cursor;
pub mod generic;

use crate::decision::GateDecision;
use crate::event::{GateError, GateEvent};

/// What an adapter writes, and the exit code the host reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// stdout, exactly as the host expects it. Never has a trailing newline
    /// added by the caller — some hosts parse strictly.
    pub stdout: String,
    /// Anything the developer should see. The host surfaces it; the model does
    /// not read it.
    pub stderr: Option<String>,
    /// Process exit code.
    pub exit_code: i32,
}

impl Encoded {
    /// A response with no stderr.
    #[must_use]
    pub fn new(stdout: impl Into<String>, exit_code: i32) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: None,
            exit_code,
        }
    }

    /// Attaches a developer-facing message.
    #[must_use]
    pub fn with_stderr(mut self, message: impl Into<String>) -> Self {
        self.stderr = Some(message.into());
        self
    }
}

/// One host's translation layer.
pub trait HostAdapter: Send + Sync {
    /// Stable id, as `--host` spells it.
    fn id(&self) -> &'static str;

    /// The host schema version this adapter was written against, for the
    /// `--help` text and for a bug report that says "which shape?".
    fn targets(&self) -> &'static str;

    /// Reads the host's event JSON.
    ///
    /// # Errors
    /// [`GateError`] when the payload is not JSON, is too large, or is an event
    /// this adapter does not recognise. An unrecognised event is *not* an
    /// allow: the caller turns it into `ask` before execution and `defer`
    /// after, which is the same asymmetry as the failure posture.
    fn parse(&self, payload: &str) -> Result<GateEvent, GateError>;

    /// Writes the decision in the host's shape.
    ///
    /// Takes the event as well as the decision, because the response shape is
    /// per-event on every host that has more than one: Claude Code reads
    /// `permissionDecision` on a `PreToolUse` and `decision` on a `Stop`, and
    /// echoing the wrong `hookEventName` back is how a hook is silently
    /// ignored.
    fn encode(&self, event: &GateEvent, decision: &GateDecision) -> Encoded;
}

/// Every adapter that ships.
#[must_use]
pub fn available_hosts() -> Vec<&'static str> {
    vec![
        claude_code::ClaudeCodeAdapter.id(),
        cursor::CursorAdapter.id(),
        generic::GenericAdapter.id(),
    ]
}

/// Looks up an adapter by id.
///
/// An unknown id yields `None` rather than falling back to `generic`: a typo in
/// a hook configuration must fail loudly, not quietly wire up a different
/// output shape than the host is parsing.
#[must_use]
pub fn adapter_for(host: &str) -> Option<Box<dyn HostAdapter>> {
    match host {
        "claude-code" => Some(Box::new(claude_code::ClaudeCodeAdapter)),
        "cursor" => Some(Box::new(cursor::CursorAdapter)),
        "generic" => Some(Box::new(generic::GenericAdapter)),
        _ => None,
    }
}

/// Pulls a string out of a JSON object by key.
pub(crate) fn string_at<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

/// Collects file paths out of a host's tool-input object.
///
/// Hosts name the field differently and sometimes send an array. Reading all of
/// the plausible spellings is deliberate: the failure mode of missing one is a
/// gate that scans nothing and reports clean.
pub(crate) fn paths_in(value: &serde_json::Value) -> Vec<String> {
    const KEYS: &[&str] = &[
        "file_path",
        "filePath",
        "path",
        "notebook_path",
        "file_paths",
        "filePaths",
        "paths",
        "files",
        "edits",
    ];
    let mut out = Vec::new();
    for key in KEYS {
        match value.get(*key) {
            Some(serde_json::Value::String(text)) => out.push(text.clone()),
            Some(serde_json::Value::Array(items)) => {
                for item in items {
                    match item {
                        serde_json::Value::String(text) => out.push(text.clone()),
                        object => {
                            if let Some(text) =
                                string_at(object, "path").or_else(|| string_at(object, "file_path"))
                            {
                                out.push(text.to_owned());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
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

    #[test]
    fn every_advertised_host_resolves_and_a_typo_does_not() {
        for host in available_hosts() {
            let adapter = adapter_for(host).expect("advertised hosts must resolve");
            assert_eq!(adapter.id(), host);
            assert!(
                !adapter.targets().is_empty(),
                "{host} names no target schema"
            );
        }
        assert!(
            adapter_for("claude").is_none(),
            "a typo must fail loudly rather than wiring up a different output shape"
        );
    }

    #[test]
    fn paths_are_read_from_every_spelling_a_host_uses() {
        let value = serde_json::json!({
            "file_path": "a.ts",
            "filePaths": ["b.ts", "c.ts"],
            "edits": [{"path": "d.ts"}, {"file_path": "e.ts"}]
        });
        let mut found = paths_in(&value);
        found.sort();
        assert_eq!(found, ["a.ts", "b.ts", "c.ts", "d.ts", "e.ts"]);
    }

    #[test]
    fn a_payload_with_no_paths_yields_none_rather_than_a_guess() {
        assert!(paths_in(&serde_json::json!({"command": "ls"})).is_empty());
    }
}
