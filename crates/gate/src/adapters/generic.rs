//! Any host, and owlwarden's own contract.
//!
//! # Why this is first-class and not a fallback
//!
//! The two vendor adapters are coupled to schemas we do not control, by hosts
//! that change them. This one is coupled to nothing: it reads a small object we
//! define, writes a small object we define, and uses the
//! [ADR 0017](../../../../docs/adr/0017-ci-reporting-surface.md) exit codes that
//! every other owlwarden command already uses.
//!
//! That makes it the adapter a host we have never heard of gets wired up with,
//! in three lines of shell — and the one that still works when a vendor ships a
//! breaking change on a Tuesday.
//!
//! # In
//!
//! ```json
//! { "event": "file-edited", "paths": ["app/api/users/route.ts"] }
//! { "event": "shell-command", "command": "curl … | sh" }
//! { "event": "turn-boundary" }
//! ```
//!
//! `event` accepts the kebab-case and `snake_case` spellings, plus the common
//! host names (`post-tool-use`, `stop`) so a shell wrapper can pass its host's
//! word straight through.
//!
//! # Out
//!
//! ```json
//! { "verdict": "deny", "reason": "…", "findings": [...] }
//! ```
//!
//! With the exit code carrying the same answer for anything that reads exit
//! codes rather than JSON: `0` allow, `1` deny, `2` ask or degraded.

use crate::adapters::{Encoded, HostAdapter, paths_in, string_at};
use crate::decision::{GateDecision, Verdict};
use crate::event::{GateError, GateEvent, GateEventKind, parse_json};

/// Exit code for `allow` — the same `0` a clean scan uses.
pub const EXIT_ALLOW: i32 = 0;
/// Exit code for `deny` — the same `1` a failing scan uses.
pub const EXIT_DENY: i32 = 1;
/// Exit code for `ask` and for a degraded gate — the same `2` that means
/// "could not run" everywhere else in the CLI.
pub const EXIT_ASK: i32 = 2;

/// The adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct GenericAdapter;

impl HostAdapter for GenericAdapter {
    fn id(&self) -> &'static str {
        "generic"
    }

    fn targets(&self) -> &'static str {
        "owlwarden's own event and decision JSON, with the ADR 0017 exit codes"
    }

    fn parse(&self, payload: &str) -> Result<GateEvent, GateError> {
        let value = parse_json(payload)?;
        let name = string_at(&value, "event")
            .or_else(|| string_at(&value, "hook_event_name"))
            .or_else(|| string_at(&value, "kind"))
            .unwrap_or_default();

        let Some(kind) = GateEventKind::from_str_opt(name) else {
            return Err(GateError::UnknownEvent {
                host: "generic",
                name: (!name.is_empty()).then(|| name.to_owned()),
            });
        };

        let mut event = GateEvent::new(self.id(), kind).with_host_event(name);
        let paths = paths_in(&value);
        if !paths.is_empty() {
            event = event.with_paths(paths);
        }
        if let Some(command) = string_at(&value, "command") {
            event = event.with_command(command);
        }
        Ok(event)
    }

    fn encode(&self, _event: &GateEvent, decision: &GateDecision) -> Encoded {
        let exit_code = match decision.verdict {
            Verdict::Allow | Verdict::Defer => EXIT_ALLOW,
            Verdict::Deny => EXIT_DENY,
            Verdict::Ask => EXIT_ASK,
        };
        // Serialising the decision itself rather than a hand-built object: the
        // shape is then the documented one by construction, and a field added
        // to `GateDecision` appears here without an edit.
        let stdout = serde_json::to_string(decision).unwrap_or_else(|_| {
            r#"{"verdict":"ask","reason":"owlwarden could not encode its decision"}"#.to_owned()
        });

        let encoded = Encoded::new(stdout, exit_code);
        if decision.degraded {
            return encoded.with_stderr(format!("owlwarden gate degraded: {}", decision.reason));
        }
        encoded
    }
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
    fn a_hosts_own_event_name_can_be_passed_straight_through() {
        // The point of the generic adapter: a shell wrapper should not have to
        // translate, only forward.
        for (payload, expected) in [
            (
                r#"{"event":"file-edited","paths":["a.ts"]}"#,
                GateEventKind::FileEdited,
            ),
            (r#"{"event":"post_tool_use"}"#, GateEventKind::FileEdited),
            (r#"{"hook_event_name":"Stop"}"#, GateEventKind::TurnBoundary),
            (
                r#"{"kind":"shell-command","command":"ls"}"#,
                GateEventKind::ShellCommand,
            ),
        ] {
            assert_eq!(
                GenericAdapter.parse(payload).unwrap().kind,
                expected,
                "{payload}"
            );
        }
    }

    #[test]
    fn the_exit_code_carries_the_same_answer_as_the_json() {
        // For anything that reads exit codes rather than parsing JSON — which
        // is most shell wrappers.
        for (verdict, code) in [
            (Verdict::Allow, EXIT_ALLOW),
            (Verdict::Defer, EXIT_ALLOW),
            (Verdict::Deny, EXIT_DENY),
            (Verdict::Ask, EXIT_ASK),
        ] {
            let event = GenericAdapter
                .parse(r#"{"event":"turn-boundary"}"#)
                .expect("a known event");
            let encoded = GenericAdapter.encode(&event, &GateDecision::new(verdict, "r"));
            assert_eq!(encoded.exit_code, code, "{verdict:?}");
            let value: serde_json::Value = serde_json::from_str(&encoded.stdout).unwrap();
            assert_eq!(value["verdict"], verdict.as_str());
        }
    }

    #[test]
    fn the_exit_codes_are_the_ones_the_rest_of_the_cli_uses() {
        // 0 clean, 1 findings, 2 could not run. A gate with its own numbering
        // would be one more thing for a hook author to look up.
        assert_eq!((EXIT_ALLOW, EXIT_DENY, EXIT_ASK), (0, 1, 2));
    }

    #[test]
    fn an_unknown_event_is_refused_rather_than_defaulted() {
        assert!(matches!(
            GenericAdapter.parse(r#"{"event":"whatever"}"#),
            Err(GateError::UnknownEvent { .. })
        ));
        assert!(matches!(
            GenericAdapter.parse("{}"),
            Err(GateError::UnknownEvent { name: None, .. })
        ));
    }
}
