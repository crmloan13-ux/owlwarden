//! Cursor.
//!
//! # The schema this targets
//!
//! Cursor runs hooks declared in `.cursor/hooks.json`, passing the event on
//! stdin as JSON and reading a JSON object from stdout. The events this adapter
//! recognises, and what it reads from each:
//!
//! ```json
//! { "hook_event_name": "beforeShellExecution", "command": "rm -rf /" }
//! { "hook_event_name": "afterFileEdit",        "file_path": "app/route.ts" }
//! { "hook_event_name": "stop" }
//! ```
//!
//! The response shape is a `permission` field — `allow`, `deny`, or `ask` —
//! with a message for the developer and one for the agent. Cursor's hook
//! surface has moved more than once, so this adapter reads both the `snake_case`
//! and camelCase spellings of the event name and writes the fields under both
//! `permission` and `continue`, which are the two shapes seen in the wild.
//!
//! **If this drifts, use `--host generic`.** That is not a consolation prize:
//! the generic adapter is owlwarden's own contract, it cannot go stale, and
//! three lines of shell wire it to anything that can run a process.

use serde_json::json;

use crate::adapters::{Encoded, HostAdapter, paths_in, string_at};
use crate::decision::{GateDecision, Verdict};
use crate::event::{GateError, GateEvent, GateEventKind, parse_json};

/// The adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct CursorAdapter;

impl HostAdapter for CursorAdapter {
    fn id(&self) -> &'static str {
        "cursor"
    }

    fn targets(&self) -> &'static str {
        "Cursor hooks.json events (beforeShellExecution / afterFileEdit / stop)"
    }

    fn parse(&self, payload: &str) -> Result<GateEvent, GateError> {
        let value = parse_json(payload)?;
        let name = string_at(&value, "hook_event_name")
            .or_else(|| string_at(&value, "hookEventName"))
            .or_else(|| string_at(&value, "event"))
            .unwrap_or_default()
            .to_owned();

        let normalised = name.to_ascii_lowercase().replace(['_', '-'], "");
        let event = match normalised.as_str() {
            "sessionstart" | "beforesession" => {
                GateEvent::new(self.id(), GateEventKind::SessionStart)
            }
            "beforeshellexecution" => {
                let command = string_at(&value, "command")
                    .or_else(|| {
                        value
                            .get("input")
                            .and_then(|input| string_at(input, "command"))
                    })
                    .unwrap_or_default();
                GateEvent::new(self.id(), GateEventKind::ShellCommand).with_command(command)
            }
            "afterfileedit" => {
                let paths = paths_in(&value);
                let kind = if paths.iter().any(|path| path.contains(".cursor")) {
                    GateEventKind::ConfigChanged
                } else {
                    GateEventKind::FileEdited
                };
                GateEvent::new(self.id(), kind).with_paths(paths)
            }
            "stop" | "afteragentturn" => GateEvent::new(self.id(), GateEventKind::TurnBoundary),
            other => {
                return Err(GateError::UnknownEvent {
                    host: "cursor",
                    name: (!other.is_empty()).then(|| name.clone()),
                });
            }
        };
        Ok(event.with_host_event(name))
    }

    fn encode(&self, _event: &GateEvent, decision: &GateDecision) -> Encoded {
        let permission = match decision.verdict {
            Verdict::Deny => "deny",
            Verdict::Ask => "ask",
            Verdict::Allow | Verdict::Defer => "allow",
        };

        // Built in one expression rather than by mutation: `serde_json`'s
        // index-assign panics on a non-object, and a gate that panics is a gate
        // that takes the session with it.
        let message = decision.context.clone().or_else(|| {
            (decision.verdict.blocks() || decision.verdict == Verdict::Ask)
                .then(|| decision.reason.clone())
        });
        let body = match message {
            Some(text) => json!({
                "permission": permission,
                "continue": !decision.verdict.blocks(),
                "agentMessage": text,
                "userMessage": text,
            }),
            // A clean gate says nothing, and costs the model nothing.
            None => json!({
                "permission": permission,
                "continue": !decision.verdict.blocks(),
            }),
        };

        let encoded = Encoded::new(body.to_string(), 0);
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

    fn parse(payload: &str) -> GateEvent {
        CursorAdapter.parse(payload).expect("a known event")
    }

    #[test]
    fn the_shell_event_is_the_pre_execution_one() {
        let event = parse(r#"{"hook_event_name":"beforeShellExecution","command":"rm -rf /"}"#);
        assert_eq!(event.kind, GateEventKind::ShellCommand);
        assert_eq!(event.command.as_deref(), Some("rm -rf /"));
    }

    #[test]
    fn both_spellings_of_the_event_name_are_read() {
        // Cursor's hook surface has moved; reading one spelling and not the
        // other is how a gate silently stops firing.
        for payload in [
            r#"{"hook_event_name":"afterFileEdit","file_path":"a.ts"}"#,
            r#"{"hookEventName":"after_file_edit","file_path":"a.ts"}"#,
            r#"{"event":"after-file-edit","file_path":"a.ts"}"#,
        ] {
            assert_eq!(parse(payload).kind, GateEventKind::FileEdited, "{payload}");
        }
    }

    #[test]
    fn editing_cursor_config_is_a_config_change() {
        assert_eq!(
            parse(r#"{"hook_event_name":"afterFileEdit","file_path":".cursor/mcp.json"}"#).kind,
            GateEventKind::ConfigChanged
        );
    }

    #[test]
    fn an_unknown_event_is_refused() {
        assert!(matches!(
            CursorAdapter.parse(r#"{"hook_event_name":"somethingNew"}"#),
            Err(GateError::UnknownEvent { .. })
        ));
    }

    #[test]
    fn a_deny_sets_permission_and_stops_the_turn() {
        let event = parse(r#"{"hook_event_name":"stop"}"#);
        let encoded = CursorAdapter.encode(&event, &GateDecision::new(Verdict::Deny, "blocked"));
        let value: serde_json::Value = serde_json::from_str(&encoded.stdout).unwrap();
        assert_eq!(value["permission"], "deny");
        assert_eq!(value["continue"], false);
        assert_eq!(value["agentMessage"], "blocked");
    }

    #[test]
    fn an_allow_says_nothing_to_the_agent() {
        let event = parse(r#"{"hook_event_name":"afterFileEdit","file_path":"a.ts"}"#);
        let value: serde_json::Value = serde_json::from_str(
            &CursorAdapter
                .encode(&event, &GateDecision::new(Verdict::Allow, "fine"))
                .stdout,
        )
        .unwrap();
        assert_eq!(value["permission"], "allow");
        assert!(
            value.get("agentMessage").is_none(),
            "a clean gate costs the model no tokens"
        );
    }
}
