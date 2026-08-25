//! What a host told us happened.
//!
//! One shape, whatever host produced it. The adapters translate; nothing
//! downstream of this type knows which vendor's JSON it came from.

use serde::{Deserialize, Serialize};

/// Longest command string carried out of an event.
///
/// Event JSON is attacker-adjacent on a hot path: a repository can influence
/// what the agent types, and the agent types it into the field we are about to
/// read. Bound it here, once, rather than in each adapter.
pub const MAX_COMMAND_CHARS: usize = 8_192;

/// Most paths carried out of one event.
pub const MAX_EVENT_PATHS: usize = 512;

/// The lifecycle moment the host is at.
///
/// The names are ours, not any host's. Four hosts spell "the model just wrote a
/// file" four ways, and the value of one vocabulary is that
/// [`decide`](crate::decide) has five arms rather than twenty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateEventKind {
    /// A session is starting. Nothing has happened yet, and nothing should be
    /// blocked; this is where a digest of the project's posture belongs.
    SessionStart,
    /// A file was written or edited. Scope: that file.
    FileEdited,
    /// A shell command is about to run. Scope: the command string.
    ///
    /// The only event where the gate sits *before* execution, which is why it
    /// is the only one that fails closed.
    ShellCommand,
    /// Agent or editor configuration changed mid-session. Scope: that file.
    ///
    /// The [ADR 0025](../../../docs/adr/0025-agent-surface-and-supply-chain.md)
    /// family at run time — the control that would have caught the `ChainDrop`
    /// foothold at the moment it was written.
    ConfigChanged,
    /// The turn is about to end. Scope: everything changed since it began.
    ///
    /// The loop-closer, and the important one. A per-edit hook makes the agent
    /// fix things one at a time and can thrash; a turn-boundary gate lets it
    /// work, then refuses to let it declare victory over code that does not
    /// pass. One scan per turn instead of one per edit.
    TurnBoundary,
}

impl GateEventKind {
    /// Wire name, for logs and the generic adapter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionStart => "session-start",
            Self::FileEdited => "file-edited",
            Self::ShellCommand => "shell-command",
            Self::ConfigChanged => "config-changed",
            Self::TurnBoundary => "turn-boundary",
        }
    }

    /// Parses a wire name. Accepts the underscore spelling too, because a hook
    /// author will type one of the two and neither is wrong.
    #[must_use]
    pub fn from_str_opt(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "session-start" | "sessionstart" => Some(Self::SessionStart),
            "file-edited" | "post-edit" | "after-edit" | "post-tool-use" => Some(Self::FileEdited),
            "shell-command" | "pre-tool-use" | "before-shell-execution" => Some(Self::ShellCommand),
            "config-changed" => Some(Self::ConfigChanged),
            "turn-boundary" | "stop" | "turn-end" => Some(Self::TurnBoundary),
            _ => None,
        }
    }

    /// Whether the gate sits before something executes.
    ///
    /// This single bit decides the failure posture, and it is a property of the
    /// event rather than of a configuration switch — because the reason is a
    /// property of the event: nothing has run yet, so refusing to guess costs
    /// the developer one prompt, and guessing wrong costs them a compromise.
    #[must_use]
    pub const fn precedes_execution(self) -> bool {
        matches!(self, Self::ShellCommand)
    }
}

/// One normalised event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateEvent {
    /// The adapter that produced it, e.g. `claude-code`.
    pub host: String,
    /// What happened.
    pub kind: GateEventKind,
    /// Project-relative paths in scope, already bounded.
    #[serde(default)]
    pub paths: Vec<String>,
    /// The command, for [`GateEventKind::ShellCommand`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The host's own name for the event, kept verbatim for the reason line and
    /// for debugging a schema drift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_event: Option<String>,
}

impl GateEvent {
    /// Builds an event, applying the bounds.
    #[must_use]
    pub fn new(host: &str, kind: GateEventKind) -> Self {
        Self {
            host: host.to_owned(),
            kind,
            paths: Vec::new(),
            command: None,
            host_event: None,
        }
    }

    /// Adds paths, deduplicated, normalised to `/`, and capped.
    #[must_use]
    pub fn with_paths(mut self, paths: impl IntoIterator<Item = String>) -> Self {
        let mut all: Vec<String> = paths
            .into_iter()
            .map(|path| path.replace('\\', "/"))
            .filter(|path| !path.trim().is_empty())
            .collect();
        all.sort();
        all.dedup();
        all.truncate(MAX_EVENT_PATHS);
        self.paths = all;
        self
    }

    /// Adds the command, capped.
    #[must_use]
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        let text: String = command.into().chars().take(MAX_COMMAND_CHARS).collect();
        self.command = Some(text);
        self
    }

    /// Records the host's own event name.
    #[must_use]
    pub fn with_host_event(mut self, name: impl Into<String>) -> Self {
        self.host_event = Some(name.into());
        self
    }
}

/// An event we could not make sense of.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// The payload was not JSON.
    #[error("the host sent something that is not JSON: {message}")]
    NotJson {
        /// Parser message.
        message: String,
    },
    /// The payload was JSON we do not recognise.
    ///
    /// Not fatal by itself: the caller decides, and for a pre-execution event
    /// the right answer is `ask`, never `allow`.
    #[error("unrecognised {host} event{}", .name.as_ref().map(|n| format!(" {n:?}")).unwrap_or_default())]
    UnknownEvent {
        /// Adapter that refused it.
        host: &'static str,
        /// The host's event name, when there was one.
        name: Option<String>,
    },
    /// The payload was too large to be an event.
    #[error("event payload is {size} bytes, over the {max}-byte limit")]
    TooLarge {
        /// Actual size.
        size: usize,
        /// The cap.
        max: usize,
    },
}

/// Largest event payload accepted on stdin.
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;

/// Parses the payload as JSON, applying the size bound first.
///
/// # Errors
/// [`GateError`] for anything oversized or unparseable.
pub fn parse_json(payload: &str) -> Result<serde_json::Value, GateError> {
    if payload.len() > MAX_EVENT_BYTES {
        return Err(GateError::TooLarge {
            size: payload.len(),
            max: MAX_EVENT_BYTES,
        });
    }
    serde_json::from_str(payload).map_err(|error| GateError::NotJson {
        message: error.to_string(),
    })
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
    fn only_the_pre_execution_event_precedes_execution() {
        assert!(GateEventKind::ShellCommand.precedes_execution());
        for kind in [
            GateEventKind::SessionStart,
            GateEventKind::FileEdited,
            GateEventKind::ConfigChanged,
            GateEventKind::TurnBoundary,
        ] {
            assert!(!kind.precedes_execution(), "{kind:?}");
        }
    }

    #[test]
    fn every_kind_round_trips_through_its_wire_name() {
        for kind in [
            GateEventKind::SessionStart,
            GateEventKind::FileEdited,
            GateEventKind::ShellCommand,
            GateEventKind::ConfigChanged,
            GateEventKind::TurnBoundary,
        ] {
            assert_eq!(GateEventKind::from_str_opt(kind.as_str()), Some(kind));
        }
        assert_eq!(
            GateEventKind::from_str_opt("post_tool_use"),
            Some(GateEventKind::FileEdited)
        );
        assert_eq!(GateEventKind::from_str_opt("nonsense"), None);
    }

    #[test]
    fn paths_are_normalised_deduplicated_and_capped() {
        let event = GateEvent::new("generic", GateEventKind::FileEdited).with_paths(
            std::iter::repeat_n("app\\route.ts".to_owned(), 3)
                .chain(std::iter::once("  ".to_owned()))
                .chain((0..MAX_EVENT_PATHS + 10).map(|index| format!("f{index}.ts"))),
        );
        assert!(event.paths.contains(&"app/route.ts".to_owned()));
        assert_eq!(event.paths.len(), MAX_EVENT_PATHS);
        assert!(!event.paths.iter().any(|path| path.trim().is_empty()));
    }

    #[test]
    fn a_giant_command_is_truncated_rather_than_carried() {
        let event =
            GateEvent::new("generic", GateEventKind::ShellCommand).with_command("x".repeat(99_999));
        assert_eq!(
            event.command.map(|c| c.chars().count()),
            Some(MAX_COMMAND_CHARS)
        );
    }

    #[test]
    fn an_oversized_payload_is_refused_before_it_is_parsed() {
        let payload = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_EVENT_BYTES));
        assert!(matches!(
            parse_json(&payload),
            Err(GateError::TooLarge { .. })
        ));
        assert!(matches!(
            parse_json("not json"),
            Err(GateError::NotJson { .. })
        ));
    }
}
