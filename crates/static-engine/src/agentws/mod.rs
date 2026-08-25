//! The agent workspace: the second scan surface.
//!
//! owlwarden's first surface answers *is the web application in this repository
//! written safely?* This one answers a different question about the same
//! repository: *is the coding agent that works here being told to do something
//! hostile?*
//!
//! The property that makes this class of file worth its own surface is simple
//! and general: **agent and editor configuration is executable, is read from
//! the working tree, and is not read by any software composition analysis
//! tool.** It is not a dependency, so no lockfile records it. It is not
//! application source, so no SAST rule parses it. It is checked in, so it
//! passes review as "config" the way a `.prettierrc` does.
//!
//! See [ADR 0025](../../../../docs/adr/0025-agent-surface-and-supply-chain.md)
//! for the decision and its alternatives, and
//! [ADR 0026](../../../../docs/adr/0026-deterministic-agent-gate.md) for the
//! gate that consumes this surface at run time.
//!
//! # Layout
//!
//! - [`paths`] — the closed allowlist, and what each path means.
//! - [`jsonc`] — a bounded JSONC parser that keeps spans.
//! - [`workspace`] — the loader, and the view every rule reads.
//! - [`command`] — judging a command string without running it.
//! - [`text`] — hidden characters and homoglyphs in instruction files.

pub mod command;
pub mod jsonc;
pub mod paths;
pub mod text;
pub mod workspace;

pub use paths::{Classification, WorkspaceFileKind, classify};
pub use workspace::{AgentWorkspace, UnreadableFile, WorkspaceFile};
