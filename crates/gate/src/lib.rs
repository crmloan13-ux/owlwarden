//! The deterministic agent gate.
//!
//! # Why this crate exists
//!
//! v0.2 shipped `owlwarden mcp` and recorded the exit criterion as met: an
//! MCP-capable agent can scan and pull remediations in one loop. That is true,
//! and it is not the same thing as the code being scanned.
//!
//! An MCP tool is *available* to the model. It is called when the model decides
//! the task warrants it, and mid-refactor it often does not. A sentence in
//! `AGENTS.md` asking the model to run the scanner is the same shape of hope in
//! a different file: an instruction competing with every other instruction in
//! the context window, and losing to whichever one the model weighted higher
//! this turn.
//!
//! **Determinism is the product.** A deterministic scanner wired in as a
//! suggestion is a deterministic scanner that runs sometimes.
//!
//! So this crate is the other shape: attach to the host's lifecycle, run
//! outside the model as a separate process, on an event the host decides, and
//! return a verdict the model cannot argue with — because the prompt is not
//! this process's input.
//!
//! # The shape
//!
//! Internally there is exactly **one** decision type. Host knowledge lives in a
//! thin adapter and nowhere else, the same way framework knowledge lives in a
//! `FrameworkProfile` and nowhere else. Adding a host is a new adapter and a
//! fixture pair, never an engine change
//! ([ADR 0026](../../../docs/adr/0026-deterministic-agent-gate.md) §1).
//!
//! ```text
//!   host event JSON ──▶ HostAdapter::parse ──▶ GateEvent
//!                                                 │
//!                                       (the CLI runs a scoped scan)
//!                                                 ▼
//!   host decision JSON ◀── HostAdapter::encode ◀── decide(event, outcome, policy)
//! ```
//!
//! # What this crate does not do
//!
//! No I/O. It does not read stdin, run a scan, or touch the filesystem — the
//! CLI does all three and hands the results in. That is what makes the whole
//! decision surface testable from a JSON string, which is what the golden
//! fixtures in `tests/` are.

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

pub mod adapters;
pub mod decision;
pub mod event;
pub mod policy;

pub use adapters::{Encoded, HostAdapter, adapter_for, available_hosts};
pub use decision::{GateDecision, Verdict};
pub use event::{GateError, GateEvent, GateEventKind};
pub use policy::{GateOutcome, GatePolicy, PostureRejection, decide};
