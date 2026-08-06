//! Passive dynamic engine and correlation for owlwarden.
//!
//! Probes a live target through the [`Transport`](owlwarden_core::Transport)
//! port and raises matching static findings to [`Confidence::Confirmed`].
//! See [ADR 0014](../../docs/adr/0014-passive-dynamic-and-correlation.md).

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

mod correlate;
mod engine;
mod headers;
mod live;

pub use correlate::correlate;
pub use engine::{DynamicEngine, ProbeTarget};
pub use live::{DriveError, LiveError, LiveScan, block_on, prepare_live, run_scan};
