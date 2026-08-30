//! `owlwarden bench` — the false-positive rate, measured rather than claimed.
//!
//! # Why this exists
//!
//! Every scanner claims low noise. The claim is unfalsifiable as stated, so
//! nobody believes it, and the first question in every thread about a new
//! security tool is some form of *how noisy is it*. The honest answers
//! available today are anecdotes.
//!
//! owlwarden's whole positioning rests on a word — honest — used about
//! confidence levels, coverage gaps, and stated limits. That is a strong
//! position and it was backed by architecture rather than by evidence.
//! `coverage` says what is not checked; nothing said how often what *is*
//! checked is wrong ([ADR 0030](../../../docs/adr/0030-published-benchmark.md)).
//!
//! # What this is not
//!
//! **Not the fixture suite.** `fixtures/` is written by the same people who
//! wrote the rules, so it measures internal consistency: the author's model of
//! the world, tested against itself. A benchmark measures the world. The two
//! are both necessary and neither substitutes.
//!
//! The corpus discipline is therefore part of the design and not an
//! afterthought — two named reviewers per repository, disagreements recorded
//! rather than resolved, repositories chosen before the rules are tuned against
//! them. A corpus without that discipline is a rubber stamp with extra steps,
//! and [`corpus`] enforces what can be enforced in code.

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

pub mod corpus;
pub mod report;
pub mod run;
pub mod score;
pub mod thresholds;

pub use corpus::{Corpus, CorpusEntry, CorpusError, GroundTruth, LabelledFinding, Verdict};
pub use report::{BenchReport, CorpusSize, RepositoryScore, RuleScore};
pub use run::{BENCH_PRESET, BenchError, BenchRequest};
pub use score::{Outcome, score_entry};
pub use thresholds::{ThresholdError, Thresholds};
