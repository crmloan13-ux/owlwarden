//! The static analysis engine: read source, parse it with oxc, run rules.
//!
//! # Shape of the engine
//!
//! One [`StaticEngine`] is a single [`Detector`](owlwarden_core::Detector) that
//! owns many rules. That is deliberate: parsing dominates the cost of static
//! analysis, so the engine parses each file **once** and hands the AST to every
//! rule. Wrapping each rule in its own `Detector` would cost one parse per rule
//! per file, which is how you miss a 5-second budget on a 1k-file project.
//!
//! Rule identity still lives on the findings — each [`rule::FileRule`] and
//! [`rule::ProjectRule`] carries its own permanent rule id. The engine's own id
//! is used only when the whole engine fails and the failure needs attributing.
//!
//! # Two rule shapes
//!
//! - [`rule::FileRule`] — "is there a bug in this file?" Runs per file.
//! - [`rule::ProjectRule`] — "is something missing from this project?" Runs
//!   once, with the whole project in view. Absence cannot be detected from a
//!   single file: a project with no `next.config.js` at all has no security
//!   headers, and no per-file pass will ever notice.
//!
//! # Framework knowledge is data, not code inside rules
//!
//! A rule never asks "am I in a Next.js project?" and branches. It asks the
//! [`framework::FrameworkSet`] whether an expression writes a response, and gets
//! an answer that is correct for whichever frameworks are actually installed.
//! The knowledge lives in [`framework::profiles`], so supporting a new framework
//! is a profile rather than an edit to every rule. [`ast`] and [`http`] are the
//! shared question-askers built on top of that, available to plugin rules as
//! much as to first-party ones.

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

pub mod agentws;
pub mod ast;
pub mod engine;
pub mod exposure;
pub mod framework;
pub mod fs_source;
pub mod http;
pub mod incremental;
pub mod line_index;
pub mod parse;
pub mod postprocess;
pub mod project;
pub mod rule;
pub mod runner;
pub mod runtime;
pub mod safe_io;
pub mod taint;
pub mod unit;

pub use engine::StaticEngine;
pub use exposure::ExposureClassifier;
pub use framework::{
    FrameworkProfile, FrameworkRegistry, FrameworkSet, HandlerStyle, HttpVocabulary, RouteInfo,
};
pub use fs_source::FsSourceProvider;
pub use line_index::LineIndex;
pub use parse::{ParseFailure, with_parsed};
pub use project::{PackageManifest, Project};
pub use rule::{FileRule, FindingSink, ProjectRule, RuleInfo};
pub use runner::{NetworkStack, RunError, ScanRequest, scan_project, scan_project_with};
pub use runtime::{ResolvedRuntime, RuntimeMap};
pub use safe_io::{read_bounded, write_replacing};
pub use taint::RequestOrigin;
pub use unit::{FileUnit, UnitMeta};

/// Extensions the engine will parse. Everything else in the tree is ignored:
/// we do not guess at file types, and parsing a `.json` as TypeScript produces
/// noise, not findings.
pub const SUPPORTED_EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];
