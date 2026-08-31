//! Built-in reporters.
//!
//! Output is a product surface, not an afterthought. Two reporters ship in
//! v0.0 and they share one rule: **render, never re-derive**.
//! If the terminal shows a reason the JSON does not carry, the formats have
//! already drifted and one of them is lying.
//!
//! - [`PrettyReporter`] — for a human at a terminal. Code frames, colour,
//!   Unicode with an ASCII fallback.
//! - [`JsonReporter`] — for CI, for tooling, and for agents. One JSON object on
//!   stdout, schema-versioned.
//! - [`SarifReporter`] — SARIF 2.1.0 for GitHub code scanning (ADR 0017).
//! - [`JunitReporter`] — `JUnit` XML for CI test-report UIs (ADR 0017).
//! - [`MdReporter`] — GitHub-flavoured Markdown for PR comments (v1.0).
//! - [`AgentReporter`] — the report on a token budget, for the model in the
//!   loop (ADR 0026). The one reporter that deliberately omits a field the
//!   others carry: `why` is written for a human deciding whether to care, and
//!   an agent has already been told to care by the verdict.
//!
//! Decoration goes to **stderr**, never stdout, so `owlwarden scan --format json`
//! stays a single parseable object no matter what else is printed.
//!
//! `REPORTERS.md` specifies what each format promises; the snapshot tests in
//! `tests/` are what stop it drifting.

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

pub mod agent;
pub mod banner;
pub mod coverage;
pub mod json;
pub mod junit;
pub mod md;
pub mod pretty;
pub mod sarif;
pub mod theme;
pub mod turn;

pub use agent::{AgentOptions, AgentReporter, DEFAULT_BUDGET_TOKENS};
pub use banner::{BannerOpts, owl_mark, print_banner, render_banner};
pub use json::JsonReporter;
pub use junit::JunitReporter;
pub use md::MdReporter;
pub use pretty::{PrettyOptions, PrettyReporter, render_to_string};
pub use sarif::SarifReporter;
pub use theme::Glyphs;

use owlwarden_core::reporter::{ReportError, Reporter};

/// Names accepted by `--format`, in the order they are offered in help text.
pub const AVAILABLE_FORMATS: &[&str] = &["pretty", "json", "sarif", "junit", "md", "agent"];

/// Builds a reporter by name, writing to the given sink.
///
/// # Errors
/// [`ReportError::UnknownFormat`] for a name we do not have, listing the ones
/// we do — an error message that only says "unknown format" wastes the reader's
/// next minute.
pub fn reporter_by_name<'w>(
    name: &str,
    writer: Box<dyn std::io::Write + 'w>,
    options: PrettyOptions,
) -> Result<Box<dyn Reporter + 'w>, ReportError> {
    match name {
        "pretty" => Ok(Box::new(PrettyReporter::new(writer, options))),
        "json" => Ok(Box::new(JsonReporter::new(writer))),
        "sarif" => Ok(Box::new(SarifReporter::new(writer))),
        "junit" => Ok(Box::new(JunitReporter::new(writer))),
        "md" => Ok(Box::new(MdReporter::new(writer))),
        "agent" => Ok(Box::new(AgentReporter::new(writer))),
        other => Err(ReportError::UnknownFormat {
            name: other.to_owned(),
            available: AVAILABLE_FORMATS.join(", "),
        }),
    }
}
