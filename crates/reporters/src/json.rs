//! The `json` reporter — the machine-readable contract.
//!
//! One JSON object, on stdout, nothing else. That is what makes
//! `owlwarden scan --format json | jq` work and what lets an agent parse the
//! result without a heuristic.
//!
//! The shape is [`Report`](owlwarden_core::Report) serialized directly, so
//! there is no second definition of the format to drift from the first. It is
//! versioned by `schemaVersion`, and `packages/sdk` validates a Rust-generated
//! golden report against its zod schema in CI — a field renamed here fails the
//! TypeScript build rather than surfacing as `undefined` in someone's pipeline.

use std::io::Write;

use owlwarden_core::report::Report;
use owlwarden_core::reporter::{ReportError, Reporter};

/// Writes a report as JSON.
pub struct JsonReporter<'w> {
    writer: Box<dyn Write + 'w>,
    pretty: bool,
}

impl<'w> JsonReporter<'w> {
    /// A reporter writing compact JSON — one object, one line.
    #[must_use]
    pub fn new(writer: Box<dyn Write + 'w>) -> Self {
        Self {
            writer,
            pretty: false,
        }
    }

    /// Indented output, for a human reading a saved report or reviewing a diff
    /// of one.
    #[must_use]
    pub fn pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }

    /// Serializes a report to a string.
    ///
    /// # Errors
    /// [`ReportError::Encode`] if serialization fails, which for this model
    /// means a bug rather than bad input.
    pub fn to_string(report: &Report, pretty: bool) -> Result<String, ReportError> {
        let encoded = if pretty {
            serde_json::to_string_pretty(report)
        } else {
            serde_json::to_string(report)
        };
        encoded.map_err(|error| ReportError::Encode {
            format: "json",
            message: error.to_string(),
        })
    }
}

impl Reporter for JsonReporter<'_> {
    fn name(&self) -> &'static str {
        "json"
    }

    fn emit(&mut self, report: &Report) -> Result<(), ReportError> {
        let encoded = Self::to_string(report, self.pretty)?;
        writeln!(self.writer, "{encoded}").map_err(|source| ReportError::Io {
            destination: "stdout".to_owned(),
            source,
        })?;
        self.writer.flush().map_err(|source| ReportError::Io {
            destination: "stdout".to_owned(),
            source,
        })
    }
}
