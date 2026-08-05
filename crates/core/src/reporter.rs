//! The `Reporter` port: turning a [`Report`] into output.
//!
//! A reporter **renders**; it never re-derives. If the terminal shows a reason
//! the JSON does not carry, the two formats have already drifted. Anything a
//! reporter needs is a field on the finding.

use crate::report::Report;

/// Renders a report to some destination.
pub trait Reporter {
    /// The name used by `--format` and in config, e.g. `"pretty"`.
    fn name(&self) -> &'static str;

    /// Writes the report.
    ///
    /// # Errors
    /// [`ReportError`] if the destination could not be written or the report
    /// could not be encoded.
    fn emit(&mut self, report: &Report) -> Result<(), ReportError>;
}

/// Failure rendering or writing a report.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// The destination could not be written.
    #[error("failed to write report to {destination}: {source}")]
    Io {
        /// Where we were writing: a path, or `stdout`/`stderr`.
        destination: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The report could not be encoded in this format.
    #[error("failed to encode report as {format}: {message}")]
    Encode {
        /// Format name.
        format: &'static str,
        /// Encoder message.
        message: String,
    },

    /// `--format` named something we do not have.
    #[error("unknown reporter {name:?}; available: {available}")]
    UnknownFormat {
        /// Name the user asked for.
        name: String,
        /// Comma-separated list of names that do exist.
        available: String,
    },
}
