//! The `pretty` reporter — the one a human reads.
//!
//! Goal, in order: read once, understand, fix. The layout follows the Rust
//! compiler and miette diagnostic style, because that is a format working
//! developers already know how to read.
//!
//! ```text
//! ──────────────────────────────────────────────────────
//! HIGH  likely  Stack trace leaked in error response  A05:2021
//! ──────────────────────────────────────────────────────
//!  app/api/users/route.ts:13
//!
//!   11 │   } catch (err) {
//!   12 │     return NextResponse.json(
//!   13 │       { error: err.stack },
//!      │                ~~~~~~~~~ leaks internal stack trace to the client
//!   14 │       { status: 500 }
//!
//!  ↳ fix (Next.js)  Return a generic message; log the error server-side.
//!  ↳ why            Stack traces expose absolute file paths…
//!  ⓘ ref            A05:2021 · CWE-209 · RULES.md#stack-trace-leak
//! ```

use std::io::Write;

use owlwarden_core::finding::{CodeFrame, Finding, ReferenceKind, Severity};
use owlwarden_core::report::Report;
use owlwarden_core::reporter::{ReportError, Reporter};

use crate::theme::{Glyphs, bold, confidence_style, dim, severity_style, underline_style};

/// Width of the horizontal rules. Fixed rather than terminal-width so output
/// diffs cleanly between machines and inside CI logs.
const RULE_WIDTH: usize = 72;

/// Label column width for the `fix` / `why` / `ref` lines.
const LABEL_WIDTH: usize = 15;

/// Width reserved for the `↳` / `ⓘ` marker, so both glyph sets line up.
const MARKER_WIDTH: usize = 2;

/// How the pretty reporter should render.
#[derive(Debug, Clone, Copy)]
pub struct PrettyOptions {
    /// Emit ANSI styling. Resolved by the caller from TTY detection,
    /// `NO_COLOR`, and `--no-color`.
    pub color: bool,
    /// Use box-drawing characters. `--ascii` turns this off.
    pub unicode: bool,
    /// Emit OSC-8 hyperlinks for paths and references.
    ///
    /// Off by default: terminal support cannot be detected reliably, and a
    /// terminal that does not understand the escape prints it as garbage in the
    /// middle of a security report. Opt in with `--hyperlinks`.
    pub hyperlinks: bool,
}

impl Default for PrettyOptions {
    fn default() -> Self {
        Self {
            color: true,
            unicode: true,
            hyperlinks: false,
        }
    }
}

/// Renders a report for a human.
pub struct PrettyReporter<'w> {
    writer: Box<dyn Write + 'w>,
    options: PrettyOptions,
}

impl<'w> PrettyReporter<'w> {
    /// Builds a reporter.
    #[must_use]
    pub fn new(writer: Box<dyn Write + 'w>, options: PrettyOptions) -> Self {
        Self { writer, options }
    }

    fn glyphs(&self) -> Glyphs {
        Glyphs::for_unicode(self.options.unicode)
    }

    /// Applies a style, or returns the text unchanged when colour is off.
    fn paint(&self, style: anstyle::Style, text: &str) -> String {
        if self.options.color {
            format!("{style}{text}{style:#}")
        } else {
            text.to_owned()
        }
    }

    /// Wraps text in an OSC-8 hyperlink when enabled.
    fn link(&self, url: &str, text: &str) -> String {
        if self.options.hyperlinks {
            format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
        } else {
            text.to_owned()
        }
    }

    /// The severity counts, printed before any detail so the reader knows the
    /// size of the problem before reading about it.
    fn write_summary(&mut self, report: &Report) -> std::io::Result<()> {
        let summary = report.summary;
        let glyphs = self.glyphs();

        let header = format!(
            "{} {} files · {} · {}.{:02}s",
            crate::banner::owl_mark(self.options.unicode),
            report.target.files_scanned,
            report.target.preset,
            report.duration_ms / 1000,
            (report.duration_ms % 1000) / 10,
        );
        writeln!(self.writer, "\n{}", self.paint(dim(), &header))?;

        if summary.total() == 0 {
            let clean = self.paint(bold(), "No findings.");
            writeln!(self.writer, "{clean}")?;
            return Ok(());
        }

        let counts = [
            (Severity::High, summary.high),
            (Severity::Medium, summary.medium),
            (Severity::Low, summary.low),
            (Severity::Info, summary.info),
        ];
        let rendered: Vec<String> = counts
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(severity, count)| {
                let label = format!("{count} {}", severity.as_str());
                self.paint(severity_style(*severity), &label)
            })
            .collect();

        writeln!(
            self.writer,
            "{} {}\n",
            self.paint(bold(), &format!("{} findings", summary.total())),
            self.paint(dim(), &format!("({})", rendered.join(", ")))
        )?;
        let _ = glyphs;
        Ok(())
    }

    /// One finding: heading, location, code frame, fix, why, references.
    fn write_finding(&mut self, finding: &Finding) -> std::io::Result<()> {
        let glyphs = self.glyphs();
        let rule: String = std::iter::repeat_n(glyphs.rule, RULE_WIDTH).collect();

        writeln!(self.writer, "{}", self.paint(dim(), &rule))?;

        let severity = self.paint(
            severity_style(finding.severity),
            &finding.severity.as_str().to_uppercase(),
        );
        let confidence = self.paint(
            confidence_style(finding.confidence),
            finding.confidence.as_str(),
        );
        let category = finding
            .owasp
            .as_ref()
            .map(|owasp| self.paint(dim(), owasp.as_str()))
            .unwrap_or_default();
        writeln!(
            self.writer,
            "{severity}  {confidence}  {}  {category}",
            self.paint(bold(), &finding.title)
        )?;
        writeln!(self.writer, "{}", self.paint(dim(), &rule))?;

        self.write_location(finding)?;
        if let Some(frame) = &finding.snippet {
            self.write_frame(frame)?;
        }
        self.write_advice(finding)?;
        writeln!(self.writer)
    }

    fn write_location(&mut self, finding: &Finding) -> std::io::Result<()> {
        let text = match &finding.location {
            owlwarden_core::finding::Location::Source(location) => {
                let position = format!("{}:{}:{}", location.path, location.line, location.col);
                match &finding.context.route {
                    Some(route) => {
                        let method = finding.context.method.as_deref().unwrap_or("").trim();
                        format!("{position}  ({method} {route})")
                    }
                    None => position,
                }
            }
            owlwarden_core::finding::Location::Endpoint(location) => {
                format!("{} {}", location.method, location.url)
            }
        };
        let linked = self.link(&format!("file://{text}"), &text);
        writeln!(self.writer, " {}\n", self.paint(bold(), &linked))
    }

    /// The code frame, with the offending span underlined.
    fn write_frame(&mut self, frame: &CodeFrame) -> std::io::Result<()> {
        let glyphs = self.glyphs();
        let last_line = frame.start_line as usize + frame.lines.len();
        let gutter_width = last_line.to_string().len();

        for (offset, text) in frame.lines.iter().enumerate() {
            let number = frame.start_line as usize + offset;
            let is_highlighted = number == frame.highlight.line as usize;

            let gutter = format!("{number:>gutter_width$} {}", glyphs.gutter);
            let source = if is_highlighted {
                text.clone()
            } else {
                self.paint(dim(), text)
            };
            writeln!(self.writer, "  {} {source}", self.paint(dim(), &gutter))?;

            if is_highlighted {
                self.write_underline(text, frame, gutter_width)?;
            }
        }
        writeln!(self.writer)
    }

    /// The `~~~` run and its message, aligned under the span.
    ///
    /// Leading whitespace is copied from the source line rather than replaced
    /// with spaces, so a tab-indented file still lines up in the reader's
    /// terminal whatever their tab width is.
    fn write_underline(
        &mut self,
        line: &str,
        frame: &CodeFrame,
        gutter_width: usize,
    ) -> std::io::Result<()> {
        let glyphs = self.glyphs();
        let start = frame.highlight.start_col.saturating_sub(1) as usize;
        let end = frame.highlight.end_col.saturating_sub(1) as usize;
        let width = end.saturating_sub(start).max(1);

        let mut padding: String = line
            .chars()
            .take(start)
            .map(|ch| if ch == '\t' { '\t' } else { ' ' })
            .collect();
        // The span can start past the end of a line we truncated for display.
        let missing = start.saturating_sub(padding.chars().count());
        padding.push_str(&" ".repeat(missing));

        let marks: String = std::iter::repeat_n(glyphs.underline, width).collect();
        let message = frame
            .highlight
            .label
            .as_deref()
            .map(|label| format!(" {label}"))
            .unwrap_or_default();

        let gutter = format!("{:>gutter_width$} {}", "", glyphs.gutter);
        writeln!(
            self.writer,
            "  {} {padding}{}",
            self.paint(dim(), &gutter),
            self.paint(underline_style(), &format!("{marks}{message}"))
        )
    }

    /// Fix, rationale, references.
    fn write_advice(&mut self, finding: &Finding) -> std::io::Result<()> {
        let glyphs = self.glyphs();

        if let Some(fix) = finding.primary_fix() {
            let label = fix
                .framework
                .as_ref()
                .map_or_else(|| "fix".to_owned(), |fw| format!("fix ({fw})"));
            self.write_labelled(glyphs.arrow, &label, &fix.summary)?;

            if let Some(patch) = &fix.patch {
                let indent = " ".repeat(1 + MARKER_WIDTH + 1 + LABEL_WIDTH);
                for line in patch.lines() {
                    writeln!(self.writer, "{indent}{}", self.paint(dim(), line))?;
                }
            }
        }

        if !finding.why.is_empty() {
            self.write_labelled(glyphs.arrow, "why", &finding.why)?;
        }

        if !finding.references.is_empty() {
            let separator = if self.options.unicode { " · " } else { " | " };
            let joined = finding
                .references
                .iter()
                .map(|reference| {
                    let label = match reference.kind {
                        ReferenceKind::Owasp => format!("OWASP {}", reference.id),
                        ReferenceKind::Cwe | ReferenceKind::Docs => reference.id.clone(),
                    };
                    self.link(&reference.url, &label)
                })
                .collect::<Vec<_>>()
                .join(separator);
            self.write_labelled(glyphs.info, "ref", &joined)?;
        }
        Ok(())
    }

    /// `↳ label   text`, wrapped under a hanging indent.
    ///
    /// The marker is padded to a fixed width so the Unicode and ASCII glyph
    /// sets produce the same column layout — otherwise `->` and `i` would start
    /// their labels one column apart in the same report.
    fn write_labelled(&mut self, marker: &str, label: &str, text: &str) -> std::io::Result<()> {
        let indent = 1 + MARKER_WIDTH + 1 + LABEL_WIDTH;
        let head = format!("{marker:<MARKER_WIDTH$} {label:<LABEL_WIDTH$}");
        writeln!(
            self.writer,
            " {}{}",
            self.paint(dim(), &head),
            wrap(text, RULE_WIDTH.saturating_sub(indent), indent)
        )
    }

    /// The closing line: what to do next.
    fn write_footer(&mut self, report: &Report) -> std::io::Result<()> {
        if let Some(first) = report.findings.first() {
            let hint = format!(
                "Run `owlwarden explain {}` for the full write-up.",
                first.id
            );
            writeln!(self.writer, "{}", self.paint(dim(), &hint))?;
        }
        if report.suppressed_count > 0 {
            let note = format!(
                "{} finding(s) hidden by inline suppressions — review them with --report-suppressions.",
                report.suppressed_count
            );
            writeln!(self.writer, "{}", self.paint(dim(), &note))?;
        }
        if report.truncated {
            writeln!(
                self.writer,
                "{}",
                self.paint(
                    bold(),
                    "Report truncated: the findings limit was reached. This is not a clean scan."
                )
            )?;
        }
        for error in &report.errors {
            let note = format!("! {} — {}", error.rule, error.message);
            writeln!(self.writer, "{}", self.paint(dim(), &note))?;
        }
        Ok(())
    }
}

/// Renders a report to a string.
///
/// Used by snapshot tests and by the napi bridge, which hands the rendered text
/// back to the TypeScript CLI rather than duplicating the layout there.
///
/// # Errors
/// [`ReportError`] if the rendered bytes are not valid UTF-8, which would mean
/// a bug in this module rather than bad input.
pub fn render_to_string(report: &Report, options: PrettyOptions) -> Result<String, ReportError> {
    let mut buffer: Vec<u8> = Vec::new();
    PrettyReporter::new(Box::new(&mut buffer), options).emit(report)?;
    String::from_utf8(buffer).map_err(|error| ReportError::Encode {
        format: "pretty",
        message: error.to_string(),
    })
}

/// Soft-wraps text at word boundaries and indents continuation lines.
///
/// A one-line `why` that runs to 300 columns is unreadable in a terminal and
/// unreviewable in a CI log. Words longer than the width (a URL, usually) are
/// left intact rather than broken — a split URL is worse than a long line.
fn wrap(text: &str, width: usize, indent: usize) -> String {
    let padding = " ".repeat(indent);
    let width = width.max(20);

    let mut out = String::new();
    for (index, paragraph) in text.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
            out.push_str(&padding);
        }
        let mut column = 0usize;
        for (position, word) in paragraph.split_whitespace().enumerate() {
            let length = word.chars().count();
            if position > 0 {
                if column + 1 + length > width {
                    out.push('\n');
                    out.push_str(&padding);
                    column = 0;
                } else {
                    out.push(' ');
                    column += 1;
                }
            }
            out.push_str(word);
            column += length;
        }
    }
    out
}

impl Reporter for PrettyReporter<'_> {
    fn name(&self) -> &'static str {
        "pretty"
    }

    fn emit(&mut self, report: &Report) -> Result<(), ReportError> {
        let io = |source| ReportError::Io {
            destination: "stdout".to_owned(),
            source,
        };

        self.write_summary(report).map_err(io)?;
        for finding in &report.findings {
            self.write_finding(finding).map_err(io)?;
        }
        self.write_footer(report).map_err(io)?;
        self.writer.flush().map_err(io)
    }
}
