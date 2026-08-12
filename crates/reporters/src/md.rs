//! Markdown reporter — pull-request comments and issue paste.
//!
//! Grouped by severity. Each finding carries the detected-framework fix.
//! Render only: every sentence is a field on [`Finding`]. Extra grouping
//! flags (`--md-group-by`, `--md-collapse`) stay later work.

use std::fmt::Write as _;
use std::io::Write;

use owlwarden_core::finding::{Finding, Location, Severity};
use owlwarden_core::report::Report;
use owlwarden_core::reporter::{ReportError, Reporter};

/// Writes a report as GitHub-flavoured Markdown.
pub struct MdReporter<'w> {
    writer: Box<dyn Write + 'w>,
}

impl<'w> MdReporter<'w> {
    /// A reporter writing Markdown to the given sink.
    #[must_use]
    pub fn new(writer: Box<dyn Write + 'w>) -> Self {
        Self { writer }
    }

    /// Serializes a report to a Markdown string.
    ///
    /// # Errors
    /// Never fails for well-formed reports; the `Result` matches the other
    /// reporters' surface.
    pub fn to_string(report: &Report) -> Result<String, ReportError> {
        Ok(build_markdown(report))
    }
}

impl Reporter for MdReporter<'_> {
    fn name(&self) -> &'static str {
        "md"
    }

    fn emit(&mut self, report: &Report) -> Result<(), ReportError> {
        let encoded = Self::to_string(report)?;
        write!(self.writer, "{encoded}").map_err(|source| ReportError::Io {
            destination: "stdout".to_owned(),
            source,
        })?;
        self.writer.flush().map_err(|source| ReportError::Io {
            destination: "stdout".to_owned(),
            source,
        })
    }
}

fn build_markdown(report: &Report) -> String {
    let mut out =
        String::with_capacity(256usize.saturating_add(report.findings.len().saturating_mul(384)));
    append_heading(&mut out, report);
    if report.findings.is_empty() {
        out.push_str("\nNo findings.\n");
        append_omissions(&mut out, report);
        return out;
    }
    let mut current: Option<Severity> = None;
    for finding in &report.findings {
        if current != Some(finding.severity) {
            current = Some(finding.severity);
            let _ = writeln!(out, "\n## {}\n", severity_heading(finding.severity));
        }
        append_finding(&mut out, finding);
    }
    append_omissions(&mut out, report);
    out
}

fn append_heading(out: &mut String, report: &Report) {
    let project = md_escape(report.target.project.trim_end_matches('/'));
    let _ = writeln!(out, "# owlwarden report — {project}");
    let seconds = report.duration_ms / 1000;
    let millis = report.duration_ms % 1000;
    let _ = writeln!(
        out,
        "_{} files · {seconds}.{millis:03}s · {}_",
        report.target.files_scanned,
        summary_line(&report.summary)
    );
}

fn summary_line(summary: &owlwarden_core::report::ReportSummary) -> String {
    if summary.total() == 0 {
        return "0 findings".to_owned();
    }
    let mut parts = Vec::new();
    push_count(&mut parts, summary.high, "high");
    push_count(&mut parts, summary.medium, "medium");
    push_count(&mut parts, summary.low, "low");
    push_count(&mut parts, summary.info, "info");
    parts.join(" · ")
}

fn push_count(parts: &mut Vec<String>, count: u32, label: &str) {
    if count > 0 {
        parts.push(format!("{count} {label}"));
    }
}

fn severity_heading(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn append_finding(out: &mut String, finding: &Finding) {
    let title = md_escape(&finding.title);
    let mut meta = String::new();
    if let Some(owasp) = finding.owasp.as_ref() {
        let _ = write!(meta, " · {}", md_escape(owasp.as_str()));
    }
    if let Some(cwe) = finding.cwe {
        let _ = write!(meta, " · CWE-{cwe}");
    }
    let _ = writeln!(out, "### {title}{meta}");
    let _ = writeln!(
        out,
        "**Where:** {}{}\n**Confidence:** {}",
        location_line(finding),
        context_suffix(finding),
        finding.confidence.as_str()
    );
    append_snippet(out, finding);
    append_fix(out, finding);
    let why = md_escape(&finding.why);
    let _ = writeln!(out, "**Why it matters:** {why}\n");
}

fn location_line(finding: &Finding) -> String {
    match &finding.location {
        Location::Source(source) => {
            format!(
                "`{}:{}:{}`",
                md_in_ticks(&source.path),
                source.line,
                source.col
            )
        }
        Location::Endpoint(endpoint) => {
            format!(
                "`{} {}`",
                md_in_ticks(&endpoint.method),
                md_in_ticks(&endpoint.url)
            )
        }
    }
}

fn context_suffix(finding: &Finding) -> String {
    let mut bits = Vec::new();
    match (
        finding.context.method.as_deref(),
        finding.context.route.as_deref(),
    ) {
        (Some(method), Some(route)) => bits.push(format!(
            "route `{method} {route}`",
            method = md_in_ticks(method),
            route = md_in_ticks(route)
        )),
        (None, Some(route)) => bits.push(format!("route `{}`", md_in_ticks(route))),
        (Some(method), None) => bits.push(format!("method `{}`", md_in_ticks(method))),
        (None, None) => {}
    }
    if let Some(framework) = finding.context.framework.as_ref() {
        bits.push(md_escape(framework.as_str()));
    }
    if bits.is_empty() {
        String::new()
    } else {
        format!(" ({})", bits.join(", "))
    }
}

fn append_snippet(out: &mut String, finding: &Finding) {
    let Some(frame) = finding.snippet.as_ref() else {
        return;
    };
    let mut body = String::new();
    for (offset, line) in frame.lines.iter().take(8).enumerate() {
        let line_no = frame
            .start_line
            .saturating_add(u32::try_from(offset).unwrap_or(0));
        let marker = if line_no == frame.highlight.line {
            frame
                .highlight
                .label
                .as_deref()
                .map_or(String::from("   // ←"), |label| {
                    format!("   // ← {}", flatten_prose(label))
                })
        } else {
            String::new()
        };
        let _ = writeln!(body, "{line_no:>4}  {}{marker}", flatten_prose(line));
    }
    let fence = code_fence(&body);
    let _ = writeln!(out, "\n{fence}\n{body}{fence}");
}

fn append_fix(out: &mut String, finding: &Finding) {
    let Some(fix) = finding.primary_fix() else {
        return;
    };
    let stack = fix
        .framework
        .as_ref()
        .map_or_else(|| "generic".to_owned(), |id| md_escape(id.as_str()));
    let summary = md_escape(&fix.summary);
    let _ = writeln!(out, "\n**Fix ({stack})** — {summary}");
    let Some(patch) = fix.patch.as_deref() else {
        return;
    };
    let fence = code_fence(patch);
    let _ = writeln!(out, "\n{fence}\n{}\n{fence}", strip_controls(patch));
}

fn append_omissions(out: &mut String, report: &Report) {
    if report.truncated {
        out.push_str(
            "\n> This report is **truncated**. The finding cap was hit; treat it as incomplete, not clean.\n",
        );
    }
    if report.suppressed_count > 0 {
        let _ = writeln!(
            out,
            "\n_{} finding(s) hidden by inline suppressions._",
            report.suppressed_count
        );
    }
    if report.baseline_hidden_count > 0 {
        let _ = writeln!(
            out,
            "\n_{} finding(s) hidden by the baseline._",
            report.baseline_hidden_count
        );
    }
}

fn code_fence(content: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for ch in content.chars() {
        if ch == '`' {
            run = run.saturating_add(1);
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat(longest.saturating_add(1).max(3))
}

/// Escapes Markdown/HTML metacharacters in prose copied from the target.
///
/// Newlines become spaces so a `why` / route / title cannot open a new heading
/// in a PR comment. Control characters are dropped.
fn md_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in flatten_prose(input).chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '*' | '_' | '[' | ']' | '`' => {
                out.push('\\');
                out.push(ch);
            }
            c => out.push(c),
        }
    }
    out
}

fn md_in_ticks(input: &str) -> String {
    flatten_prose(input).replace('`', "'")
}

/// One line of untrusted text: no control chars, no raw newlines.
fn flatten_prose(input: &str) -> String {
    input
        .chars()
        .filter(|c| *c == '\t' || !c.is_control() || *c == '\n' || *c == '\r')
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

fn strip_controls(input: &str) -> String {
    input
        .chars()
        .filter(|c| *c == '\n' || *c == '\t' || !c.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{MdReporter, code_fence, md_escape};
    use owlwarden_core::finding::{
        CodeFrame, Finding, FindingContext, Highlight, Location, RuleId, Severity, SourceLocation,
    };
    use owlwarden_core::report::{Report, ReportSummary, SCHEMA_VERSION, ScanTarget, ToolInfo};

    #[test]
    fn md_escape_neutralises_html_and_emphasis() {
        assert_eq!(md_escape("<b>*x*</b>"), "&lt;b&gt;\\*x\\*&lt;/b&gt;");
    }

    #[test]
    fn md_escape_flattens_newlines_so_they_cannot_open_a_heading() {
        let escaped = md_escape("ok\n\n## injected");
        assert!(!escaped.contains('\n'));
        assert!(escaped.contains("## injected"));
    }

    #[test]
    fn fence_lengthens_when_the_patch_contains_backticks() {
        assert_eq!(code_fence("ok"), "```");
        assert_eq!(code_fence("```js"), "````");
    }

    fn report_with(finding: Finding) -> Report {
        Report {
            schema_version: SCHEMA_VERSION.to_owned(),
            tool: ToolInfo::default(),
            scanned_at: "2026-01-01T00:00:00Z".to_owned(),
            duration_ms: 1,
            target: ScanTarget {
                project: "apps/api".to_owned(),
                ..ScanTarget::default()
            },
            summary: ReportSummary::of(std::slice::from_ref(&finding)),
            findings: vec![finding],
            suppressed_count: 0,
            suppressions: Vec::new(),
            baseline_hidden_count: 0,
            truncated: false,
            errors: Vec::new(),
        }
    }

    #[test]
    fn route_newlines_cannot_open_a_heading() {
        let finding = Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t")
            .why("because")
            .location(Location::Source(SourceLocation {
                path: "app.ts".to_owned(),
                line: 1,
                col: 1,
            }))
            .context(FindingContext {
                route: Some("/x\n\n## pwned".to_owned()),
                method: Some("GET".to_owned()),
                ..FindingContext::default()
            })
            .build();
        let encoded = MdReporter::to_string(&report_with(finding)).unwrap();
        assert!(
            !encoded.contains("\n## pwned"),
            "route must not split the markdown document: {encoded}"
        );
    }

    #[test]
    fn snippet_backticks_cannot_close_the_fence() {
        let finding = Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t")
            .why("because")
            .snippet(CodeFrame {
                path: "app.ts".to_owned(),
                start_line: 1,
                lines: vec!["```".to_owned(), "## pwned".to_owned()],
                highlight: Highlight {
                    line: 1,
                    start_col: 1,
                    end_col: 4,
                    label: None,
                },
            })
            .build();
        let encoded = MdReporter::to_string(&report_with(finding)).unwrap();
        assert!(
            encoded.contains("````"),
            "snippet with ``` must lengthen the fence: {encoded}"
        );
        let after_open = encoded.split_once("````\n").map(|(_, rest)| rest);
        assert!(
            after_open.is_some_and(|rest| rest.contains("## pwned") && rest.contains("````")),
            "pwned line must stay inside the lengthened fence: {encoded}"
        );
    }

    #[test]
    fn why_newlines_cannot_open_a_heading() {
        let finding = Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t")
            .why("real reason\n\n## Security review passed")
            .build();
        let encoded = MdReporter::to_string(&report_with(finding)).unwrap();
        assert!(!encoded.contains("\n## Security review passed"));
    }
}
