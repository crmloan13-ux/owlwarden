//! `JUnit` XML reporter — CI UIs that already render test suites.
//!
//! One `<testcase>` per finding. Failures describe the finding; this format
//! never redefines the CLI exit code (ADR 0017).

use std::fmt::Write as _;
use std::io::Write;

use owlwarden_core::finding::{Finding, Location};
use owlwarden_core::report::Report;
use owlwarden_core::reporter::{ReportError, Reporter};

/// Writes a report as `JUnit` XML.
pub struct JunitReporter<'w> {
    writer: Box<dyn Write + 'w>,
}

impl<'w> JunitReporter<'w> {
    /// A reporter writing `JUnit` XML to the given sink.
    #[must_use]
    pub fn new(writer: Box<dyn Write + 'w>) -> Self {
        Self { writer }
    }

    /// Serializes a report to a `JUnit` XML string.
    ///
    /// # Errors
    /// Never fails for well-formed reports; the `Result` matches the other
    /// reporters' surface.
    pub fn to_string(report: &Report) -> Result<String, ReportError> {
        Ok(build_xml(report))
    }
}

impl Reporter for JunitReporter<'_> {
    fn name(&self) -> &'static str {
        "junit"
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

fn build_xml(report: &Report) -> String {
    let mut out =
        String::with_capacity(256usize.saturating_add(report.findings.len().saturating_mul(256)));
    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    out.push('\n');

    let failures = report.findings.len();
    // A clean scan is one passing case so CI UIs show a green suite rather than
    // an empty one that looks like "nothing ran".
    let tests = if failures == 0 { 1 } else { failures };
    let name = xml_escape(&format!(
        "owlwarden:{}",
        report.target.project.trim_end_matches('/')
    ));
    let seconds = report.duration_ms / 1000;
    let millis = report.duration_ms % 1000;
    let _ = write!(
        out,
        r#"<testsuite name="{name}" tests="{tests}" failures="{failures}" errors="0" skipped="0" time="{seconds}.{millis:03}">"#
    );
    out.push('\n');

    if report.findings.is_empty() {
        out.push_str(r#"  <testcase classname="owlwarden" name="no findings" time="0"/>"#);
        out.push('\n');
    } else {
        for finding in &report.findings {
            append_testcase(&mut out, finding);
        }
    }

    out.push_str("</testsuite>\n");
    out
}

fn append_testcase(out: &mut String, finding: &Finding) {
    let classname = xml_escape(finding.id.as_str());
    let name = xml_escape(&testcase_name(finding));
    let _ = write!(
        out,
        r#"  <testcase classname="{classname}" name="{name}" time="0">"#
    );
    out.push('\n');

    let message = xml_escape(&format!(
        "[{}] {} ({})",
        finding.severity.as_str(),
        finding.title,
        finding.confidence.as_str()
    ));
    let body = xml_escape(&failure_body(finding));
    let _ = write!(
        out,
        r#"    <failure type="{classname}" message="{message}">{body}</failure>"#
    );
    out.push('\n');
    out.push_str("  </testcase>\n");
}

fn testcase_name(finding: &Finding) -> String {
    match &finding.location {
        Location::Source(source) => {
            format!("{}:{}:{}", source.path, source.line, source.col)
        }
        Location::Endpoint(endpoint) => {
            format!("{} {}", endpoint.method, endpoint.url)
        }
    }
}

fn failure_body(finding: &Finding) -> String {
    let mut body = finding.why.clone();
    if let Some(owasp) = finding.owasp.as_ref() {
        body.push_str("\nOWASP: ");
        body.push_str(owasp.as_str());
    }
    if let Some(cwe) = finding.cwe {
        let _ = write!(body, "\nCWE-{cwe}");
    }
    if let Some(fix) = finding.remediation.first() {
        body.push_str("\nFix: ");
        body.push_str(&fix.summary);
    }
    body
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::xml_escape;

    #[test]
    fn xml_escape_covers_the_five_entities() {
        assert_eq!(
            xml_escape(r#"a&b<c>d"e'f"#),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }
}
