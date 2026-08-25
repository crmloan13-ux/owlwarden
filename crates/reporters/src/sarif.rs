//! SARIF 2.1.0 reporter — GitHub code scanning and other SARIF consumers.
//!
//! Render only: every field is copied from [`Report`] / [`Finding`]. Severity
//! maps to SARIF `level` per ADR 0017; confidence / OWASP / CWE that levels
//! cannot carry go in `result.properties`.

use std::collections::BTreeMap;
use std::io::Write;

use owlwarden_core::finding::{Finding, Location, Severity};
use owlwarden_core::report::Report;
use owlwarden_core::reporter::{ReportError, Reporter};
use serde_json::{Map, Value, json};

/// Writes a report as SARIF 2.1.0 JSON.
pub struct SarifReporter<'w> {
    writer: Box<dyn Write + 'w>,
}

impl<'w> SarifReporter<'w> {
    /// A reporter writing compact SARIF.
    #[must_use]
    pub fn new(writer: Box<dyn Write + 'w>) -> Self {
        Self { writer }
    }

    /// Serializes a report to a SARIF 2.1.0 document string.
    ///
    /// # Errors
    /// [`ReportError::Encode`] if serialization fails.
    pub fn to_string(report: &Report) -> Result<String, ReportError> {
        let document = build_document(report);
        serde_json::to_string(&document).map_err(|error| ReportError::Encode {
            format: "sarif",
            message: error.to_string(),
        })
    }

    /// Pretty-printed SARIF for saved artifacts.
    ///
    /// # Errors
    /// [`ReportError::Encode`] if serialization fails.
    pub fn to_string_pretty(report: &Report) -> Result<String, ReportError> {
        let document = build_document(report);
        serde_json::to_string_pretty(&document).map_err(|error| ReportError::Encode {
            format: "sarif",
            message: error.to_string(),
        })
    }
}

impl Reporter for SarifReporter<'_> {
    fn name(&self) -> &'static str {
        "sarif"
    }

    fn emit(&mut self, report: &Report) -> Result<(), ReportError> {
        let encoded = Self::to_string(report)?;
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

fn build_document(report: &Report) -> Value {
    let mut rules_by_id: BTreeMap<&str, &Finding> = BTreeMap::new();
    for finding in &report.findings {
        rules_by_id.entry(finding.id.as_str()).or_insert(finding);
    }

    let rules: Vec<Value> = rules_by_id
        .values()
        .map(|finding| {
            let mut rule = Map::new();
            rule.insert("id".into(), json!(finding.id.as_str()));
            rule.insert("name".into(), json!(finding.id.as_str()));
            rule.insert("shortDescription".into(), json!({ "text": finding.title }));
            rule.insert("fullDescription".into(), json!({ "text": finding.why }));
            rule.insert(
                "defaultConfiguration".into(),
                json!({ "level": severity_level(finding.severity) }),
            );
            if let Some(help) = finding.remediation.first().map(|fix| fix.summary.as_str()) {
                rule.insert("help".into(), json!({ "text": help }));
            }
            Value::Object(rule)
        })
        .collect();

    let results: Vec<Value> = report.findings.iter().map(finding_to_result).collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool.name,
                    "version": report.tool.version,
                    "informationUri": "https://github.com/suthat/owlwarden",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}

fn finding_to_result(finding: &Finding) -> Value {
    let mut properties = Map::new();
    properties.insert("confidence".into(), json!(finding.confidence.as_str()));
    properties.insert("severity".into(), json!(finding.severity.as_str()));
    if let Some(owasp) = finding.owasp.as_ref() {
        properties.insert("owasp".into(), json!(owasp.as_str()));
    }
    if let Some(asi) = finding.asi.as_ref() {
        properties.insert("asi".into(), json!(asi.as_str()));
    }
    if let Some(cwe) = finding.cwe {
        properties.insert("cwe".into(), json!(format!("CWE-{cwe}")));
    }
    // `runtimeScope` rides in properties rather than modifying `level`,
    // deliberately. A `template`-scoped finding is not a less severe problem —
    // it is the same problem in a file nothing loads — and encoding that as a
    // lower SARIF level would tell code scanning a different story than the
    // terminal tells the developer.
    if let Some(scope) = finding.runtime_scope {
        properties.insert("runtimeScope".into(), json!(scope.as_str()));
    }
    if let Some(host) = finding.context.host.as_ref() {
        properties.insert("agentHost".into(), json!(host.as_str()));
    }

    let mut result = Map::new();
    result.insert("ruleId".into(), json!(finding.id.as_str()));
    result.insert("level".into(), json!(severity_level(finding.severity)));
    result.insert(
        "message".into(),
        json!({ "text": format!("{}: {}", finding.title, finding.why) }),
    );
    result.insert("properties".into(), Value::Object(properties));

    if let Some(cwe) = finding.cwe {
        result.insert(
            "taxa".into(),
            json!([{
                "id": format!("CWE-{cwe}"),
                "toolComponent": { "name": "CWE" },
            }]),
        );
    }
    result.insert("locations".into(), locations_for(finding));

    Value::Object(result)
}

fn locations_for(finding: &Finding) -> Value {
    match &finding.location {
        Location::Source(source) => {
            let mut region = Map::new();
            region.insert("startLine".into(), json!(source.line));
            region.insert("startColumn".into(), json!(source.col));
            if let Some(snippet) = &finding.snippet {
                region.insert("endLine".into(), json!(snippet.highlight.line));
                region.insert("endColumn".into(), json!(snippet.highlight.end_col));
                if let Some(line_text) = snippet
                    .lines
                    .get(snippet.highlight.line.saturating_sub(snippet.start_line) as usize)
                {
                    region.insert("snippet".into(), json!({ "text": line_text }));
                }
            }
            let physical = json!({
                "artifactLocation": {
                    "uri": source.path,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": Value::Object(region),
            });
            json!([{ "physicalLocation": physical }])
        }
        Location::Endpoint(endpoint) => {
            // URLs come from the live target; strip controls so a hostile
            // Location/header cannot break SARIF consumers or terminal logs.
            let url = strip_controls(&endpoint.url);
            json!([{
                "physicalLocation": {
                    "artifactLocation": { "uri": url },
                },
                "logicalLocations": [{
                    "fullyQualifiedName": format!("{} {}", endpoint.method, url),
                    "kind": "endpoint",
                }],
            }])
        }
    }
}

/// Drops ASCII control characters (including CR/LF) from a SARIF string field.
fn strip_controls(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

const fn severity_level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::{severity_level, strip_controls};
    use owlwarden_core::finding::Severity;

    #[test]
    fn endpoint_uris_do_not_carry_control_characters() {
        assert_eq!(
            strip_controls("https://example.com/\r\nX-Injected: 1"),
            "https://example.com/X-Injected: 1"
        );
    }

    #[test]
    fn severity_mapping_matches_adr_0017() {
        assert_eq!(severity_level(Severity::High), "error");
        assert_eq!(severity_level(Severity::Medium), "warning");
        assert_eq!(severity_level(Severity::Low), "note");
        assert_eq!(severity_level(Severity::Info), "none");
    }
}
