//! Correlation: raise agreeing static+dynamic findings to `Confirmed`.
//!
//! Pure over a finished finding list — detectors run in parallel and cannot
//! see each other, so this is a post-pass
//! ([ADR 0014](../../../docs/adr/0014-passive-dynamic-and-correlation.md)).

use owlwarden_core::finding::{Confidence, Finding, Location};
use owlwarden_detectors::security_headers::{
    SecurityHeadersMissing, missing_headers_from_evidence,
};

use crate::headers::HEADERS_PRESENT_EVIDENCE;

/// Correlates static and dynamic observations of the same rule.
///
/// For `security-headers-missing`:
/// - both report overlapping missing headers → keep the source finding at
///   [`Confidence::Confirmed`], drop the endpoint duplicate;
/// - dynamic saw the headers present → drop the static finding (infrastructure
///   was covering it) and drop the "present" observation;
/// - dynamic-only missing → keep the endpoint finding at `Likely`;
/// - static-only → unchanged.
#[must_use]
pub fn correlate(findings: Vec<Finding>) -> Vec<Finding> {
    let rule = SecurityHeadersMissing::meta().id;
    let (headers, mut rest): (Vec<_>, Vec<_>) =
        findings.into_iter().partition(|finding| finding.id == rule);

    if headers.is_empty() {
        return rest;
    }

    let mut static_findings = Vec::new();
    let mut dynamic_missing: Vec<Finding> = Vec::new();
    let mut dynamic_present = false;

    for finding in headers {
        match &finding.location {
            Location::Source(_) => static_findings.push(finding),
            Location::Endpoint(_) => {
                let evidence = finding.context.evidence.as_deref().unwrap_or("");
                if evidence == HEADERS_PRESENT_EVIDENCE {
                    dynamic_present = true;
                } else {
                    dynamic_missing.push(finding);
                }
            }
        }
    }

    if dynamic_present {
        // Runtime has the headers. Static was looking at source alone and
        // could not see the CDN/ingress — drop both sides so we do not report
        // a problem the live target does not have.
        rest.sort_by(Finding::cmp_for_report);
        return rest;
    }

    if dynamic_missing.is_empty() {
        rest.extend(static_findings);
        rest.sort_by(Finding::cmp_for_report);
        return rest;
    }

    // One probe today; take the first dynamic observation.
    let Some(dynamic) = dynamic_missing.into_iter().next() else {
        rest.extend(static_findings);
        rest.sort_by(Finding::cmp_for_report);
        return rest;
    };
    let dynamic_missing_headers = dynamic
        .context
        .evidence
        .as_deref()
        .map(missing_headers_from_evidence)
        .unwrap_or_default();
    let probed_url = match &dynamic.location {
        Location::Endpoint(endpoint) => endpoint.url.clone(),
        Location::Source(_) => String::new(),
    };

    if static_findings.is_empty() {
        rest.push(dynamic);
        rest.sort_by(Finding::cmp_for_report);
        return rest;
    }

    let mut confirmed_any = false;
    for mut finding in static_findings {
        let static_missing = finding
            .context
            .evidence
            .as_deref()
            .map(missing_headers_from_evidence)
            .unwrap_or_default();
        let overlap = static_missing
            .iter()
            .any(|header| dynamic_missing_headers.iter().any(|other| other == header));
        if overlap {
            finding.confidence = Confidence::Confirmed;
            let note = format!("confirmed at runtime ({probed_url})");
            finding.context.evidence = Some(match finding.context.evidence.take() {
                Some(existing) => format!("{existing}; {note}"),
                None => note,
            });
            confirmed_any = true;
        }
        rest.push(finding);
    }

    if !confirmed_any {
        // Static and dynamic disagreed on *which* headers — keep both so a
        // human can judge, rather than inventing agreement.
        rest.push(dynamic);
    }

    rest.sort_by(Finding::cmp_for_report);
    rest
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use owlwarden_core::finding::{
        Confidence, EndpointLocation, Finding, FindingContext, Location, RuleId, Severity,
        SourceLocation,
    };

    use super::*;
    use crate::headers::HEADERS_PRESENT_EVIDENCE;

    fn source_finding(evidence: &str, confidence: Confidence) -> Finding {
        Finding::builder(
            RuleId::new_static("security-headers-missing"),
            Severity::Medium,
            "Security headers are not configured",
        )
        .confidence(confidence)
        .why("why")
        .location(Location::Source(SourceLocation {
            path: "next.config.js".into(),
            line: 1,
            col: 1,
        }))
        .context(FindingContext {
            evidence: Some(evidence.into()),
            ..FindingContext::default()
        })
        .build()
    }

    fn endpoint_finding(evidence: &str) -> Finding {
        Finding::builder(
            RuleId::new_static("security-headers-missing"),
            Severity::Medium,
            "Security headers are not configured",
        )
        .confidence(Confidence::Likely)
        .why("why")
        .location(Location::Endpoint(EndpointLocation {
            url: "http://127.0.0.1:3000/".into(),
            method: "HEAD".into(),
        }))
        .context(FindingContext {
            evidence: Some(evidence.into()),
            ..FindingContext::default()
        })
        .build()
    }

    #[test]
    fn overlapping_missing_headers_become_confirmed() {
        let out = correlate(vec![
            source_finding(
                "no header configuration found; missing: content-security-policy, x-frame-options",
                Confidence::Possible,
            ),
            endpoint_finding(
                "runtime observed; missing: content-security-policy, strict-transport-security",
            ),
        ]);
        assert_eq!(out.len(), 1);
        let finding = out.first().expect("len checked");
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert!(finding.location.as_source().is_some());
        assert!(
            finding
                .context
                .evidence
                .as_deref()
                .unwrap()
                .contains("confirmed at runtime")
        );
    }

    #[test]
    fn runtime_present_clears_static_finding() {
        let out = correlate(vec![
            source_finding(
                "no header configuration found; missing: content-security-policy",
                Confidence::Possible,
            ),
            endpoint_finding(HEADERS_PRESENT_EVIDENCE),
        ]);
        assert!(out.is_empty());
    }

    #[test]
    fn dynamic_only_stays_likely() {
        let out = correlate(vec![endpoint_finding(
            "runtime observed; missing: content-security-policy",
        )]);
        assert_eq!(out.len(), 1);
        let finding = out.first().expect("len checked");
        assert_eq!(finding.confidence, Confidence::Likely);
        assert!(matches!(finding.location, Location::Endpoint(_)));
    }

    #[test]
    fn unrelated_findings_pass_through() {
        let other = Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t")
            .confidence(Confidence::Likely)
            .why("w")
            .location(Location::Source(SourceLocation {
                path: "a.ts".into(),
                line: 1,
                col: 1,
            }))
            .build();
        let out = correlate(vec![other.clone()]);
        assert_eq!(out, vec![other]);
    }

    #[test]
    fn disagreeing_header_sets_keep_both_rather_than_inventing_agreement() {
        let out = correlate(vec![
            source_finding(
                "no header configuration found; missing: content-security-policy",
                Confidence::Possible,
            ),
            endpoint_finding("runtime observed; missing: x-frame-options"),
        ]);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|f| f.location.as_source().is_some()));
        assert!(
            out.iter()
                .any(|f| matches!(f.location, Location::Endpoint(_)))
        );
        assert!(out.iter().all(|f| f.confidence != Confidence::Confirmed));
    }

    #[test]
    fn static_only_is_unchanged() {
        let out = correlate(vec![source_finding(
            "no header configuration found; missing: content-security-policy",
            Confidence::Possible,
        )]);
        assert_eq!(out.len(), 1);
        assert_eq!(out.first().expect("len").confidence, Confidence::Possible);
    }

    #[test]
    fn present_marker_must_match_exactly() {
        // A crafted evidence string that merely contains the marker must not
        // clear static findings — only the exact sentinel from our probe.
        let out = correlate(vec![
            source_finding(
                "no header configuration found; missing: content-security-policy",
                Confidence::Possible,
            ),
            endpoint_finding(&format!("note: {HEADERS_PRESENT_EVIDENCE} (spoofed)")),
        ]);
        assert_eq!(out.len(), 2);
    }
}
