//! Passive probe for missing security response headers.
//!
//! Shares the header list and rule id with the static
//! `security-headers-missing` rule so correlation can match them
//! ([ADR 0014](../../../docs/adr/0014-passive-dynamic-and-correlation.md)).

use owlwarden_core::ScanContext;
use owlwarden_core::detector::DetectorError;
use owlwarden_core::finding::{
    Confidence, EndpointLocation, Finding, FindingContext, Framework, Location, Reference,
};
use owlwarden_core::transport::{BoundedRequest, Method};
use owlwarden_detectors::build::finding_builder;
use owlwarden_detectors::security_headers::{REQUIRED_HEADERS, SecurityHeadersMissing};
use owlwarden_static::rule::RuleInfo;

use crate::engine::ProbeTarget;

/// Evidence string when the live response sets every required header.
pub const HEADERS_PRESENT_EVIDENCE: &str = "runtime: security headers present";

/// Probes `target` once (HEAD, then GET on 405/501) and reports what it saw.
///
/// # Errors
/// [`DetectorError::Transport`] when the exchange fails.
/// [`DetectorError::MissingCapability`] when this run has no transport.
pub async fn probe_security_headers(
    ctx: &ScanContext<'_>,
    target: &ProbeTarget,
) -> Result<Vec<Finding>, DetectorError> {
    let meta = SecurityHeadersMissing.meta();
    let transport = ctx
        .transport()
        .ok_or_else(|| DetectorError::MissingCapability {
            id: meta.id.clone(),
            capability: "network",
        })?;

    let url = target.url.clone();
    let mut request = BoundedRequest::get(&url);
    request.method = Method::Head;
    // Headers-only: do not retain a body even if the server sends one.
    request.limits.max_body_bytes = 0;

    let mut response = transport.send(request).await?;
    let mut method_used = "HEAD";
    if matches!(response.status, 405 | 501) {
        let mut fallback = BoundedRequest::get(&url);
        fallback.limits.max_body_bytes = 0;
        response = transport.send(fallback).await?;
        method_used = "GET";
    }

    let missing: Vec<&str> = REQUIRED_HEADERS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| response.header(name).is_none())
        .collect();

    if missing.is_empty() {
        return Ok(vec![observed_finding(
            &url,
            method_used,
            &target.path,
            HEADERS_PRESENT_EVIDENCE.to_owned(),
            "The live response sets the baseline security headers.".to_owned(),
        )]);
    }

    Ok(vec![observed_finding(
        &url,
        method_used,
        &target.path,
        format!("runtime observed; missing: {}", missing.join(", ")),
        format!("The live response is missing: {}.", missing.join(", ")),
    )])
}

fn observed_finding(url: &str, method: &str, path: &str, evidence: String, why: String) -> Finding {
    let meta = SecurityHeadersMissing.meta();
    let fixes = SecurityHeadersMissing
        .remediation()
        .select(&Framework::GENERIC);

    finding_builder(&meta)
        .confidence(Confidence::Likely)
        .why(why)
        .location(Location::Endpoint(EndpointLocation {
            url: url.to_owned(),
            method: method.to_owned(),
        }))
        .context(FindingContext {
            framework: None,
            host: None,
            route: Some(path.to_owned()),
            method: Some(method.to_owned()),
            evidence: Some(evidence),
        })
        .fixes(fixes)
        .reference(Reference::rule_page(&meta.id))
        .build()
}
