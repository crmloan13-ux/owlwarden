//! `csrf-cross-origin-post` — active probe for cross-origin state-changing POSTs.
//!
//! Opt-in only (`--target` + `--allow-active`). Sends one canary POST with an
//! untrusted `Origin` ([ADR 0019](../../../docs/adr/0019-first-party-active-detector.md)).
//! Catalogue / `explain` see [`CsrfCrossOriginPost`]; runtime findings come from
//! [`CsrfCrossOriginPostDetector`].

use std::sync::Arc;

use async_trait::async_trait;
use owlwarden_core::context::ScanContext;
use owlwarden_core::detector::{Capabilities, Detector, DetectorError, DetectorKind, DetectorMeta};
use owlwarden_core::finding::{
    Confidence, EndpointLocation, Finding, FindingContext, Framework, Location, OwaspRef,
    Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::transport::{BoundedRequest, Method};
use owlwarden_static::rule::RuleInfo;

use crate::SUPPORTED_FRAMEWORKS;
use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "csrf-cross-origin-post";

/// Fixed Origin used for the probe — never taken from the repository.
pub const PROBE_ORIGIN: &str = "https://owlwarden-untrusted.invalid";

/// Fixed canary body. Documented; not attacker-controlled.
pub const PROBE_BODY: &str = "owlwarden_probe=1";

/// Catalogue / explain / coverage entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct CsrfCrossOriginPost;

impl CsrfCrossOriginPost {
    /// Metadata shared with the runtime detector.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Endpoint accepted a cross-origin state-changing POST".into(),
            severity: Severity::High,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A01:2021")),
            cwe: Some(352),
            category: "csrf".into(),
            description: "With `--allow-active`, owlwarden POSTs a canary body to `--target` \
                          using Origin https://owlwarden-untrusted.invalid. A 2xx response means \
                          the route accepted a cross-origin state-changing request — the classic \
                          CSRF shape on cookie-session apps. Requires staging you control; the \
                          canary may still create a resource if the route is a create endpoint."
                .into(),
        }
    }
}

impl RuleInfo for CsrfCrossOriginPost {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

/// Runtime active detector aimed at one probe URL.
#[derive(Debug, Clone)]
pub struct CsrfCrossOriginPostDetector {
    url: String,
    path: String,
}

/// Builds the active detector for `--allow-active` against `url`.
#[must_use]
pub fn csrf_cross_origin_post_detector(
    url: impl Into<String>,
    path: impl Into<String>,
) -> Arc<dyn Detector> {
    Arc::new(CsrfCrossOriginPostDetector {
        url: url.into(),
        path: path.into(),
    })
}

#[async_trait]
impl Detector for CsrfCrossOriginPostDetector {
    fn meta(&self) -> DetectorMeta {
        CsrfCrossOriginPost::meta()
    }

    fn kind(&self) -> DetectorKind {
        DetectorKind::Dynamic
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::active_network()
    }

    async fn run(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        if !ctx.settings().allow_active {
            return Ok(Vec::new());
        }
        let transport = ctx
            .transport()
            .ok_or_else(|| DetectorError::MissingCapability {
                id: self.meta().id,
                capability: "network",
            })?;

        let mut request = BoundedRequest::get(&self.url);
        request.method = Method::Post;
        request.headers = vec![
            ("origin".to_owned(), PROBE_ORIGIN.to_owned()),
            (
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            ),
        ];
        request.body = Some(PROBE_BODY.as_bytes().to_vec());
        // One small response is enough; do not buffer an HTML dump.
        request.limits.max_body_bytes = 4 * 1024;

        let response = transport.send(request).await?;
        if !(200..300).contains(&response.status) {
            return Ok(Vec::new());
        }

        let fixes = remediation().select(&Framework::GENERIC);
        Ok(vec![finding_builder(&self.meta())
            .confidence(Confidence::Likely)
            .why(
                "The live target returned 2xx for a POST that carried an untrusted Origin and a \
                 canary form body. Cookie-session apps that accept that shape are CSRF-vulnerable \
                 unless a synchronizer token (or equivalent) rejected the request. Token-auth JSON \
                 APIs can also return 2xx — treat staging results as a lead, not proof."
                    .to_owned(),
            )
            .location(Location::Endpoint(EndpointLocation {
                url: self.url.clone(),
                method: "POST".to_owned(),
            }))
            .context(FindingContext {
                framework: None,
                route: Some(self.path.clone()),
                method: Some("POST".to_owned()),
                evidence: Some(format!(
                    "POST {} → {} (Origin: {PROBE_ORIGIN}; body: {PROBE_BODY})",
                    self.url, response.status
                )),
            })
            .fixes(fixes)
            .reference(Reference::rule_page(&self.meta().id))
            .build()])
    }
}

fn remediation() -> Remediation {
    let summary = "Require a CSRF synchroniser token (or SameSite=Strict session cookies plus \
                   Origin checks) before accepting state-changing requests from browsers.";
    let patch = "// Reject cross-site state-changing requests without a CSRF token.\n\
         // Example (Express):\n\
         // app.use(csrfProtection)\n\
         // Or set session cookies with SameSite=Strict / Lax and verify Origin.";
    Remediation::new(summary)
        .generic_patch(patch)
        .manual_each(SUPPORTED_FRAMEWORKS, summary, patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_constants_are_fixed_canaries() {
        assert!(PROBE_ORIGIN.contains("owlwarden-untrusted"));
        assert_eq!(PROBE_BODY, "owlwarden_probe=1");
    }

    #[test]
    fn declares_active_network_capability() {
        let detector = CsrfCrossOriginPostDetector {
            url: "http://127.0.0.1:9/".into(),
            path: "/".into(),
        };
        let caps = detector.capabilities();
        assert!(caps.network);
        assert!(caps.active);
        assert!(!caps.source);
    }
}
