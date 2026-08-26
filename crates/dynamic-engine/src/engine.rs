//! The dynamic engine: one [`Detector`] that runs passive probes.

use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use owlwarden_core::ScanContext;
use owlwarden_core::detector::{Capabilities, Detector, DetectorError, DetectorKind, DetectorMeta};
use owlwarden_core::finding::{Confidence, Finding, RuleId, Severity};
use owlwarden_core::scope::Target;
use owlwarden_core::surface::Surface;

use crate::headers;

/// A validated absolute URL to probe.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    /// Absolute URL string passed to the transport.
    pub url: String,
    /// Path component, for finding context.
    pub path: String,
}

impl ProbeTarget {
    /// Builds a probe target from a parsed [`Target`].
    ///
    /// Uses the target's origin + path (query/fragment dropped on purpose —
    /// they are not part of scope matching and must not affect which route we
    /// claim to have probed).
    #[must_use]
    pub fn from_target(target: &Target) -> Self {
        let path = if target.path.is_empty() {
            "/".to_owned()
        } else {
            target.path.clone()
        };
        let url = if path == "/" {
            format!("{}://{}:{}/", target.scheme, target.host, target.port)
        } else {
            format!(
                "{}://{}:{}{}",
                target.scheme, target.host, target.port, path
            )
        };
        Self { url, path }
    }
}

/// Runs the passive dynamic probes for one scan.
pub struct DynamicEngine {
    target: ProbeTarget,
    routes_probed: AtomicU32,
}

impl DynamicEngine {
    /// Creates an engine aimed at `target`.
    #[must_use]
    pub fn new(target: ProbeTarget) -> Self {
        Self {
            target,
            routes_probed: AtomicU32::new(0),
        }
    }

    /// How many routes were successfully probed (for the report).
    #[must_use]
    pub fn routes_probed(&self) -> u32 {
        self.routes_probed.load(Ordering::Acquire)
    }
}

#[async_trait]
impl Detector for DynamicEngine {
    fn meta(&self) -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static("dynamic-engine"),
            title: "Passive dynamic analysis engine".into(),
            severity: Severity::Info,
            max_confidence: Confidence::Likely,
            owasp: None,
            asi: None,
            cwe: None,
            surface: Surface::WebApp,
            category: "engine".into(),
            description: "Probes a live target through the bounded transport and \
                          reports runtime observations for correlation."
                .into(),
        }
    }

    fn kind(&self) -> DetectorKind {
        DetectorKind::Dynamic
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::passive_network()
    }

    async fn run(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        if ctx.transport().is_none() {
            return Err(DetectorError::MissingCapability {
                id: self.meta().id,
                capability: "network",
            });
        }

        let findings = headers::probe_security_headers(ctx, &self.target).await?;
        // A successful probe (including "headers present") counts as one route.
        self.routes_probed.fetch_add(1, Ordering::AcqRel);
        Ok(findings)
    }
}
