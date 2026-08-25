//! Turning rule metadata into a finding, without copying it by hand.
//!
//! Every rule was repeating the same six lines: start a builder, then
//! conditionally copy `owasp` and `cwe` across from its own metadata. Six lines
//! is nothing, but they were six lines that could disagree with the metadata —
//! and a finding whose OWASP category differs from the one in `RULES.md` for
//! the same rule is a bug a reader has no way to diagnose.

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{Finding, FindingBuilder, Severity};

/// A builder seeded from a rule's metadata: id, severity, title, OWASP, ASI, CWE.
///
/// The caller still supplies everything that varies per finding — location,
/// confidence, evidence, remediation — because those are properties of what was
/// found, not of the rule.
#[must_use]
pub fn finding_builder(meta: &DetectorMeta) -> FindingBuilder {
    let mut builder = Finding::builder(meta.id.clone(), meta.severity, meta.title.clone());
    if let Some(owasp) = &meta.owasp {
        builder = builder.owasp(owasp.clone());
    }
    if let Some(asi) = &meta.asi {
        builder = builder.asi(asi.clone());
    }
    if let Some(cwe) = meta.cwe {
        builder = builder.cwe(cwe);
    }
    builder
}

/// A builder seeded from metadata but with a different severity.
///
/// For rules whose severity depends on what they found: a permissive CORS
/// policy is Medium on its own and High when it is combined with credentials,
/// and reporting both at the same level would flatten a real distinction.
#[must_use]
pub fn finding_builder_with(meta: &DetectorMeta, severity: Severity) -> FindingBuilder {
    let mut builder = Finding::builder(meta.id.clone(), severity, meta.title.clone());
    if let Some(owasp) = &meta.owasp {
        builder = builder.owasp(owasp.clone());
    }
    if let Some(asi) = &meta.asi {
        builder = builder.asi(asi.clone());
    }
    if let Some(cwe) = meta.cwe {
        builder = builder.cwe(cwe);
    }
    builder
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use owlwarden_core::surface::Surface;
    use owlwarden_core::finding::{Confidence, OwaspRef, RuleId};

    fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static("stack-trace-leak"),
            title: "Title".into(),
            severity: Severity::High,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A05:2021")),
            asi: None,
            cwe: Some(209),
            surface: Surface::WebApp,
            category: "c".into(),
            description: "d".into(),
        }
    }

    #[test]
    fn the_finding_cannot_disagree_with_the_catalogue() {
        let finding = finding_builder(&meta()).build();
        assert_eq!(finding.id.as_str(), "stack-trace-leak");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.cwe, Some(209));
        assert_eq!(
            finding.owasp.as_ref().map(OwaspRef::as_str),
            Some("A05:2021")
        );
    }

    #[test]
    fn severity_can_be_raised_for_what_was_actually_found() {
        let finding = finding_builder_with(&meta(), Severity::Low).build();
        assert_eq!(finding.severity, Severity::Low);
        // Everything else still comes from the catalogue.
        assert_eq!(finding.cwe, Some(209));
    }
}
