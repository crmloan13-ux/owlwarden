//! `security-headers-missing` — the app never sets the baseline response
//! headers.
//!
//! # Why this is a project rule
//!
//! The bug here is an *absence*. A project with no `next.config.js` at all sets
//! no headers, and no per-file pass can see a file that does not exist. So this
//! rule looks at the project: which frameworks, which configuration files
//! exist, and what those files actually configure.
//!
//! Which files count is not written here. It comes from the detected
//! frameworks' profiles, so a Nuxt project is checked at `nuxt.config.ts` and a
//! Fastify one at its bootstrap without this rule naming either.
//!
//! # Why confidence varies
//!
//! Headers can legitimately be set outside the codebase — by a CDN, an ingress,
//! or `vercel.json`. Static analysis cannot see any of that. So:
//!
//! - configuration exists and manages *some* of the headers → `Likely`, because
//!   the team clearly owns headers in the app and has gaps;
//! - no configuration anywhere → `Possible`, because infrastructure may be
//!   handling it. Shown, explained, and never fails CI on its own.
//!
//! Claiming certainty here would be the fastest way to teach users that our
//! severity labels mean nothing.

use owlwarden_core::detector::{DetectorError, DetectorMeta};
use owlwarden_core::finding::{
    Confidence, Finding, FindingContext, Framework, Location, OwaspRef, Reference, RuleId,
    Severity, SourceLocation,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_static::ast::property_name;
use owlwarden_static::project::Project;
use owlwarden_static::rule::{FindingSink, ProjectRule, RuleInfo};
use owlwarden_static::unit::FileUnit;
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "security-headers-missing";

/// The headers we expect an app to set, and what each one prevents.
///
/// Deliberately short. A longer list would flag more projects but each extra
/// entry is another chance to be wrong about someone's threat model, and a rule
/// that reports six things nobody acts on is noise.
///
/// Shared with the dynamic probe so correlation compares the same set
/// ([ADR 0014](../../../docs/adr/0014-passive-dynamic-and-correlation.md)).
pub const REQUIRED_HEADERS: &[(&str, &str)] = &[
    (
        "strict-transport-security",
        "forces HTTPS for future requests",
    ),
    (
        "content-security-policy",
        "limits which scripts and origins the page may load",
    ),
    (
        "x-content-type-options",
        "stops browsers guessing a response's content type",
    ),
    ("x-frame-options", "blocks clickjacking via framing"),
    ("referrer-policy", "stops URLs leaking to third parties"),
];

/// Packages that set every header on our list by default. Their presence in a
/// config or bootstrap file closes the finding.
///
/// Auditing an individual helmet option is a separate, more precise rule than
/// this one; this rule only answers "is anything setting these at all".
const HEADER_MIDDLEWARE: &[&str] = &["helmet", "fastifyHelmet", "nuxtSecurity"];

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecurityHeadersMissing;

impl SecurityHeadersMissing {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Security headers are not configured",
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A05:2021")),
            cwe: Some(693),
            category: "headers",
            description: "The application does not set the baseline security response headers. \
                          Without them a browser will not enforce HTTPS, will guess content \
                          types, and will allow the page to be framed. Headers set by a CDN or \
                          ingress are invisible to static analysis, so this rule reports lower \
                          confidence when it finds no header configuration at all.",
        }
    }
}

impl RuleInfo for SecurityHeadersMissing {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation(&all_header_names())
    }
}

impl ProjectRule for SecurityHeadersMissing {
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink) -> Result<(), DetectorError> {
        let frameworks = project.frameworks();

        // With nothing detected we have no idea where headers would be
        // configured, and guessing produces advice that does not apply.
        if frameworks.all().is_empty() {
            return Ok(());
        }

        // Both lists: a Next.js app can set headers in `next.config.js` or in
        // `middleware.ts`, and a Nest app does it in its bootstrap. Checking
        // only one would report a gap the other had already closed.
        let mut candidates = frameworks.config_files();
        for bootstrap in frameworks.bootstrap_files() {
            if !candidates.contains(&bootstrap) {
                candidates.push(bootstrap);
            }
        }

        let evidence = collect_evidence(project, &candidates);
        if evidence.uses_middleware {
            return Ok(());
        }

        let missing: Vec<&str> = REQUIRED_HEADERS
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| !evidence.configured.iter().any(|found| found == name))
            .collect();

        if missing.is_empty() {
            return Ok(());
        }

        sink.push(build_finding(project.framework(), &evidence, &missing));
        Ok(())
    }
}

/// What we learned by reading the project's configuration files.
struct HeaderEvidence {
    /// Header names, lowercased, that appear as string literals in a config
    /// file.
    configured: Vec<String>,
    /// Whether a header middleware is used anywhere in the bootstrap.
    uses_middleware: bool,
    /// The file we should point the user at, and where in it.
    anchor: Option<Anchor>,
}

/// Where to put the finding.
struct Anchor {
    path: String,
    line: u32,
    col: u32,
    frame: Option<owlwarden_core::finding::CodeFrame>,
}

/// Reads the candidate configuration files and records what they set.
///
/// Infallible on purpose: a config file we cannot read or parse is skipped, and
/// the absence shows up as lower confidence rather than as a failed scan.
fn collect_evidence(project: &Project<'_>, candidates: &[String]) -> HeaderEvidence {
    let mut evidence = HeaderEvidence {
        configured: Vec::new(),
        uses_middleware: false,
        anchor: None,
    };

    for file in project.find_files(candidates) {
        // A config file that exists but does not parse tells us nothing; skip
        // it rather than reporting a header gap we cannot substantiate.
        let Ok(scan) = project.with_parsed_file(file, scan_config_file) else {
            continue;
        };

        evidence.uses_middleware |= scan.uses_middleware;
        for header in scan.headers {
            if !evidence.configured.contains(&header) {
                evidence.configured.push(header);
            }
        }
        if evidence.anchor.is_none() {
            evidence.anchor = Some(scan.anchor);
        }
    }

    evidence
}

/// What one configuration file contributes.
struct ConfigScan {
    headers: Vec<String>,
    uses_middleware: bool,
    anchor: Anchor,
}

/// Reads one configuration file.
fn scan_config_file(unit: &FileUnit<'_>) -> ConfigScan {
    let mut visitor = ConfigVisitor::default();
    visitor.visit_program(unit.program);

    let anchor_span = visitor.anchor_span.unwrap_or(Span::new(0, 0));
    let (line, col) = unit.position(anchor_span.start);

    ConfigScan {
        headers: visitor.headers,
        uses_middleware: visitor.uses_middleware,
        anchor: Anchor {
            path: unit.path.to_string(),
            line,
            col,
            frame: Some(unit.code_frame(anchor_span, "no security headers configured here")),
        },
    }
}

/// Collects header names and middleware usage from a configuration file.
///
/// String-literal matching rather than data-flow analysis: a header name in a
/// config file is overwhelmingly a header being set, and following the value
/// through a `headers()` async function into a returned array would be a lot of
/// machinery for very little extra precision.
#[derive(Default)]
struct ConfigVisitor {
    headers: Vec<String>,
    uses_middleware: bool,
    /// Where to point the user: the `headers` key if there is one, otherwise
    /// the first export we saw.
    anchor_span: Option<Span>,
    anchor_is_headers_key: bool,
}

impl ConfigVisitor {
    fn note_middleware(&mut self, name: &str) {
        if HEADER_MIDDLEWARE
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
        {
            self.uses_middleware = true;
        }
    }
}

impl<'a> Visit<'a> for ConfigVisitor {
    fn visit_string_literal(&mut self, literal: &oxc_ast::ast::StringLiteral<'a>) {
        let value = literal.value.as_str().to_ascii_lowercase();
        if REQUIRED_HEADERS.iter().any(|(name, _)| *name == value) && !self.headers.contains(&value)
        {
            self.headers.push(value);
        } else {
            // `app.register(import('@fastify/helmet'))` names the middleware in
            // a string rather than as an identifier.
            self.note_middleware(literal.value.as_str());
            if literal.value.as_str().contains("helmet") {
                self.uses_middleware = true;
            }
        }
    }

    fn visit_identifier_reference(&mut self, identifier: &oxc_ast::ast::IdentifierReference<'a>) {
        self.note_middleware(identifier.name.as_str());
    }

    fn visit_object_property(&mut self, property: &oxc_ast::ast::ObjectProperty<'a>) {
        if !self.anchor_is_headers_key && property_name(&property.key) == Some("headers") {
            self.anchor_span = Some(property.span);
            self.anchor_is_headers_key = true;
        }
        oxc_ast_visit::walk::walk_object_property(self, property);
    }

    fn visit_export_default_declaration(
        &mut self,
        declaration: &oxc_ast::ast::ExportDefaultDeclaration<'a>,
    ) {
        if self.anchor_span.is_none() {
            self.anchor_span = Some(declaration.span);
        }
        oxc_ast_visit::walk::walk_export_default_declaration(self, declaration);
    }

    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        // `module.exports = { ... }` — the CommonJS spelling of the same thing.
        if self.anchor_span.is_none()
            && let Some(target) = assignment.left.as_member_expression()
            && owlwarden_static::ast::member_property(target) == Some("exports")
        {
            self.anchor_span = Some(assignment.span);
        }
        oxc_ast_visit::walk::walk_assignment_expression(self, assignment);
    }

    fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
        // Anchor on the line that builds the server, so the finding lands on
        // the bootstrap rather than at line 1.
        if self.anchor_span.is_none()
            && let Some(root) = owlwarden_static::ast::root_identifier(&call.callee)
            && matches!(root, "NestFactory" | "app" | "fastify" | "express")
        {
            self.anchor_span = Some(call.span);
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

/// Builds the finding.
fn build_finding(framework: &Framework, evidence: &HeaderEvidence, missing: &[&str]) -> Finding {
    let meta = SecurityHeadersMissing::meta();

    // Configuration exists and manages some headers: the gap is real and the
    // team owns it. Nothing at all: infrastructure may be covering it.
    let has_configuration = evidence.anchor.is_some();
    let partially_configured = !evidence.configured.is_empty();
    let confidence = if has_configuration && partially_configured {
        Confidence::Likely
    } else {
        Confidence::Possible
    };

    let location = evidence.anchor.as_ref().map_or_else(
        || {
            Location::Source(SourceLocation {
                // Every project we fire on has a manifest — that is how the
                // framework was detected in the first place.
                path: "package.json".to_owned(),
                line: 1,
                col: 1,
            })
        },
        |anchor| {
            Location::Source(SourceLocation {
                path: anchor.path.clone(),
                line: anchor.line,
                col: anchor.col,
            })
        },
    );

    let evidence_text = if partially_configured {
        format!(
            "configured: {}; missing: {}",
            evidence.configured.join(", "),
            missing.join(", ")
        )
    } else {
        format!(
            "no header configuration found; missing: {}",
            missing.join(", ")
        )
    };

    let mut builder = finding_builder(&meta)
        .confidence(confidence)
        .why(missing_why(missing))
        .location(location)
        .context(FindingContext {
            framework: Some(framework.clone()),
            route: None,
            method: None,
            evidence: Some(evidence_text),
        })
        .fixes(remediation(missing).select(framework))
        .reference(Reference::rule_page(&meta.id));

    if let Some(anchor) = &evidence.anchor
        && let Some(frame) = anchor.frame.clone()
    {
        builder = builder.snippet(frame);
    }

    builder.build()
}

/// A "why it matters" line naming what each missing header would have done, so
/// the reader can judge the risk instead of taking our word for it.
fn missing_why(missing: &[&str]) -> String {
    let explained: Vec<String> = REQUIRED_HEADERS
        .iter()
        .filter(|(name, _)| missing.contains(name))
        .map(|(name, purpose)| format!("{name} {purpose}"))
        .collect();
    format!(
        "Without these headers the browser enforces nothing: {}.",
        explained.join("; ")
    )
}

fn all_header_names() -> Vec<&'static str> {
    REQUIRED_HEADERS.iter().map(|(name, _)| *name).collect()
}

/// Header names listed after `missing:` in a finding's evidence string.
///
/// Used by correlation to decide whether static and dynamic observations agree
/// without inventing a second structured field on [`Finding`].
#[must_use]
pub fn missing_headers_from_evidence(evidence: &str) -> Vec<String> {
    const MARKER: &str = "missing: ";
    let Some(index) = evidence.rfind(MARKER) else {
        return Vec::new();
    };
    let rest = evidence.get(index + MARKER.len()..).unwrap_or("").trim();
    if rest.is_empty() {
        return Vec::new();
    }
    rest.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .take(REQUIRED_HEADERS.len())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Every framework's fix, for `owlwarden explain` and the rule catalogue page.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation(&all_header_names()).all()
}

/// Framework-specific remediation.
///
/// All `Manual`. A generated Content-Security-Policy will break a real
/// application's inline scripts and third-party embeds, and a tool that
/// silently breaks production to close a Medium finding does not get a second
/// chance.
fn remediation(missing: &[&str]) -> Remediation {
    Remediation::new(format!(
        "Set these response headers at the edge or in the app: {}.",
        missing.join(", ")
    ))
    .manual(
        Framework::NEXT,
        "Add a headers() block to next.config.js.",
        NEXT_HEADERS_PATCH,
    )
    .manual(
        Framework::NUXT,
        "Enable Nuxt's routeRules headers, or install nuxt-security.",
        NUXT_HEADERS_PATCH,
    )
    .manual(
        Framework::NEST,
        "Register helmet in the bootstrap; it sets all of these.",
        "import helmet from 'helmet'\n\n\
         const app = await NestFactory.create(AppModule)\n\
         app.use(helmet())",
    )
    .manual(
        Framework::EXPRESS,
        "Register helmet before your routes; it sets all of these.",
        "import helmet from 'helmet'\n\napp.use(helmet())",
    )
    .manual(
        Framework::FASTIFY,
        "Register @fastify/helmet before your routes.",
        "import helmet from '@fastify/helmet'\n\nawait app.register(helmet)",
    )
}

/// The copy-paste block for Next.js. Kept as a constant so the shipped
/// remediation and the documentation site render the identical text.
const NEXT_HEADERS_PATCH: &str = r#"// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
          { key: 'Content-Security-Policy', value: "default-src 'self'" },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ]
  },
}"#;

/// The copy-paste block for Nuxt.
const NUXT_HEADERS_PATCH: &str = r#"// nuxt.config.ts
export default defineNuxtConfig({
  routeRules: {
    '/**': {
      headers: {
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
      },
    },
  },
})"#;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn missing_headers_parser_uses_the_last_marker() {
        let parsed = missing_headers_from_evidence(
            "configured: x-frame-options; missing: content-security-policy, referrer-policy",
        );
        assert_eq!(
            parsed,
            vec![
                "content-security-policy".to_owned(),
                "referrer-policy".to_owned()
            ]
        );
    }

    #[test]
    fn missing_headers_parser_ignores_noise_without_marker() {
        assert!(missing_headers_from_evidence("runtime: security headers present").is_empty());
    }

    #[test]
    fn missing_headers_parser_is_bounded() {
        let flood = format!(
            "missing: {}",
            (0..100)
                .map(|i| format!("h{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(missing_headers_from_evidence(&flood).len() <= REQUIRED_HEADERS.len());
    }
}
