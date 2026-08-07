//! `sensitive-data-logged` — credentials written to a log sink.
//!
//! # What we look for
//!
//! A call to `console.*`, `logger.*`, `this.logger.*`, or `request.log.*` whose
//! argument is an object property or member expression named like a secret
//! (`password`, `token`, `authorization`, …). That is the shape that ends up in
//! centralised logging with a session cookie or a password still attached.
//!
//! # What we deliberately do not look for
//!
//! - String literals containing the word "password". `console.log('password
//!   reset sent')` is ordinary product logging.
//! - Absence of logging on auth failures. That is a monitoring question and a
//!   false-positive magnet; this rule only flags data that is clearly being
//!   written out.
//! - Response sinks. Leaking a stack to the client is `stack-trace-leak`
//!   (A05); this rule is about server-side logs (A09).

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    Confidence, Finding, Framework, OwaspRef, Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::RelPath;
use owlwarden_static::ast::{property_name, static_property};
use owlwarden_static::rule::{FileRule, FindingSink, RuleInfo};
use owlwarden_static::taint::RequestOrigin;
use owlwarden_static::unit::FileUnit;
use oxc_ast::ast::{CallExpression, Expression, ObjectPropertyKind};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "sensitive-data-logged";

/// Findings collected from one file before the visitor stops.
const MAX_PER_FILE: usize = 16;

/// Property / identifier names that mean a secret is being handled.
const SENSITIVE_NAMES: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "accesstoken",
    "refreshtoken",
    "authorization",
    "authheader",
    "cookie",
    "cookies",
    "apikey",
    "privatekey",
    "clientsecret",
    "idtoken",
];

/// Log method names we recognise on `console` / `logger` / `*.log`.
const LOG_METHODS: &[&str] = &["log", "info", "debug", "warn", "error", "trace", "fatal"];

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct SensitiveDataLogged;

impl SensitiveDataLogged {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Sensitive data written to a log".into(),
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A09:2021")),
            cwe: Some(532),
            category: "logging".into(),
            description: "A password, token, cookie, or similar value is passed to a log sink. \
                          Centralised logs are widely readable inside an organisation and often \
                          retained for months — a credential that lands there is a credential \
                          that has left the application's control."
                .into(),
        }
    }
}

impl RuleInfo for SensitiveDataLogged {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for SensitiveDataLogged {
    fn applies_to(&self, path: &RelPath) -> bool {
        // Same filter as hardcoded-secret: a test logging a fixture password
        // is not the incident this rule exists to catch.
        let path = path.as_str();
        !path.ends_with(".d.ts")
            && !path.contains("/__tests__/")
            && !path.contains("/__fixtures__/")
            && !path.contains(".test.")
            && !path.contains(".spec.")
            && !path.contains("/fixtures/")
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = LogVisitor::default();
        visitor.visit_program(unit.program);
        for hit in visitor.hits {
            if !sink.push(build_finding(unit, &hit)) {
                break;
            }
        }
    }
}

#[derive(Debug)]
struct Hit {
    span: Span,
    evidence: String,
    from_request: bool,
}

#[derive(Default)]
struct LogVisitor {
    origin: RequestOrigin,
    hits: Vec<Hit>,
}

impl<'a> Visit<'a> for LogVisitor {
    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        self.origin.observe(declarator);
        oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.hits.len() < MAX_PER_FILE && is_log_call(&call.callee) {
            for argument in &call.arguments {
                if let Some(expression) = argument.as_expression() {
                    self.inspect_arg(expression);
                }
            }
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

impl LogVisitor {
    fn inspect_arg(&mut self, expression: &Expression<'_>) {
        if self.hits.len() >= MAX_PER_FILE {
            return;
        }
        match expression {
            Expression::ObjectExpression(object) => {
                for property in &object.properties {
                    let ObjectPropertyKind::ObjectProperty(entry) = property else {
                        continue;
                    };
                    let Some(name) = property_name(&entry.key) else {
                        continue;
                    };
                    if is_sensitive_name(name) {
                        self.hits.push(Hit {
                            span: entry.span,
                            evidence: format!("{name}: …"),
                            from_request: self.origin.taints(&entry.value),
                        });
                    }
                }
            }
            Expression::StaticMemberExpression(member) => {
                let name = member.property.name.as_str();
                if is_sensitive_name(name) {
                    self.hits.push(Hit {
                        span: member.span,
                        evidence: format!("….{name}"),
                        from_request: self.origin.taints(expression),
                    });
                }
            }
            Expression::Identifier(identifier) if is_sensitive_name(identifier.name.as_str()) => {
                self.hits.push(Hit {
                    span: identifier.span,
                    evidence: identifier.name.to_string(),
                    from_request: self.origin.taints(expression),
                });
            }
            _ => {}
        }
    }
}

fn is_log_call(callee: &Expression<'_>) -> bool {
    let Some(method) = static_property(callee) else {
        return false;
    };
    if !LOG_METHODS.contains(&method) {
        return false;
    }
    let Expression::StaticMemberExpression(member) = callee else {
        return false;
    };
    match &member.object {
        Expression::Identifier(identifier) => {
            matches!(identifier.name.as_str(), "console" | "logger" | "log")
        }
        // `this.logger.log`, `request.log.info`, `app.logger.error`.
        Expression::StaticMemberExpression(inner) => {
            let name = inner.property.name.as_str();
            name == "logger" || name == "log"
        }
        _ => false,
    }
}

fn is_sensitive_name(name: &str) -> bool {
    let compact: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect();
    SENSITIVE_NAMES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(&compact))
}

fn build_finding(unit: &FileUnit<'_>, hit: &Hit) -> Finding {
    let meta = SensitiveDataLogged::meta();
    let confidence = if hit.from_request {
        Confidence::Likely
    } else {
        // A local `password` variable might already be a hash. Still worth
        // showing, never fails CI alone.
        Confidence::Possible
    };
    finding_builder(&meta)
        .confidence(confidence)
        .why(
            "Logs are copied into aggregators, retained for months, and readable by anyone with \
             access to the logging system. A credential that reaches a log has left the \
             application's trust boundary.",
        )
        .location(unit.location(hit.span))
        .snippet(unit.code_frame(hit.span, "sensitive value written to a log"))
        .context(unit.context(None, Some(hit.evidence.clone())))
        .fixes(remediation().select(unit.framework()))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

fn remediation() -> Remediation {
    Remediation::new("Log a redacted shape — an id, a boolean, a length — never the secret itself.")
        .manual(
            Framework::NEXT,
            "Log that the attempt happened, not the credential.",
            "console.info({ event: 'login_attempt', userId })\n\
         // never: console.info({ password })",
        )
        .manual(
            Framework::NUXT,
            "Log that the attempt happened, not the credential.",
            "console.info({ event: 'login_attempt', userId })\n\
         // never: console.info({ password: body.password })",
        )
        .manual(
            Framework::NEST,
            "Use the Nest logger with a redacted payload.",
            "this.logger.log({ event: 'login_attempt', userId })\n\
         // never: this.logger.log({ password: dto.password })",
        )
        .manual(
            Framework::EXPRESS,
            "Log that the attempt happened, not the credential.",
            "console.info({ event: 'login_attempt', userId })\n\
         // never: console.info({ password: req.body.password })",
        )
        .manual(
            Framework::FASTIFY,
            "Use request.log with a redacted payload.",
            "request.log.info({ event: 'login_attempt', userId })\n\
         // never: request.log.info({ password: request.body.password })",
        )
        .manual(
            Framework::HONO,
            "Log that the attempt happened, not the credential.",
            "console.info({ event: 'login_attempt', userId })\n\
         // never: console.info({ password: body.password })",
        )
        .manual(
            Framework::KOA,
            "Log that the attempt happened, not the credential.",
            "console.info({ event: 'login_attempt', userId })\n\
         // never: console.info({ password: ctx.request.body.password })",
        )
        .manual(
            Framework::HAPI,
            "Use request.log with a redacted payload.",
            "request.log(['info'], { event: 'login_attempt', userId })\n\
         // never: request.log(['info'], { password: request.payload.password })",
        )
        .manual(
            Framework::SAILS,
            "Use sails.log with a redacted payload.",
            "sails.log.info({ event: 'login_attempt', userId })\n\
         // never: sails.log.info({ password: inputs.password })",
        )
        .manual(
            Framework::ASTRO,
            "Log that the attempt happened, not the credential.",
            "console.info({ event: 'login_attempt', userId })\n\
         // never: console.info({ password: body.password })",
        )
        .manual(
            Framework::REMIX,
            "Log that the attempt happened, not the credential.",
            "console.info({ event: 'login_attempt', userId })\n\
         // never: console.info({ password: form.get('password') })",
        )
        .manual(
            Framework::GATSBY,
            "Log that the attempt happened, not the credential.",
            "console.info({ event: 'login_attempt', userId })\n\
         // never: console.info({ password: req.body.password })",
        )
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matching_is_punctuation_tolerant() {
        assert!(is_sensitive_name("password"));
        assert!(is_sensitive_name("api_key"));
        assert!(is_sensitive_name("apiKey"));
        assert!(is_sensitive_name("accessToken"));
        assert!(!is_sensitive_name("passwordLength"));
        assert!(!is_sensitive_name("tokenCount"));
    }
}
