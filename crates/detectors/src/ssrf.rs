//! `ssrf` — a URL the caller controls being fetched by the server.
//!
//! # Why this one is worth having
//!
//! Server-Side Request Forgery is the bug where an attacker hands your server a
//! URL and your server fetches it. On a laptop that is a curiosity. In a cloud
//! account it is a full compromise: the server can reach the metadata endpoint
//! at `169.254.169.254` and hand back the instance's IAM credentials, or reach
//! internal services that have no authentication because "they are not exposed
//! to the internet".
//!
//! It is also nearly invisible in review. `fetch(url)` looks like every other
//! line of code in the file; the bug is entirely in where `url` came from.
//! That combination — severe, common, and hard to see by reading — is what a
//! static rule is for.
//!
//! # What it looks for
//!
//! An HTTP client call whose URL argument is caller-controlled, using the
//! shared [`RequestOrigin`] analysis so that a value parked in a local one line
//! earlier still counts. Both halves are required: `fetch(config.webhookUrl)`
//! is not a finding, and neither is `logger.info(req.query.url)`.
//!
//! # Confidence
//!
//! `Likely` when the URL is the whole argument — nothing in the source
//! constrains where the request goes. `Possible` when the caller's value is
//! only interpolated into the URL, because a hardcoded prefix
//! (`` `https://api.example.com/${id}` ``) often does constrain it. It is still
//! reported: a `..` in `id` walks out of the prefix, and path traversal in a
//! URL is how that constraint gets broken.
//!
//! # What it will miss
//!
//! A URL assembled across function boundaries, or fetched through a wrapper
//! this rule does not recognise. That is the honest limit of one-hop origin
//! analysis, stated here rather than discovered later — see
//! `owlwarden_static::taint`.

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    Confidence, Finding, Framework, OwaspRef, Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::RelPath;
use owlwarden_static::ast::{root_identifier, static_property};
use owlwarden_static::rule::{FileRule, FindingSink, RuleInfo};
use owlwarden_static::taint::RequestOrigin;
use owlwarden_static::unit::FileUnit;
use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "ssrf";

/// Bare functions that perform an outbound request.
const FETCH_FUNCTIONS: &[&str] = &["fetch", "$fetch", "ofetch"];

/// Client objects whose methods perform an outbound request.
///
/// Required alongside the method name, or `array.get(0)` and `cache.delete(key)`
/// become findings.
const CLIENT_OBJECTS: &[&str] = &[
    "axios",
    "http",
    "https",
    "got",
    "needle",
    "superagent",
    "request",
    "ky",
    "undici",
    "client",
    "api",
];

/// Methods on a client object that perform an outbound request.
const CLIENT_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "request", "fetch", "stream",
];

/// Findings collected from one file before the visitor stops.
const MAX_PER_FILE: usize = 32;

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ssrf;

impl Ssrf {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Server fetches a URL the caller controls".into(),
            severity: Severity::High,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A10:2021")),
            cwe: Some(918),
            category: "ssrf".into(),
            description: "An outbound HTTP request is made to a URL that came from the caller. \
                          The server can reach hosts the caller cannot — cloud metadata \
                          endpoints, internal admin services, databases bound to localhost — so \
                          this turns the server into a proxy into its own network. Validate the \
                          destination against an allowlist before fetching it."
                .into(),
        }
    }
}

impl RuleInfo for Ssrf {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for Ssrf {
    fn applies_to(&self, path: &RelPath) -> bool {
        !path.as_str().ends_with(".d.ts")
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = FetchVisitor::default();
        visitor.visit_program(unit.program);

        for hit in &visitor.hits {
            if !sink.push(build_finding(unit, hit)) {
                break;
            }
        }
    }
}

/// How much of the URL the caller controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Control {
    /// The whole URL. Nothing constrains the destination.
    Whole,
    /// Interpolated into a URL with a fixed prefix.
    Partial,
}

/// One outbound request to a caller-controlled URL.
struct Hit {
    span: Span,
    control: Control,
}

#[derive(Default)]
struct FetchVisitor {
    hits: Vec<Hit>,
    origin: RequestOrigin,
}

impl<'a> Visit<'a> for FetchVisitor {
    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        self.origin.observe(declarator);
        oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.hits.len() < MAX_PER_FILE
            && is_fetch_sink(call)
            && let Some(url) = call.arguments.first().and_then(Argument::as_expression)
            && let Some(control) = self.control_over(url)
        {
            self.hits.push(Hit {
                span: call.span,
                control,
            });
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

impl FetchVisitor {
    /// How much of the URL expression the caller controls, if any.
    fn control_over(&self, url: &Expression<'_>) -> Option<Control> {
        if self.origin.taints(url) {
            return Some(Control::Whole);
        }
        match url {
            Expression::TemplateLiteral(template) => template
                .expressions
                .iter()
                .any(|part| self.origin.taints(part))
                .then_some(Control::Partial),
            Expression::BinaryExpression(binary) => (self.origin.taints(&binary.left)
                || self.origin.taints(&binary.right))
            .then_some(Control::Partial),
            Expression::ParenthesizedExpression(inner) => self.control_over(&inner.expression),
            // `new URL(userInput)` and `new URL(path, base)` are both reachable
            // destinations; the constructor validates syntax, not target.
            Expression::NewExpression(expression) => (root_identifier(&expression.callee)
                == Some("URL")
                && expression
                    .arguments
                    .iter()
                    .filter_map(Argument::as_expression)
                    .any(|argument| self.origin.taints(argument)))
            .then_some(Control::Whole),
            _ => None,
        }
    }
}

/// Whether a call performs an outbound HTTP request.
fn is_fetch_sink(call: &CallExpression<'_>) -> bool {
    match &call.callee {
        Expression::Identifier(identifier) => FETCH_FUNCTIONS.contains(&identifier.name.as_str()),
        callee => {
            let Some(method) = static_property(callee) else {
                return false;
            };
            if !CLIENT_METHODS.contains(&method) {
                return false;
            }
            // `axios.get(url)` yes, `map.get(key)` no. Requiring a recognised
            // client is what keeps this rule out of everybody's collection code.
            root_identifier(callee).is_some_and(|root| {
                CLIENT_OBJECTS.contains(&root) || root.to_ascii_lowercase().contains("http")
            })
        }
    }
}

/// Builds the finding.
fn build_finding(unit: &FileUnit<'_>, hit: &Hit) -> Finding {
    let meta = Ssrf::meta();

    let (confidence, why, evidence) = match hit.control {
        Control::Whole => (
            Confidence::Likely,
            "The destination of this request comes from the caller, so they choose which host \
             the server connects to. That includes hosts they cannot reach themselves: the cloud \
             metadata endpoint that hands out IAM credentials, internal services that skip \
             authentication because they are 'not exposed', and anything bound to localhost.",
            "the URL argument is caller-controlled",
        ),
        Control::Partial => (
            Confidence::Possible,
            "Part of this URL comes from the caller. The fixed prefix usually keeps the request \
             inside one host, but it is not a guarantee — a value containing '..' walks out of \
             the path, and one containing '@' or a scheme can redirect the whole request \
             elsewhere.",
            "caller-controlled value interpolated into the URL",
        ),
    };

    finding_builder(&meta)
        .confidence(confidence)
        .why(why)
        .location(unit.location(hit.span))
        .snippet(unit.code_frame(hit.span, "destination chosen by the caller"))
        .context(unit.context(None, Some(evidence.to_owned())))
        .fixes(remediation().select(unit.framework()))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

/// The allowlist check, written once; the frameworks differ only in where the
/// URL arrives and how you refuse.
const ALLOWLIST_HELPER: &str = "// lib/safe-fetch.ts\n\
     const ALLOWED_HOSTS = new Set(['api.partner.com', 'cdn.example.com'])\n\
     \n\
     export function assertAllowedUrl(raw: string): URL {\n  \
     const url = new URL(raw)\n  \
     if (url.protocol !== 'https:') throw new Error('only https is allowed')\n  \
     if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('host not allowed')\n  \
     return url\n\
     }";

/// Every framework's fix.
fn remediation() -> Remediation {
    Remediation::new(
        "Check the destination against an allowlist of hosts before fetching it. Blocklists do \
         not work here: DNS rebinding, redirects, and IPv6-mapped addresses all defeat them.",
    )
    .generic_patch(ALLOWLIST_HELPER)
    .manual(
        Framework::NEXT,
        "Validate the URL in the route handler before fetching, and disable redirect following.",
        "const url = assertAllowedUrl(body.url)\n\
         const upstream = await fetch(url, { redirect: 'error' })",
    )
    .manual(
        Framework::NUXT,
        "Validate before calling $fetch, and refuse redirects.",
        "const { url } = await readBody(event)\n\
         const target = assertAllowedUrl(url)\n\
         return await $fetch(target.toString(), { redirect: 'error' })",
    )
    .manual(
        Framework::NEST,
        "Validate in the service, not the controller, so every caller of it is covered.",
        "const target = assertAllowedUrl(dto.url)\n\
         return firstValueFrom(this.http.get(target.toString(), { maxRedirects: 0 }))",
    )
    .manual(
        Framework::EXPRESS,
        "Validate before the request and refuse redirects.",
        "const target = assertAllowedUrl(req.body.url)\n\
         const upstream = await fetch(target, { redirect: 'error' })",
    )
    .manual(
        Framework::FASTIFY,
        "Validate in the handler; a schema alone checks the shape, not the destination.",
        "const target = assertAllowedUrl((request.body as { url: string }).url)\n\
         const upstream = await fetch(target, { redirect: 'error' })",
    )
    .manual(
        Framework::HONO,
        "Validate the URL in the handler before fetching, and disable redirect following.",
        "const body = await c.req.json()\n\
         const target = assertAllowedUrl(body.url)\n\
         const upstream = await fetch(target, { redirect: 'error' })",
    )
    .manual(
        Framework::KOA,
        "Validate before fetching and refuse redirects.",
        "const target = assertAllowedUrl(ctx.request.body.url)\n\
         const upstream = await fetch(target, { redirect: 'error' })",
    )
    .manual(
        Framework::HAPI,
        "Validate in the handler; a schema alone checks the shape, not the destination.",
        "const target = assertAllowedUrl((request.payload as { url: string }).url)\n\
         const upstream = await fetch(target, { redirect: 'error' })",
    )
    .manual(
        Framework::SAILS,
        "Validate in the action, not a helper, so every caller is covered.",
        "const target = assertAllowedUrl(inputs.url)\n\
         const upstream = await fetch(target, { redirect: 'error' })",
    )
    .manual(
        Framework::ASTRO,
        "Validate before fetching in the API route, and refuse redirects.",
        "const { url } = await request.json()\n\
         const target = assertAllowedUrl(url)\n\
         const upstream = await fetch(target, { redirect: 'error' })",
    )
    .manual(
        Framework::REMIX,
        "Validate in the action before fetching, and refuse redirects.",
        "export async function action({ request }: ActionFunctionArgs) {\n  \
         const body = await request.formData()\n  \
         const target = assertAllowedUrl(body.get('url'))\n  \
         return fetch(target, { redirect: 'error' })\n\
         }",
    )
    .manual(
        Framework::GATSBY,
        "Validate in the Function handler before fetching, and refuse redirects.",
        "const target = assertAllowedUrl(req.body.url)\n\
         const upstream = await fetch(target, { redirect: 'error' })",
    )
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_recognised_client_is_required_not_just_a_method_name() {
        // `map.get(key)` and `cache.delete(id)` are the reason this rule needs
        // both halves. A rule that fired on every `.get(` would be uninstalled
        // the same afternoon.
        assert!(CLIENT_METHODS.contains(&"get"));
        assert!(!CLIENT_OBJECTS.contains(&"map"));
        assert!(!CLIENT_OBJECTS.contains(&"cache"));
    }

    #[test]
    fn the_remediation_never_recommends_a_blocklist() {
        // Blocking 169.254.169.254 by string match is the fix people reach for
        // and it does not hold: DNS rebinding, redirects, decimal-encoded IPs,
        // and IPv6-mapped addresses all get past it. If this advice ever
        // regresses to a blocklist, the rule is teaching a broken fix.
        let text = remediation()
            .all()
            .iter()
            .filter_map(|fix| fix.patch.clone())
            .collect::<String>()
            .to_ascii_lowercase();
        assert!(!text.contains("169.254"), "advice fell back to a blocklist");
        assert!(text.contains("allowed"), "advice must be an allowlist");
    }
}
