//! `cors-permissive` — a cross-origin policy that lets anyone call the API.
//!
//! # The two shapes worth reporting
//!
//! **Reflecting any origin with credentials.** `{ origin: true, credentials:
//! true }` tells the browser to echo whatever `Origin` the caller sent and to
//! include cookies. Any website a logged-in user visits can then make
//! authenticated requests to the API and read the responses. This is the case
//! that matters, and it is reported as High.
//!
//! **A wildcard origin.** `{ origin: '*' }` without credentials is a deliberate
//! choice for a public API and a mistake on an internal one, and nothing in the
//! source says which this is. Medium, and the finding says why it might be
//! fine.
//!
//! The distinction is load-bearing. Browsers already refuse `*` together with
//! credentials, so a rule that treated them identically would rank a
//! browser-blocked configuration alongside a live authentication bypass.
//!
//! # Where the sink list comes from
//!
//! The framework profiles. `cors()` in Express, `app.enableCors()` in NestJS,
//! `@fastify/cors` in Fastify — the rule asks the detected
//! [`FrameworkSet`](owlwarden_static::FrameworkSet) rather than listing them.

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    Confidence, Finding, Framework, OwaspRef, Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::RelPath;
use owlwarden_core::surface::Surface;
use owlwarden_static::ast::{argument_object, is_true_literal, object_property, string_value};
use owlwarden_static::framework::FrameworkSet;
use owlwarden_static::http::is_cors_enabler;
use owlwarden_static::rule::{FileRule, FindingSink, RuleInfo};
use owlwarden_static::unit::FileUnit;
use oxc_ast::ast::{CallExpression, Expression, ObjectExpression};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder_with;

/// The rule id. Permanent public API.
pub const ID: &str = "cors-permissive";

/// The header a hand-rolled CORS policy sets.
const ALLOW_ORIGIN_HEADER: &str = "access-control-allow-origin";
/// The header that turns a permissive origin into an authenticated one.
const ALLOW_CREDENTIALS_HEADER: &str = "access-control-allow-credentials";

/// Findings collected from one file before the visitor stops.
const MAX_PER_FILE: usize = 16;

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct CorsPermissive;

impl CorsPermissive {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Cross-origin policy accepts any origin".into(),
            // The catalogue severity is the common case; a finding that also
            // enables credentials is raised to High when it is built.
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A05:2021")),
            asi: None,
            cwe: Some(942),
            surface: Surface::WebApp,
            category: "cors".into(),
            description: "The CORS configuration accepts requests from any origin. Combined with \
                          credentials this lets any site a logged-in user visits make \
                          authenticated calls to the API and read the responses. Without \
                          credentials it may be intentional for a public API — the finding says \
                          which case it found."
                .into(),
        }
    }
}

impl RuleInfo for CorsPermissive {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for CorsPermissive {
    fn applies_to(&self, path: &RelPath) -> bool {
        !path.as_str().ends_with(".d.ts")
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = CorsVisitor {
            frameworks: unit.frameworks(),
            hits: Vec::new(),
            allows_credentials_header: false,
        };
        visitor.visit_program(unit.program);

        let credentials_elsewhere = visitor.allows_credentials_header;
        for hit in &visitor.hits {
            let with_credentials = hit.credentials || credentials_elsewhere;
            if !sink.push(build_finding(unit, hit, with_credentials)) {
                break;
            }
        }
    }
}

/// How permissive the origin setting is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// `origin: '*'`.
    Wildcard,
    /// `origin: true` — echo whatever the caller sent.
    Reflected,
    /// `origin: (origin, callback) => callback(null, true)` — a function we
    /// cannot evaluate, whose common form accepts everything.
    Callback,
}

impl Origin {
    const fn evidence(self) -> &'static str {
        match self {
            Self::Wildcard => "origin: '*'",
            Self::Reflected => "origin: true (reflects the caller's Origin)",
            Self::Callback => "origin resolved by a callback",
        }
    }
}

/// One permissive configuration.
struct Hit {
    span: Span,
    origin: Origin,
    credentials: bool,
}

struct CorsVisitor<'f> {
    frameworks: &'f FrameworkSet,
    hits: Vec<Hit>,
    /// A separate `Access-Control-Allow-Credentials: true` anywhere in the
    /// file. Hand-rolled CORS is written as two independent `setHeader` calls,
    /// and judging the origin without the credentials half would under-report
    /// the exact combination that matters.
    allows_credentials_header: bool,
}

impl<'a> Visit<'a> for CorsVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.hits.len() < MAX_PER_FILE {
            self.inspect_enabler(call);
            self.inspect_header_call(call);
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

impl CorsVisitor<'_> {
    /// `cors({ ... })`, `app.enableCors({ ... })`.
    fn inspect_enabler(&mut self, call: &CallExpression<'_>) {
        if !is_cors_enabler(self.frameworks, &call.callee) {
            return;
        }
        // `cors()` with no options defaults to `origin: *` without credentials.
        let Some(options) = call.arguments.first().and_then(argument_object) else {
            self.hits.push(Hit {
                span: call.span,
                origin: Origin::Wildcard,
                credentials: false,
            });
            return;
        };
        if let Some(origin) = classify_origin(options) {
            self.hits.push(Hit {
                span: call.span,
                origin,
                credentials: object_property(options, "credentials").is_some_and(is_true_literal),
            });
        }
    }

    /// `res.setHeader('Access-Control-Allow-Origin', '*')` and the `header()`
    /// spellings of the same thing.
    fn inspect_header_call(&mut self, call: &CallExpression<'_>) {
        let Some(method) = owlwarden_static::ast::static_property(&call.callee) else {
            return;
        };
        if !matches!(method, "setHeader" | "header" | "set" | "append") {
            return;
        }
        let Some(name) = call
            .arguments
            .first()
            .and_then(oxc_ast::ast::Argument::as_expression)
            .and_then(string_value)
        else {
            return;
        };
        let name = name.to_ascii_lowercase();
        let value = call
            .arguments
            .get(1)
            .and_then(oxc_ast::ast::Argument::as_expression);

        if name == ALLOW_CREDENTIALS_HEADER
            && value
                .is_some_and(|value| string_value(value) == Some("true") || is_true_literal(value))
        {
            self.allows_credentials_header = true;
            return;
        }

        if name == ALLOW_ORIGIN_HEADER && value.and_then(string_value) == Some("*") {
            self.hits.push(Hit {
                span: call.span,
                origin: Origin::Wildcard,
                credentials: false,
            });
        }
    }
}

/// Reads the `origin` option, returning `None` when it names actual origins.
///
/// An allowlist — a string that is not `*`, or an array — is the correct
/// configuration and must stay silent.
fn classify_origin(options: &ObjectExpression<'_>) -> Option<Origin> {
    let origin = object_property(options, "origin")?;
    match origin {
        Expression::BooleanLiteral(literal) if literal.value => Some(Origin::Reflected),
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
            Some(Origin::Callback)
        }
        other => (string_value(other) == Some("*")).then_some(Origin::Wildcard),
    }
}

/// Builds the finding.
fn build_finding(unit: &FileUnit<'_>, hit: &Hit, with_credentials: bool) -> Finding {
    let meta = CorsPermissive::meta();

    // The browser refuses `*` alongside credentials, so that combination is not
    // the dangerous one. Reflecting the caller's origin with credentials is.
    let dangerous = with_credentials && hit.origin != Origin::Wildcard;
    let severity = if dangerous {
        Severity::High
    } else {
        Severity::Medium
    };
    // A callback we cannot evaluate might well be a correct allowlist.
    let confidence = if hit.origin == Origin::Callback {
        Confidence::Possible
    } else {
        Confidence::Likely
    };

    let why = if dangerous {
        "The response echoes the caller's origin and permits credentials, so any site a \
         logged-in user visits can make authenticated requests to this API and read the \
         replies. The browser's same-origin protection is switched off for every origin."
    } else {
        "Any origin may call this API and read the response. That is a deliberate choice for a \
         public endpoint and a mistake for anything behind a session — nothing in the source \
         says which this is, so it is reported for you to decide."
    };

    let evidence = if with_credentials {
        format!("{}, credentials allowed", hit.origin.evidence())
    } else {
        hit.origin.evidence().to_owned()
    };

    finding_builder_with(&meta, severity)
        .confidence(confidence)
        .why(why)
        .location(unit.location(hit.span))
        .snippet(unit.code_frame(hit.span, "accepts requests from any origin"))
        .context(unit.context(None, Some(evidence)))
        .fixes(remediation().select(unit.framework()))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

/// Every framework's fix.
fn remediation() -> Remediation {
    let table = Remediation::new(
        "Replace the wildcard with the origins that actually need access, and only send \
         credentials to those.",
    )
    .manual(
        Framework::NEXT,
        "Return an explicit origin from the route or middleware, not '*'.",
        "const allowed = new Set(['https://app.example.com'])\n\
         const origin = request.headers.get('origin') ?? ''\n\
         if (allowed.has(origin)) {\n  \
         response.headers.set('Access-Control-Allow-Origin', origin)\n  \
         response.headers.set('Vary', 'Origin')\n}",
    )
    .manual(
        Framework::NUXT,
        "List the origins in the route rules rather than reflecting the caller's.",
        "// nuxt.config.ts\nrouteRules: {\n  \
         '/api/**': {\n    \
         cors: true,\n    \
         headers: { 'Access-Control-Allow-Origin': 'https://app.example.com' },\n  \
         },\n}",
    )
    .manual(
        Framework::NEST,
        "Give enableCors an explicit origin list.",
        "app.enableCors({\n  \
         origin: ['https://app.example.com'],\n  \
         credentials: true,\n\
         })",
    )
    .manual(
        Framework::EXPRESS,
        "Give the cors middleware an explicit origin list.",
        "app.use(cors({\n  \
         origin: ['https://app.example.com'],\n  \
         credentials: true,\n\
         }))",
    )
    .manual(
        Framework::FASTIFY,
        "Register @fastify/cors with an explicit origin list.",
        "await app.register(cors, {\n  \
         origin: ['https://app.example.com'],\n  \
         credentials: true,\n\
         })",
    );
    newer_framework_fixes(table)
}

/// The frameworks added after the original five. Split from [`remediation`] to
/// stay under the function-length lint — the table itself is one continuous
/// declaration either way.
fn newer_framework_fixes(table: Remediation) -> Remediation {
    table
    .manual(
        Framework::HONO,
        "Use hono/cors with an explicit origin list.",
        "import { cors } from 'hono/cors'\n\n\
         app.use('*', cors({\n  \
         origin: ['https://app.example.com'],\n  \
         credentials: true,\n\
         }))",
    )
    .manual(
        Framework::KOA,
        "Give @koa/cors an explicit origin list.",
        "import cors from '@koa/cors'\n\n\
         app.use(cors({\n  \
         origin: ['https://app.example.com'],\n  \
         credentials: true,\n\
         }))",
    )
    .manual(
        Framework::HAPI,
        "Give the route's cors option an explicit origin list.",
        "server.route({\n  \
         method: 'GET',\n  \
         path: '/api/data',\n  \
         options: {\n    \
         cors: {\n      \
         origin: ['https://app.example.com'],\n      \
         credentials: true,\n    \
         },\n  \
         },\n  \
         handler: (request, h) => h.response({ ok: true }),\n\
         })",
    )
    .manual(
        Framework::SAILS,
        "Give sails.config.security.cors an explicit origin list.",
        "// config/security.js\n\
         module.exports.security = {\n  \
         cors: {\n    \
         allRoutes: true,\n    \
         allowOrigins: ['https://app.example.com'],\n    \
         allowCredentials: true,\n  \
         },\n\
         }",
    )
    .manual(
        Framework::ASTRO,
        "Set the header explicitly in the endpoint rather than reflecting the caller's origin.",
        "// src/pages/api/data.ts\n\
         const ALLOWED_ORIGIN = 'https://app.example.com'\n\n\
         export async function GET({ request }: APIContext) {\n  \
         const origin = request.headers.get('origin')\n  \
         const headers = new Headers()\n  \
         if (origin === ALLOWED_ORIGIN) {\n    \
         headers.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN)\n    \
         headers.set('Vary', 'Origin')\n  \
         }\n  \
         return new Response(JSON.stringify({ ok: true }), { headers })\n\
         }",
    )
    .manual(
        Framework::REMIX,
        "Return an explicit origin from the loader/action headers, not '*'.",
        "import { json } from '@remix-run/node'\n\n\
         export async function loader({ request }: LoaderFunctionArgs) {\n  \
         const allowed = new Set(['https://app.example.com'])\n  \
         const origin = request.headers.get('origin') ?? ''\n  \
         const headers = new Headers()\n  \
         if (allowed.has(origin)) {\n    \
         headers.set('Access-Control-Allow-Origin', origin)\n    \
         headers.set('Vary', 'Origin')\n  \
         }\n  \
         return json({ ok: true }, { headers })\n\
         }",
    )
    .manual(
        Framework::GATSBY,
        "Set the header explicitly in the Function handler, not '*'.",
        "// src/api/data.ts\n\
         const ALLOWED = new Set(['https://app.example.com'])\n\n\
         export default function handler(req: GatsbyFunctionRequest, res: GatsbyFunctionResponse) {\n  \
         const origin = req.headers.origin ?? ''\n  \
         if (ALLOWED.has(origin)) {\n    \
         res.setHeader('Access-Control-Allow-Origin', origin)\n    \
         res.setHeader('Vary', 'Origin')\n  \
         }\n  \
         res.json({ ok: true })\n\
         }",
    )
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}
