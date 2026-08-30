//! `open-redirect` — a redirect target the caller chooses.
//!
//! # Why it matters more than it looks
//!
//! `res.redirect(req.query.next)` reads like plumbing. It is the standard
//! ingredient in a credible phishing link: the URL genuinely starts with your
//! domain, the certificate is genuinely yours, and the user lands on the
//! attacker's login page. It is also the standard way an OAuth flow leaks its
//! authorisation code, because the code is handed to whatever redirect the
//! caller nominated.
//!
//! It survives review because the `?next=` parameter is a real feature — you do
//! want to send someone back where they came from after login. The bug is not
//! the parameter, it is the missing check on it, and "missing" is exactly what
//! is hard to see when reading code.
//!
//! # What it looks for
//!
//! A redirect sink whose target is caller-controlled, using the shared
//! [`RequestOrigin`] analysis. A redirect to a literal, to a config value, or
//! to a path this file assembles from its own constants is not a finding.
//!
//! # Why a leading-slash check is not enough
//!
//! Half the fixes people write are `if (next.startsWith('/'))`. That admits
//! `//evil.com`, which a browser reads as a protocol-relative URL to `evil.com`
//! — the check passes and the redirect leaves the site. The remediation here
//! resolves against a known base and compares the origin, which is the version
//! that holds.

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    Confidence, Finding, Framework, OwaspRef, Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::RelPath;
use owlwarden_core::surface::Surface;
use owlwarden_static::ast::{root_identifier, static_property};
use owlwarden_static::rule::{FileRule, FindingSink, RuleInfo};
use owlwarden_static::taint::RequestOrigin;
use owlwarden_static::unit::FileUnit;
use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "open-redirect";

/// Bare functions that redirect.
///
/// `redirect` is Next's and Nuxt's; `sendRedirect` is h3's.
const REDIRECT_FUNCTIONS: &[&str] = &["redirect", "sendRedirect", "navigateTo"];

/// Methods that redirect when called on a response-shaped object.
const REDIRECT_METHODS: &[&str] = &["redirect"];

/// The `Location` header, set by hand.
const LOCATION_HEADER: &str = "location";

/// Methods that set a header by name.
const HEADER_SETTERS: &[&str] = &["setHeader", "set", "header", "append"];

/// Findings collected from one file before the visitor stops.
const MAX_PER_FILE: usize = 16;

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenRedirect;

impl OpenRedirect {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Redirect target comes from the caller".into(),
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A01:2021")),
            asi: None,
            cwe: Some(601),
            surface: Surface::WebApp,
            category: "redirect".into(),
            description: "The destination of a redirect is taken from the request without being \
                          checked. An attacker can send a link that starts with your domain and \
                          ends on theirs, which is what makes a phishing page credible — and in \
                          an OAuth callback it hands the authorisation code to whoever asked. \
                          Resolve the target against your own origin and refuse anything else."
                .into(),
        }
    }
}

impl RuleInfo for OpenRedirect {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for OpenRedirect {
    fn applies_to(&self, path: &RelPath) -> bool {
        !path.as_str().ends_with(".d.ts")
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = RedirectVisitor::default();
        visitor.visit_program(unit.program);

        for hit in &visitor.hits {
            if !sink.push(build_finding(unit, hit)) {
                break;
            }
        }
    }
}

/// One redirect to a caller-chosen destination.
struct Hit {
    span: Span,
    /// Whether the whole target is the caller's, or only part of it.
    whole: bool,
}

#[derive(Default)]
struct RedirectVisitor {
    hits: Vec<Hit>,
    origin: RequestOrigin,
}

impl<'a> Visit<'a> for RedirectVisitor {
    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        self.origin.observe(declarator);
        oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.hits.len() < MAX_PER_FILE
            && let Some(target) = RedirectVisitor::redirect_target(call)
            && let Some(whole) = self.control_over(target)
        {
            self.hits.push(Hit {
                span: call.span,
                whole,
            });
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }

    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        // `set.headers.Location = next` — Elysia's canonical redirect, and the
        // same shape in any framework that exposes headers as an object rather
        // than a setter. A rule that only understood `setHeader('Location', …)`
        // would be structurally blind to a whole framework's idiom.
        if self.hits.len() < MAX_PER_FILE
            && let Some(property) = assignment_property(&assignment.left)
            && property.eq_ignore_ascii_case(LOCATION_HEADER)
            && let Some(whole) = self.control_over(&assignment.right)
        {
            self.hits.push(Hit {
                span: assignment.span,
                whole,
            });
        }
        oxc_ast_visit::walk::walk_assignment_expression(self, assignment);
    }
}

/// The property an assignment target names, for both `a.b` and `a['b']`.
///
/// The computed form matters: `set.headers['location'] = url` is the spelling a
/// lowercase header name forces, and it is as much a redirect as the dotted one.
fn assignment_property<'a>(target: &'a oxc_ast::ast::AssignmentTarget<'a>) -> Option<&'a str> {
    match target {
        oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member) => {
            Some(member.property.name.as_str())
        }
        oxc_ast::ast::AssignmentTarget::ComputedMemberExpression(member) => {
            owlwarden_static::ast::string_value(&member.expression)
        }
        _ => None,
    }
}

/// Whether an argument is an HTTP status code rather than a destination.
///
/// Only a bare numeric literal in the 3xx range counts. A variable holding a
/// status is not skipped, because a variable holding a *destination* is the
/// case that matters and the two are indistinguishable here — and skipping one
/// too many arguments would mean silently not firing.
fn is_status_literal(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::NumericLiteral(literal) if literal.value >= 300.0 && literal.value < 400.0
    )
}

impl RedirectVisitor {
    /// The expression naming where the caller will be sent, if this call is a
    /// redirect at all.
    fn redirect_target<'a>(call: &'a CallExpression<'a>) -> Option<&'a Expression<'a>> {
        let arguments: Vec<&Expression<'_>> = call
            .arguments
            .iter()
            .filter_map(Argument::as_expression)
            .collect();

        if let Expression::Identifier(identifier) = &call.callee
            && REDIRECT_FUNCTIONS.contains(&identifier.name.as_str())
        {
            // Three shapes share this name and none of them agree on argument
            // order: `redirect(to)`, `sendRedirect(event, to)` puts the event
            // first, and SvelteKit's `redirect(302, to)` puts the status first.
            //
            // So skip both — the first argument that is neither the event nor a
            // bare status number is the destination. Taking the *last* argument
            // instead, as the method arm does, would read `navigateTo(to, opts)`
            // as redirecting to an options object and quietly stop firing.
            return arguments
                .iter()
                .find(|argument| {
                    root_identifier(argument) != Some("event") && !is_status_literal(argument)
                })
                .copied();
        }

        let method = static_property(&call.callee)?;

        if REDIRECT_METHODS.contains(&method) {
            // Three orders again, and this time they disagree in both
            // directions: `res.redirect(url)`, Express's `res.redirect(302,
            // url)`, and the fetch API's `Response.redirect(url, 302)`. The
            // last argument that is not a status number is the destination in
            // all three.
            return arguments
                .iter()
                .rev()
                .find(|argument| !is_status_literal(argument))
                .copied();
        }

        // `res.setHeader('Location', url)` — the hand-rolled form, and the one
        // people reach for when they want a status code the helper will not
        // give them.
        if HEADER_SETTERS.contains(&method)
            && let [name, value] = arguments.as_slice()
            && owlwarden_static::ast::string_value(name)
                .is_some_and(|header| header.eq_ignore_ascii_case(LOCATION_HEADER))
        {
            return Some(value);
        }

        None
    }

    /// Whether the caller controls the target, and whether they control all of
    /// it. `None` when they do not control it at all.
    fn control_over(&self, target: &Expression<'_>) -> Option<bool> {
        if self.origin.taints(target) {
            return Some(true);
        }
        match target {
            Expression::TemplateLiteral(template) => template
                .expressions
                .iter()
                .any(|part| self.origin.taints(part))
                .then_some(false),
            Expression::BinaryExpression(binary) => (self.origin.taints(&binary.left)
                || self.origin.taints(&binary.right))
            .then_some(false),
            Expression::ParenthesizedExpression(inner) => self.control_over(&inner.expression),
            _ => None,
        }
    }
}

/// Builds the finding.
fn build_finding(unit: &FileUnit<'_>, hit: &Hit) -> Finding {
    let meta = OpenRedirect::meta();

    let (confidence, why, evidence) = if hit.whole {
        (
            Confidence::Likely,
            "The whole redirect target comes from the request, so a link to this endpoint can \
             send a visitor anywhere. The URL they click genuinely belongs to you, which is what \
             makes the page they land on convincing — and on an OAuth callback the \
             authorisation code goes with them.",
            "redirect target is caller-controlled",
        )
    } else {
        (
            Confidence::Possible,
            "Part of the redirect target comes from the request. A fixed prefix usually keeps \
             it on this site, but a value beginning with '//' is read by the browser as another \
             host entirely, and one containing '@' can move the destination as well.",
            "caller-controlled value interpolated into the redirect target",
        )
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

/// The check that actually holds, written once.
///
/// Resolving against a base and comparing origins, rather than a
/// `startsWith('/')` test — the latter is the fix most people write and it
/// admits `//evil.com`.
const SAFE_REDIRECT_HELPER: &str = "// lib/safe-redirect.ts\n\
     export function safeRedirect(target: unknown, base: string, fallback = '/'): string {\n  \
     if (typeof target !== 'string') return fallback\n  \
     try {\n    \
     const resolved = new URL(target, base)\n    \
     // Same origin only. This rejects '//evil.com', 'https://evil.com',\n    \
     // and 'javascript:' alike. A leading-slash test does not: the browser\n    \
     // reads '//evil.com' as a URL to another host.\n    \
     return resolved.origin === new URL(base).origin ? resolved.pathname + resolved.search : fallback\n  \
     } catch {\n    \
     return fallback\n  \
     }\n\
     }";

/// Every framework's fix.
fn remediation() -> Remediation {
    let table = Remediation::new(
        "Resolve the target against your own origin and refuse anything that lands elsewhere. Do \
         not use a startsWith('/') check: '//evil.com' passes it and leaves the site.",
    )
    .generic_patch(SAFE_REDIRECT_HELPER)
    .manual(
        Framework::NEXT,
        "Validate before calling redirect(); request.nextUrl.origin is the base.",
        "import { redirect } from 'next/navigation'\n\n\
         const next = request.nextUrl.searchParams.get('next')\n\
         redirect(safeRedirect(next, request.nextUrl.origin))",
    )
    .manual(
        Framework::NUXT,
        "Validate before sendRedirect(); getRequestURL(event).origin is the base.",
        "const { next } = getQuery(event)\n\
         await sendRedirect(event, safeRedirect(next, getRequestURL(event).origin), 302)",
    )
    .manual(
        Framework::NEST,
        "Validate in the controller, or put the check in a pipe so every redirect gets it.",
        "@Get('login')\n\
         @Redirect()\n\
         login(@Query('next') next: string) {\n  \
         return { url: safeRedirect(next, this.config.publicUrl) }\n\
         }",
    )
    .manual(
        Framework::EXPRESS,
        "Validate before res.redirect().",
        "const base = `${req.protocol}://${req.get('host')}`\n\
         res.redirect(safeRedirect(req.query.next, base))",
    )
    .manual(
        Framework::FASTIFY,
        "Validate before reply.redirect().",
        "const base = `${request.protocol}://${request.hostname}`\n\
         const next = (request.query as { next?: string }).next\n\
         return reply.redirect(safeRedirect(next, base))",
    )
    .manual(
        Framework::HONO,
        "Validate before calling c.redirect(); new URL(c.req.url).origin is the base.",
        "const next = c.req.query('next')\n\
         const base = new URL(c.req.url).origin\n\
         return c.redirect(safeRedirect(next, base))",
    )
    .manual(
        Framework::KOA,
        "Validate before ctx.redirect().",
        "const base = `${ctx.protocol}://${ctx.host}`\n\
         ctx.redirect(safeRedirect(ctx.query.next, base))",
    )
    .manual(
        Framework::HAPI,
        "Validate before h.redirect().",
        "const base = `${request.server.info.protocol}://${request.info.host}`\n\
         return h.redirect(safeRedirect(request.query.next, base))",
    )
    .manual(
        Framework::SAILS,
        "Validate before res.redirect().",
        "const base = `${req.protocol}://${req.get('host')}`\n\
         return res.redirect(safeRedirect(req.query.next, base))",
    )
    .manual(
        Framework::ASTRO,
        "Validate before calling redirect(); the request URL's origin is the base.",
        "export async function GET({ request, redirect }: APIContext) {\n  \
         const next = new URL(request.url).searchParams.get('next')\n  \
         return redirect(safeRedirect(next, new URL(request.url).origin))\n\
         }",
    )
    .manual(
        Framework::REMIX,
        "Validate before calling redirect(); the request URL's origin is the base.",
        "import { redirect } from '@remix-run/node'\n\n\
         export async function loader({ request }: LoaderFunctionArgs) {\n  \
         const url = new URL(request.url)\n  \
         const next = url.searchParams.get('next')\n  \
         return redirect(safeRedirect(next, url.origin))\n\
         }",
    )
    .manual(
        Framework::GATSBY,
        "Validate before res.redirect() in the Function handler.",
        "const base = `${req.headers['x-forwarded-proto'] ?? 'https'}://${req.headers.host}`\n\
         res.redirect(safeRedirect(req.query.next, base))",
    );
    fixes_added_in_1_2(table)
}

/// The four frameworks added in 1.2, and the runtime deltas.
///
/// A continuation rather than more of the same function. Sixteen profiles plus
/// the deltas is past what fits on a screen, and a table nobody scrolls to the
/// end of is a table with a hole in it.
fn fixes_added_in_1_2(table: Remediation) -> Remediation {
    table    .manual(
        Framework::SVELTEKIT,
        "Resolve the target against your own origin before redirecting. `redirect()` throws, so the check has to come first.",
        "redirect(302, safeRedirect(url.searchParams.get('next'), 'https://app.example.com'))",
    )
    .manual(
        Framework::TANSTACK_START,
        "Resolve the target against your own origin before redirecting.",
        "return Response.redirect(safeRedirect(next, 'https://app.example.com'), 302)",
    )
    .manual(
        Framework::SOLIDSTART,
        "Resolve the target against your own origin before redirecting.",
        "return redirect(safeRedirect(next, 'https://app.example.com'))",
    )
    .manual(
        Framework::ELYSIA,
        "Resolve the target against your own origin, then set Location.",
        "set.status = 302\nset.headers.Location = safeRedirect(query.next, 'https://app.example.com')",
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
    fn the_advice_does_not_recommend_a_leading_slash_check() {
        // `startsWith('/')` is the fix people write and it admits '//evil.com'.
        // Shipping it as remediation would be teaching the bug.
        let text = remediation()
            .all()
            .iter()
            .filter_map(|fix| fix.patch.clone())
            .collect::<String>();
        assert!(
            !text.contains("startsWith('/')"),
            "remediation regressed to a check that '//evil.com' defeats"
        );
    }

    #[test]
    fn the_generic_advice_compares_origins() {
        assert!(SAFE_REDIRECT_HELPER.contains("origin ==="));
    }
}
