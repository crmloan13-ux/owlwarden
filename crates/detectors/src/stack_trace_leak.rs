//! `stack-trace-leak` — an error's `.stack` reaching an HTTP response body.
//!
//! # What it looks for, and why that shape
//!
//! The rule fires on one thing: a `.stack` member access somewhere inside the
//! arguments of a call that sends a response. Both halves matter.
//!
//! Matching `.stack` alone is far too broad — `res.json({ stack: project.stack })`
//! is a technology list, not a leak. Matching only inside a `catch` block is too
//! narrow — plenty of handlers stash the error and respond later.
//!
//! So we require **response sink + error-ish binding**:
//! `NextResponse.json({ error: err.stack })` fires; `console.error(err.stack)`
//! does not, because logging a stack trace server-side is correct behaviour and
//! flagging it would train users to ignore the tool.
//!
//! # Where the framework knowledge comes from
//!
//! What counts as a response sink is not written here. The rule asks the
//! project's [`FrameworkSet`](owlwarden_static::FrameworkSet) via
//! [`owlwarden_static::http`], so it recognises `reply.send` in a Fastify app
//! and `NextResponse.json` in a Next.js one without containing either name. Add
//! a framework profile and this rule covers it with no edit.

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    Confidence, Finding, Framework, OwaspRef, Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::RelPath;
use owlwarden_core::surface::Surface;
use owlwarden_static::ast::{http_method_export, looks_like_error_binding, root_identifier};
use owlwarden_static::framework::FrameworkSet;
use owlwarden_static::http::{is_response_constructor, is_response_sink};
use owlwarden_static::rule::{FileRule, FindingSink, RuleInfo};
use owlwarden_static::unit::FileUnit;
use oxc_ast::ast::{
    BindingPattern, CallExpression, CatchClause, NewExpression, StaticMemberExpression,
};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "stack-trace-leak";

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct StackTraceLeak;

impl StackTraceLeak {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Stack trace leaked in error response".into(),
            severity: Severity::High,
            // Static analysis can see the expression but not whether the route
            // is reachable in production, so this rule stops at Likely. Only
            // correlation with a live response promotes it to Confirmed.
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A05:2021")),
            asi: None,
            cwe: Some(209),
            surface: Surface::WebApp,
            category: "error-handling".into(),
            description: "Returning an error's `.stack` to the client exposes absolute file \
                          paths, dependency versions, and internal call structure. Attackers \
                          use it to map the application and to fingerprint vulnerable \
                          dependency versions. Log the stack server-side and return a generic \
                          message."
                .into(),
        }
    }
}

impl RuleInfo for StackTraceLeak {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for StackTraceLeak {
    fn applies_to(&self, path: &RelPath) -> bool {
        // Type declaration files contain no executable code.
        !path.as_str().ends_with(".d.ts")
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = LeakVisitor::new(unit.frameworks());
        visitor.visit_program(unit.program);

        for leak in visitor.leaks {
            if !sink.push(build_finding(unit, &leak)) {
                break;
            }
        }
    }
}

/// One `.stack` access found inside a response body.
struct Leak {
    /// Span of the `<binding>.stack` expression, for the underline.
    span: Span,
    /// HTTP method of the enclosing handler, when we could name it.
    method: Option<String>,
    /// Whether the binding is a `catch` parameter in scope, which makes the
    /// match unambiguous rather than name-based.
    from_catch: bool,
}

/// Findings collected before the visitor gives up. A file that trips this many
/// times is generated or the rule is wrong; either way the report is already
/// unreadable.
const MAX_LEAKS_PER_FILE: usize = 64;

/// Walks the file looking for the sink-plus-error-binding shape.
struct LeakVisitor<'f> {
    frameworks: &'f FrameworkSet,
    leaks: Vec<Leak>,
    /// Bindings introduced by enclosing `catch` clauses.
    catch_bindings: Vec<String>,
    /// How many response-sink argument lists we are currently inside. A counter
    /// rather than a flag because sinks nest:
    /// `res.json({ e: JSON.stringify(err.stack) })`.
    sink_depth: u32,
    /// Name of the enclosing HTTP handler, if the framework's conventions name
    /// one.
    current_method: Option<String>,
}

impl<'f> LeakVisitor<'f> {
    fn new(frameworks: &'f FrameworkSet) -> Self {
        Self {
            frameworks,
            leaks: Vec::new(),
            catch_bindings: Vec::new(),
            sink_depth: 0,
            current_method: None,
        }
    }

    /// Whether `.stack` on this object is a real error stack.
    fn is_error_stack(&self, member: &StaticMemberExpression<'_>) -> Option<bool> {
        if member.property.name.as_str() != "stack" {
            return None;
        }
        let root = root_identifier(&member.object)?;
        if self.catch_bindings.iter().any(|binding| binding == root) {
            return Some(true);
        }
        if looks_like_error_binding(root) {
            return Some(false);
        }
        None
    }
}

impl<'a> Visit<'a> for LeakVisitor<'_> {
    fn visit_catch_clause(&mut self, clause: &CatchClause<'a>) {
        let bound = clause
            .param
            .as_ref()
            .and_then(|param| match &param.pattern {
                BindingPattern::BindingIdentifier(identifier) => Some(identifier.name.to_string()),
                // `catch ({ stack })` destructures; there is no binding left to
                // track, so such a file falls back to name matching.
                _ => None,
            });

        if let Some(name) = bound {
            self.catch_bindings.push(name);
            oxc_ast_visit::walk::walk_catch_clause(self, clause);
            self.catch_bindings.pop();
        } else {
            oxc_ast_visit::walk::walk_catch_clause(self, clause);
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.visit_expression(&call.callee);

        let is_sink = is_response_sink(self.frameworks, &call.callee);
        if is_sink {
            self.sink_depth = self.sink_depth.saturating_add(1);
        }
        for argument in &call.arguments {
            self.visit_argument(argument);
        }
        if is_sink {
            self.sink_depth = self.sink_depth.saturating_sub(1);
        }
    }

    fn visit_new_expression(&mut self, expression: &NewExpression<'a>) {
        self.visit_expression(&expression.callee);

        let is_sink = is_response_constructor(self.frameworks, &expression.callee);
        if is_sink {
            self.sink_depth = self.sink_depth.saturating_add(1);
        }
        for argument in &expression.arguments {
            self.visit_argument(argument);
        }
        if is_sink {
            self.sink_depth = self.sink_depth.saturating_sub(1);
        }
    }

    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        // Koa (and friends) write the body with `ctx.body = …` rather than a
        // method call. Treat that assignment as a response sink when the left
        // side is `<responseObject>.body`.
        let is_body_assign = match &assignment.left {
            oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member)
                if member.property.name.as_str() == "body" =>
            {
                root_identifier(&member.object).is_some_and(|root| {
                    self.frameworks
                        .any(|profile| profile.http.is_response_object(root))
                })
            }
            _ => false,
        };
        if is_body_assign {
            self.sink_depth = self.sink_depth.saturating_add(1);
        }
        oxc_ast_visit::walk::walk_assignment_expression(self, assignment);
        if is_body_assign {
            self.sink_depth = self.sink_depth.saturating_sub(1);
        }
    }

    fn visit_static_member_expression(&mut self, member: &StaticMemberExpression<'a>) {
        if self.sink_depth > 0
            && self.leaks.len() < MAX_LEAKS_PER_FILE
            && let Some(from_catch) = self.is_error_stack(member)
        {
            self.leaks.push(Leak {
                span: member.span,
                method: self.current_method.clone(),
                from_catch,
            });
        }
        oxc_ast_visit::walk::walk_static_member_expression(self, member);
    }

    fn visit_function(
        &mut self,
        function: &oxc_ast::ast::Function<'a>,
        flags: oxc_syntax::scope::ScopeFlags,
    ) {
        let previous = self.current_method.take();
        self.current_method = function
            .id
            .as_ref()
            .and_then(|id| http_method_export(id.name.as_str()))
            .or(previous.clone());
        oxc_ast_visit::walk::walk_function(self, function, flags);
        self.current_method = previous;
    }

    fn visit_method_definition(&mut self, method: &oxc_ast::ast::MethodDefinition<'a>) {
        // NestJS: `@Get()` on a class method names the HTTP verb.
        let previous = self.current_method.take();
        self.current_method = crate::decorator::method_from_decorators(&method.decorators)
            .or_else(|| previous.clone());
        oxc_ast_visit::walk::walk_method_definition(self, method);
        self.current_method = previous;
    }

    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        // `export const GET = async () => { ... }` — the App Router's other
        // spelling of a handler.
        let named = match &declarator.id {
            BindingPattern::BindingIdentifier(identifier) => {
                http_method_export(identifier.name.as_str())
            }
            _ => None,
        };

        if let Some(method) = named {
            let previous = self.current_method.replace(method);
            oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
            self.current_method = previous;
        } else {
            oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
        }
    }
}

/// Turns one leak into a finding, with the fix for the detected framework.
fn build_finding(unit: &FileUnit<'_>, leak: &Leak) -> Finding {
    let meta = StackTraceLeak::meta();
    let context = unit.context(leak.method.clone(), Some(unit.span_text(leak.span, 80)));

    finding_builder(&meta)
        // A `.stack` on a binding we watched a `catch` introduce is not a
        // guess. A name-based match ("err") is still strong, but it is one
        // inference away, so it does not claim the same certainty.
        .confidence(if leak.from_catch {
            Confidence::Likely
        } else {
            Confidence::Possible
        })
        .why(
            "Stack traces expose absolute file paths, dependency versions, and internal call \
             structure — enough to fingerprint the stack and locate other weaknesses.",
        )
        .location(unit.location(leak.span))
        .snippet(unit.code_frame(leak.span, "leaks internal stack trace to the client"))
        .context(context)
        .fixes(remediation().select(unit.framework()))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

/// Drop-in for the underlined `.stack` expression. Safe: same type (string),
/// no API-shape guess — only stops leaking the trace. Framework-specific
/// entries below stay Manual educational examples for `explain`.
const SAFE_STACK_REPLACEMENT: &str = "'Internal Server Error'";

/// Every framework's fix.
///
/// The generic entry is `Safe` so `--fix` can replace the highlighted
/// `.stack` expression. Framework rows stay `Manual` multi-line examples —
/// those rewrite the whole handler and must not be auto-applied.
fn remediation() -> Remediation {
    Remediation::new("Log the error server-side and return a generic message to the client.")
        .generic_patch(SAFE_STACK_REPLACEMENT)
        .generic_safety(owlwarden_core::finding::FixSafety::Safe)
        .manual(
            Framework::NEXT,
            "Return a generic message; log the error server-side.",
            "console.error(err)\n\
             return NextResponse.json(\n  \
             { error: 'Internal Server Error' },\n  \
             { status: 500 },\n)",
        )
        .manual(
            Framework::NUXT,
            "Throw a createError() without the internal detail; Nitro shapes the response.",
            "console.error(err)\n\
             throw createError({\n  \
             statusCode: 500,\n  \
             statusMessage: 'Internal Server Error',\n\
             })",
        )
        .manual(
            Framework::NEST,
            "Throw the exception without a custom body; let the built-in filter shape the \
             response.",
            "this.logger.error(err)\nthrow new InternalServerErrorException()",
        )
        .manual(
            Framework::EXPRESS,
            "Log server-side and send a generic body.",
            "console.error(err)\nres.status(500).json({ error: 'Internal Server Error' })",
        )
        .manual(
            Framework::FASTIFY,
            "Log through the request logger and send a generic body.",
            "request.log.error(err)\n\
             reply.code(500).send({ error: 'Internal Server Error' })",
        )
        .manual(
            Framework::HONO,
            "Log server-side and send a generic body.",
            "console.error(err)\nreturn c.json({ error: 'Internal Server Error' }, 500)",
        )
        .manual(
            Framework::KOA,
            "Log server-side and send a generic body.",
            "console.error(err)\nctx.status = 500\nctx.body = { error: 'Internal Server Error' }",
        )
        .manual(
            Framework::HAPI,
            "Log server-side and let Boom shape a generic error response.",
            "request.log(['error'], err)\nthrow Boom.internal('Internal Server Error')",
        )
        .manual(
            Framework::SAILS,
            "Log server-side and send a generic body.",
            "sails.log.error(err)\nreturn res.status(500).json({ error: 'Internal Server Error' })",
        )
        .manual(
            Framework::ASTRO,
            "Log server-side and return a generic response.",
            "console.error(err)\n\
             return new Response(JSON.stringify({ error: 'Internal Server Error' }), {\n  \
             status: 500,\n  \
             headers: { 'Content-Type': 'application/json' },\n\
             })",
        )
        .manual(
            Framework::REMIX,
            "Log server-side and return a generic response.",
            "import { json } from '@remix-run/node'\n\n\
             console.error(err)\n\
             return json({ error: 'Internal Server Error' }, { status: 500 })",
        )
        .manual(
            Framework::GATSBY,
            "Log server-side and send a generic body.",
            "console.error(err)\nres.status(500).json({ error: 'Internal Server Error' })",
        )
    .manual(
        Framework::SVELTEKIT,
        "Log server-side and return a generic body from the endpoint. SvelteKit's `handleError` hook is where the detail belongs.",
        "console.error(err)\nreturn json({ error: 'Internal Server Error' }, { status: 500 })",
    )
    .manual(
        Framework::TANSTACK_START,
        "Log server-side and return a generic body from the server function.",
        "console.error(err)\nreturn new Response(JSON.stringify({ error: 'Internal Server Error' }), {\n  status: 500,\n  headers: { 'content-type': 'application/json' },\n})",
    )
    .manual(
        Framework::SOLIDSTART,
        "Log server-side and return a generic body from the API route.",
        "console.error(err)\nreturn json({ error: 'Internal Server Error' }, { status: 500 })",
    )
    .manual(
        Framework::ELYSIA,
        "Use `onError` so every route answers the same way, and keep the detail in the log.",
        "app.onError(({ error, set }) => {\n  console.error(error)\n  set.status = 500\n  return { error: 'Internal Server Error' }\n})",
    )
}

/// Every framework's fix, for `owlwarden explain` and the rule catalogue page.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}
