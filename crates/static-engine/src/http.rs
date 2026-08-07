//! Framework-aware AST questions: "is this a response sink?", "which handler
//! am I in?".
//!
//! Every rule that cares about data reaching a client needs to answer the first
//! question, and every rule that wants to say `GET /api/users` needs the
//! second. Before this module they were answered by private constants inside
//! one rule, which meant the second rule to need them copied the list, and the
//! copy went stale.
//!
//! The answers come from the detected [`FrameworkSet`], so the same rule works
//! on Fastify and Next.js without knowing either exists.

use oxc_ast::ast::{CallExpression, Expression, NewExpression};

use crate::ast::{root_identifier, static_property};
use crate::framework::FrameworkSet;

/// Whether a call writes an HTTP response body.
///
/// Requires **both** a known response object and a known body method:
/// `res.json(...)` is a sink, `logger.json(...)` is not, and `res.status(500)`
/// is not either. Matching on the method alone would flag every logging call in
/// a codebase, which is the single fastest way to make a rule useless.
#[must_use]
pub fn is_response_sink(frameworks: &FrameworkSet, callee: &Expression<'_>) -> bool {
    // h3, and therefore Nuxt, writes responses with bare helpers:
    // `send(event, body)`, `createError({ ... })`. No object to anchor on, so
    // the name has to carry the whole signal — which is why the helper lists in
    // the profiles are short and specific.
    if let Expression::Identifier(identifier) = callee {
        let name = identifier.name.as_str();
        return frameworks.any(|profile| profile.http.is_response_helper(name));
    }

    let Some(method) = static_property(callee) else {
        return false;
    };
    let Some(root) = root_identifier(callee) else {
        return false;
    };
    frameworks
        .any(|profile| profile.http.is_body_method(method) && profile.http.is_response_object(root))
}

/// Whether `new X(...)` builds a response or an HTTP error carrying a body.
///
/// The `*Exception` suffix is accepted beyond the names any profile lists,
/// because NestJS users subclass `HttpException` constantly and a third-party
/// exception is as much a response sink as a built-in one. It is a naming
/// convention rather than a guess: a class called `PaymentRequiredException`
/// that is not an HTTP exception is not a thing anyone writes.
#[must_use]
pub fn is_response_constructor(frameworks: &FrameworkSet, callee: &Expression<'_>) -> bool {
    let Expression::Identifier(identifier) = callee else {
        return false;
    };
    let name = identifier.name.as_str();
    if name.ends_with("Exception") {
        return true;
    }
    frameworks.any(|profile| profile.http.is_response_constructor(name))
}

/// Whether a call sets a cookie, and on which object.
///
/// Matches both the `object.method` spelling any profile declares
/// (`res.cookie`, `reply.setCookie`, `ctx.cookies.set`) and the bare helper
/// form (`setCookie(event, ...)`) that h3 and Nuxt use.
///
/// Nested members matter: Koa's idiomatic `ctx.cookies.set(...)` is three
/// parts, and matching only `root.method` would see `ctx.set` and miss it.
#[must_use]
pub fn is_cookie_setter(frameworks: &FrameworkSet, callee: &Expression<'_>) -> bool {
    if let Expression::Identifier(identifier) = callee {
        let name = identifier.name.as_str();
        return frameworks.any(|profile| {
            profile
                .http
                .cookie_setters
                .iter()
                .any(|setter| setter == name)
        });
    }

    // Prefer the full static chain (`ctx.cookies.set`). When the chain has a
    // call in the middle (`cookies().set`), fall back to `root.method` — the
    // Next.js spelling — because there is no single identifier path.
    if let Some(path) = member_path(callee)
        && cookie_path_matches(frameworks, &path)
    {
        return true;
    }

    let Some(method) = static_property(callee) else {
        return false;
    };
    let Some(root) = root_identifier(callee) else {
        return false;
    };
    cookie_path_matches(frameworks, &format!("{root}.{method}"))
        || frameworks.any(|profile| {
            profile
                .http
                .cookie_setters
                .iter()
                .any(|setter| setter == method)
        })
}

fn cookie_path_matches(frameworks: &FrameworkSet, path: &str) -> bool {
    frameworks.any(|profile| {
        profile.http.cookie_setters.iter().any(|setter| {
            setter == path
                || path.ends_with(&format!(".{setter}"))
                || path
                    .rsplit_once('.')
                    .is_some_and(|(_, method)| method == setter)
        })
    })
}

/// A dotted member path such as `ctx.cookies.set`, bounded so a hostile
/// chain cannot force unbounded work. Stops at a call (`cookies().set`) —
/// callers fall back to [`root_identifier`] for that spelling.
fn member_path(expression: &Expression<'_>) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    let mut current = expression;
    for _ in 0..8 {
        match current {
            Expression::StaticMemberExpression(member) => {
                parts.push(member.property.name.as_str());
                current = &member.object;
            }
            Expression::ChainExpression(chain) => match &chain.expression {
                oxc_ast::ast::ChainElement::StaticMemberExpression(member) => {
                    parts.push(member.property.name.as_str());
                    current = &member.object;
                }
                _ => return None,
            },
            Expression::Identifier(identifier) => {
                parts.push(identifier.name.as_str());
                parts.reverse();
                return Some(parts.join("."));
            }
            _ => return None,
        }
    }
    None
}

/// Whether a call enables CORS (`app.use(cors(...))`, `app.enableCors(...)`).
#[must_use]
pub fn is_cors_enabler(frameworks: &FrameworkSet, callee: &Expression<'_>) -> bool {
    let name = match callee {
        Expression::Identifier(identifier) => identifier.name.as_str(),
        _ => match static_property(callee) {
            Some(method) => method,
            None => return false,
        },
    };
    frameworks.any(|profile| {
        profile
            .http
            .cors_enablers
            .iter()
            .any(|enabler| enabler == name)
    })
}

/// A route registration found in the AST: `app.get('/users', handler)`.
///
/// This is how Express and Fastify routes are discovered, since their paths are
/// arguments rather than file names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRegistration {
    /// Uppercase HTTP method, or `ANY` for `app.all`.
    pub method: String,
    /// The path literal, when it is a literal. A computed path is skipped
    /// rather than guessed at.
    pub path: String,
}

/// Reads a route registration out of a call, if it is one.
///
/// Requires a known router object, a verb method, and a literal first argument.
/// `app.use(...)` is deliberately not a registration: it mounts middleware on
/// everything, so reporting it as a route would attribute findings to a path
/// the code does not own.
#[must_use]
pub fn route_registration(
    frameworks: &FrameworkSet,
    call: &CallExpression<'_>,
) -> Option<RouteRegistration> {
    let method_name = static_property(&call.callee)?;
    let method = crate::ast::router_method(method_name)?;
    let root = root_identifier(&call.callee)?;

    if !frameworks.any(|profile| profile.http.is_router_object(root)) {
        return None;
    }

    let first = call.arguments.first()?.as_expression()?;
    let path = crate::ast::string_value(first)?;
    // A router verb whose first argument is not a path is something else, such
    // as `app.get('trust proxy')` reading an Express setting. Requiring a
    // leading slash keeps those out.
    if !path.starts_with('/') {
        return None;
    }

    Some(RouteRegistration {
        method,
        path: path.to_owned(),
    })
}

/// Whether a `new` expression constructs a response.
#[must_use]
pub fn new_is_response(frameworks: &FrameworkSet, expression: &NewExpression<'_>) -> bool {
    is_response_constructor(frameworks, &expression.callee)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::framework::FrameworkRegistry;
    use crate::parse::with_parsed;
    use crate::unit::UnitMeta;
    use owlwarden_core::finding::Framework;
    use owlwarden_core::source::RelPath;
    use oxc_ast_visit::Visit;

    fn frameworks(id: &Framework) -> FrameworkSet {
        let registry = FrameworkRegistry::builtin();
        let profile = registry.get(id).expect("a builtin profile");
        FrameworkSet::new(vec![profile], registry.generic())
    }

    /// Collects the answer to one question over every call in a snippet.
    struct Probe<'q> {
        frameworks: &'q FrameworkSet,
        sinks: usize,
        cookies: usize,
        routes: Vec<RouteRegistration>,
    }

    impl<'a> Visit<'a> for Probe<'_> {
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            if is_response_sink(self.frameworks, &call.callee) {
                self.sinks += 1;
            }
            if is_cookie_setter(self.frameworks, &call.callee) {
                self.cookies += 1;
            }
            if let Some(route) = route_registration(self.frameworks, call) {
                self.routes.push(route);
            }
            oxc_ast_visit::walk::walk_call_expression(self, call);
        }
    }

    fn rel(path: &str) -> RelPath {
        RelPath::new(std::path::Path::new(path)).expect("a relative path")
    }

    fn probe(id: &Framework, source: &str) -> (usize, usize, Vec<RouteRegistration>) {
        let set = frameworks(id);
        let path = rel("app.ts");
        let meta = UnitMeta {
            frameworks: std::sync::Arc::new(set),
            route: None,
        };
        with_parsed(&path, source, meta, |unit| {
            let mut probe = Probe {
                frameworks: &unit.meta.frameworks,
                sinks: 0,
                cookies: 0,
                routes: Vec::new(),
            };
            probe.visit_program(unit.program);
            (probe.sinks, probe.cookies, probe.routes)
        })
        .expect("snippet parses")
    }

    #[test]
    fn a_response_write_is_a_sink_in_every_framework() {
        assert_eq!(probe(&Framework::EXPRESS, "res.json({ a: 1 })").0, 1);
        assert_eq!(probe(&Framework::FASTIFY, "reply.send({ a: 1 })").0, 1);
        assert_eq!(probe(&Framework::NEXT, "NextResponse.json({ a: 1 })").0, 1);
    }

    #[test]
    fn logging_and_metadata_calls_are_not_sinks() {
        // The whole point of requiring object *and* method.
        assert_eq!(probe(&Framework::EXPRESS, "logger.json({ a: 1 })").0, 0);
        assert_eq!(probe(&Framework::EXPRESS, "console.write('x')").0, 0);
        assert_eq!(probe(&Framework::EXPRESS, "res.status(500)").0, 0);
        assert_eq!(probe(&Framework::EXPRESS, "res.setHeader('x', 'y')").0, 0);
    }

    #[test]
    fn a_chained_write_is_still_a_sink() {
        assert_eq!(probe(&Framework::EXPRESS, "res.status(500).json({})").0, 1);
        assert_eq!(
            probe(&Framework::FASTIFY, "reply.code(500).send({})").0,
            1,
            "fastify chains code() before send()"
        );
    }

    #[test]
    fn cookie_setters_are_recognised_in_each_framework_spelling() {
        assert_eq!(probe(&Framework::EXPRESS, "res.cookie('s', v)").1, 1);
        assert_eq!(probe(&Framework::FASTIFY, "reply.setCookie('s', v)").1, 1);
        assert_eq!(probe(&Framework::NUXT, "setCookie(event, 's', v)").1, 1);
        assert_eq!(
            probe(&Framework::KOA, "ctx.cookies.set('s', v)").1,
            1,
            "Koa's three-part chain must match"
        );
        assert_eq!(
            probe(&Framework::NEXT, "cookies().set('s', v)").1,
            1,
            "Next's cookies().set must still match through the call"
        );
        assert_eq!(
            probe(&Framework::HONO, "c.header('X-Request-Id', '1')").1,
            0,
            "ordinary headers are not cookie writes"
        );
        assert_eq!(
            probe(
                &Framework::GATSBY,
                "res.setHeader('Content-Type', 'text/plain')"
            )
            .1,
            0,
            "setHeader is not a cookie write"
        );
    }

    #[test]
    fn route_registrations_come_from_the_call_not_the_path() {
        let (_, _, routes) = probe(
            &Framework::EXPRESS,
            "app.get('/users', h); app.post('/users/:id', h); app.all('/any', h)",
        );
        assert_eq!(
            routes,
            vec![
                RouteRegistration {
                    method: "GET".to_owned(),
                    path: "/users".to_owned()
                },
                RouteRegistration {
                    method: "POST".to_owned(),
                    path: "/users/:id".to_owned()
                },
                RouteRegistration {
                    method: "ANY".to_owned(),
                    path: "/any".to_owned()
                },
            ]
        );
    }

    #[test]
    fn settings_and_middleware_are_not_route_registrations() {
        // Express's setting reader shares the name of its route verb.
        assert!(
            probe(&Framework::EXPRESS, "app.get('trust proxy')")
                .2
                .is_empty()
        );
        assert!(probe(&Framework::EXPRESS, "app.use(helmet())").2.is_empty());
        // A computed path is skipped rather than guessed at.
        assert!(
            probe(&Framework::EXPRESS, "app.get(basePath, h)")
                .2
                .is_empty()
        );
    }

    #[test]
    fn a_nest_app_still_sees_the_express_response_underneath() {
        let registry = FrameworkRegistry::builtin();
        let set = FrameworkSet::new(
            vec![
                registry.get(&Framework::NEST).expect("nest"),
                registry.get(&Framework::EXPRESS).expect("express"),
            ],
            registry.generic(),
        );
        let path = rel("controller.ts");
        let meta = UnitMeta {
            frameworks: std::sync::Arc::new(set),
            route: None,
        };
        let sinks = with_parsed(&path, "res.jsonp({ a: 1 })", meta, |unit| {
            let mut probe = Probe {
                frameworks: &unit.meta.frameworks,
                sinks: 0,
                cookies: 0,
                routes: Vec::new(),
            };
            probe.visit_program(unit.program);
            probe.sinks
        })
        .expect("snippet parses");

        // `jsonp` is Express vocabulary, not Nest's. A single-framework lookup
        // would miss it, which is why the set is queried rather than the
        // primary.
        assert_eq!(sinks, 1);
    }
}
