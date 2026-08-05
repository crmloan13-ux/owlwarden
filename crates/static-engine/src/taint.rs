//! Where a value came from: shared request-origin analysis.
//!
//! Almost every injection-shaped rule asks the same question — *did this value
//! come from the caller?* — and the answer decides whether a finding is
//! actionable today or merely poor practice. When each rule answered it
//! privately, they disagreed: `sql-injection` knew about `searchParams`,
//! nothing knew about a value held in a local for one line, and the frameworks
//! each spell the request differently. A rule was as good as whichever list its
//! author remembered to write.
//!
//! This module is that question, once. A rule declares its sinks; the origin
//! analysis is infrastructure, so a new rule inherits it and a fix here reaches
//! every rule at the same time — including plugin rules, which is the point of
//! putting it in the engine rather than in the first-party detector crate.
//!
//! # What it is, precisely
//!
//! A **one-hop, intra-procedural, flow-insensitive** origin check:
//!
//! - *One hop* — `const id = req.params.id` marks `id`. `const a = id` does
//!   not mark `a`.
//! - *Intra-procedural* — nothing crosses a function boundary.
//! - *Flow-insensitive* — a later reassignment does not clear the mark.
//!
//! # Why not a real taint engine
//!
//! Because a partial one that people believe is worse than an honest heuristic.
//! Full inter-procedural taint tracking over TypeScript needs type resolution
//! and a call graph; it is a different project, it is slow, and it fails on
//! dynamic dispatch in ways the reader cannot predict. What it *does* deliver is
//! a claim of completeness — "if it were reachable we would have found it" —
//! which this cannot honestly make.
//!
//! So the contract is narrow and stated: this decides
//! [`Confidence`](owlwarden_core::finding::Confidence), never whether to report.
//! A rule fires on its sink either way; the origin only separates *"the caller
//! controls this"* (`Likely`) from *"this is assembled at runtime and might"*
//! (`Possible`). A false negative here costs a confidence level, not a missed
//! finding, and that is the right thing to be wrong about.
//!
//! Growing past this is a deliberate decision with an ADR, not a patch.

use oxc_ast::ast::{BindingPattern, Expression, VariableDeclarator};

use crate::ast::root_identifier;
use crate::framework::FrameworkSet;

/// Identifiers that hold caller-controlled data in the frameworks we support.
///
/// Framework-independent because the names overlap heavily and a false entry
/// costs a confidence level rather than a wrong finding. Anything genuinely
/// framework-specific belongs in that framework's
/// [`HttpVocabulary`](crate::framework::HttpVocabulary), where a plugin can
/// extend it.
const UNIVERSAL_SOURCES: &[&str] = &[
    "req",
    "request",
    "params",
    "query",
    "body",
    "searchParams",
    "input",
    "payload",
    "ctx",
    "context",
    "event",
    "args",
    "formData",
    "headers",
    "cookies",
    "userInput",
    "untrusted",
];

/// Properties that yield caller data when read off anything.
///
/// Catches the shapes the root-identifier check misses: `getQuery(event).id`
/// returns a fresh object, and `someWrapper.body` is request data regardless of
/// what the wrapper is called.
const SOURCE_PROPERTIES: &[&str] = &["body", "query", "params", "searchParams", "formData"];

/// Framework helpers that return request data.
///
/// Nuxt/h3 reads the request through free functions rather than off an object,
/// so a root-identifier check sees `getQuery` and learns nothing.
const SOURCE_HELPERS: &[&str] = &[
    "getQuery",
    "readBody",
    "readRawBody",
    "getRouterParams",
    "getRouterParam",
    "getRequestHeaders",
    "getRequestHeader",
    "getCookie",
    "useQuery",
    "readMultipartFormData",
    "readValidatedBody",
    "getValidatedQuery",
];

/// Locals tracked per file.
///
/// A hand-written module does not declare more than this from request data; one
/// that does is generated, and analysing it further buys nothing. Bounded
/// because the input is untrusted (`ARCHITECTURE.md` §"Coding Standards").
const MAX_TRACKED_LOCALS: usize = 256;

/// Tracks which locals in the current file hold caller-controlled data.
///
/// Build one per file, feed it every [`VariableDeclarator`] as the visitor
/// walks, and ask [`RequestOrigin::taints`] at the sink. Rules that already
/// walk the tree can drive it from their own visitor; see `sql_injection.rs`.
#[derive(Debug, Default, Clone)]
pub struct RequestOrigin {
    locals: Vec<String>,
}

impl RequestOrigin {
    /// An empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a declaration, marking the binding if its initialiser is
    /// caller-controlled.
    ///
    /// Only simple `const x = <expr>` bindings are tracked. Destructuring —
    /// `const { id } = req.params` — is deliberately skipped: marking every
    /// name in the pattern would be right here and wrong for
    /// `const { rows } = await db.query(...)`, and the engine cannot tell the
    /// two apart without types.
    pub fn observe(&mut self, declarator: &VariableDeclarator<'_>) {
        if self.locals.len() >= MAX_TRACKED_LOCALS {
            return;
        }
        let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
            return;
        };
        let Some(init) = &declarator.init else {
            return;
        };
        if is_request_expression(init) {
            self.locals.push(identifier.name.to_string());
        }
    }

    /// Whether an expression carries caller-controlled data, directly or
    /// through a local this tracker has seen assigned from one.
    #[must_use]
    pub fn taints(&self, expression: &Expression<'_>) -> bool {
        if is_request_expression(expression) {
            return true;
        }
        root_identifier(expression).is_some_and(|root| self.locals.iter().any(|held| held == root))
    }

    /// Number of locals currently marked. Exposed for tests and diagnostics.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.locals.len()
    }
}

/// Whether an expression reads caller-controlled data, ignoring locals.
///
/// Three shapes, because the frameworks disagree about how you reach the
/// request: rooted at a request object (`req.body.email`), reading a request
/// property off anything (`input.query.q`), or calling a framework helper
/// (`getQuery(event).sort`).
#[must_use]
pub fn is_request_expression(expression: &Expression<'_>) -> bool {
    if root_identifier(expression).is_some_and(|root| UNIVERSAL_SOURCES.contains(&root)) {
        return true;
    }
    if reads_source_property(expression) {
        return true;
    }
    calls_source_helper(expression)
}

/// Whether the chain reads one of the request-bearing property names.
fn reads_source_property(expression: &Expression<'_>) -> bool {
    let mut current = expression;
    // Bounded: a member chain longer than this is not something we can reason
    // about, and an unbounded walk over untrusted input is exactly what
    // `ARCHITECTURE.md` forbids.
    for _ in 0..16 {
        match current {
            Expression::StaticMemberExpression(member) => {
                if SOURCE_PROPERTIES.contains(&member.property.name.as_str()) {
                    return true;
                }
                current = &member.object;
            }
            Expression::ComputedMemberExpression(member) => current = &member.object,
            // Descend past the *method name*, not through it. `db.query(...)`
            // is a call to something named `query`, not a read of a `query`
            // property, and conflating the two made every database call in the
            // codebase look caller-controlled.
            Expression::CallExpression(call) => match &call.callee {
                Expression::StaticMemberExpression(member) => current = &member.object,
                other => current = other,
            },
            Expression::TSNonNullExpression(inner) => current = &inner.expression,
            Expression::TSAsExpression(inner) => current = &inner.expression,
            Expression::ParenthesizedExpression(inner) => current = &inner.expression,
            Expression::AwaitExpression(inner) => current = &inner.argument,
            _ => return false,
        }
    }
    false
}

/// Whether the chain bottoms out in a framework request helper.
fn calls_source_helper(expression: &Expression<'_>) -> bool {
    let mut current = expression;
    for _ in 0..16 {
        match current {
            Expression::CallExpression(call) => match &call.callee {
                Expression::Identifier(identifier) => {
                    return SOURCE_HELPERS.contains(&identifier.name.as_str());
                }
                Expression::StaticMemberExpression(member) => {
                    if SOURCE_HELPERS.contains(&member.property.name.as_str()) {
                        return true;
                    }
                    current = &member.object;
                }
                other => current = other,
            },
            Expression::StaticMemberExpression(member) => current = &member.object,
            Expression::ComputedMemberExpression(member) => current = &member.object,
            Expression::AwaitExpression(inner) => current = &inner.argument,
            Expression::TSNonNullExpression(inner) => current = &inner.expression,
            Expression::TSAsExpression(inner) => current = &inner.expression,
            Expression::ParenthesizedExpression(inner) => current = &inner.expression,
            _ => return false,
        }
    }
    false
}

/// Whether a framework in this project reads the request through free
/// functions, which changes what an unqualified call means.
///
/// Nuxt/h3 does; Express does not. Kept here so a rule does not have to know
/// the difference.
#[must_use]
pub fn uses_functional_request_api(frameworks: &FrameworkSet) -> bool {
    frameworks.contains(&owlwarden_core::finding::Framework::NUXT)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::parse::with_parsed;
    use crate::unit::UnitMeta;
    use owlwarden_core::source::RelPath;

    /// Parses a snippet and hands the unit to `f`.
    fn parsed<T>(source: &str, f: impl FnOnce(&crate::unit::FileUnit<'_>) -> T) -> T {
        let path = RelPath::new(std::path::Path::new("t.ts")).unwrap();
        with_parsed(&path, source, UnitMeta::generic(), f).expect("snippet should parse")
    }

    /// Whether the initialiser in `const out = <source>` reads request data.
    fn taints(source: &str) -> bool {
        let mut answer = false;
        parsed(&format!("const out = {source};"), |unit| {
            let origin = RequestOrigin::new();
            for statement in &unit.program.body {
                if let oxc_ast::ast::Statement::VariableDeclaration(declaration) = statement {
                    for declarator in &declaration.declarations {
                        if let Some(init) = &declarator.init {
                            answer = origin.taints(init);
                        }
                    }
                }
            }
        });
        answer
    }

    #[test]
    fn a_value_rooted_at_the_request_is_caller_controlled() {
        assert!(taints("req.body.email"));
        assert!(taints("request.query.sort"));
        assert!(taints("params.id"));
        assert!(taints("searchParams.get('q')"));
    }

    #[test]
    fn typescript_assertions_do_not_hide_the_root() {
        // The idiom in every strict-mode codebase. Missing this made the origin
        // check useless on exactly the projects most likely to run it.
        assert!(taints("(request.query as { q: string }).q"));
        assert!(taints("(req.body as Payload).email"));
    }

    #[test]
    fn framework_helpers_count_as_the_request() {
        assert!(taints("getQuery(event).sort"));
        assert!(taints("await readBody(event)"));
        assert!(taints("getRouterParam(event, 'id')"));
    }

    #[test]
    fn ordinary_values_are_not_caller_controlled() {
        assert!(!taints("config.database.host"));
        assert!(!taints("'SELECT 1'"));
        assert!(!taints("user.id"));
        assert!(!taints("await db.query('SELECT 1')"));
    }

    #[test]
    fn a_local_holding_request_data_carries_the_mark_one_hop() {
        parsed(
            "const term = req.query.q; const other = term; sink(term);",
            |unit| {
                let mut origin = RequestOrigin::new();
                for statement in &unit.program.body {
                    if let oxc_ast::ast::Statement::VariableDeclaration(declaration) = statement {
                        for declarator in &declaration.declarations {
                            origin.observe(declarator);
                        }
                    }
                }
                assert_eq!(
                    origin.tracked(),
                    1,
                    "only the direct assignment is tracked; the second hop is out of scope by design"
                );
            },
        );
    }

    #[test]
    fn tracking_is_bounded() {
        let mut origin = RequestOrigin {
            locals: (0..MAX_TRACKED_LOCALS)
                .map(|index| format!("v{index}"))
                .collect(),
        };
        parsed("const extra = req.body.x;", |unit| {
            for statement in &unit.program.body {
                if let oxc_ast::ast::Statement::VariableDeclaration(declaration) = statement {
                    for declarator in &declaration.declarations {
                        origin.observe(declarator);
                    }
                }
            }
        });
        assert_eq!(origin.tracked(), MAX_TRACKED_LOCALS, "the cap held");
    }
}
