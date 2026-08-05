//! Small AST questions that more than one rule needs to ask.
//!
//! These live in the engine rather than in the detector crate because they are
//! infrastructure: a plugin rule needs them as much as a first-party one does,
//! and a plugin cannot reach into `owlwarden-detectors`.
//!
//! Every traversal here is bounded. The input is a file we did not write, and a
//! deeply nested expression must cost us a `None`, not the stack.

use oxc_ast::ast::{Argument, Expression, MemberExpression, ObjectPropertyKind, PropertyKey};

/// How far a chain walk will follow before giving up.
const MAX_CHAIN_DEPTH: usize = 32;

/// The identifier a member/call chain is rooted at.
///
/// `res.status(500).json` and `res.json` both root at `res`; `NextResponse.json`
/// roots at `NextResponse`. Rules use this to recognise a response object
/// without enumerating every chain shape a codebase might use.
#[must_use]
pub fn root_identifier<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    let mut current = expression;
    for _ in 0..MAX_CHAIN_DEPTH {
        match current {
            Expression::Identifier(identifier) => return Some(identifier.name.as_str()),
            Expression::ThisExpression(_) => return Some("this"),
            Expression::StaticMemberExpression(member) => current = &member.object,
            Expression::ComputedMemberExpression(member) => current = &member.object,
            Expression::CallExpression(call) => current = &call.callee,
            Expression::ParenthesizedExpression(inner) => current = &inner.expression,
            Expression::TSNonNullExpression(inner) => current = &inner.expression,
            // `(err as Error).stack` is how the same code is written in a
            // TypeScript codebase with `unknown` catch bindings — which is to
            // say, in most of them. Stopping at the assertion made every rule
            // that follows a chain blind to idiomatic TypeScript.
            Expression::TSAsExpression(inner) => current = &inner.expression,
            Expression::TSSatisfiesExpression(inner) => current = &inner.expression,
            Expression::TSTypeAssertion(inner) => current = &inner.expression,
            Expression::AwaitExpression(inner) => current = &inner.argument,
            Expression::ChainExpression(chain) => {
                current = match &chain.expression {
                    oxc_ast::ast::ChainElement::CallExpression(call) => &call.callee,
                    oxc_ast::ast::ChainElement::StaticMemberExpression(member) => &member.object,
                    oxc_ast::ast::ChainElement::ComputedMemberExpression(member) => &member.object,
                    oxc_ast::ast::ChainElement::PrivateFieldExpression(member) => &member.object,
                    oxc_ast::ast::ChainElement::TSNonNullExpression(inner) => &inner.expression,
                };
            }
            _ => return None,
        }
    }
    None
}

/// The property name of a non-computed member access, e.g. `json` in
/// `res.json`.
#[must_use]
pub fn static_property<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::StaticMemberExpression(member) => Some(member.property.name.as_str()),
        Expression::ChainExpression(chain) => match &chain.expression {
            oxc_ast::ast::ChainElement::StaticMemberExpression(member) => {
                Some(member.property.name.as_str())
            }
            _ => None,
        },
        _ => None,
    }
}

/// The property name of a member expression node.
#[must_use]
pub fn member_property<'a>(member: &'a MemberExpression<'a>) -> Option<&'a str> {
    match member {
        MemberExpression::StaticMemberExpression(inner) => Some(inner.property.name.as_str()),
        _ => None,
    }
}

/// The name of an object key, in either bare or quoted form.
#[must_use]
pub fn property_name<'a>(key: &'a PropertyKey<'a>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(identifier.name.as_str()),
        PropertyKey::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// The value of an object literal's property, by key name.
///
/// Only looks one level down and only at literal keys. Rules use it to read
/// small option objects (`{ credentials: true }`); anything that needs to
/// follow a spread or a computed key needs data flow, which this is not.
#[must_use]
pub fn object_property<'a>(
    object: &'a oxc_ast::ast::ObjectExpression<'a>,
    name: &str,
) -> Option<&'a Expression<'a>> {
    object.properties.iter().find_map(|property| {
        let ObjectPropertyKind::ObjectProperty(entry) = property else {
            return None;
        };
        (property_name(&entry.key) == Some(name)).then_some(&entry.value)
    })
}

/// The object literal an argument holds, seeing through parentheses.
#[must_use]
pub fn argument_object<'a>(
    argument: &'a Argument<'a>,
) -> Option<&'a oxc_ast::ast::ObjectExpression<'a>> {
    match argument.as_expression()? {
        Expression::ObjectExpression(object) => Some(object),
        Expression::ParenthesizedExpression(inner) => match &inner.expression {
            Expression::ObjectExpression(object) => Some(object),
            _ => None,
        },
        _ => None,
    }
}

/// The literal string an expression evaluates to, if it plainly is one.
///
/// Template literals with no interpolation count; anything with a `${}` does
/// not, because its value is not knowable here.
#[must_use]
pub fn string_value<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
            .quasis
            .first()
            .and_then(|quasi| quasi.value.cooked.as_ref())
            .map(oxc_ast::ast::Str::as_str),
        Expression::ParenthesizedExpression(inner) => string_value(&inner.expression),
        _ => None,
    }
}

/// Whether an expression is the literal `true`.
#[must_use]
pub fn is_true_literal(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::BooleanLiteral(literal) => literal.value,
        Expression::ParenthesizedExpression(inner) => is_true_literal(&inner.expression),
        _ => false,
    }
}

/// Whether an expression is the literal `false`.
#[must_use]
pub fn is_false_literal(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::BooleanLiteral(literal) => !literal.value,
        Expression::ParenthesizedExpression(inner) => is_false_literal(&inner.expression),
        _ => false,
    }
}

/// Whether an identifier looks like it holds an error.
///
/// Used to keep `.stack` matching honest: `project.stack` in a response body is
/// a technology list, not a stack trace, and reporting it as a vulnerability is
/// exactly the kind of noise that gets a scanner uninstalled.
#[must_use]
pub fn looks_like_error_binding(name: &str) -> bool {
    matches!(
        name,
        "e" | "err"
            | "error"
            | "ex"
            | "exc"
            | "exception"
            | "cause"
            | "reason"
            | "thrown"
            | "caught"
    )
}

/// Whether a call reads an environment variable or a secret manager.
///
/// The negative case for several rules: `process.env.API_KEY` is how a secret
/// is *supposed* to arrive, so a rule looking for hardcoded credentials has to
/// recognise it and stay quiet.
#[must_use]
pub fn reads_from_environment(expression: &Expression<'_>) -> bool {
    let Some(root) = root_identifier(expression) else {
        return false;
    };
    matches!(root, "process" | "env" | "Deno" | "import" | "config")
}

/// HTTP method names, uppercase, as they appear as handler exports.
pub const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// Whether a name is an HTTP verb used as a handler export (`export function GET`).
#[must_use]
pub fn http_method_export(name: &str) -> Option<String> {
    HTTP_METHODS
        .contains(&name)
        .then(|| name.to_ascii_uppercase())
}

/// Whether a decorator name is a NestJS route verb (`@Get`, `@Post`).
#[must_use]
pub fn nest_method_decorator(name: &str) -> Option<String> {
    const DECORATORS: &[&str] = &["Get", "Post", "Put", "Patch", "Delete", "Head", "Options"];
    DECORATORS
        .contains(&name)
        .then(|| name.to_ascii_uppercase())
}

/// Whether a router method name is an HTTP verb (`app.get`, `fastify.post`).
///
/// `all` and `use` register a handler for every method, and report as such.
#[must_use]
pub fn router_method(name: &str) -> Option<String> {
    const VERBS: &[&str] = &[
        "get", "post", "put", "patch", "delete", "head", "options", "all",
    ];
    if name == "all" {
        return Some("ANY".to_owned());
    }
    VERBS.contains(&name).then(|| name.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn router_verbs_map_to_methods_and_all_means_any() {
        assert_eq!(router_method("get").as_deref(), Some("GET"));
        assert_eq!(router_method("all").as_deref(), Some("ANY"));
        assert_eq!(router_method("listen"), None);
        assert_eq!(router_method("use"), None);
    }

    #[test]
    fn handler_exports_are_recognised_only_when_uppercase() {
        assert_eq!(http_method_export("GET").as_deref(), Some("GET"));
        // A lowercase `get` is an ordinary function, not an App Router handler.
        assert_eq!(http_method_export("get"), None);
    }

    #[test]
    fn nest_decorators_map_to_methods() {
        assert_eq!(nest_method_decorator("Get").as_deref(), Some("GET"));
        assert_eq!(nest_method_decorator("Injectable"), None);
    }
}
