//! Reading NestJS decorators.
//!
//! Nest states its routing in decorators rather than in file paths, so this is
//! the equivalent of [`owlwarden_static::framework::routing`] for that
//! framework: `@Controller('users')` on the class and `@Get(':id')` on the
//! method together make `GET /users/:id`.
//!
//! Shared because more than one rule wants it — attributing a finding to a
//! method is useful whatever the finding is.

use owlwarden_static::ast::{nest_method_decorator, string_value};
use oxc_ast::ast::{Decorator, Expression};

/// The HTTP method a set of method decorators declares, if any.
///
/// `@Get()` gives `GET`. A method carrying several route decorators is not
/// something Nest supports, so the first match wins.
#[must_use]
pub fn method_from_decorators(decorators: &[Decorator<'_>]) -> Option<String> {
    decorators.iter().find_map(|decorator| {
        let name = decorator_name(decorator)?;
        nest_method_decorator(name)
    })
}

/// The path argument of a routing decorator, if it is a literal.
///
/// `@Get('profile')` gives `profile`; `@Get()` and `@Get(SOME_CONST)` give
/// `None`, because a route we would have to guess at is worse than no route.
#[must_use]
pub fn path_from_decorators(decorators: &[Decorator<'_>], names: &[&str]) -> Option<String> {
    decorators.iter().find_map(|decorator| {
        let name = decorator_name(decorator)?;
        if !names.contains(&name) {
            return None;
        }
        let Expression::CallExpression(call) = &decorator.expression else {
            return None;
        };
        let first = call.arguments.first()?.as_expression()?;
        string_value(first).map(std::borrow::ToOwned::to_owned)
    })
}

/// Whether any decorator in the list has one of the given names.
#[must_use]
pub fn has_decorator(decorators: &[Decorator<'_>], names: &[&str]) -> bool {
    decorators
        .iter()
        .filter_map(decorator_name)
        .any(|name| names.contains(&name))
}

/// The bare name of a decorator, with or without a call: both `@Injectable` and
/// `@Injectable()` give `Injectable`.
#[must_use]
pub fn decorator_name<'a>(decorator: &'a Decorator<'a>) -> Option<&'a str> {
    match &decorator.expression {
        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
        Expression::CallExpression(call) => match &call.callee {
            Expression::Identifier(identifier) => Some(identifier.name.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// Joins a `@Controller` prefix and a method path into a route.
///
/// Nest is forgiving about leading and trailing slashes; the report should not
/// be, because `/users//profile` looks like a bug in the tool.
#[must_use]
pub fn join_route(controller: Option<&str>, method_path: Option<&str>) -> Option<String> {
    let segments: Vec<&str> = [controller, method_path]
        .into_iter()
        .flatten()
        .flat_map(|part| part.split('/'))
        .filter(|segment| !segment.is_empty())
        .collect();

    if segments.is_empty() {
        return controller.or(method_path).map(|_| "/".to_owned());
    }
    Some(format!("/{}", segments.join("/")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn routes_join_without_doubled_slashes() {
        assert_eq!(
            join_route(Some("users"), Some(":id")).as_deref(),
            Some("/users/:id")
        );
        assert_eq!(
            join_route(Some("/users/"), Some("/profile")).as_deref(),
            Some("/users/profile")
        );
        assert_eq!(join_route(Some("users"), None).as_deref(), Some("/users"));
        assert_eq!(join_route(Some(""), None).as_deref(), Some("/"));
        assert_eq!(join_route(None, None), None);
    }
}
