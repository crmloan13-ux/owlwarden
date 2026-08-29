//! Reading one file for everything that decides its exposure.
//!
//! One visitor rather than five, because the questions overlap: the same
//! `app.use(requireAuth)` is a mount, a gate reference, and — if the file also
//! registers routes — the gate for those routes. Answering them in separate
//! passes would mean resolving the same identifier three times and, worse,
//! three chances for the answers to disagree.
//!
//! Nothing here decides an [`Exposure`](owlwarden_core::finding::Exposure). It
//! collects evidence; [`super::ExposureClassifier`] weighs it. That split is
//! what keeps the loud-direction rule in one place instead of spread across a
//! visitor.

use std::collections::BTreeMap;

use oxc_ast::ast::{
    Argument, CallExpression, Class, Decorator, Expression, ImportDeclaration, ObjectExpression,
    Program, Statement, VariableDeclarator,
};
use oxc_ast_visit::Visit;

use crate::ast::{property_name, root_identifier, static_property, string_value};
use crate::framework::FrameworkProfile;
use crate::framework::auth;
use crate::unit::FileUnit;

use super::ModuleResolver;

/// Route registrations, mounts, and imports read from one file.
///
/// Bounded at every list: the input is a file in a repository nobody vetted,
/// and an unbounded collection here is memory an attacker chooses the size of.
const MAX_ITEMS: usize = 64;

/// A gate that was positively identified, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRef {
    /// The name as the source spells it: `requireAuth`, `clerkMiddleware`.
    pub name: String,
    /// `path:line` of the declaration.
    pub location: String,
    /// One clause naming what identified it, for the reader who disagrees.
    pub reason: String,
}

/// A gate mounted for later requests, and the path prefix it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMount {
    /// The prefix the mount covers. `None` means every route on that router —
    /// `app.use(requireAuth)` with no path.
    pub prefix: Option<String>,
    /// The gate, when what was mounted is one. A mount of something we do not
    /// recognise carries `None` and gates nothing.
    pub gate: Option<GateRef>,
    /// `path:line`, used only to make the order of equal mounts total.
    pub declared_at: String,
}

impl RouteMount {
    /// Whether this mount covers a route.
    ///
    /// A prefix-less mount covers everything. A prefixed mount covers a route
    /// that starts with the prefix at a segment boundary, so `/api` covers
    /// `/api/users` and does not cover `/apikeys`.
    ///
    /// An unknown route is covered only by a prefix-less mount. Guessing that a
    /// prefixed mount probably applies is exactly the reassuring direction this
    /// axis refuses to fail in.
    #[must_use]
    pub fn covers(&self, route: Option<&str>) -> bool {
        let Some(prefix) = &self.prefix else {
            return true;
        };
        let Some(route) = route else {
            return false;
        };
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() || prefix == "/" {
            return true;
        }
        route == prefix
            || route
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// Everything one file says about its own exposure.
#[derive(Debug, Clone, Default)]
pub struct FileFacts {
    /// Routes this file registers with a call, as literal paths.
    pub routes: Vec<String>,
    /// Mounts declared in this file.
    pub mounts: Vec<RouteMount>,
    /// A gate covering every route the server serves, declared here.
    pub global_gate: Option<GateRef>,
    /// A gate covering the handlers in this file: a decorator, a route option,
    /// or an enforcing call inside the handler.
    pub inline_gate: Option<GateRef>,
    /// Whether the file declares an HTTP handler at all — an exported verb, a
    /// Nest method decorator, a `defineEventHandler`.
    pub declares_handler: bool,
    /// Whether it default-exports a `fetch` handler, which is how every
    /// fetch-API runtime spells "this file serves requests".
    pub exports_fetch: bool,
}

/// Reads one parsed file.
#[must_use]
pub fn collect_facts(
    unit: &FileUnit<'_>,
    profiles: &[&FrameworkProfile],
    resolver: &ModuleResolver,
) -> FileFacts {
    let mut imports = ImportMap::default();
    imports.read(unit.program);

    let mut visitor = FactVisitor {
        unit,
        profiles,
        resolver,
        imports: &imports,
        facts: FileFacts::default(),
        session_bindings: Vec::new(),
        guarded_bindings: Vec::new(),
    };
    visitor.visit_program(unit.program);
    visitor.finish()
}

/// Local name to module specifier, for the imports of one file.
#[derive(Debug, Default)]
struct ImportMap {
    bindings: BTreeMap<String, String>,
}

impl ImportMap {
    fn read(&mut self, program: &Program<'_>) {
        for statement in program.body.iter().take(512) {
            let Statement::ImportDeclaration(import) = statement else {
                continue;
            };
            self.read_declaration(import);
        }
    }

    fn read_declaration(&mut self, import: &ImportDeclaration<'_>) {
        let specifier = import.source.value.as_str().to_owned();
        let Some(specifiers) = &import.specifiers else {
            return;
        };
        for entry in specifiers.iter().take(MAX_ITEMS) {
            let local = match entry {
                oxc_ast::ast::ImportDeclarationSpecifier::ImportSpecifier(named) => {
                    named.local.name.as_str()
                }
                oxc_ast::ast::ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => {
                    default.local.name.as_str()
                }
                oxc_ast::ast::ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => {
                    namespace.local.name.as_str()
                }
            };
            if self.bindings.len() >= MAX_ITEMS {
                return;
            }
            self.bindings.insert(local.to_owned(), specifier.clone());
        }
    }

    fn specifier(&self, name: &str) -> Option<&str> {
        self.bindings.get(name).map(String::as_str)
    }
}

struct FactVisitor<'a, 'p> {
    unit: &'a FileUnit<'a>,
    profiles: &'p [&'p FrameworkProfile],
    resolver: &'p ModuleResolver,
    imports: &'p ImportMap,
    facts: FileFacts,
    /// Names bound to the result of a session-reading call.
    session_bindings: Vec<(String, String, u32)>,
    /// Names later checked in a branch that returns or throws.
    guarded_bindings: Vec<String>,
}

impl FactVisitor<'_, '_> {
    fn finish(mut self) -> FileFacts {
        if self.facts.inline_gate.is_none() {
            // A session read only becomes a gate once something is done about
            // the answer. `const session = await auth()` on its own gates
            // nothing, and calling it one would be the reassuring lie.
            if let Some((_name, call, line)) = self
                .session_bindings
                .iter()
                .find(|(name, _, _)| self.guarded_bindings.iter().any(|held| held == name))
            {
                self.facts.inline_gate = Some(GateRef {
                    name: call.clone(),
                    location: format!("{}:{line}", self.unit.path.as_str()),
                    reason: format!(
                        "`{call}` is checked in a branch that returns or throws before the handler \
                         continues"
                    ),
                });
            }
        }
        self.facts
    }

    fn line_of(&self, span: oxc_span::Span) -> u32 {
        self.unit.position(span.start).0
    }

    fn here(&self, span: oxc_span::Span) -> String {
        format!("{}:{}", self.unit.path.as_str(), self.line_of(span))
    }

    /// Whether an expression, used as middleware, is a positively identified
    /// gate — and what to call it.
    fn gate_of(&self, expression: &Expression<'_>) -> Option<GateRef> {
        match expression {
            Expression::Identifier(identifier) => {
                let name = identifier.name.as_str();
                self.gate_of_name(name, identifier.span)
            }
            // `passport.authenticate('jwt')`, `jwt({ secret })`,
            // `clerkMiddleware()` — the gate is whatever the call is rooted in.
            Expression::CallExpression(call) => self.gate_of_call(call),
            Expression::TSAsExpression(inner) => self.gate_of(&inner.expression),
            Expression::TSNonNullExpression(inner) => self.gate_of(&inner.expression),
            Expression::ParenthesizedExpression(inner) => self.gate_of(&inner.expression),
            // An inline arrow or function expression is a middleware whose body
            // we would have to understand. We do not, so it is not a gate.
            _ => None,
        }
    }

    fn gate_of_call(&self, call: &CallExpression<'_>) -> Option<GateRef> {
        let root = root_identifier(&call.callee)?;
        let method = static_property(&call.callee);
        let name = method.map_or_else(|| root.to_owned(), |method| format!("{root}.{method}"));

        if let Some(specifier) = self.imports.specifier(root) {
            if auth::is_auth_package(specifier) {
                return Some(GateRef {
                    name,
                    location: self.here(call.span),
                    reason: format!("`{root}` is imported from `{specifier}`, an auth package"),
                });
            }
            if auth::is_relative_specifier(specifier)
                && self.resolver.resolves(self.unit.path.as_str(), specifier)
                && (auth::is_gate_name(root) || method.is_some_and(auth::is_gate_name))
            {
                return Some(GateRef {
                    name,
                    location: self.here(call.span),
                    reason: format!("`{root}` is defined in `{specifier}`"),
                });
            }
            return None;
        }
        // Locally defined, in this file.
        if auth::is_gate_name(root) || method.is_some_and(auth::is_gate_name) {
            return Some(GateRef {
                name,
                location: self.here(call.span),
                reason: "the middleware's name identifies it as an authentication check".to_owned(),
            });
        }
        None
    }

    fn gate_of_name(&self, name: &str, span: oxc_span::Span) -> Option<GateRef> {
        if let Some(specifier) = self.imports.specifier(name) {
            return super::imported_name_is_gate(
                self.resolver,
                self.unit.path.as_str(),
                name,
                specifier,
            )
            .then(|| GateRef {
                name: name.to_owned(),
                location: self.here(span),
                reason: format!("`{name}` is imported from `{specifier}`"),
            });
        }
        // Not imported: either defined here or a global. A global we cannot see
        // is not a gate, and the only way to tell them apart cheaply is that a
        // gate defined here has a name that says so.
        auth::is_gate_name(name).then(|| GateRef {
            name: name.to_owned(),
            location: self.here(span),
            reason: "the middleware's name identifies it as an authentication check".to_owned(),
        })
    }

    /// Records a `app.use(...)` / `fastify.addHook(...)` style mount.
    fn record_mount(&mut self, call: &CallExpression<'_>, method: &str) {
        if self.facts.mounts.len() >= MAX_ITEMS {
            return;
        }
        let mut arguments = call.arguments.iter();
        let first = arguments.next().and_then(Argument::as_expression);

        // Fastify's `addHook('onRequest', gate)` names the lifecycle point in
        // the first argument; a hook that is not a pre-handler point cannot
        // gate anything, however good the second argument looks.
        if self.profiles.iter().any(|profile| {
            profile
                .auth
                .mount_methods
                .iter()
                .any(|known| known == method)
                && !profile.auth.pre_handler_hooks.is_empty()
        }) && let Some(hook) = first.and_then(string_value)
            && !hook.starts_with('/')
        {
            let is_pre_handler = self
                .profiles
                .iter()
                .any(|profile| profile.auth.is_pre_handler_hook(hook));
            if !is_pre_handler {
                return;
            }
            let gate = call
                .arguments
                .iter()
                .skip(1)
                .take(4)
                .filter_map(Argument::as_expression)
                .find_map(|argument| self.gate_of(argument));
            self.facts.mounts.push(RouteMount {
                prefix: None,
                gate,
                declared_at: self.here(call.span),
            });
            return;
        }

        let prefix = first
            .and_then(string_value)
            .filter(|value| value.starts_with('/'))
            .map(mount_prefix);
        let gate = call
            .arguments
            .iter()
            .take(8)
            .filter_map(Argument::as_expression)
            .find_map(|argument| self.gate_of(argument));
        self.facts.mounts.push(RouteMount {
            prefix,
            gate,
            declared_at: self.here(call.span),
        });
    }

    /// A route registration: `app.get('/users', handler)`.
    fn record_route(&mut self, call: &CallExpression<'_>) {
        let Some(route) = crate::http::route_registration(self.unit.frameworks(), call) else {
            return;
        };
        if self.facts.routes.len() < MAX_ITEMS {
            self.facts.routes.push(route.path);
        }
        // Fastify and Hapi carry the gate in the route's own options object.
        if self.facts.inline_gate.is_some() {
            return;
        }
        for argument in call.arguments.iter().take(8) {
            let Some(Expression::ObjectExpression(options)) = argument.as_expression() else {
                continue;
            };
            if let Some(gate) = self.gate_in_options(options) {
                self.facts.inline_gate = Some(gate);
                return;
            }
        }
    }

    /// A gate declared inside a route-options object.
    fn gate_in_options(&self, options: &ObjectExpression<'_>) -> Option<GateRef> {
        for property in options.properties.iter().take(MAX_ITEMS) {
            let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(entry) = property else {
                continue;
            };
            let Some(key) = property_name(&entry.key) else {
                continue;
            };
            if !self
                .profiles
                .iter()
                .any(|profile| profile.auth.is_gate_option_key(key))
            {
                continue;
            }
            // Hapi: `{ auth: 'jwt' }` or `{ auth: { strategy: 'jwt' } }`. The
            // key alone is the declaration, but `auth: false` is the documented
            // way to *open* a route and must never read as a gate.
            if crate::ast::is_false_literal(&entry.value) {
                continue;
            }
            if let Some(gate) = self.gate_of(&entry.value) {
                return Some(gate);
            }
            if let Expression::ArrayExpression(items) = &entry.value
                && let Some(gate) = items
                    .elements
                    .iter()
                    .take(MAX_ITEMS)
                    .filter_map(|element| element.as_expression())
                    .find_map(|element| self.gate_of(element))
            {
                return Some(gate);
            }
            if string_value(&entry.value).is_some()
                || matches!(
                    &entry.value,
                    Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
                )
            {
                return Some(GateRef {
                    name: key.to_owned(),
                    location: self.here(entry.span),
                    reason: format!(
                        "the route declares `{key}`, which this framework treats as an \
                         authentication requirement"
                    ),
                });
            }
        }
        None
    }

    /// Handler-level gate declared with a decorator: `@UseGuards(JwtGuard)`.
    fn gate_in_decorators(&self, decorators: &[Decorator<'_>]) -> Option<GateRef> {
        for decorator in decorators.iter().take(MAX_ITEMS) {
            let name = match &decorator.expression {
                Expression::Identifier(identifier) => identifier.name.as_str(),
                Expression::CallExpression(call) => match &call.callee {
                    Expression::Identifier(identifier) => identifier.name.as_str(),
                    _ => continue,
                },
                _ => continue,
            };
            if !self
                .profiles
                .iter()
                .any(|profile| profile.auth.is_gate_decorator(name))
            {
                continue;
            }
            return Some(GateRef {
                name: format!("@{name}"),
                location: self.here(decorator.span),
                reason: format!("`@{name}` gates the handler it decorates"),
            });
        }
        None
    }

    /// The dotted call path, for matching against declared call lists.
    fn call_path(call: &CallExpression<'_>) -> Option<String> {
        let root = root_identifier(&call.callee)?;
        Some(match static_property(&call.callee) {
            Some(method) => format!("{root}.{method}"),
            None => root.to_owned(),
        })
    }
}

impl<'a> Visit<'a> for FactVisitor<'_, '_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(path) = Self::call_path(call) {
            let method = static_property(&call.callee);

            // A gate covering the whole server.
            if self.facts.global_gate.is_none()
                && self.profiles.iter().any(|profile| {
                    profile
                        .auth
                        .global_gate_calls
                        .iter()
                        .any(|known| known == &path)
                })
            {
                self.facts.global_gate = Some(GateRef {
                    name: path.clone(),
                    location: self.here(call.span),
                    reason: format!("`{path}` applies to every route the server serves"),
                });
            }

            // A call that rejects the request by itself.
            if self.facts.inline_gate.is_none()
                && self
                    .profiles
                    .iter()
                    .any(|profile| profile.auth.is_enforcing_call(&path))
            {
                self.facts.inline_gate = Some(GateRef {
                    name: path.clone(),
                    location: self.here(call.span),
                    reason: format!("`{path}` rejects the request when there is no session"),
                });
            }

            if let Some(method) = method {
                if self
                    .profiles
                    .iter()
                    .any(|profile| profile.auth.is_mount_method(method))
                {
                    self.record_mount(call, method);
                }
                if crate::ast::router_method(method).is_some() {
                    self.record_route(call);
                }
            }

            // `defineEventHandler(...)` and friends: the file serves requests.
            if matches!(
                path.as_str(),
                "defineEventHandler" | "eventHandler" | "defineLazyEventHandler" | "createRoute"
            ) {
                self.facts.declares_handler = true;
            }
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        // `export const POST = async (request) => { ... }`.
        if let Some(name) = declarator.id.get_identifier_name()
            && crate::ast::http_method_export(name.as_str()).is_some()
        {
            self.facts.declares_handler = true;
        }
        if let Some(init) = &declarator.init
            && let Some(name) = declarator.id.get_identifier_name()
        {
            let call = match init {
                Expression::AwaitExpression(await_expression) => match &await_expression.argument {
                    Expression::CallExpression(call) => Some(&**call),
                    _ => None,
                },
                Expression::CallExpression(call) => Some(&**call),
                _ => None,
            };
            if let Some(call) = call
                && let Some(path) = Self::call_path(call)
                && self
                    .profiles
                    .iter()
                    .any(|profile| profile.auth.is_session_reader(&path))
                && self.session_bindings.len() < MAX_ITEMS
            {
                self.session_bindings.push((
                    name.as_str().to_owned(),
                    path,
                    self.line_of(call.span),
                ));
            }
        }
        oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
    }

    fn visit_if_statement(&mut self, statement: &oxc_ast::ast::IfStatement<'a>) {
        if branch_exits(&statement.consequent) {
            collect_tested_names(&statement.test, &mut self.guarded_bindings);
        }
        oxc_ast_visit::walk::walk_if_statement(self, statement);
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        if self.facts.inline_gate.is_none()
            && let Some(gate) = self.gate_in_decorators(&class.decorators)
        {
            self.facts.inline_gate = Some(gate);
        }
        for element in class.body.body.iter().take(256) {
            let oxc_ast::ast::ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if crate::ast::HTTP_METHODS.iter().any(|verb| {
                method.decorators.iter().any(|decorator| {
                    matches!(&decorator.expression,
                        Expression::CallExpression(call)
                            if matches!(&call.callee, Expression::Identifier(id)
                                if crate::ast::nest_method_decorator(id.name.as_str()).as_deref() == Some(*verb)))
                })
            }) {
                self.facts.declares_handler = true;
            }
            if self.facts.inline_gate.is_none()
                && let Some(gate) = self.gate_in_decorators(&method.decorators)
            {
                self.facts.inline_gate = Some(gate);
            }
        }
        oxc_ast_visit::walk::walk_class(self, class);
    }

    fn visit_function(
        &mut self,
        function: &oxc_ast::ast::Function<'a>,
        flags: oxc_syntax::scope::ScopeFlags,
    ) {
        // `export async function GET()` — the App Router's spelling, and the
        // one Astro, Remix, and SolidStart share.
        if let Some(id) = &function.id
            && crate::ast::http_method_export(id.name.as_str()).is_some()
        {
            self.facts.declares_handler = true;
        }
        oxc_ast_visit::walk::walk_function(self, function, flags);
    }

    fn visit_export_default_declaration(
        &mut self,
        declaration: &oxc_ast::ast::ExportDefaultDeclaration<'a>,
    ) {
        if let oxc_ast::ast::ExportDefaultDeclarationKind::ObjectExpression(object) =
            &declaration.declaration
        {
            for property in object.properties.iter().take(MAX_ITEMS) {
                let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(entry) = property else {
                    continue;
                };
                if property_name(&entry.key) == Some("fetch") {
                    self.facts.exports_fetch = true;
                }
            }
        }
        oxc_ast_visit::walk::walk_export_default_declaration(self, declaration);
    }
}

/// The prefix a mount covers, normalised so `/api/` and `/api` are one thing.
fn mount_prefix(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Whether a branch body leaves the handler — a `return` or a `throw`.
///
/// Bounded to the statements directly in the block. A guard nested three blocks
/// deep is not recognised, which costs a false `internet`; recursing without a
/// bound on a file nobody vetted costs a stack.
fn branch_exits(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(block) => block.body.iter().take(64).any(|inner| {
            matches!(
                inner,
                Statement::ReturnStatement(_) | Statement::ThrowStatement(_)
            )
        }),
        _ => false,
    }
}

/// Identifier names referenced anywhere in a boolean test.
///
/// Bounded traversal: `!session`, `session === null`, `!session?.user` and
/// `!user || !user.id` all name the binding, and that is all the caller needs.
fn collect_tested_names(expression: &Expression<'_>, out: &mut Vec<String>) {
    fn walk(expression: &Expression<'_>, out: &mut Vec<String>, depth: u8) {
        if depth > 8 || out.len() >= MAX_ITEMS {
            return;
        }
        match expression {
            Expression::Identifier(identifier) => out.push(identifier.name.as_str().to_owned()),
            Expression::UnaryExpression(unary) => walk(&unary.argument, out, depth + 1),
            Expression::LogicalExpression(logical) => {
                walk(&logical.left, out, depth + 1);
                walk(&logical.right, out, depth + 1);
            }
            Expression::BinaryExpression(binary) => {
                walk(&binary.left, out, depth + 1);
                walk(&binary.right, out, depth + 1);
            }
            Expression::ParenthesizedExpression(inner) => walk(&inner.expression, out, depth + 1),
            Expression::ChainExpression(chain) => {
                if let oxc_ast::ast::ChainElement::StaticMemberExpression(member) =
                    &chain.expression
                {
                    walk(&member.object, out, depth + 1);
                }
            }
            Expression::StaticMemberExpression(member) => walk(&member.object, out, depth + 1),
            Expression::CallExpression(call) => walk(&call.callee, out, depth + 1),
            _ => {}
        }
    }
    walk(expression, out, 0);
}
