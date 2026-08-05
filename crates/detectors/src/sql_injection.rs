//! `sql-injection` — a query string built by interpolation reaching a database
//! driver.
//!
//! # What it looks for
//!
//! Three things have to be true at once, and the conjunction is what makes the
//! rule usable:
//!
//! 1. **A database sink.** `db.query(...)`, `knex.raw(...)`,
//!    `prisma.$queryRawUnsafe(...)`. Not every function called `query`.
//! 2. **A string built at runtime.** A template literal with `${}` in it, or a
//!    `+` concatenation. A plain literal is not injectable.
//! 3. **The string looks like SQL.** It contains `SELECT`, `INSERT`, `WHERE`
//!    and friends.
//!
//! Drop any one and the rule becomes noise. Without (3),
//! `analytics.query(`event ${name}`)` fires. Without (2), every parameterised
//! query in the codebase fires — which is to say, all the correct ones.
//!
//! # What it deliberately does not flag
//!
//! Prisma's `$queryRaw` and postgres.js's `` sql`...` `` are **tagged
//! templates**: the driver receives the fragments and the values separately and
//! parameterises them. They look exactly like the dangerous form and are safe,
//! so they are excluded by name and by shape. Flagging the safe spelling of a
//! dangerous API is how a rule teaches people to ignore it.
//!
//! # Why the confidence varies
//!
//! Interpolating something that came from the request (`req.query.id`,
//! `params.id`, `searchParams.get(...)`) is injection. Interpolating a table
//! name held in a constant is bad practice and usually not exploitable. The
//! first is `Likely`; the second is `Possible`, reported and never failing CI
//! on its own. Reporting both as certain would be dishonest about the one case
//! the reader has to act on today.

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
use oxc_ast::ast::{CallExpression, Expression};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "sql-injection";

/// Method names that hand a string to a database driver.
///
/// Every entry is an API that takes raw SQL. The `Unsafe` suffixes are Prisma's
/// own naming: `$queryRaw` parameterises and `$queryRawUnsafe` does not, and
/// the library is explicit about the difference.
const QUERY_METHODS: &[&str] = &[
    "query",
    "execute",
    "raw",
    "unsafe",
    "$queryRawUnsafe",
    "$executeRawUnsafe",
    "exec",
];

/// Objects a query method is called on.
///
/// Required alongside the method name so `analytics.query(...)` and
/// `element.execute(...)` stay quiet. Names come from the drivers people
/// actually use: `pg`, `mysql2`, `knex`, `sequelize`, `prisma`, `typeorm`,
/// `drizzle`.
const QUERY_OBJECTS: &[&str] = &[
    "db",
    "database",
    "pool",
    "client",
    "connection",
    "conn",
    "sequelize",
    "knex",
    "prisma",
    "sql",
    "manager",
    "entityManager",
    "repository",
    "repo",
    "datasource",
    "dataSource",
    "queryRunner",
    "drizzle",
    "this",
];

/// Tagged-template APIs that parameterise. Never a finding, even though the
/// call site looks identical to the dangerous one.
const SAFE_TAGGED_TEMPLATES: &[&str] = &["$queryRaw", "$executeRaw", "sql", "sqlTag"];

/// Keywords that make a string recognisably SQL.
const SQL_KEYWORDS: &[&str] = &[
    "select ",
    "insert ",
    "update ",
    "delete ",
    "where ",
    " from ",
    "drop ",
    "union ",
    "values ",
    "set ",
    "join ",
    "truncate ",
];

/// Findings collected from one file before the visitor stops.
const MAX_PER_FILE: usize = 32;

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct SqlInjection;

impl SqlInjection {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "SQL query built by string interpolation",
            severity: Severity::High,
            // A static read cannot prove the interpolated value is
            // attacker-controlled; only a live probe can. So this stops at
            // Likely, however obvious the case looks.
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A03:2021")),
            cwe: Some(89),
            category: "injection",
            description: "A SQL string is assembled with a template literal or concatenation and \
                          passed to a database driver. Any value interpolated into it is executed \
                          as SQL, so a request parameter can read, modify, or destroy data the \
                          query was never meant to touch. Use the driver's parameter binding \
                          instead; every driver has it.",
        }
    }
}

impl RuleInfo for SqlInjection {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for SqlInjection {
    fn applies_to(&self, path: &RelPath) -> bool {
        !path.as_str().ends_with(".d.ts")
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = QueryVisitor::default();
        visitor.visit_program(unit.program);

        for hit in visitor.hits {
            if !sink.push(build_finding(unit, &hit)) {
                break;
            }
        }
    }
}

/// One interpolated query.
struct Hit {
    span: Span,
    /// Whether an interpolated expression is rooted at something that carries
    /// request data.
    request_derived: bool,
    /// How the string was assembled, for the evidence line.
    shape: &'static str,
}

/// Walks a file looking for query sinks, carrying the shared request-origin
/// tracker so `const term = req.query.q` a line earlier still counts.
///
/// The tracker is [`RequestOrigin`], not a private list: every injection-shaped
/// rule needs the same answer, and when they each kept their own they
/// disagreed about which spellings of "the request" existed.
#[derive(Default)]
struct QueryVisitor {
    hits: Vec<Hit>,
    origin: RequestOrigin,
}

impl<'a> Visit<'a> for QueryVisitor {
    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        self.origin.observe(declarator);
        oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.hits.len() < MAX_PER_FILE
            && is_query_sink(call)
            && let Some(argument) = call
                .arguments
                .first()
                .and_then(oxc_ast::ast::Argument::as_expression)
            && let Some(mut hit) = inspect_query_argument(argument)
        {
            if !hit.request_derived {
                hit.request_derived = interpolated_parts(argument)
                    .iter()
                    .any(|part| self.origin.taints(part));
            }
            self.hits.push(hit);
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

/// The expressions interpolated into a template or concatenation.
fn interpolated_parts<'a>(expression: &'a Expression<'a>) -> Vec<&'a Expression<'a>> {
    match expression {
        Expression::TemplateLiteral(template) => template.expressions.iter().collect(),
        Expression::BinaryExpression(_) => {
            let mut literals = Vec::new();
            let mut dynamic = Vec::new();
            flatten_concatenation(expression, &mut literals, &mut dynamic, 0);
            dynamic
        }
        Expression::ParenthesizedExpression(inner) => interpolated_parts(&inner.expression),
        _ => Vec::new(),
    }
}

/// Whether a call hands a string to a database driver.
fn is_query_sink(call: &CallExpression<'_>) -> bool {
    let Some(method) = static_property(&call.callee) else {
        return false;
    };
    if SAFE_TAGGED_TEMPLATES.contains(&method) {
        return false;
    }
    if !QUERY_METHODS.contains(&method) {
        return false;
    }
    // `knex.raw` and `db.query` root at a known object. `sql.unsafe` too.
    root_identifier(&call.callee).is_some_and(|root| {
        QUERY_OBJECTS.contains(&root) || root.to_ascii_lowercase().contains("db")
    })
}

/// Whether the first argument is an interpolated SQL string, and how sure we
/// are about where the interpolated value came from.
fn inspect_query_argument(argument: &Expression<'_>) -> Option<Hit> {
    match argument {
        Expression::TemplateLiteral(template) => {
            if template.expressions.is_empty() {
                // No `${}`: a constant query, which is the safe spelling.
                return None;
            }
            let text: String = template
                .quasis
                .iter()
                .filter_map(|quasi| quasi.value.cooked.as_ref())
                .map(oxc_ast::ast::Str::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            if !looks_like_sql(&text) {
                return None;
            }
            Some(Hit {
                span: template.span,
                request_derived: template
                    .expressions
                    .iter()
                    .any(|expression| is_request_derived(expression)),
                shape: "template literal",
            })
        }
        Expression::BinaryExpression(binary) => {
            if binary.operator != oxc_syntax::operator::BinaryOperator::Addition {
                return None;
            }
            let mut literals = Vec::new();
            let mut dynamic = Vec::new();
            flatten_concatenation(argument, &mut literals, &mut dynamic, 0);
            if dynamic.is_empty() || !looks_like_sql(&literals.join(" ")) {
                return None;
            }
            Some(Hit {
                span: binary.span,
                request_derived: dynamic
                    .iter()
                    .any(|expression| is_request_derived(expression)),
                shape: "string concatenation",
            })
        }
        Expression::ParenthesizedExpression(inner) => inspect_query_argument(&inner.expression),
        _ => None,
    }
}

/// How deep a `+` chain is followed. `'a' + b + 'c' + d` nests to the left, and
/// a generated file can nest it a long way.
const MAX_CONCAT_DEPTH: u32 = 64;

/// Splits a `+` chain into its literal and non-literal parts.
fn flatten_concatenation<'a>(
    expression: &'a Expression<'a>,
    literals: &mut Vec<String>,
    dynamic: &mut Vec<&'a Expression<'a>>,
    depth: u32,
) {
    if depth > MAX_CONCAT_DEPTH {
        return;
    }
    match expression {
        Expression::BinaryExpression(binary)
            if binary.operator == oxc_syntax::operator::BinaryOperator::Addition =>
        {
            flatten_concatenation(&binary.left, literals, dynamic, depth + 1);
            flatten_concatenation(&binary.right, literals, dynamic, depth + 1);
        }
        Expression::StringLiteral(literal) => literals.push(literal.value.to_string()),
        Expression::ParenthesizedExpression(inner) => {
            flatten_concatenation(&inner.expression, literals, dynamic, depth + 1);
        }
        other => dynamic.push(other),
    }
}

/// Whether a string is recognisably SQL rather than an arbitrary message.
fn looks_like_sql(text: &str) -> bool {
    let lowered = format!(" {} ", text.to_ascii_lowercase());
    SQL_KEYWORDS
        .iter()
        .filter(|keyword| lowered.contains(*keyword))
        .count()
        >= 2
}

/// Whether an interpolated expression reads request data on its own, without
/// the local tracking the visitor adds.
fn is_request_derived(expression: &Expression<'_>) -> bool {
    owlwarden_static::taint::is_request_expression(expression)
}

/// Builds the finding.
fn build_finding(unit: &FileUnit<'_>, hit: &Hit) -> Finding {
    let meta = SqlInjection::meta();

    finding_builder(&meta)
        .confidence(if hit.request_derived {
            Confidence::Likely
        } else {
            Confidence::Possible
        })
        .why(if hit.request_derived {
            "A value taken from the request is interpolated into SQL, so the caller controls part \
             of the statement. That is enough to read other users' rows, bypass a WHERE clause, \
             or drop a table."
        } else {
            "The query is assembled as text, so whatever is interpolated becomes SQL. Even if \
             today's value is internal, the next change to this line makes it a request \
             parameter and nothing here will stop it."
        })
        .location(unit.location(hit.span))
        .snippet(unit.code_frame(hit.span, "query text is built at runtime"))
        .context(unit.context(
            None,
            Some(format!("{}: {}", hit.shape, unit.span_text(hit.span, 70))),
        ))
        .fixes(remediation().select(unit.framework()))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

/// Every framework's fix.
///
/// The framework barely matters here — the fix belongs to the database driver —
/// so the entries name the driver each framework's users most often reach for,
/// and every one of them says the same thing: bind, do not interpolate.
fn remediation() -> Remediation {
    Remediation::new(
        "Pass the values as query parameters instead of interpolating them. Every driver \
         supports it, and the binding is not optional formatting — it is what stops the value \
         being parsed as SQL.",
    )
    .manual(
        Framework::NEXT,
        "Use a parameterised query, or Prisma's tagged $queryRaw which binds automatically.",
        "// node-postgres\nawait db.query('SELECT * FROM users WHERE id = $1', [id])\n\n\
         // Prisma: the tagged form binds; $queryRawUnsafe does not\n\
         await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`",
    )
    .manual(
        Framework::NUXT,
        "Bind the value; keep the SQL text constant.",
        "await db.query('SELECT * FROM users WHERE id = $1', [id])",
    )
    .manual(
        Framework::NEST,
        "Use the repository API, or bind parameters on the query builder.",
        "await this.repo\n  \
         .createQueryBuilder('user')\n  \
         .where('user.id = :id', { id })\n  \
         .getOne()",
    )
    .manual(
        Framework::EXPRESS,
        "Bind the value; keep the SQL text constant.",
        "await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id])",
    )
    .manual(
        Framework::FASTIFY,
        "Bind the value; keep the SQL text constant.",
        "await fastify.pg.query('SELECT * FROM users WHERE id = $1', [request.params.id])",
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
    fn sql_recognition_needs_more_than_one_keyword() {
        assert!(looks_like_sql("SELECT * FROM users WHERE id ="));
        assert!(looks_like_sql("delete from sessions"));
        // One keyword on its own appears in plenty of ordinary strings.
        assert!(!looks_like_sql("set the value"));
        assert!(!looks_like_sql("user updated"));
        assert!(!looks_like_sql(""));
    }
}
