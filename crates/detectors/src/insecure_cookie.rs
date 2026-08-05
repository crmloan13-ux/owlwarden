//! `insecure-cookie` — a cookie set without the attributes that protect it.
//!
//! # The three attributes
//!
//! | Attribute | Without it |
//! |---|---|
//! | `httpOnly` | JavaScript can read the cookie, so one XSS becomes a stolen session |
//! | `secure` | The cookie is sent over plain HTTP, so anyone on the network path has it |
//! | `sameSite` | The browser attaches it to cross-site requests, which is CSRF |
//!
//! # Why it reads the last argument
//!
//! Every framework puts the options object last and disagrees about everything
//! before it: `res.cookie(name, value, options)` in Express,
//! `setCookie(event, name, value, options)` in Nuxt,
//! `cookies().set(name, value, options)` in Next.js. Taking the final object
//! literal handles all of them and does not need a per-framework argument
//! index — one fewer table to keep in step with the profiles.
//!
//! # Why confidence varies
//!
//! An options object that sets `sameSite` but forgets `secure` is a team that
//! owns its cookie configuration and has a gap: `Likely`. A bare
//! `res.cookie('theme', 'dark')` might be a preference cookie that genuinely
//! does not need protecting, so it is `Possible` — reported, explained, and
//! never failing CI on its own.

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    Confidence, Finding, Framework, OwaspRef, Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::RelPath;
use owlwarden_static::ast::{
    argument_object, is_false_literal, is_true_literal, object_property, string_value,
};
use owlwarden_static::framework::FrameworkSet;
use owlwarden_static::http::is_cookie_setter;
use owlwarden_static::rule::{FileRule, FindingSink, RuleInfo};
use owlwarden_static::unit::FileUnit;
use oxc_ast::ast::CallExpression;
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "insecure-cookie";

/// Findings collected from one file before the visitor stops.
const MAX_PER_FILE: usize = 32;

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct InsecureCookie;

impl InsecureCookie {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Cookie set without its protective attributes",
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A05:2021")),
            cwe: Some(614),
            category: "cookies",
            description: "A cookie is written without `httpOnly`, `secure`, or `sameSite`. \
                          Missing `httpOnly` turns any cross-site scripting bug into session \
                          theft; missing `secure` sends the cookie over plain HTTP; missing \
                          `sameSite` attaches it to cross-site requests. A cookie holding no \
                          sensitive value may not need all three, which is why the finding \
                          names the ones it did not find rather than assuming the worst.",
        }
    }
}

impl RuleInfo for InsecureCookie {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for InsecureCookie {
    fn applies_to(&self, path: &RelPath) -> bool {
        !path.as_str().ends_with(".d.ts")
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = CookieVisitor {
            frameworks: unit.frameworks(),
            hits: Vec::new(),
        };
        visitor.visit_program(unit.program);

        for hit in &visitor.hits {
            if !sink.push(build_finding(unit, hit)) {
                break;
            }
        }
    }
}

/// One cookie write and what it was missing.
struct Hit {
    span: Span,
    /// Attribute names that were absent or set to a weak value.
    missing: Vec<&'static str>,
    /// Whether the call passed an options object at all.
    has_options: bool,
    /// A `sameSite: 'none'` without `secure`, which browsers reject outright —
    /// worth naming separately because the cookie simply will not work.
    same_site_none_without_secure: bool,
}

struct CookieVisitor<'f> {
    frameworks: &'f FrameworkSet,
    hits: Vec<Hit>,
}

impl<'a> Visit<'a> for CookieVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.hits.len() < MAX_PER_FILE
            && is_cookie_setter(self.frameworks, &call.callee)
            && let Some(hit) = inspect(call)
        {
            self.hits.push(hit);
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

/// The state of a boolean cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flag {
    /// Absent from the options object.
    Absent,
    /// Explicitly `false`.
    Disabled,
    /// `true`, or an expression we cannot evaluate.
    Set,
}

/// Reads a boolean attribute, treating anything we cannot evaluate as set.
///
/// This matters more than it looks. `secure: process.env.NODE_ENV ===
/// 'production'` is the pattern every framework's documentation recommends —
/// it is the pattern in this rule's own remediation — and an earlier version
/// that required a literal `true` flagged it. A rule that fires on the fix it
/// prints is worse than no rule: the reader concludes the tool does not
/// understand their code, and they are right.
///
/// The trade is that `secure: someAlwaysFalseFlag` is missed. That is the
/// correct side to err on. Static analysis cannot evaluate the expression, and
/// guessing it is `false` invents a vulnerability.
fn flag(options: &oxc_ast::ast::ObjectExpression<'_>, name: &str) -> Flag {
    match object_property(options, name) {
        None => Flag::Absent,
        Some(value) if is_false_literal(value) => Flag::Disabled,
        Some(value) if is_true_literal(value) => Flag::Set,
        Some(_) => Flag::Set,
    }
}

/// Reads the options object off a cookie write.
fn inspect(call: &CallExpression<'_>) -> Option<Hit> {
    // The options object is always last; everything before it differs per
    // framework. `cookies().set({ name, value, httpOnly })` puts it first, and
    // "last" finds it there too because it is the only argument.
    let options = call.arguments.last().and_then(argument_object);

    let mut missing = Vec::new();
    let mut same_site_none_without_secure = false;

    let Some(options) = options else {
        return Some(Hit {
            span: call.span,
            missing: vec!["httpOnly", "secure", "sameSite"],
            has_options: false,
            same_site_none_without_secure: false,
        });
    };

    let secure = flag(options, "secure");
    let http_only = flag(options, "httpOnly");

    if http_only != Flag::Set {
        missing.push("httpOnly");
    }
    if secure != Flag::Set {
        missing.push("secure");
    }

    match object_property(options, "sameSite") {
        None => missing.push("sameSite"),
        // `sameSite: 'none'` needs `secure` or the browser drops the cookie
        // entirely. Worth naming even when everything else is configured,
        // because the symptom is "my cookie disappeared", not "I was hacked".
        Some(value) => {
            if string_value(value).is_some_and(|value| value.eq_ignore_ascii_case("none"))
                && secure != Flag::Set
            {
                same_site_none_without_secure = true;
            }
        }
    }

    if missing.is_empty() && !same_site_none_without_secure {
        return None;
    }

    Some(Hit {
        span: call.span,
        missing,
        has_options: true,
        same_site_none_without_secure,
    })
}

/// What each attribute would have prevented. Written out so the reader can
/// judge whether this particular cookie needs it.
fn purpose(attribute: &str) -> &'static str {
    match attribute {
        "httpOnly" => {
            "httpOnly keeps the cookie out of reach of JavaScript, so a cross-site \
                       scripting bug cannot read the session"
        }
        "secure" => "secure stops the cookie being sent over plain HTTP",
        _ => "sameSite stops the browser attaching the cookie to cross-site requests",
    }
}

/// Builds the finding.
fn build_finding(unit: &FileUnit<'_>, hit: &Hit) -> Finding {
    let meta = InsecureCookie::meta();

    // Options present means the team configures cookies here and has a gap. No
    // options at all might be an unimportant preference cookie.
    let confidence = if hit.has_options {
        Confidence::Likely
    } else {
        Confidence::Possible
    };

    let mut why = if hit.missing.is_empty() {
        String::new()
    } else {
        let explained: Vec<&str> = hit.missing.iter().map(|name| purpose(name)).collect();
        format!(
            "This cookie is missing protections: {}.",
            explained.join("; ")
        )
    };
    if hit.same_site_none_without_secure {
        if !why.is_empty() {
            why.push(' ');
        }
        why.push_str(
            "It also sets sameSite: 'none' without secure, which browsers reject outright — the \
             cookie will not be stored at all.",
        );
    }

    let evidence = if hit.has_options {
        format!("missing: {}", hit.missing.join(", "))
    } else {
        "no cookie options passed".to_owned()
    };

    finding_builder(&meta)
        .confidence(confidence)
        .why(why)
        .location(unit.location(hit.span))
        .snippet(unit.code_frame(hit.span, "cookie written without httpOnly/secure/sameSite"))
        .context(unit.context(None, Some(evidence)))
        .fixes(remediation().select(unit.framework()))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

/// Every framework's fix.
///
/// `sameSite: 'lax'` rather than `'strict'` in every patch: `strict` drops the
/// cookie on inbound links, which breaks sign-in flows, and a fix people revert
/// is not a fix.
fn remediation() -> Remediation {
    Remediation::new(
        "Set httpOnly, secure, and sameSite when writing a cookie that carries anything the user \
         would not want read or replayed.",
    )
    .manual(
        Framework::NEXT,
        "Pass the attributes to the cookie store.",
        "cookies().set('session', token, {\n  \
         httpOnly: true,\n  \
         secure: process.env.NODE_ENV === 'production',\n  \
         sameSite: 'lax',\n  \
         path: '/',\n\
         })",
    )
    .manual(
        Framework::NUXT,
        "Pass the attributes to setCookie.",
        "setCookie(event, 'session', token, {\n  \
         httpOnly: true,\n  \
         secure: process.env.NODE_ENV === 'production',\n  \
         sameSite: 'lax',\n\
         })",
    )
    .manual(
        Framework::NEST,
        "Pass the attributes through the injected response.",
        "res.cookie('session', token, {\n  \
         httpOnly: true,\n  \
         secure: process.env.NODE_ENV === 'production',\n  \
         sameSite: 'lax',\n\
         })",
    )
    .manual(
        Framework::EXPRESS,
        "Pass the attributes to res.cookie.",
        "res.cookie('session', token, {\n  \
         httpOnly: true,\n  \
         secure: process.env.NODE_ENV === 'production',\n  \
         sameSite: 'lax',\n\
         })",
    )
    .manual(
        Framework::FASTIFY,
        "Pass the attributes to reply.setCookie.",
        "reply.setCookie('session', token, {\n  \
         httpOnly: true,\n  \
         secure: process.env.NODE_ENV === 'production',\n  \
         sameSite: 'lax',\n  \
         path: '/',\n\
         })",
    )
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}
