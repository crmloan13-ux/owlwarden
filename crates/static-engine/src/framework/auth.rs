//! What "this route is guarded" looks like, per framework.
//!
//! Gate recognition is declared here and consumed by [`crate::exposure`], for
//! the reason every other piece of framework knowledge is declared rather than
//! written into a rule: sixteen frameworks spell "run this before the handler"
//! sixteen ways, and a rule that learned one of them would be silently blind to
//! the other fifteen
//! ([ADR 0029](../../../../docs/adr/0029-exposure-model.md) §3).
//!
//! # The direction this module is allowed to be wrong in
//!
//! Everything here answers *did we positively identify a gate*. Nothing here
//! answers *is the route unguarded* — that is the absence of an answer, and the
//! classifier turns it into [`Exposure::Internet`](owlwarden_core::finding::Exposure::Internet)
//! on purpose. So a name missing from a list below costs a false `internet`,
//! which is noise; a name wrongly present costs a false `authenticated`, which
//! is a finding somebody deprioritises. Every list is therefore short and
//! specific, and a name earns its place by being an auth gate rather than by
//! appearing near one.
//!
//! `express-session` is the worked example of a name that does not qualify. It
//! attaches a session store to every request and gates nothing; treating it as
//! a gate would mark every route in a very large number of Express
//! applications as behind auth, which is the exact failure this axis exists to
//! avoid.

/// The identifiers, methods, and files one framework uses to gate a route.
///
/// Nine fields, and each answers a question the others cannot. A mount
/// (`app.use`) is not a hook (`onRequest`) is not a decorator (`@UseGuards`) is
/// not a route option (`{ auth: 'jwt' }`), and a framework that expresses
/// gating one way is structurally invisible to a classifier that only knows
/// another.
#[derive(Debug, Clone, Default)]
pub struct AuthVocabulary {
    /// Methods that mount something to run on later requests:
    /// `use`, `addHook`, `register`.
    ///
    /// Mounting is not gating. A mount counts only when what it mounts is
    /// recognised as a gate.
    pub mount_methods: Vec<String>,
    /// Lifecycle hook names that run before a handler, so a gate installed on
    /// one covers the routes it applies to: `onRequest`, `preHandler`,
    /// `onPreAuth`.
    pub pre_handler_hooks: Vec<String>,
    /// Decorators that gate the class or method they sit on: `UseGuards`.
    ///
    /// Never the inverse: `@Public()` marks a route as *ungated* and is
    /// deliberately absent, because a list that mixed the two would gate a
    /// route by the presence of the decorator that opens it.
    pub gate_decorators: Vec<String>,
    /// Route-option keys whose presence on a route definition gates it —
    /// Hapi's `auth`, Fastify's `onRequest` inside the options object.
    pub gate_option_keys: Vec<String>,
    /// Calls whose presence anywhere in a bootstrap file gates every route the
    /// server serves: `useGlobalGuards`, `auth.default`.
    ///
    /// These need no argument inspection, because the developer declaring one
    /// *is* the declaration. Dotted paths are matched against the call's own
    /// member chain, so `server.auth.default('jwt')` matches `auth.default`.
    pub global_gate_calls: Vec<String>,
    /// Calls that reject the request by themselves when there is no session:
    /// `requireUserId`, `withApiAuthRequired`, `authenticator.isAuthenticated`.
    ///
    /// The in-handler half of the answer, for frameworks whose idiom is to
    /// check inside the loader or action rather than in front of it. A name
    /// belongs here only if calling it and ignoring the result is not a thing
    /// the API allows.
    pub enforcing_calls: Vec<String>,
    /// Calls that *read* a session without enforcing one: `getServerSession`,
    /// `currentUser`, `getUser`.
    ///
    /// These are not a gate on their own — `const session = await
    /// getServerSession()` with nothing done about the answer gates nothing —
    /// so the classifier counts one only when the value it returns is checked
    /// in a branch that returns or throws. That is the difference between
    /// observing a call and identifying a gate, and on this axis the difference
    /// is the whole design.
    pub session_readers: Vec<String>,
    /// Files that run before requests this framework routes, and therefore gate
    /// them when they contain a gate. Project-relative, checked in order.
    pub middleware_files: Vec<String>,
    /// Directories whose files all run as middleware — Nuxt's
    /// `server/middleware`, where the file name is the developer's choice and
    /// no list could enumerate it.
    pub middleware_dirs: Vec<String>,
}

impl AuthVocabulary {
    /// Whether a method name mounts middleware in this framework.
    #[must_use]
    pub fn is_mount_method(&self, name: &str) -> bool {
        self.mount_methods.iter().any(|known| known == name)
    }

    /// Whether a name is a pre-handler lifecycle hook here.
    #[must_use]
    pub fn is_pre_handler_hook(&self, name: &str) -> bool {
        self.pre_handler_hooks.iter().any(|known| known == name)
    }

    /// Whether a route-option key gates the route it sits on.
    #[must_use]
    pub fn is_gate_option_key(&self, name: &str) -> bool {
        self.gate_option_keys.iter().any(|known| known == name)
    }

    /// Whether a decorator gates what it decorates.
    #[must_use]
    pub fn is_gate_decorator(&self, name: &str) -> bool {
        self.gate_decorators.iter().any(|known| known == name)
    }

    /// Whether a call, by itself, rejects an unauthenticated request.
    #[must_use]
    pub fn is_enforcing_call(&self, path: &str) -> bool {
        self.enforcing_calls.iter().any(|known| known == path)
    }

    /// Whether a call merely reads a session.
    #[must_use]
    pub fn is_session_reader(&self, path: &str) -> bool {
        self.session_readers.iter().any(|known| known == path)
    }
}

/// npm packages whose middleware, when mounted, genuinely gates a route.
///
/// Curated, cross-framework, and deliberately short. A package is on this list
/// because mounting it *rejects unauthenticated requests*, not because it is
/// adjacent to authentication: `jsonwebtoken` signs and verifies tokens and
/// gates nothing on its own, `express-session` attaches a store, and neither is
/// here.
pub const AUTH_PACKAGES: &[&str] = &[
    "passport",
    "express-jwt",
    "express-oauth2-jwt-bearer",
    "express-basic-auth",
    "express-openid-connect",
    "@fastify/auth",
    "@fastify/jwt",
    "@fastify/basic-auth",
    "@fastify/passport",
    "fastify-auth",
    "fastify-jwt",
    "@nestjs/passport",
    "@auth/core",
    "next-auth",
    "@auth0/nextjs-auth0",
    "@clerk/nextjs",
    "@clerk/express",
    "@clerk/backend",
    "@kinde-oss/kinde-auth-nextjs",
    "@workos-inc/authkit-nextjs",
    "lucia",
    "@lucia-auth/adapter-drizzle",
    "better-auth",
    "koa-passport",
    "koa-jwt",
    "@hapi/basic",
    "@hapi/jwt",
    "hapi-auth-jwt2",
    "hono/jwt",
    "@hono/clerk-auth",
    "@hono/auth-js",
    "@elysiajs/jwt",
    "@elysiajs/bearer",
    "elysia-clerk",
    "remix-auth",
    "@auth/sveltekit",
    "@auth/solid-start",
    "supertokens-node",
];

/// Exported symbols that are an auth gate wherever they appear, whatever
/// package they came from.
///
/// Distinct from [`AUTH_PACKAGES`] because a project may re-export a gate from
/// a local barrel file, and because some packages export both a gate and much
/// else — `hono/jwt` exports `jwt`, and `@clerk/nextjs/server` exports
/// `clerkMiddleware` alongside a dozen unrelated helpers.
pub const AUTH_EXPORTS: &[&str] = &[
    "authMiddleware",
    "clerkMiddleware",
    "requiresAuth",
    "withApiAuthRequired",
    "withPageAuthRequired",
    "auth",
    "jwt",
    "bearer",
    "basicAuth",
    "jwtVerify",
    "verifyAuth",
    "requireAuth",
    "requireUser",
    "requireSession",
    "ensureAuthenticated",
    "ensureLoggedIn",
    "isAuthenticated",
    "authenticate",
    "authenticator",
    "protect",
    "authGuard",
    "AuthGuard",
    "JwtAuthGuard",
];

/// Whether a bare identifier reads as an authentication gate.
///
/// The shape rule from [ADR 0029](../../../../docs/adr/0029-exposure-model.md)
/// §3, applied to a name the project defined itself. It is deliberately
/// narrower than "contains auth": `authorRouter` and `sessionStore` both
/// contain a listed stem and neither gates anything, so a stem only counts at a
/// word boundary and only alongside a verb that means *check*, or as a
/// standalone noun that means *the check*.
///
/// A name that passes this is still not a gate until the module it came from
/// resolves — see [`crate::exposure`]. The shape narrows the candidates; the
/// resolution is what makes it evidence.
#[must_use]
pub fn is_gate_name(name: &str) -> bool {
    if AUTH_EXPORTS.contains(&name) {
        return true;
    }
    let words = split_words(name);
    if words.is_empty() {
        return false;
    }

    // `requireAuth`, `checkSession`, `verifyToken`, `ensureLoggedIn`.
    let verbs = [
        "require", "ensure", "check", "verify", "assert", "validate", "protect", "guard", "is",
        "has", "with", "must",
    ];
    let nouns = [
        "auth",
        "authn",
        "authz",
        "authenticated",
        "authentication",
        "authorization",
        "authorized",
        "authorised",
        "session",
        "login",
        "loggedin",
        "user",
        "identity",
        "principal",
        "jwt",
        "token",
        "guard",
        "permission",
        "permissions",
        "rbac",
        "acl",
    ];

    let has_noun = words.iter().any(|word| nouns.contains(&word.as_str()));
    if !has_noun {
        return false;
    }
    // A noun on its own is a gate only when the noun *is* the check.
    let standalone = [
        "auth",
        "authn",
        "authz",
        "authguard",
        "authenticate",
        "authenticated",
        "authorize",
        "authorise",
        "guard",
        "authmiddleware",
    ];
    if words.len() == 1 {
        return standalone.contains(&words.first().map(String::as_str).unwrap_or_default());
    }
    words.iter().any(|word| verbs.contains(&word.as_str()))
        || words
            .first()
            .is_some_and(|word| word == "auth" || word == "authenticated")
}

/// Splits `requireAuthMiddleware`, `require_auth`, and `require-auth` into
/// lowercase words.
///
/// Bounded at 16 words: the input is an identifier read out of a file nobody
/// vetted, and an unbounded split on a pathological name is work an attacker
/// chooses the size of.
fn split_words(name: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    for ch in name.chars().take(128) {
        if ch == '_' || ch == '-' || ch == '.' {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        if ch.is_ascii_uppercase() && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(ch.to_ascii_lowercase());
        if words.len() >= 16 {
            break;
        }
    }
    if !current.is_empty() && words.len() < 16 {
        words.push(current);
    }
    words
}

/// Whether a module specifier is one of [`AUTH_PACKAGES`], allowing the
/// subpath spellings packages actually ship (`@clerk/nextjs/server`,
/// `hono/jwt`, `passport/lib`).
#[must_use]
pub fn is_auth_package(specifier: &str) -> bool {
    AUTH_PACKAGES.iter().any(|package| {
        specifier == *package
            || specifier
                .strip_prefix(package)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Whether a module specifier points inside the project rather than at a
/// package.
#[must_use]
pub fn is_relative_specifier(specifier: &str) -> bool {
    specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier.starts_with('~')
        || specifier.starts_with('#')
        || specifier.starts_with("@/")
        || specifier.starts_with("src/")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn gate_shapes_match_the_names_people_actually_write() {
        for name in [
            "requireAuth",
            "require_auth",
            "ensureAuthenticated",
            "checkSession",
            "verifyJwt",
            "authGuard",
            "isAuthenticated",
            "withAuth",
            "authenticate",
            "JwtAuthGuard",
        ] {
            assert!(is_gate_name(name), "{name} should read as a gate");
        }
    }

    #[test]
    fn names_that_merely_contain_a_stem_are_not_gates() {
        // Each of these appears in real codebases next to routes, and each
        // would mark a route as behind auth if the rule were "contains auth".
        for name in [
            "authorRouter",
            "sessionStore",
            "userService",
            "tokenizer",
            "authorize_url_builder",
            "permissionsTable",
            "guardrails",
            "logger",
            "createUser",
            "userController",
        ] {
            assert!(!is_gate_name(name), "{name} must not read as a gate");
        }
    }

    #[test]
    fn package_matching_accepts_subpaths_and_nothing_else() {
        assert!(is_auth_package("passport"));
        assert!(is_auth_package("@clerk/nextjs/server"));
        assert!(is_auth_package("hono/jwt"));
        assert!(!is_auth_package("passportjs"));
        assert!(!is_auth_package("express-session"));
        assert!(!is_auth_package("jsonwebtoken"));
    }

    #[test]
    fn word_splitting_is_bounded() {
        let hostile = "a".repeat(4096);
        assert!(split_words(&hostile).len() <= 16);
        let alternating: String = std::iter::repeat_n("aB", 4096).collect();
        assert!(split_words(&alternating).len() <= 16);
    }
}
