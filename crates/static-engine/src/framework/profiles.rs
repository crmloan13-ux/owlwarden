//! The first-party framework profiles.
//!
//! This is the file you edit to teach owlwarden about a new framework, and — if
//! the framework routes and responds in a shape one of the [`HandlerStyle`]
//! variants already covers — it is the only file. That property is the point of
//! the whole module: before it existed, the same knowledge was spread through
//! every rule as private constants.
//!
//! Two conventions worth knowing before adding one:
//!
//! - **`specificity` reflects the dependency graph, not our opinion.** NestJS
//!   sits above Express because a Nest app declares Express as a dependency,
//!   not because we consider it more important. Get this wrong and users see
//!   remediation for a framework they are not writing.
//! - **Vocabulary is what the framework's own documentation calls things.**
//!   `reply` is in Fastify's vocabulary because Fastify's docs name the second
//!   handler argument `reply`. Adding a name because someone might use it makes
//!   every rule that consults the vocabulary less precise.

use owlwarden_core::finding::Framework;

use super::{FrameworkProfile, HandlerStyle, HttpVocabulary, routing};

/// Every profile owlwarden ships with.
#[must_use]
pub fn builtin() -> Vec<FrameworkProfile> {
    vec![
        nest(),
        sails(),
        next(),
        nuxt(),
        astro(),
        remix(),
        gatsby(),
        fastify(),
        hono(),
        hapi(),
        express(),
        koa(),
    ]
}

/// Names shared by most Node HTTP code, regardless of framework.
///
/// Kept in one place so a project with no detected framework still gets useful
/// answers, and so every profile inherits the baseline rather than repeating
/// it.
fn node_baseline() -> HttpVocabulary {
    HttpVocabulary {
        response_objects: strings(&["res", "response"]),
        body_methods: strings(&["json", "send", "end", "write"]),
        response_helpers: Vec::new(),
        response_constructors: strings(&["Response"]),
        cookie_setters: strings(&["setCookie"]),
        router_objects: strings(&["app", "router", "server"]),
        cors_enablers: strings(&["cors"]),
    }
}

/// The fallback used when no framework is detected.
///
/// Not an empty profile: a plain Node or Koa service still writes `res.json`,
/// and a scan that recognised nothing should still find a leaked stack trace.
/// It only lacks the framework-specific remediation.
#[must_use]
pub fn generic() -> FrameworkProfile {
    FrameworkProfile {
        id: Framework::GENERIC,
        packages: Vec::new(),
        specificity: 0,
        config_files: Vec::new(),
        bootstrap_files: strings(&[
            "src/server.ts",
            "src/server.js",
            "src/index.ts",
            "src/index.js",
            "server.ts",
            "server.js",
            "index.ts",
            "index.js",
        ]),
        http: HttpVocabulary {
            // `ctx` covers Koa and anything else following its convention.
            response_objects: strings(&["res", "response", "ctx", "reply"]),
            ..node_baseline()
        },
        handlers: vec![HandlerStyle::RouterCall],
        route_for_path: None,
    }
}

/// Next.js — App Router and Pages Router.
fn next() -> FrameworkProfile {
    let baseline = node_baseline();
    FrameworkProfile {
        id: Framework::NEXT,
        packages: strings(&["next"]),
        specificity: 30,
        config_files: strings(&[
            "next.config.js",
            "next.config.mjs",
            "next.config.cjs",
            "next.config.ts",
            "middleware.ts",
            "middleware.js",
            "src/middleware.ts",
            "src/middleware.js",
            // Deployment-level headers. Reading it stops us reporting a gap the
            // team has already closed outside the framework.
            "vercel.json",
        ]),
        bootstrap_files: strings(&["next.config.js", "next.config.mjs", "next.config.ts"]),
        http: HttpVocabulary {
            response_objects: strings(&["NextResponse", "Response", "res", "response"]),
            response_constructors: strings(&["NextResponse", "Response"]),
            // `cookies()` from `next/headers` returns a store you `.set()` on.
            cookie_setters: strings(&["cookies.set", "res.setHeader"]),
            // Next has no router object; routes are files.
            router_objects: Vec::new(),
            ..baseline
        },
        handlers: vec![HandlerStyle::ExportedVerb],
        route_for_path: Some(routing::next),
    }
}

/// Nuxt, including its Nitro server engine.
fn nuxt() -> FrameworkProfile {
    FrameworkProfile {
        id: Framework::NUXT,
        // `nitropack` on its own is a standalone Nitro app, which routes
        // identically. `nuxt3` is the pre-3.0 package name, still in the wild.
        packages: strings(&["nuxt", "nuxt3", "nitropack"]),
        specificity: 30,
        config_files: strings(&["nuxt.config.ts", "nuxt.config.js", "nuxt.config.mjs"]),
        bootstrap_files: strings(&[
            "nuxt.config.ts",
            "nuxt.config.js",
            "server/middleware/headers.ts",
            "server/plugins/security.ts",
        ]),
        http: HttpVocabulary {
            // h3 hands the handler an `event`, and everything is a helper
            // function taking it.
            response_objects: strings(&["event", "res", "response"]),
            body_methods: strings(&["json", "send", "end", "write", "respondWith"]),
            // `createError` is the h3 way to end a request with an error, and
            // its `message`/`data` become the response body — so it is a sink
            // in exactly the way `throw new HttpException(...)` is in Nest.
            response_helpers: strings(&["send", "sendError", "sendStream", "createError"]),
            response_constructors: strings(&["Response", "H3Error"]),
            cookie_setters: strings(&["setCookie"]),
            router_objects: strings(&["router", "app"]),
            cors_enablers: strings(&["cors", "handleCors"]),
        },
        handlers: vec![HandlerStyle::FileSuffixVerb],
        route_for_path: Some(routing::nitro),
    }
}

/// NestJS. Sits above Express and Fastify because a Nest app declares one of
/// them as its underlying platform.
fn nest() -> FrameworkProfile {
    let baseline = node_baseline();
    FrameworkProfile {
        id: Framework::NEST,
        packages: strings(&["@nestjs/core"]),
        specificity: 40,
        config_files: strings(&["src/main.ts", "src/main.js", "main.ts"]),
        bootstrap_files: strings(&["src/main.ts", "src/main.js", "main.ts"]),
        http: HttpVocabulary {
            // `@Res()` injects the platform response, so the underlying
            // framework's names appear in Nest code too.
            response_objects: strings(&["res", "response", "reply", "ctx"]),
            // Nest's exception filters take the body from the thrown exception,
            // which makes every `*Exception` constructor a response sink.
            response_constructors: strings(&[
                "HttpException",
                "BadRequestException",
                "UnauthorizedException",
                "ForbiddenException",
                "NotFoundException",
                "ConflictException",
                "InternalServerErrorException",
                "ServiceUnavailableException",
                "Response",
            ]),
            cookie_setters: strings(&["res.cookie", "reply.setCookie", "response.cookie"]),
            router_objects: strings(&["app"]),
            cors_enablers: strings(&["enableCors", "cors"]),
            ..baseline
        },
        handlers: vec![HandlerStyle::MethodDecorator],
        route_for_path: None,
    }
}

/// Express.
fn express() -> FrameworkProfile {
    let baseline = node_baseline();
    FrameworkProfile {
        id: Framework::EXPRESS,
        packages: strings(&["express"]),
        specificity: 10,
        config_files: Vec::new(),
        bootstrap_files: strings(&[
            "src/app.ts",
            "src/app.js",
            "src/server.ts",
            "src/server.js",
            "src/index.ts",
            "src/index.js",
            "app.ts",
            "app.js",
            "server.ts",
            "server.js",
            "index.js",
        ]),
        http: HttpVocabulary {
            body_methods: strings(&[
                "json", "send", "end", "write", "jsonp", "sendFile", "render",
            ]),
            cookie_setters: strings(&["res.cookie", "response.cookie"]),
            ..baseline
        },
        handlers: vec![HandlerStyle::RouterCall],
        route_for_path: None,
    }
}

/// Fastify.
fn fastify() -> FrameworkProfile {
    let baseline = node_baseline();
    FrameworkProfile {
        id: Framework::FASTIFY,
        packages: strings(&["fastify"]),
        specificity: 20,
        config_files: Vec::new(),
        bootstrap_files: strings(&[
            "src/app.ts",
            "src/app.js",
            "src/server.ts",
            "src/server.js",
            "src/index.ts",
            "src/index.js",
            "app.ts",
            "server.ts",
            "server.js",
        ]),
        http: HttpVocabulary {
            // Fastify's docs name the second handler argument `reply`.
            response_objects: strings(&["reply", "res", "response"]),
            // `code()` and `type()` are Fastify's status and content-type
            // setters. They chain in front of `send()`, so counting them as
            // body writes would double-report every response.
            body_methods: strings(&["send", "json"]),
            cookie_setters: strings(&["reply.setCookie", "reply.cookie"]),
            router_objects: strings(&["fastify", "app", "server", "instance", "router"]),
            cors_enablers: strings(&["cors", "fastifyCors"]),
            ..baseline
        },
        handlers: vec![HandlerStyle::RouterCall],
        route_for_path: None,
    }
}

/// Hono. Context is `c`; responses are `c.json` / `c.text` / `c.html`.
fn hono() -> FrameworkProfile {
    FrameworkProfile {
        id: Framework::HONO,
        packages: strings(&["hono"]),
        specificity: 15,
        config_files: Vec::new(),
        bootstrap_files: strings(&[
            "src/index.ts",
            "src/index.js",
            "src/app.ts",
            "src/app.js",
            "index.ts",
            "app.ts",
        ]),
        http: HttpVocabulary {
            response_objects: strings(&["c", "context"]),
            body_methods: strings(&["json", "text", "html", "body", "redirect"]),
            response_helpers: Vec::new(),
            response_constructors: strings(&["Response"]),
            // Only the cookie helper. `c.header` sets any response header and
            // must not be treated as a cookie write — that would flag every
            // `c.header('X-Request-Id', …)` as insecure-cookie.
            cookie_setters: strings(&["setCookie"]),
            router_objects: strings(&["app", "hono", "api", "router"]),
            cors_enablers: strings(&["cors"]),
        },
        handlers: vec![HandlerStyle::RouterCall],
        route_for_path: None,
    }
}

/// Koa. Middleware receives `ctx`; the body is often assigned (`ctx.body = …`).
fn koa() -> FrameworkProfile {
    let baseline = node_baseline();
    FrameworkProfile {
        id: Framework::KOA,
        packages: strings(&["koa"]),
        specificity: 10,
        config_files: Vec::new(),
        bootstrap_files: strings(&[
            "src/app.ts",
            "src/app.js",
            "src/server.ts",
            "src/server.js",
            "src/index.ts",
            "app.ts",
            "server.ts",
            "index.js",
        ]),
        http: HttpVocabulary {
            response_objects: strings(&["ctx", "context", "res", "response"]),
            // `body` is listed so assignment sinks (`ctx.body = …`) and the
            // rarer `ctx.body(...)` helper spelling both resolve.
            body_methods: strings(&["json", "send", "end", "write", "body"]),
            cookie_setters: strings(&["cookies.set", "ctx.cookies.set"]),
            router_objects: strings(&["app", "router"]),
            cors_enablers: strings(&["cors"]),
            ..baseline
        },
        handlers: vec![HandlerStyle::RouterCall],
        route_for_path: None,
    }
}

/// Hapi. Toolkit is `h`; handlers receive `request`.
fn hapi() -> FrameworkProfile {
    FrameworkProfile {
        id: Framework::HAPI,
        packages: strings(&["@hapi/hapi", "hapi"]),
        specificity: 15,
        config_files: Vec::new(),
        bootstrap_files: strings(&[
            "src/server.ts",
            "src/server.js",
            "src/index.ts",
            "server.ts",
            "server.js",
            "index.js",
        ]),
        http: HttpVocabulary {
            // `h.response(body)` builds the payload; `.code()` / `.header()`
            // chain after it and must not count as body writes.
            response_objects: strings(&["h", "reply", "response", "res"]),
            body_methods: strings(&["response"]),
            response_helpers: Vec::new(),
            response_constructors: strings(&["Response"]),
            cookie_setters: strings(&["h.state", "state"]),
            router_objects: strings(&["server", "app"]),
            cors_enablers: strings(&["cors"]),
        },
        handlers: vec![HandlerStyle::RouterCall],
        route_for_path: None,
    }
}

/// Sails.js sits on Express. Specificity beats Express so remediation names Sails.
fn sails() -> FrameworkProfile {
    let baseline = node_baseline();
    FrameworkProfile {
        id: Framework::SAILS,
        packages: strings(&["sails"]),
        specificity: 35,
        config_files: strings(&[
            "config/http.js",
            "config/http.ts",
            "config/security.js",
            "config/security.ts",
            "config/routes.js",
            "config/routes.ts",
        ]),
        bootstrap_files: strings(&["config/http.js", "config/http.ts", "app.js", "app.ts"]),
        http: HttpVocabulary {
            body_methods: strings(&[
                "json", "send", "end", "write", "jsonp", "sendFile", "view", "ok",
            ]),
            cookie_setters: strings(&["res.cookie", "response.cookie"]),
            cors_enablers: strings(&["cors"]),
            ..baseline
        },
        handlers: vec![HandlerStyle::RouterCall],
        route_for_path: None,
    }
}

/// Astro — file-based pages and `src/pages/api` endpoints.
fn astro() -> FrameworkProfile {
    let baseline = node_baseline();
    FrameworkProfile {
        id: Framework::ASTRO,
        packages: strings(&["astro"]),
        specificity: 30,
        config_files: strings(&[
            "astro.config.mjs",
            "astro.config.js",
            "astro.config.ts",
            "astro.config.cjs",
        ]),
        bootstrap_files: strings(&["astro.config.mjs", "astro.config.js", "astro.config.ts"]),
        http: HttpVocabulary {
            response_objects: strings(&["Response", "Astro", "res", "response", "context"]),
            response_constructors: strings(&["Response"]),
            cookie_setters: strings(&["cookies.set", "Astro.cookies.set"]),
            router_objects: Vec::new(),
            cors_enablers: strings(&["cors"]),
            ..baseline
        },
        handlers: vec![HandlerStyle::ExportedVerb],
        route_for_path: Some(routing::astro),
    }
}

/// Remix — loaders/actions on file routes, Web Fetch Response API.
fn remix() -> FrameworkProfile {
    FrameworkProfile {
        id: Framework::REMIX,
        packages: strings(&[
            "@remix-run/node",
            "@remix-run/react",
            "remix",
            "@remix-run/serve",
        ]),
        specificity: 30,
        config_files: strings(&[
            "remix.config.js",
            "remix.config.mjs",
            "vite.config.ts",
            "vite.config.js",
        ]),
        bootstrap_files: strings(&["remix.config.js", "app/root.tsx", "app/entry.server.tsx"]),
        http: HttpVocabulary {
            response_objects: strings(&["Response", "res", "response"]),
            body_methods: strings(&["json", "redirect", "defer"]),
            response_helpers: strings(&["json", "redirect", "defer"]),
            response_constructors: strings(&["Response"]),
            // Options live on `createCookie(...)`, not on `serialize(token)`.
            // Matching bare `serialize` would flag every schema.serialize call
            // in the tree as an insecure cookie.
            cookie_setters: strings(&["createCookie"]),
            router_objects: Vec::new(),
            cors_enablers: strings(&["cors"]),
        },
        handlers: vec![HandlerStyle::ExportedVerb],
        route_for_path: Some(routing::remix),
    }
}

/// Gatsby — Functions under `src/api` use an Express-shaped `(req, res)`.
fn gatsby() -> FrameworkProfile {
    let baseline = node_baseline();
    FrameworkProfile {
        id: Framework::GATSBY,
        packages: strings(&["gatsby"]),
        specificity: 25,
        config_files: strings(&["gatsby-config.js", "gatsby-config.ts", "gatsby-node.js"]),
        bootstrap_files: strings(&["gatsby-config.js", "gatsby-config.ts", "gatsby-node.js"]),
        http: HttpVocabulary {
            // `status()` only sets the code; counting it as a body write would
            // double-report every `res.status(500).json(...)` chain.
            body_methods: strings(&["json", "send", "end", "write"]),
            // `res.setHeader` is every header, not a cookie write. Cookie
            // helpers on Gatsby Functions are Express-shaped `res.cookie`.
            cookie_setters: strings(&["res.cookie", "response.cookie"]),
            router_objects: Vec::new(),
            cors_enablers: strings(&["cors"]),
            ..baseline
        },
        handlers: vec![HandlerStyle::ExportedVerb, HandlerStyle::RouterCall],
        route_for_path: Some(routing::gatsby),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_profile_can_say_how_a_response_is_written() {
        for profile in builtin().into_iter().chain(std::iter::once(generic())) {
            assert!(
                !profile.http.response_objects.is_empty(),
                "{} names no response object, so no rule can see a leak in it",
                profile.id
            );
            assert!(
                !profile.http.body_methods.is_empty(),
                "{} names no body method",
                profile.id
            );
        }
    }

    #[test]
    fn every_detectable_profile_declares_a_package_to_detect_it_by() {
        for profile in builtin() {
            assert!(
                !profile.packages.is_empty(),
                "{} can never be detected",
                profile.id
            );
            assert!(
                profile.specificity > 0,
                "{} would tie with the generic fallback",
                profile.id
            );
        }
        assert!(
            generic().packages.is_empty(),
            "the fallback must not be detectable"
        );
    }

    #[test]
    fn status_and_header_setters_are_not_body_methods() {
        // `res.status(500)` sets metadata. A rule looking for data leaving the
        // process must not treat it as a write, or every error path in every
        // codebase becomes a finding — and a chained call would be counted
        // twice.
        for profile in builtin() {
            for setter in ["status", "setHeader", "code", "type", "header"] {
                assert!(
                    !profile.http.is_body_method(setter),
                    "{} treats {setter}() as a body write",
                    profile.id
                );
            }
        }
    }

    #[test]
    fn only_file_routed_frameworks_map_paths() {
        let by_id = |id: &Framework| {
            builtin()
                .into_iter()
                .find(|profile| &profile.id == id)
                .expect("registered profile")
        };

        assert!(by_id(&Framework::NEXT).route_for_path.is_some());
        assert!(by_id(&Framework::NUXT).route_for_path.is_some());
        assert!(by_id(&Framework::ASTRO).route_for_path.is_some());
        assert!(by_id(&Framework::REMIX).route_for_path.is_some());
        assert!(by_id(&Framework::GATSBY).route_for_path.is_some());
        // These register routes with a call, so a path tells us nothing.
        assert!(by_id(&Framework::EXPRESS).route_for_path.is_none());
        assert!(by_id(&Framework::FASTIFY).route_for_path.is_none());
        assert!(by_id(&Framework::NEST).route_for_path.is_none());
        assert!(by_id(&Framework::HONO).route_for_path.is_none());
        assert!(by_id(&Framework::KOA).route_for_path.is_none());
        assert!(by_id(&Framework::HAPI).route_for_path.is_none());
        assert!(by_id(&Framework::SAILS).route_for_path.is_none());
    }

    #[test]
    fn nest_and_sails_rank_above_the_platforms_they_run_on() {
        let rank = |id: &Framework| {
            builtin()
                .into_iter()
                .find(|profile| &profile.id == id)
                .map(|profile| profile.specificity)
                .expect("registered profile")
        };
        assert!(rank(&Framework::NEST) > rank(&Framework::EXPRESS));
        assert!(rank(&Framework::NEST) > rank(&Framework::FASTIFY));
        assert!(rank(&Framework::SAILS) > rank(&Framework::EXPRESS));
        assert!(rank(&Framework::HONO) > rank(&Framework::EXPRESS));
        assert!(rank(&Framework::ASTRO) > rank(&Framework::GATSBY));
    }
}
