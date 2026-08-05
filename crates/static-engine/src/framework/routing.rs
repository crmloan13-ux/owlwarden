//! Mapping a source path to the route it serves.
//!
//! Only for frameworks that route by file layout. Express and Fastify register
//! routes with a call (`app.get('/users', ...)`), so their routes come from the
//! AST — see [`crate::http`] — and their profiles supply no mapping here.
//!
//! Every function returns `None` the moment the mapping stops being certain. A
//! route in a report is a claim about the reader's application: `GET /api/users`
//! next to a finding tells them which request to reproduce, and if it is wrong
//! they reproduce the wrong thing and conclude the tool is wrong. Silence costs
//! a line of context; a wrong route costs the reader's trust.

/// A route derived from a file path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInfo {
    /// URL path, e.g. `/api/users/:id`. Dynamic segments keep the framework's
    /// own spelling where it is unambiguous.
    pub path: String,
    /// HTTP method, when the file layout states it. Nitro encodes it in the
    /// file name (`users.get.ts`); Next.js does not, and takes it from the
    /// exported handler instead.
    pub method: Option<String>,
}

impl RouteInfo {
    /// A route whose method is not known from the path alone.
    #[must_use]
    pub fn path_only(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            method: None,
        }
    }
}

/// Source extensions a route file may use.
const ROUTE_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];

/// HTTP methods Nitro accepts as a file-name suffix.
const NITRO_METHOD_SUFFIXES: &[&str] =
    &["get", "post", "put", "patch", "delete", "head", "options"];

/// Next.js: the App Router (`app/api/users/route.ts`) and the Pages Router
/// (`pages/api/users.ts`).
#[must_use]
pub fn next(path: &str) -> Option<RouteInfo> {
    // Both routers allow an optional `src/` prefix.
    let path = path.strip_prefix("src/").unwrap_or(path);

    if let Some(rest) = path.strip_prefix("app/") {
        let (dir, file) = rest.rsplit_once('/')?;
        let stem = strip_extension(file)?;
        // Only `route.*` handles a request. `page.tsx` renders, and reporting a
        // route for a component would attribute a finding to a request that
        // never reaches it.
        if stem != "route" {
            return None;
        }
        return Some(RouteInfo::path_only(format!(
            "/{}",
            strip_next_route_groups(dir)
        )));
    }

    if let Some(rest) = path.strip_prefix("pages/api/") {
        let stem = strip_extension(rest)?;
        let stem = stem.strip_suffix("/index").unwrap_or(stem);
        if stem == "index" {
            return Some(RouteInfo::path_only("/api"));
        }
        return Some(RouteInfo::path_only(format!("/api/{stem}")));
    }

    None
}

/// Nuxt's Nitro server routes: `server/api/users.get.ts`,
/// `server/routes/health.ts`, `server/middleware/auth.ts`.
///
/// `server/api/**` is mounted under `/api`; `server/routes/**` is mounted at
/// the root. Middleware runs on every request and has no route of its own, so
/// it deliberately maps to nothing.
#[must_use]
pub fn nitro(path: &str) -> Option<RouteInfo> {
    let rest = path.strip_prefix("server/")?;

    let (prefix, rest) = match rest.strip_prefix("api/") {
        Some(rest) => ("/api", rest),
        None => ("", rest.strip_prefix("routes/")?),
    };

    let stem = strip_extension(rest)?;
    let (stem, method) = split_nitro_method(stem);
    let stem = stem.strip_suffix("/index").unwrap_or(stem);

    // `server/api/index.ts` serves the prefix itself.
    let segments = if stem == "index" { "" } else { stem };

    let mut route = String::from(prefix);
    for segment in segments.split('/').filter(|segment| !segment.is_empty()) {
        route.push('/');
        route.push_str(&nitro_segment(segment));
    }
    if route.is_empty() {
        route.push('/');
    }

    Some(RouteInfo {
        path: route,
        method,
    })
}

/// Splits a trailing `.get` / `.post` method suffix off a Nitro file stem.
fn split_nitro_method(stem: &str) -> (&str, Option<String>) {
    let Some((rest, suffix)) = stem.rsplit_once('.') else {
        return (stem, None);
    };
    if NITRO_METHOD_SUFFIXES.contains(&suffix) {
        return (rest, Some(suffix.to_ascii_uppercase()));
    }
    (stem, None)
}

/// Converts one Nitro path segment to its URL form.
///
/// `[id]` is a parameter and `[...slug]` a catch-all; both are rendered in the
/// `:name` spelling Nitro itself documents.
fn nitro_segment(segment: &str) -> String {
    let Some(inner) = segment
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return segment.to_owned();
    };
    inner
        .strip_prefix("...")
        .map_or_else(|| format!(":{inner}"), |name| format!("**:{name}"))
}

/// Removes Next.js route groups (`(marketing)`) and parallel-route segments
/// (`@modal`), which organise files without appearing in the URL.
fn strip_next_route_groups(dir: &str) -> String {
    dir.split('/')
        .filter(|segment| {
            let is_route_group = segment.starts_with('(') && segment.ends_with(')');
            let is_parallel_route = segment.starts_with('@');
            !is_route_group && !is_parallel_route
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Strips a recognised source extension, or returns `None` for anything else.
///
/// Refusing unknown extensions matters: `server/api/users.json` is data a route
/// reads, not a route.
fn strip_extension(file: &str) -> Option<&str> {
    let (stem, extension) = file.rsplit_once('.')?;
    ROUTE_EXTENSIONS.contains(&extension).then_some(stem)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn next_path(path: &str) -> Option<String> {
        next(path).map(|route| route.path)
    }

    #[test]
    fn next_app_router_maps_route_files_only() {
        assert_eq!(
            next_path("app/api/users/route.ts").as_deref(),
            Some("/api/users")
        );
        assert_eq!(
            next_path("src/app/api/users/[id]/route.ts").as_deref(),
            Some("/api/users/[id]")
        );
        assert_eq!(next_path("app/api/users/helpers.ts"), None);
        assert_eq!(next_path("app/dashboard/page.tsx"), None);
    }

    #[test]
    fn next_route_groups_do_not_appear_in_the_url() {
        assert_eq!(
            next_path("app/(internal)/api/health/route.ts").as_deref(),
            Some("/api/health")
        );
        assert_eq!(
            next_path("app/@modal/api/x/route.ts").as_deref(),
            Some("/api/x")
        );
    }

    #[test]
    fn next_pages_router_maps_the_api_directory() {
        assert_eq!(
            next_path("pages/api/users.ts").as_deref(),
            Some("/api/users")
        );
        assert_eq!(
            next_path("pages/api/users/index.ts").as_deref(),
            Some("/api/users")
        );
        assert_eq!(next_path("pages/api/index.ts").as_deref(), Some("/api"));
        assert_eq!(next_path("pages/about.tsx"), None);
    }

    #[test]
    fn nitro_takes_the_method_from_the_file_name() {
        let route = nitro("server/api/users.get.ts").expect("a route");
        assert_eq!(route.path, "/api/users");
        assert_eq!(route.method.as_deref(), Some("GET"));

        let route = nitro("server/api/users.post.ts").expect("a route");
        assert_eq!(route.method.as_deref(), Some("POST"));

        let route = nitro("server/api/users.ts").expect("a route");
        assert_eq!(route.method, None, "no suffix means any method");
    }

    #[test]
    fn nitro_maps_parameters_and_catch_alls() {
        let route = nitro("server/api/users/[id].get.ts").expect("a route");
        assert_eq!(route.path, "/api/users/:id");

        let route = nitro("server/api/files/[...path].ts").expect("a route");
        assert_eq!(route.path, "/api/files/**:path");
    }

    #[test]
    fn nitro_root_routes_are_not_under_api() {
        let route = nitro("server/routes/health.ts").expect("a route");
        assert_eq!(route.path, "/health");
        assert_eq!(nitro("server/api/index.ts").expect("a route").path, "/api");
    }

    #[test]
    fn nitro_ignores_what_is_not_a_route() {
        // Middleware runs on everything and owns no path of its own.
        assert_eq!(nitro("server/middleware/auth.ts"), None);
        assert_eq!(nitro("server/utils/db.ts"), None);
        // Data read by a route is not a route.
        assert_eq!(nitro("server/api/seed.json"), None);
        assert_eq!(nitro("app.vue"), None);
    }

    #[test]
    fn a_dotted_name_that_is_not_a_method_keeps_its_dots() {
        let route = nitro("server/api/users.schema.ts").expect("a route");
        assert_eq!(route.path, "/api/users.schema");
        assert_eq!(route.method, None);
    }
}
