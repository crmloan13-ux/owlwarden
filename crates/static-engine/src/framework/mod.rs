//! What owlwarden knows about a web framework, as data a rule can query.
//!
//! # The problem this solves
//!
//! The first two rules each carried their own copy of the framework knowledge
//! they needed: `stack-trace-leak` had a private list of response objects,
//! `security-headers-missing` had a private list of configuration file names,
//! and both ended in a `match framework { ... }` producing remediation. That
//! shape costs `rules × frameworks` edits to add a framework, and every rule
//! that forgets an entry is silently blind to that stack rather than visibly
//! broken.
//!
//! A [`FrameworkProfile`] states the knowledge once: how to detect the
//! framework, where its configuration lives, what its response objects are
//! called, and how its routes map to files. Rules ask the profile. Adding
//! Fastify is then one profile, not an edit to every rule.
//!
//! # Why a registry and not a table of constants
//!
//! The [`FrameworkRegistry`] is a `Vec` you can push into, and profiles are
//! owned values rather than `&'static` data. That costs one small allocation
//! per scan and buys the thing the plugin tier needs: a profile can be built at
//! runtime from a manifest the host did not compile in. The WASM host that
//! loads untrusted profiles is v0.2, but the seam it will use is this one, and
//! it is exercised today by [`FrameworkRegistry::register`].
//!
//! # What is still closed, and why
//!
//! [`HandlerStyle`] is an enum, not a callback. Recognising `@Get()` on a class
//! method is structural AST work living in [`crate::http`], not a string
//! transform, so a genuinely new *shape* of routing needs engine code. A new
//! framework that reuses an existing shape — and most do — needs data only.
//! Pretending otherwise with a callback that a WASM plugin cannot supply would
//! be a worse lie than the honest limit.

pub mod profiles;
pub mod routing;

use std::sync::Arc;

use owlwarden_core::finding::Framework;

use crate::project::PackageManifest;

pub use routing::RouteInfo;

/// The identifiers and method names one framework uses to speak HTTP.
///
/// Rules consult this instead of hardcoding names, which is what lets a single
/// rule work across every registered framework. See [`crate::http`] for the AST
/// questions built on top of it.
#[derive(Debug, Clone, Default)]
pub struct HttpVocabulary {
    /// Identifiers that hold something you can write a response to:
    /// `res`, `reply`, `NextResponse`.
    pub response_objects: Vec<String>,
    /// Methods on a response object that write a body. Deliberately excludes
    /// `status` and `header`, which set metadata — a rule looking for data
    /// leaving the process must not fire on `res.status(500)`.
    pub body_methods: Vec<String>,
    /// Bare functions that write a response, with no object in front.
    ///
    /// h3 — and therefore Nuxt — is built this way: `send(event, body)` rather
    /// than `res.send(body)`. Without this the whole framework is invisible to
    /// any rule that tracks data reaching a client, which is most of them.
    pub response_helpers: Vec<String>,
    /// Constructors that build a response or an HTTP error carrying a body:
    /// `Response`, `NextResponse`, `HttpException`.
    pub response_constructors: Vec<String>,
    /// Calls that set a cookie, as `object.method` or a bare function name.
    /// `res.cookie`, `reply.setCookie`, `setCookie`.
    pub cookie_setters: Vec<String>,
    /// Objects that routes are registered on: `app`, `router`, `fastify`.
    pub router_objects: Vec<String>,
    /// Calls that enable CORS: `cors`, `enableCors`, `registerCors`.
    pub cors_enablers: Vec<String>,
}

impl HttpVocabulary {
    /// Whether a name denotes a response object in this framework.
    #[must_use]
    pub fn is_response_object(&self, name: &str) -> bool {
        self.response_objects.iter().any(|known| known == name)
    }

    /// Whether a method name writes a response body.
    #[must_use]
    pub fn is_body_method(&self, name: &str) -> bool {
        self.body_methods.iter().any(|known| known == name)
    }

    /// Whether a bare function name writes a response body.
    #[must_use]
    pub fn is_response_helper(&self, name: &str) -> bool {
        self.response_helpers.iter().any(|known| known == name)
    }

    /// Whether a constructor produces a response or an HTTP error.
    #[must_use]
    pub fn is_response_constructor(&self, name: &str) -> bool {
        self.response_constructors.iter().any(|known| known == name)
    }

    /// Whether an object is one routes get registered on.
    #[must_use]
    pub fn is_router_object(&self, name: &str) -> bool {
        self.router_objects.iter().any(|known| known == name)
    }
}

/// How a framework spells "this function handles an HTTP request".
///
/// Used to attribute a finding to a method (`GET /api/users`) rather than just
/// a file. A profile may list more than one: a Next.js project uses the App
/// Router's exported verbs and, in older code, a default-exported Pages API
/// handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerStyle {
    /// `export async function GET()` or `export const POST = ...`.
    /// Next.js App Router.
    ExportedVerb,
    /// `@Get()` / `@Post()` on a class method, with `@Controller('users')` on
    /// the class. `NestJS`.
    MethodDecorator,
    /// `app.get('/users', handler)`. Express, Fastify.
    RouterCall,
    /// `export default defineEventHandler(...)`, with the verb in the file name
    /// (`users.get.ts`). Nuxt's Nitro server routes.
    FileSuffixVerb,
}

/// Everything owlwarden knows about one framework.
#[derive(Debug, Clone)]
pub struct FrameworkProfile {
    /// The id that travels on findings and fixes.
    pub id: Framework,
    /// npm packages whose presence identifies this framework. Any match counts.
    pub packages: Vec<String>,
    /// Tie-break when several profiles match. Higher wins.
    ///
    /// This matters because the dependency sets overlap by design: a NestJS app
    /// declares `express`, and a Nuxt app pulls in `h3`. Both frameworks are
    /// genuinely present, but only one of them is the answer to "where do I put
    /// this fix", and showing an Express fix to a Nest user is how remediation
    /// stops being trusted.
    pub specificity: u8,
    /// Files that configure app-wide response behaviour: headers, CORS,
    /// redirects. Checked in order.
    pub config_files: Vec<String>,
    /// Files where the server is constructed and middleware registered.
    pub bootstrap_files: Vec<String>,
    /// The framework's HTTP vocabulary.
    pub http: HttpVocabulary,
    /// How its handlers are recognised.
    pub handlers: Vec<HandlerStyle>,
    /// Maps a project-relative source path to the route it serves, for
    /// frameworks that route by file layout.
    ///
    /// A function pointer rather than an enum because this is a pure string
    /// transform with no AST involved, so it is the one part of a profile a
    /// future host really can supply from outside.
    ///
    /// Returns `None` when the mapping is not certain. A route printed in a
    /// report is a claim about the reader's application, and a wrong one sends
    /// them to the wrong file.
    pub route_for_path: Option<fn(&str) -> Option<RouteInfo>>,
}

impl FrameworkProfile {
    /// Whether this profile handles a given handler style.
    #[must_use]
    pub fn uses(&self, style: HandlerStyle) -> bool {
        self.handlers.contains(&style)
    }

    /// The route a file serves, if this framework routes by file layout.
    #[must_use]
    pub fn route(&self, path: &str) -> Option<RouteInfo> {
        (self.route_for_path?)(path)
    }
}

/// The profiles available to a scan.
///
/// Built with the first-party set and then, in v0.2, extended by the plugin
/// host. Order is by descending specificity so detection can take the first
/// match.
#[derive(Debug, Clone)]
pub struct FrameworkRegistry {
    profiles: Vec<Arc<FrameworkProfile>>,
    generic: Arc<FrameworkProfile>,
}

impl FrameworkRegistry {
    /// The frameworks owlwarden ships with.
    #[must_use]
    pub fn builtin() -> Self {
        let mut registry = Self {
            profiles: Vec::new(),
            generic: Arc::new(profiles::generic()),
        };
        for profile in profiles::builtin() {
            registry.register(profile);
        }
        registry
    }

    /// Adds a profile, keeping the registry sorted by descending specificity.
    ///
    /// A profile whose id is already registered replaces the previous one, so a
    /// plugin can correct a first-party profile rather than having to fight it.
    /// That is deliberate: the alternative is a user who cannot make the tool
    /// understand their own fork of a framework.
    pub fn register(&mut self, profile: FrameworkProfile) {
        self.profiles.retain(|existing| existing.id != profile.id);
        self.profiles.push(Arc::new(profile));
        // Secondary sort on the id keeps the order total, so two profiles with
        // equal specificity cannot make a scan non-deterministic.
        self.profiles.sort_by(|left, right| {
            right
                .specificity
                .cmp(&left.specificity)
                .then_with(|| left.id.cmp(&right.id))
        });
    }

    /// The fallback profile, used when nothing is detected.
    #[must_use]
    pub fn generic(&self) -> Arc<FrameworkProfile> {
        Arc::clone(&self.generic)
    }

    /// Looks up a registered profile by id.
    #[must_use]
    pub fn get(&self, id: &Framework) -> Option<Arc<FrameworkProfile>> {
        self.profiles
            .iter()
            .find(|profile| &profile.id == id)
            .map(Arc::clone)
    }

    /// Every registered profile, most specific first.
    #[must_use]
    pub fn all(&self) -> &[Arc<FrameworkProfile>] {
        &self.profiles
    }

    /// Which frameworks a project's declared dependencies point at.
    ///
    /// Reads the manifest rather than guessing from file layout. A wrong guess
    /// produces remediation that does not apply to the reader's codebase, which
    /// is worse than the generic advice it displaced.
    #[must_use]
    pub fn detect(&self, manifest: &PackageManifest) -> FrameworkSet {
        let matched: Vec<Arc<FrameworkProfile>> = self
            .profiles
            .iter()
            .filter(|profile| {
                profile
                    .packages
                    .iter()
                    .any(|package| manifest.depends_on(package))
            })
            .map(Arc::clone)
            .collect();

        FrameworkSet::new(matched, self.generic())
    }
}

impl Default for FrameworkRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

/// The frameworks detected in one project.
///
/// More than one is normal, not an error state. A NestJS service really is an
/// Express application underneath, and a monorepo scanned from its root really
/// does contain both a Next.js app and a Fastify API. The `primary` decides
/// which remediation is shown; `all` decides what the rules recognise, so a
/// Nest handler using the underlying `res.json` is still seen as writing a
/// response.
#[derive(Debug, Clone)]
pub struct FrameworkSet {
    primary: Arc<FrameworkProfile>,
    all: Vec<Arc<FrameworkProfile>>,
}

impl FrameworkSet {
    /// Builds a set from detected profiles, falling back to `generic`.
    #[must_use]
    pub fn new(matched: Vec<Arc<FrameworkProfile>>, generic: Arc<FrameworkProfile>) -> Self {
        let primary = matched.first().map_or(generic, Arc::clone);
        Self {
            primary,
            all: matched,
        }
    }

    /// A set containing only the generic profile, for tests and for projects
    /// with no recognisable manifest.
    #[must_use]
    pub fn generic_only() -> Self {
        let generic = Arc::new(profiles::generic());
        Self {
            primary: Arc::clone(&generic),
            all: Vec::new(),
        }
    }

    /// The framework remediation is written for.
    #[must_use]
    pub fn primary(&self) -> &FrameworkProfile {
        &self.primary
    }

    /// The primary framework's id.
    #[must_use]
    pub fn id(&self) -> &Framework {
        &self.primary.id
    }

    /// Every detected profile, most specific first. Empty when nothing matched.
    #[must_use]
    pub fn all(&self) -> &[Arc<FrameworkProfile>] {
        &self.all
    }

    /// Whether a specific framework was detected.
    #[must_use]
    pub fn contains(&self, id: &Framework) -> bool {
        self.all.iter().any(|profile| &profile.id == id)
    }

    /// Runs a query against every detected profile, and against the generic
    /// profile when nothing was detected.
    ///
    /// This is how a rule stays correct in a project with two frameworks
    /// without knowing that it is in one.
    pub fn any<F>(&self, mut question: F) -> bool
    where
        F: FnMut(&FrameworkProfile) -> bool,
    {
        if self.all.is_empty() {
            return question(&self.primary);
        }
        self.all.iter().any(|profile| question(profile))
    }

    /// The first route mapping any detected framework can produce for a path.
    #[must_use]
    pub fn route(&self, path: &str) -> Option<RouteInfo> {
        self.all
            .iter()
            .find_map(|profile| profile.route(path))
            .or_else(|| self.primary.route(path))
    }

    /// Config file candidates across every detected framework, in order and
    /// without duplicates.
    #[must_use]
    pub fn config_files(&self) -> Vec<String> {
        self.collect(|profile| &profile.config_files)
    }

    /// Bootstrap file candidates across every detected framework.
    #[must_use]
    pub fn bootstrap_files(&self) -> Vec<String> {
        self.collect(|profile| &profile.bootstrap_files)
    }

    fn collect<F>(&self, field: F) -> Vec<String>
    where
        F: Fn(&FrameworkProfile) -> &Vec<String>,
    {
        let mut out: Vec<String> = Vec::new();
        let sources: Vec<&Arc<FrameworkProfile>> = if self.all.is_empty() {
            vec![&self.primary]
        } else {
            self.all.iter().collect()
        };
        for profile in sources {
            for candidate in field(profile) {
                if !out.contains(candidate) {
                    out.push(candidate.clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn manifest(deps: &[&str]) -> PackageManifest {
        PackageManifest {
            name: Some("fixture".to_owned()),
            dependencies: deps
                .iter()
                .map(|name| ((*name).to_owned(), "1.0.0".to_owned()))
                .collect(),
            scripts: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn every_builtin_framework_is_detected_from_its_package() {
        let registry = FrameworkRegistry::builtin();
        for (package, expected) in [
            ("next", Framework::NEXT),
            ("nuxt", Framework::NUXT),
            ("@nestjs/core", Framework::NEST),
            ("express", Framework::EXPRESS),
            ("fastify", Framework::FASTIFY),
        ] {
            let detected = registry.detect(&manifest(&[package]));
            assert_eq!(
                detected.id(),
                &expected,
                "{package} should detect {expected}"
            );
        }
    }

    #[test]
    fn nest_wins_over_express_because_a_nest_app_declares_both() {
        let registry = FrameworkRegistry::builtin();
        let detected = registry.detect(&manifest(&["@nestjs/core", "express"]));

        assert_eq!(detected.id(), &Framework::NEST);
        assert!(
            detected.contains(&Framework::EXPRESS),
            "express is still present, and its response objects still apply"
        );
        assert_eq!(detected.all().len(), 2);
    }

    #[test]
    fn a_monorepo_with_two_frameworks_keeps_both() {
        let registry = FrameworkRegistry::builtin();
        let detected = registry.detect(&manifest(&["next", "fastify"]));

        assert!(detected.contains(&Framework::NEXT));
        assert!(detected.contains(&Framework::FASTIFY));
        // Both routings are available, so a finding in either half of the
        // repository still gets a route.
        assert!(detected.route("app/api/users/route.ts").is_some());
    }

    #[test]
    fn nothing_recognised_falls_back_to_generic() {
        let registry = FrameworkRegistry::builtin();
        let detected = registry.detect(&manifest(&["lodash"]));

        assert_eq!(detected.id(), &Framework::GENERIC);
        assert!(detected.all().is_empty());
        // Generic still answers vocabulary questions, so rules keep working on
        // a plain Node service.
        assert!(detected.any(|profile| profile.http.is_response_object("res")));
    }

    #[test]
    fn a_registered_profile_replaces_a_builtin_of_the_same_id() {
        let mut registry = FrameworkRegistry::builtin();
        let before = registry.all().len();

        registry.register(FrameworkProfile {
            id: Framework::EXPRESS,
            packages: vec!["express".to_owned()],
            specificity: 200,
            config_files: Vec::new(),
            bootstrap_files: Vec::new(),
            http: HttpVocabulary {
                response_objects: vec!["reply".to_owned()],
                ..HttpVocabulary::default()
            },
            handlers: Vec::new(),
            route_for_path: None,
        });

        assert_eq!(registry.all().len(), before, "replaced, not appended");
        let detected = registry.detect(&manifest(&["express", "@nestjs/core"]));
        assert_eq!(
            detected.id(),
            &Framework::EXPRESS,
            "the override's specificity now beats NestJS"
        );
    }

    #[test]
    fn a_plugin_can_add_a_framework_core_has_never_heard_of() {
        let mut registry = FrameworkRegistry::builtin();
        let hono = Framework::parse("hono").expect("valid id");

        registry.register(FrameworkProfile {
            id: hono.clone(),
            packages: vec!["hono".to_owned()],
            specificity: 25,
            config_files: Vec::new(),
            bootstrap_files: vec!["src/index.ts".to_owned()],
            http: HttpVocabulary {
                response_objects: vec!["c".to_owned()],
                body_methods: vec!["json".to_owned(), "text".to_owned()],
                ..HttpVocabulary::default()
            },
            handlers: vec![HandlerStyle::RouterCall],
            route_for_path: None,
        });

        let detected = registry.detect(&manifest(&["hono"]));
        assert_eq!(detected.id(), &hono);
        assert!(detected.any(|profile| profile.http.is_body_method("text")));
    }

    #[test]
    fn detection_order_is_total_so_scans_are_deterministic() {
        let registry = FrameworkRegistry::builtin();
        let ids: Vec<&str> = registry
            .all()
            .iter()
            .map(|profile| profile.id.as_str())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate framework id registered");

        for window in registry.all().windows(2) {
            let [left, right] = window else { continue };
            assert!(
                left.specificity > right.specificity
                    || (left.specificity == right.specificity && left.id < right.id),
                "registry order must be total"
            );
        }
    }
}
