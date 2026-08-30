//! Attacking the exposure classifier and the runtime detector.
//!
//! Both read a repository nobody has vetted, and both feed a judgement a reader
//! acts on. The classifier's failure mode is the worse one and gets most of the
//! space here: **making a finding look safer than it is**.
//!
//! An attacker who can shape the tree — a dependency's example directory, a
//! contributed fixture, a pull request — wins if they can persuade the
//! classifier that a reachable handler is behind authentication. Every test
//! below is an attempt at that, plus the usual resource questions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

use owlwarden_core::finding::{Exposure, Finding, Location, RuleId, Severity, SourceLocation};
use owlwarden_static::exposure::ExposureClassifier;
use owlwarden_static::project::Project;
use owlwarden_static::{FrameworkRegistry, FsSourceProvider};

fn write(root: &Path, relative: &str, body: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn express_project() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "package.json",
        r#"{"name":"t","dependencies":{"express":"^4.19.2"}}"#,
    );
    root
}

fn classify(root: &Path, path: &str) -> Exposure {
    let provider = FsSourceProvider::new(root).unwrap();
    let project = Project::discover_with(&provider, &FrameworkRegistry::builtin()).unwrap();
    let mut classifier = ExposureClassifier::build(&project);
    let mut finding = Finding::builder(RuleId::new_static("ssrf"), Severity::High, "t")
        .location(Location::Source(SourceLocation {
            path: path.to_owned(),
            line: 1,
            col: 1,
        }))
        .build();
    classifier.classify_all(std::slice::from_mut(&mut finding));
    finding.exposure.expect("classified")
}

// ── forging a gate ──────────────────────────────────────────────────────────

#[test]
fn a_gate_imported_from_a_module_that_does_not_exist_is_not_a_gate() {
    // The single most valuable assertion in this file. Delete or rename the
    // middleware and every route it used to guard must stop claiming to be
    // guarded — otherwise a refactor silently marks live routes as safe.
    let root = express_project();
    write(
        root.path(),
        "src/app.ts",
        "import express from 'express'\n\
         import { requireAuth } from './middleware/auth'\n\
         const app = express()\n\
         app.use('/admin', requireAuth)\n",
    );
    write(
        root.path(),
        "src/admin.ts",
        "import express from 'express'\n\
         const router = express.Router()\n\
         router.get('/admin/x', (req, res) => res.json({}))\n\
         export default router\n",
    );
    assert_eq!(classify(root.path(), "src/admin.ts"), Exposure::Internet);
}

#[test]
fn a_gate_from_an_unknown_package_is_not_a_gate() {
    // A third-party package we have no opinion about must not become a gate by
    // being imported with a promising name.
    let root = express_project();
    write(
        root.path(),
        "src/app.ts",
        "import express from 'express'\n\
         import { requireAuth } from 'totally-legit-auth'\n\
         const app = express()\n\
         app.use('/admin', requireAuth)\n",
    );
    write(
        root.path(),
        "src/admin.ts",
        "import express from 'express'\n\
         const router = express.Router()\n\
         router.get('/admin/x', (req, res) => res.json({}))\n\
         export default router\n",
    );
    assert_eq!(classify(root.path(), "src/admin.ts"), Exposure::Internet);
}

#[test]
fn a_relative_import_cannot_climb_out_of_the_tree_to_find_a_gate() {
    // `../../../../etc/auth` must not resolve. A resolver that walked past the
    // root could be pointed at any path that happens to exist on the runner.
    let root = express_project();
    write(
        root.path(),
        "src/app.ts",
        "import express from 'express'\n\
         import { requireAuth } from '../../../../etc/auth'\n\
         const app = express()\n\
         app.use('/admin', requireAuth)\n",
    );
    write(
        root.path(),
        "src/admin.ts",
        "import express from 'express'\n\
         const router = express.Router()\n\
         router.get('/admin/x', (req, res) => res.json({}))\n\
         export default router\n",
    );
    assert_eq!(classify(root.path(), "src/admin.ts"), Exposure::Internet);
}

#[test]
fn an_inline_arrow_middleware_is_not_a_gate_whatever_it_is_called() {
    // `app.use('/admin', (req, res, next) => next())` mounts something whose
    // body we do not understand. Reading the variable name as evidence would
    // make a one-line edit enough to mark a route safe.
    let root = express_project();
    write(
        root.path(),
        "src/app.ts",
        "import express from 'express'\n\
         const app = express()\n\
         const requireAuth = (req, res, next) => next()\n\
         app.use('/admin', (req, res, next) => next())\n",
    );
    write(
        root.path(),
        "src/admin.ts",
        "import express from 'express'\n\
         const router = express.Router()\n\
         router.get('/admin/x', (req, res) => res.json({}))\n\
         export default router\n",
    );
    assert_eq!(classify(root.path(), "src/admin.ts"), Exposure::Internet);
}

#[test]
fn a_session_read_with_nothing_done_about_it_is_not_a_gate() {
    // `const session = await auth()` and then nothing. The value was read; the
    // request was not refused.
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "package.json",
        r#"{"name":"t","dependencies":{"next":"^14.2.0"}}"#,
    );
    write(
        root.path(),
        "app/api/x/route.ts",
        "import { auth } from '@/lib/auth'\n\
         export async function GET() {\n  \
         const session = await auth()\n  \
         return Response.json({ ok: true })\n\
         }\n",
    );
    write(
        root.path(),
        "lib/auth.ts",
        "export async function auth() { return null }\n",
    );
    assert_eq!(
        classify(root.path(), "app/api/x/route.ts"),
        Exposure::Internet
    );
}

#[test]
fn a_middleware_matcher_that_cannot_be_read_covers_nothing() {
    // An unparseable matcher must narrow to nothing, not widen to everything.
    // Widening would mark every route in the application as behind auth on the
    // strength of a file we failed to read.
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "package.json",
        r#"{"name":"t","dependencies":{"next":"^14.2.0","@clerk/nextjs":"^5.0.0"}}"#,
    );
    write(
        root.path(),
        "middleware.ts",
        "import { clerkMiddleware } from '@clerk/nextjs/server'\n\
         export default clerkMiddleware()\n\
         export const config = { matcher: MATCHERS }\n",
    );
    write(
        root.path(),
        "app/api/x/route.ts",
        "export async function GET() { return Response.json({}) }\n",
    );
    assert_eq!(
        classify(root.path(), "app/api/x/route.ts"),
        Exposure::Internet
    );
}

#[test]
fn a_prefix_mount_does_not_cover_a_route_it_merely_prefixes_textually() {
    // `/api` must not cover `/apikeys`. A `starts_with` without a segment
    // boundary would mark a neighbouring route as gated.
    let root = express_project();
    write(
        root.path(),
        "src/middleware/auth.ts",
        "export function requireAuth(req, res, next) { next() }\n",
    );
    write(
        root.path(),
        "src/app.ts",
        "import express from 'express'\n\
         import { requireAuth } from './middleware/auth'\n\
         const app = express()\n\
         app.use('/api', requireAuth)\n",
    );
    write(
        root.path(),
        "src/keys.ts",
        "import express from 'express'\n\
         const router = express.Router()\n\
         router.get('/apikeys/list', (req, res) => res.json({}))\n\
         export default router\n",
    );
    assert_eq!(classify(root.path(), "src/keys.ts"), Exposure::Internet);
}

// ── the loud direction, stated as a property ────────────────────────────────

#[test]
fn no_tree_shape_makes_an_unresolvable_gate_produce_authenticated() {
    // A property rather than an example: whatever the tree looks like, a gate
    // whose module is absent never yields `authenticated`.
    for specifier in [
        "./missing",
        "../missing",
        "@/missing",
        "~/missing",
        "src/missing",
        "./middleware/auth",
        "#internal/auth",
    ] {
        let root = express_project();
        write(
            root.path(),
            "src/app.ts",
            &format!(
                "import express from 'express'\n\
                 import {{ requireAuth }} from '{specifier}'\n\
                 const app = express()\n\
                 app.use('/admin', requireAuth)\n"
            ),
        );
        write(
            root.path(),
            "src/admin.ts",
            "import express from 'express'\n\
             const router = express.Router()\n\
             router.get('/admin/x', (req, res) => res.json({}))\n\
             export default router\n",
        );
        assert_ne!(
            classify(root.path(), "src/admin.ts"),
            Exposure::Authenticated,
            "{specifier} forged a gate"
        );
    }
}

// ── bounded work ────────────────────────────────────────────────────────────

#[test]
fn a_tree_full_of_middleware_files_does_not_make_classification_unbounded() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "package.json",
        r#"{"name":"t","dependencies":{"nuxt":"^3.12.0"}}"#,
    );
    // Nuxt reads every file under `server/middleware`, so the cap is what stops
    // a repository choosing how long a scan takes.
    for index in 0..2_000 {
        write(
            root.path(),
            &format!("server/middleware/m{index}.ts"),
            "export default defineEventHandler(() => {})\n",
        );
    }
    write(
        root.path(),
        "server/api/x.get.ts",
        "export default defineEventHandler(() => ({}))\n",
    );

    let started = std::time::Instant::now();
    let exposure = classify(root.path(), "server/api/x.get.ts");
    assert!(
        started.elapsed().as_secs() < 30,
        "classification should be bounded by MAX_GATE_FILES"
    );
    assert_ne!(exposure, Exposure::Authenticated);
}

#[test]
fn a_pathological_source_file_does_not_stall_or_crash_the_classifier() {
    for body in [
        "app.use(".repeat(20_000) + &")".repeat(20_000),
        "import { a } from './b'\n".repeat(50_000),
        format!("const x = '{}'\n", "a".repeat(500_000)),
        "\u{0}\u{0}\u{0}".to_owned(),
        "export const runtime = ".to_owned() + &"'edge'".repeat(10_000),
    ] {
        let root = express_project();
        write(root.path(), "src/x.ts", &body);
        // The contract is: it answers, in bounded time, without panicking.
        let _ = classify(root.path(), "src/x.ts");
    }
}

// ── the runtime detector ────────────────────────────────────────────────────

#[test]
fn a_hostile_runtime_export_line_does_not_stall_the_scanner() {
    use owlwarden_static::runtime::declared_in_source;

    for body in [
        " ".repeat(2_000_000) + "export const runtime = 'edge'",
        "export const runtime = ".repeat(100_000),
        "export const runtime = '".to_owned() + &"e".repeat(1_000_000),
        "\n".repeat(2_000_000),
        "export\t const \t runtime \t = \t 'edge'".to_owned(),
    ] {
        let started = std::time::Instant::now();
        let _ = declared_in_source(&body);
        assert!(
            started.elapsed().as_secs() < 5,
            "the source scan must stay bounded"
        );
    }
}

#[test]
fn a_declaration_file_cannot_point_the_runtime_outside_its_own_directory() {
    use owlwarden_static::runtime::RuntimeMap;

    // A `wrangler.toml` in `apps/api` must not change how `apps/jobs` is
    // classified — otherwise one package's config decides another's fixes.
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "package.json",
        r#"{"name":"t","dependencies":{"hono":"^4.5.0"}}"#,
    );
    write(root.path(), "apps/api/wrangler.toml", "name = \"api\"\n");
    write(root.path(), "apps/api/src/index.ts", "export default {}\n");
    write(
        root.path(),
        "apps/jobs/src/run.ts",
        "export function run() {}\n",
    );

    let provider = FsSourceProvider::new(root.path()).unwrap();
    let project = Project::discover_with(&provider, &FrameworkRegistry::builtin()).unwrap();
    let map: &RuntimeMap = project.runtimes();

    assert_eq!(
        map.for_path("apps/api/src/index.ts").runtime,
        owlwarden_core::runtime::Runtime::WebWorker
    );
    assert_ne!(
        map.for_path("apps/jobs/src/run.ts").runtime,
        owlwarden_core::runtime::Runtime::WebWorker,
        "one package's declaration decided another package's runtime"
    );
}

#[test]
fn a_module_specifier_cannot_carry_a_newline_or_a_bidi_override_into_the_evidence() {
    // A specifier is a string literal, so it can hold anything — and on Unix a
    // filename can too, which makes a hostile one resolvable. The evidence it
    // ends up in reaches a terminal, a JSON file, a SARIF result, a
    // pull-request comment, and `--format agent`.
    use owlwarden_static::exposure::GateRef;

    let forged = GateRef::new(
        "requireAuth\nrouter.get('/admin', open)",
        "src/a.ts:1\n\nAll checks passed.",
        "`requireAuth` is defined in `./mid\u{202e}ware`",
    );
    for field in [&forged.name, &forged.location, &forged.reason] {
        assert!(!field.contains('\n'), "a raw newline survived: {field:?}");
        assert!(
            !field.contains('\u{202e}'),
            "a bidi override survived: {field:?}"
        );
        assert!(!field.contains('\r'));
    }
}

#[test]
fn gate_evidence_is_bounded_however_long_the_source_identifier_is() {
    use owlwarden_static::exposure::GateRef;

    let enormous = "a".repeat(1_000_000);
    let forged = GateRef::new(&enormous, &enormous, &enormous);
    for field in [&forged.name, &forged.location, &forged.reason] {
        assert!(
            field.chars().count() < 500,
            "evidence is a glance, not a listing"
        );
    }
}
