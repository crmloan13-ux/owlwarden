//! The exposure classifier, asserted against a fixture per framework.
//!
//! These tests classify a synthetic finding at a known path rather than waiting
//! for a rule to fire there. That is deliberate: the property under test is
//! *where the finding sits and what guards it*, and routing it through a rule
//! would mean a change in that rule's precision silently changed what this file
//! proves.
//!
//! # The assertion that matters
//!
//! Every framework gets three cases, and the third is the one to keep:
//!
//! 1. A gated route classifies `authenticated`.
//! 2. An ungated route classifies `internet`.
//! 3. **With the gate removed, the gated route never classifies
//!    `authenticated`.**
//!
//! The third is asserted by copying the fixture into a temporary directory and
//! deleting the gate, so it tests the classifier's direction of failure rather
//! than its agreement with a fixture we wrote.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use owlwarden_core::finding::{
    Exposure, Finding, Framework, Location, RuleId, Severity, SourceLocation,
};
use owlwarden_static::exposure::ExposureClassifier;
use owlwarden_static::project::Project;
use owlwarden_static::{FrameworkRegistry, FsSourceProvider};

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/exposure")
        .join(relative)
}

/// A finding at one path, with no other context — everything the classifier
/// uses must come from the tree, not from the finding.
fn at(path: &str) -> Finding {
    Finding::builder(RuleId::new_static("stack-trace-leak"), Severity::High, "t")
        .location(Location::Source(SourceLocation {
            path: path.to_owned(),
            line: 1,
            col: 1,
        }))
        .build()
}

/// Classifies one path inside one fixture project.
fn classify_in(root: &Path, path: &str) -> (Exposure, Option<String>) {
    let provider = FsSourceProvider::new(root).expect("fixture root should be readable");
    let project =
        Project::discover_with(&provider, &FrameworkRegistry::builtin()).expect("walkable tree");
    let mut classifier = ExposureClassifier::build(&project);
    let mut finding = at(path);
    classifier.classify_all(std::slice::from_mut(&mut finding));
    (
        finding
            .exposure
            .expect("every application finding is classified"),
        finding.exposure_evidence.and_then(|evidence| evidence.gate),
    )
}

fn classify(project: &str, path: &str) -> Exposure {
    classify_in(&fixture(project), path).0
}

/// Copies a fixture into a temporary directory so a test can delete part of it.
fn copy_without(project: &str, omit: &[&str]) -> tempfile::TempDir {
    let temporary = tempfile::tempdir().expect("temp dir");
    copy_tree(&fixture(project), temporary.path(), &fixture(project), omit);
    temporary
}

fn copy_tree(from: &Path, to: &Path, root: &Path, omit: &[&str]) {
    for entry in fs::read_dir(from).expect("readable fixture") {
        let entry = entry.expect("readable entry");
        let source = entry.path();
        let relative = source.strip_prefix(root).expect("under root");
        let relative_str = relative.to_string_lossy().replace('\\', "/");
        if omit.contains(&relative_str.as_str()) {
            continue;
        }
        let destination = to.join(relative);
        if source.is_dir() {
            fs::create_dir_all(&destination).expect("mkdir");
            copy_tree(&source, to, root, omit);
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            fs::copy(&source, &destination).expect("copy");
        }
    }
}

/// One row of the matrix: the project, its gated route, its ungated route (when
/// it has one), and the file whose deletion removes the gate.
struct Case {
    framework: Framework,
    project: &'static str,
    gated: &'static str,
    ungated: Option<&'static str>,
    /// Deleting this must stop the gated route being `authenticated`.
    gate_source: &'static str,
    internal: &'static str,
}

fn matrix() -> Vec<Case> {
    vec![
        Case {
            framework: Framework::EXPRESS,
            project: "express",
            gated: "src/admin.ts",
            ungated: Some("src/public.ts"),
            gate_source: "src/middleware/auth.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::FASTIFY,
            project: "fastify",
            gated: "src/admin.ts",
            ungated: Some("src/public.ts"),
            gate_source: "src/admin.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::NEST,
            project: "nest",
            gated: "src/admin.controller.ts",
            ungated: Some("src/public.controller.ts"),
            gate_source: "src/admin.controller.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::NEXT,
            project: "next",
            gated: "app/api/admin/reports/route.ts",
            ungated: Some("app/api/public/reports/route.ts"),
            gate_source: "middleware.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::NUXT,
            project: "nuxt",
            gated: "server/api/reports.get.ts",
            ungated: None,
            gate_source: "server/middleware/auth.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::HONO,
            project: "hono",
            gated: "src/admin.ts",
            ungated: Some("src/public.ts"),
            gate_source: "src/index.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::KOA,
            project: "koa",
            gated: "src/admin.ts",
            ungated: Some("src/public.ts"),
            gate_source: "src/admin.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::HAPI,
            project: "hapi",
            gated: "src/admin.ts",
            ungated: Some("src/public.ts"),
            gate_source: "src/admin.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::SAILS,
            project: "sails",
            gated: "api/controllers/admin/reports.js",
            ungated: None,
            gate_source: "config/policies.js",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::ASTRO,
            project: "astro",
            gated: "src/pages/api/reports.ts",
            ungated: None,
            gate_source: "src/middleware.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::GATSBY,
            project: "gatsby",
            gated: "src/api/admin/reports.ts",
            ungated: Some("src/api/reports.ts"),
            gate_source: "src/lib/auth.ts",
            internal: "scripts/seed.ts",
        },
        Case {
            framework: Framework::REMIX,
            project: "remix",
            gated: "app/routes/admin.reports.tsx",
            ungated: Some("app/routes/public.reports.tsx"),
            gate_source: "app/utils/session.server.ts",
            internal: "scripts/seed.ts",
        },
    ]
}

#[test]
fn a_gated_route_is_behind_auth_in_every_framework() {
    for case in matrix() {
        let (exposure, gate) = classify_in(&fixture(case.project), case.gated);
        assert_eq!(
            exposure,
            Exposure::Authenticated,
            "{}: {} should be gated",
            case.framework,
            case.gated
        );
        assert!(
            gate.is_some(),
            "{}: an `authenticated` finding must name the gate that decided it",
            case.framework
        );
    }
}

#[test]
fn an_ungated_route_is_internet_reachable_in_every_framework() {
    for case in matrix() {
        let Some(ungated) = case.ungated else {
            continue;
        };
        assert_eq!(
            classify(case.project, ungated),
            Exposure::Internet,
            "{}: {} has no gate and must say so",
            case.framework,
            ungated
        );
    }
}

#[test]
fn removing_the_gate_never_leaves_a_route_behind_auth() {
    // The assertion this whole axis rests on. Not "it becomes internet" —
    // "it is never `authenticated`", which is the property that holds even if
    // the route stops resolving for some unrelated reason.
    for case in matrix() {
        let stripped = copy_without(case.project, &[case.gate_source]);
        let (exposure, _) = classify_in(stripped.path(), case.gated);
        assert_ne!(
            exposure,
            Exposure::Authenticated,
            "{}: deleting {} left {} claiming to be behind auth",
            case.framework,
            case.gate_source,
            case.gated
        );
    }
}

#[test]
fn a_build_script_is_internal_in_every_framework() {
    for case in matrix() {
        assert_eq!(
            classify(case.project, case.internal),
            Exposure::Internal,
            "{}: {} is not on a request path",
            case.framework,
            case.internal
        );
    }
}

#[test]
fn an_unresolvable_middleware_module_is_internet_not_authenticated_and_not_unknown() {
    // ADR 0029 exit criterion 3, stated as its own test because it is the case
    // a reviewer will want to find by name. `src/app.ts` still says
    // `app.use('/admin', requireAuth)`; the module it imports is gone.
    let stripped = copy_without("express", &["src/middleware/auth.ts"]);
    let (exposure, gate) = classify_in(stripped.path(), "src/admin.ts");
    assert_eq!(exposure, Exposure::Internet);
    assert!(gate.is_none(), "no gate may be named when none was found");
}

#[test]
fn a_matcher_that_does_not_cover_a_route_leaves_it_reachable() {
    // Next's `config.matcher` is the only thing separating `/admin` from
    // `/public` in that fixture. If matcher handling regressed to "middleware
    // gates everything", this is the test that catches it.
    assert_eq!(
        classify("next", "app/api/public/reports/route.ts"),
        Exposure::Internet
    );
    assert_eq!(
        classify("next", "app/api/admin/reports/route.ts"),
        Exposure::Authenticated
    );
}

#[test]
fn a_library_file_is_unclassified_rather_than_claimed_internal() {
    // `internal` is a claim that nothing reaches it. We have no basis for that
    // claim about a helper module, and making it would be the reassuring lie
    // in a different costume.
    let temporary = copy_without("express", &[]);
    fs::write(
        temporary.path().join("src/lib.ts"),
        "export function load(id: unknown) { return id }\n",
    )
    .expect("write");
    let (exposure, _) = classify_in(temporary.path(), "src/lib.ts");
    assert_eq!(exposure, Exposure::Unknown);
}

#[test]
fn a_file_that_resolves_to_a_route_is_never_left_unclassified() {
    // ADR 0029 exit criterion 1. A framework whose profile claims route
    // resolution must place every finding in a file it resolves — silence
    // there would put a reachable finding in the bucket the reader skims.
    for case in matrix() {
        let root = fixture(case.project);
        let provider = FsSourceProvider::new(&root).expect("readable");
        let project =
            Project::discover_with(&provider, &FrameworkRegistry::builtin()).expect("walkable");
        if project.frameworks().primary().route_for_path.is_none() {
            continue;
        }
        let mut classifier = ExposureClassifier::build(&project);
        for file in project.files() {
            let path = file.path.as_str();
            if project.frameworks().route(path).is_none() {
                continue;
            }
            let mut finding = at(path);
            classifier.classify_all(std::slice::from_mut(&mut finding));
            assert_ne!(
                finding.exposure,
                Some(Exposure::Unknown),
                "{}: {path} resolves to a route and must not be unclassified",
                case.framework
            );
        }
    }
}

#[test]
fn classification_is_deterministic_across_runs() {
    // Two scans of the same tree must produce the same answer, or the report
    // diff a team reads every morning is noise. The gate map is sorted for
    // exactly this reason.
    for case in matrix() {
        let first = classify(case.project, case.gated);
        let second = classify(case.project, case.gated);
        assert_eq!(first, second, "{}", case.framework);
    }
}
