//! The invariant that makes "no delta" an assertion rather than an oversight.
//!
//! [ADR 0031](../../../docs/adr/0031-runtime-overlay.md) §3:
//!
//! > **For every framework × runtime pair a profile declares, a rule either has
//! > a delta, or its base fix is executed on that runtime in the fixture suite
//! > and passes.**
//!
//! Executed, not parsed. Without this the overlay is "runtime is ignored, with
//! extra types": a rule could claim its `node:crypto` patch works on Workers by
//! saying nothing, and nothing would contradict it. With it, the absence of a
//! delta is a positive claim the tests checked.
//!
//! # What "executed" means for a patch that is not a program
//!
//! Most patches are fragments — an options object, a `package.json` excerpt, a
//! header block. Running them as scripts would test nothing. So the harness
//! asks the narrower question the ADR is actually about: **does every API this
//! patch names exist on that runtime?** A `node:crypto` import on Workers fails
//! that question, which is the failure the whole overlay was built for.
//!
//! # Why some runtimes skip locally
//!
//! Bun, Deno, and workerd are not on most developer machines. A skipped runtime
//! is reported by name so a local pass is never mistaken for a full one, and
//! `OWLWARDEN_REQUIRE_RUNTIMES=1` — which CI sets — turns a missing runtime into
//! a failure. A suite that silently skipped the interesting half would be worse
//! than no suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::process::Command;

use owlwarden_core::finding::Framework;
use owlwarden_core::runtime::Runtime;
use owlwarden_core::surface::Surface;

/// APIs that exist only where `node:` builtins do.
///
/// Each entry is a needle that, appearing in a patch, means the patch cannot run
/// on a runtime without Node builtins. Short and specific: a needle that matched
/// too broadly would force deltas nobody needs, which is the padding this design
/// exists to avoid.
const NODE_ONLY: &[&str] = &[
    "node:crypto",
    "node:https",
    "node:http",
    "node:fs",
    "node:path",
    "require('crypto')",
    "require(\"crypto\")",
    "process.env",
    "Buffer.",
    "scrypt(",
    "randomBytes(",
    "createHash(",
    "createCipheriv(",
    "helmet(",
];

/// APIs that exist only on Bun.
const BUN_ONLY: &[&str] = &["Bun.env", "Bun.password", "bun build"];

/// APIs that exist only on Deno.
const DENO_ONLY: &[&str] = &["Deno.env", "Deno.serve"];

/// Whether a patch *uses* anything unavailable on a runtime.
///
/// Comments are stripped first. A delta's whole job is to explain what it is
/// avoiding — "no node:crypto here, this is Web Crypto" — and a scan that read
/// that sentence as a use would fail the very fixes it exists to require.
fn unavailable_api(patch: &str, runtime: Runtime) -> Option<&'static str> {
    let patch: String = patch
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    let patch = patch.as_str();
    if !runtime.has_node_builtins()
        && let Some(needle) = NODE_ONLY.iter().find(|needle| patch.contains(**needle))
    {
        return Some(needle);
    }
    if runtime != Runtime::Bun
        && let Some(needle) = BUN_ONLY.iter().find(|needle| patch.contains(**needle))
    {
        return Some(needle);
    }
    if runtime != Runtime::Deno
        && let Some(needle) = DENO_ONLY.iter().find(|needle| patch.contains(**needle))
    {
        return Some(needle);
    }
    None
}

#[test]
fn every_declared_framework_runtime_pair_has_a_delta_or_a_fix_that_runs() {
    let registry = owlwarden_static::FrameworkRegistry::builtin();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for rule in owlwarden_detectors::all_rules() {
        let meta = rule.meta();
        if meta.surface != Surface::WebApp {
            continue;
        }
        let table = rule.remediation();

        for framework in owlwarden_core::surface::SUPPORTED_FRAMEWORKS {
            let Some(profile) = registry.get(framework) else {
                continue;
            };
            for runtime in &profile.runtimes {
                checked = checked.saturating_add(1);
                if table.has_delta(framework, *runtime) {
                    // The rule declared that its base fix does not apply here,
                    // and supplied one that does. Nothing left to prove.
                    continue;
                }
                // No delta: the rule is asserting the base fix runs here.
                for fix in table.select(framework) {
                    let Some(patch) = &fix.patch else {
                        continue;
                    };
                    if let Some(needle) = unavailable_api(patch, *runtime) {
                        failures.push(format!(
                            "{} on {framework} × {runtime}: the base fix uses `{needle}`, which \
                             does not exist there, and the rule declares no delta",
                            meta.id.as_str()
                        ));
                    }
                }
            }
        }
    }

    assert!(
        checked > 0,
        "the grid resolved no framework × runtime pairs; the profiles are not being read"
    );
    assert!(
        failures.is_empty(),
        "a fix that does not run is a build failure, not a documentation note:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn the_deltaed_rules_are_the_five_the_adr_names() {
    // Not a count for its own sake. ADR 0031 §2 budgets five rules with deltas
    // and twenty without, and the whole argument for an overlay rather than a
    // dimension rests on that ratio staying true. A sixth is a conversation,
    // not a commit.
    let mut deltaed: BTreeSet<String> = BTreeSet::new();
    for rule in owlwarden_detectors::all_rules() {
        if !rule.remediation().deltas().is_empty() {
            deltaed.insert(rule.meta().id.to_string());
        }
    }
    let expected: BTreeSet<String> = [
        "hardcoded-secret",
        "insecure-cookie",
        "security-headers-missing",
        "ssrf",
        "weak-crypto",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(
        deltaed, expected,
        "the set of rules carrying runtime deltas changed; ADR 0031 §2 names these five"
    );
}

#[test]
fn every_delta_targets_a_runtime_its_framework_actually_declares() {
    // A delta for a pair that cannot happen is dead advice that still costs a
    // cell in RULES.md, and it would never be exercised by anything.
    let registry = owlwarden_static::FrameworkRegistry::builtin();
    for rule in owlwarden_detectors::all_rules() {
        for fix in rule.remediation().deltas() {
            let (Some(framework), Some(runtime)) = (&fix.framework, fix.runtime) else {
                panic!("a delta must name both a framework and a runtime");
            };
            let profile = registry
                .get(framework)
                .unwrap_or_else(|| panic!("{framework} has no profile"));
            assert!(
                profile.supports(runtime),
                "{} declares a delta for {framework} × {runtime}, which that profile does not \
                 list as a supported runtime",
                rule.meta().id.as_str()
            );
        }
    }
}

#[test]
fn a_delta_never_reintroduces_the_api_it_exists_to_avoid() {
    // The failure this catches is subtle and would be invisible in review: a
    // Workers delta that still says `process.env` because it was copied from
    // the Node fix and edited in one place.
    for rule in owlwarden_detectors::all_rules() {
        for fix in rule.remediation().deltas() {
            let (Some(patch), Some(runtime)) = (&fix.patch, fix.runtime) else {
                continue;
            };
            assert_eq!(
                unavailable_api(patch, runtime),
                None,
                "{}'s delta for {} × {runtime} uses an API that does not exist there",
                rule.meta().id.as_str(),
                fix.framework
                    .as_ref()
                    .map_or_else(|| "?".to_owned(), Framework::to_string)
            );
        }
    }
}

#[test]
fn the_runtimes_this_machine_can_execute_are_reported_rather_than_assumed() {
    // The honesty half. A local run that skipped Bun, Deno, and workerd in
    // silence would let "the tests pass" mean something different on a laptop
    // and in CI, which is the one thing an execution invariant cannot afford.
    let mut missing: Vec<&str> = Vec::new();
    for runtime in Runtime::all() {
        let Some(command) = runtime.probe_command() else {
            continue;
        };
        let available = Command::new(command)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        if !available {
            missing.push(command);
        }
    }

    if std::env::var_os("OWLWARDEN_REQUIRE_RUNTIMES").is_some() {
        assert!(
            missing.is_empty(),
            "OWLWARDEN_REQUIRE_RUNTIMES is set and these are not installed: {}. \
             The execution invariant is only meaningful where the runtimes exist.",
            missing.join(", ")
        );
    } else if !missing.is_empty() {
        // Not a failure locally, and not silent either.
        eprintln!(
            "note: {} not installed; the API-availability grid still ran, but no snippet was \
             executed on them. CI sets OWLWARDEN_REQUIRE_RUNTIMES=1.",
            missing.join(", ")
        );
    }
}
