//! The generated catalogue must stay in step with the compiled-in rules.
//!
//! Every finding carries a reference to `RULES.md#<rule-id>`. That link is only
//! worth printing if the anchor is there, and a rule added without regenerating
//! the catalogue would ship a 404 in every report it produces — which is how a
//! reader decides a tool is unmaintained. So the build fails instead.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

/// The generated rule catalogue at the workspace root.
fn rules_md() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../RULES.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

#[test]
fn every_rule_has_an_anchor_in_the_catalogue() {
    let catalogue = rules_md();

    let missing: Vec<String> = owlwarden_detectors::all_rules()
        .iter()
        .map(|rule| rule.meta().id.as_str().to_owned())
        .filter(|id| !catalogue.contains(&format!("### `{id}`")))
        .collect();

    assert!(
        missing.is_empty(),
        "RULES.md has no section for {missing:?}; run `node scripts/generate-rules-md.mjs`"
    );
}

#[test]
fn the_catalogue_has_no_sections_for_rules_that_no_longer_exist() {
    let catalogue = rules_md();
    let known: Vec<String> = owlwarden_detectors::all_rules()
        .iter()
        .map(|rule| rule.meta().id.as_str().to_owned())
        .collect();

    // Rule ids are permanent public API, so a stale section is not merely
    // untidy: it is a documented rule that no longer runs, and a reader with a
    // suppression naming it has no way to learn that it went away.
    let stale: Vec<&str> = catalogue
        .lines()
        .filter_map(|line| line.strip_prefix("### `"))
        .filter_map(|line| line.strip_suffix('`'))
        .filter(|id| !known.iter().any(|known| known == id))
        .collect();

    assert!(
        stale.is_empty(),
        "RULES.md documents {stale:?}, which no rule produces; \
         run `node scripts/generate-rules-md.mjs`"
    );
}

#[test]
fn a_rule_reference_points_at_its_own_anchor() {
    let rule = owlwarden_detectors::all_rules()
        .first()
        .expect("there is at least one rule")
        .meta()
        .id
        .clone();

    let url = owlwarden_core::rule_url(rule.as_str());

    assert!(
        url.ends_with(&format!("RULES.md#{rule}")),
        "the reference URL {url} does not match the anchor the generator writes"
    );
}
