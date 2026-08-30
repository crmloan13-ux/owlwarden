//! Attacking the benchmark harness.
//!
//! The corpus is somebody else's code, vendored as a submodule or fetched and
//! checksummed, and its `ground-truth.json` sits next to it. Both are input.
//!
//! The interesting attack here is not memory or time — it is **moving the
//! number**. A corpus entry that could make precision look better than it is
//! would turn the one artefact whose whole value is that it is checkable into
//! the marketing claim it exists to replace.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

use owlwarden_bench::corpus::{self, CorpusError};

fn write_entry(root: &Path, name: &str, body: &str) {
    let directory = root.join(name);
    fs::create_dir_all(directory.join("source")).unwrap();
    fs::write(directory.join("ground-truth.json"), body).unwrap();
}

const VALID: &str = r#"{
  "repo": "https://github.com/example/app",
  "commit": "a1b2c3d4e5f6a7b8",
  "licence": "MIT",
  "framework": "express",
  "labelledBy": ["first", "second"],
  "labelledAt": "2026-08-27",
  "findings": []
}"#;

// -- moving the number ------------------------------------------------------

#[test]
fn an_entry_that_breaks_the_discipline_stops_the_whole_run() {
    // Not "is skipped". A corpus that quietly dropped the entry it could not
    // validate would publish a rate over whatever was left, which is the
    // denominator being chosen by whoever wrote the bad entry.
    let root = tempfile::tempdir().unwrap();
    write_entry(root.path(), "good", VALID);
    write_entry(
        root.path(),
        "bad",
        &VALID.replace(r#"["first", "second"]"#, r#"["only-me"]"#),
    );
    let error = corpus::load(root.path()).unwrap_err();
    assert!(matches!(error, CorpusError::OneReviewer { .. }));
}

#[test]
fn a_reviewer_cannot_be_two_people_by_being_written_twice() {
    let root = tempfile::tempdir().unwrap();
    write_entry(
        root.path(),
        "app",
        &VALID.replace(r#"["first", "second"]"#, r#"["me", " me ", "me"]"#),
    );
    assert!(matches!(
        corpus::load(root.path()).unwrap_err(),
        CorpusError::OneReviewer { found: 1, .. }
    ));
}

#[test]
fn a_repository_pinned_to_a_branch_is_refused() {
    // A moving target is not a benchmark: the number would describe whatever
    // that branch happened to contain the day CI ran.
    let root = tempfile::tempdir().unwrap();
    for reference in ["main", "HEAD", "v1.2.3", "", "not-a-sha-at-all"] {
        write_entry(
            root.path(),
            "app",
            &VALID.replace("a1b2c3d4e5f6a7b8", reference),
        );
        assert!(
            matches!(
                corpus::load(root.path()).unwrap_err(),
                CorpusError::NotPinned { .. }
            ),
            "{reference:?} was accepted as a pin"
        );
    }
}

#[test]
fn a_label_with_no_reasoning_is_refused() {
    let root = tempfile::tempdir().unwrap();
    write_entry(
        root.path(),
        "app",
        &VALID.replace(
            r#""findings": []"#,
            r#""findings": [{"rule":"ssrf","path":"a.ts","line":1,"verdict":"true-positive","note":"   "}]"#,
        ),
    );
    assert!(matches!(
        corpus::load(root.path()).unwrap_err(),
        CorpusError::UnexplainedLabel { .. }
    ));
}

#[test]
fn the_corpus_loads_in_a_deterministic_order() {
    // Directory order is not stable across filesystems, and the published
    // artefact has to be byte-identical on three platforms.
    let root = tempfile::tempdir().unwrap();
    for name in ["zeta", "alpha", "mid"] {
        write_entry(root.path(), name, VALID);
    }
    let names: Vec<String> = corpus::load(root.path())
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(names, vec!["alpha", "mid", "zeta"]);
}

// -- resource limits --------------------------------------------------------

#[test]
fn an_enormous_ground_truth_file_is_refused_before_it_is_parsed() {
    let root = tempfile::tempdir().unwrap();
    let size = usize::try_from(corpus::MAX_GROUND_TRUTH_BYTES).unwrap() + 1024;
    write_entry(root.path(), "app", &"x".repeat(size));
    assert!(matches!(
        corpus::load(root.path()).unwrap_err(),
        CorpusError::Malformed { .. }
    ));
}

#[test]
fn a_hostile_ground_truth_file_never_panics() {
    let root = tempfile::tempdir().unwrap();
    for body in [
        String::new(),
        "null".to_owned(),
        "[]".to_owned(),
        "{".to_owned(),
        "[".repeat(200_000),
        "{\"repo\":null}".to_owned(),
        "{\"labelledBy\":\"not an array\"}".to_owned(),
        format!("{{\"repo\":\"{}\"}}", "a".repeat(1_000_000)),
    ] {
        write_entry(root.path(), "app", &body);
        assert!(corpus::load(root.path()).is_err(), "accepted {body:.30?}");
    }
}

#[test]
fn a_directory_with_no_ground_truth_is_skipped_rather_than_failing() {
    // A stray directory -- a `.git`, an editor's scratch folder -- is not a
    // corpus entry and must not stop the run.
    let root = tempfile::tempdir().unwrap();
    write_entry(root.path(), "app", VALID);
    fs::create_dir_all(root.path().join(".git")).unwrap();
    fs::create_dir_all(root.path().join("scratch")).unwrap();
    assert_eq!(corpus::load(root.path()).unwrap().entries.len(), 1);
}

// -- the thresholds file ----------------------------------------------------

#[test]
fn a_hostile_thresholds_file_never_panics_and_never_silently_passes() {
    use owlwarden_bench::thresholds;

    for body in [
        "overall".to_owned(),
        "overall =".to_owned(),
        "overall = NaN".to_owned(),
        "overall = inf".to_owned(),
        "overall = 2".to_owned(),
        "overall = -1".to_owned(),
        "= 0.9".to_owned(),
        "overall = 0.9 = 0.8".to_owned(),
    ] {
        if let Ok(parsed) = thresholds::parse(&body, "t.toml", None) {
            // If it parsed at all, it must not have produced a floor outside
            // the range: a floor of 2.0 can never be met and would fail every
            // build; -1.0 can never be breached and would gate nothing.
            for value in [parsed.overall, parsed.authenticated].into_iter().flatten() {
                assert!((0.0..=1.0).contains(&value), "{body:?} yielded {value}");
            }
        }
    }
}

#[test]
fn a_note_cannot_be_reused_to_cover_a_second_lowering() {
    use owlwarden_bench::thresholds;

    // One note, two lowerings. The second has no explanation of its own, and
    // the whole mechanism is that a lowering is a decision somebody recorded.
    let before = thresholds::parse("overall = 0.95\nssrf = 0.95\n", "t.toml", None).unwrap();
    let error = thresholds::parse(
        "# note: ssrf now covers `got`\nssrf = 0.80\noverall = 0.80\n",
        "t.toml",
        Some(&before),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        thresholds::ThresholdError::UnexplainedLowering { key, .. } if key == "overall"
    ));
}
