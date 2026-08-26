//! The shared sanitiser contract, engine side.
//!
//! `crates/core/src/untrusted_text.rs` and `packages/cli/src/mcp/agent-safety.ts`
//! do the same job in two languages, deliberately: one runs inside the engine on
//! a keystroke path, the other assembles MCP payloads in TypeScript and never
//! crosses the napi boundary. That is a reasonable split and it has one obvious
//! failure mode, which already happened — the TypeScript side stripped the
//! Unicode Tags block and the Rust side did not, so the same filename was safe
//! through MCP and carried an invisible sentence through `--format agent`.
//!
//! Neither side owns the list any more. `fixtures/untrusted-text-vectors.json`
//! does, and `packages/cli/test/untrusted-text-vectors.test.ts` reads the same
//! file. A character added there fails on whichever side does not handle it.

use std::path::Path;

use owlwarden_core::untrusted_text;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    why: String,
    input: String,
    must_not_contain: Vec<String>,
}

fn cases() -> Vec<Case> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/untrusted-text-vectors.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    let parsed: Vectors = serde_json::from_str(&raw).expect("vectors are valid JSON");
    assert!(
        parsed.cases.len() >= 12,
        "the vector file has shrunk to {} cases; a case is only removed when the \
         attack it describes is impossible, which is rare",
        parsed.cases.len()
    );
    parsed.cases
}

#[test]
fn one_line_removes_everything_the_vectors_name() {
    for case in cases() {
        let rendered = untrusted_text::one_line(&case.input, 4_096);
        for forbidden in &case.must_not_contain {
            assert!(
                !rendered.contains(forbidden.as_str()),
                "{}: {:?} survived one_line\n  why it matters: {}\n  output: {:?}",
                case.name,
                forbidden,
                case.why,
                rendered
            );
        }
    }
}

#[test]
fn block_removes_them_too() {
    // `block` renders a multi-line snippet for a model. It delegates per line,
    // but a future rewrite that stopped delegating would silently lose all of
    // this, so it is asserted rather than assumed.
    for case in cases() {
        let rendered = untrusted_text::block(&case.input, 64, 4_096);
        for forbidden in &case.must_not_contain {
            // A newline is what `block` produces between lines, so it is the one
            // thing this function is allowed to emit.
            if forbidden == "\n" {
                continue;
            }
            assert!(
                !rendered.contains(forbidden.as_str()),
                "{}: {:?} survived block\n  why it matters: {}",
                case.name,
                forbidden,
                case.why
            );
        }
    }
}

#[test]
fn the_vectors_are_hostile_enough_to_be_worth_running() {
    // A vector file whose inputs are already clean would pass against a
    // sanitiser that did nothing at all. Every case must actually contain the
    // thing it says must not survive.
    for case in cases() {
        for forbidden in &case.must_not_contain {
            assert!(
                case.input.contains(forbidden.as_str()),
                "{}: the input does not contain {:?}, so the case proves nothing",
                case.name,
                forbidden
            );
        }
    }
}

#[test]
fn sanitising_is_idempotent() {
    // The output of one pass is fed to reporters that may render it again.
    // A second pass must not find new work, or the two would disagree about
    // what a finding says depending on how many layers it crossed.
    for case in cases() {
        let once = untrusted_text::one_line(&case.input, 4_096);
        let twice = untrusted_text::one_line(&once, 4_096);
        assert_eq!(
            once, twice,
            "{}: sanitising twice changed the result",
            case.name
        );
    }
}

#[test]
fn visible_text_is_left_alone() {
    // The other half of the contract, and the one a reader notices: a finding
    // about a real file must still read like a finding about a real file.
    for text in [
        "src/app/api/users/route.ts",
        "createHash(\"md5\") is broken for anything protecting a secret",
        "ตัวอย่างภาษาไทย",
        "café — naïve — 日本語",
        "a <b> tag and a [bracket] that are not markers",
    ] {
        assert_eq!(
            untrusted_text::one_line(text, 4_096),
            text,
            "ordinary text was altered"
        );
    }
}
