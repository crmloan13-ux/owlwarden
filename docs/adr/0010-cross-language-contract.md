# 0010. Golden files pin the Rust and TypeScript models together

**Status:** Accepted
**Date:** 2026-01-25

## Context

ADR 0003 sends JSON across the language boundary, which means the report format
is declared twice: once in serde (`crates/core/src/report.rs`) and once in zod
(`packages/sdk/src/report.ts`).

Duplicated declarations drift. The dangerous version of the drift is silent:
rename `detector` to `rule` in Rust, and zod — which strips unknown keys rather
than rejecting them — parses the report happily, produces an object missing that
field, and everything downstream reads `undefined`.

Code generation would remove the duplication, but it also removes the ability to
express things zod is good at (refinements, useful error messages) and adds a
build step that must run before typecheck.

## Decision

Keep both declarations, and force them together with checked-in golden files.

1. `crates/reporters/tests/ts_contract.rs` scans a fixture with the real engine
   and writes the report, the rule catalogue, and the full `should_fail` truth
   table to `fixtures/golden/`. The test fails if the checked-in files differ.
2. `packages/sdk/test/contract.test.ts` parses those files with the zod schemas,
   and — the part that catches the silent case — asserts that the parsed key set
   equals the raw key set.
3. The truth table pins `shouldFail` in TypeScript against `should_fail` in Rust
   across all twelve threshold combinations, because a disagreement there means
   CI passes when it should fail.

Regenerate with `OWLWARDEN_UPDATE_GOLDEN=1 cargo test -p owlwarden-reporters`.

## Consequences

- A field rename in Rust fails the Rust test (golden is stale). Regenerating
  then fails the TypeScript test until the schema is updated. There is no order
  of operations in which the two quietly disagree.
- The goldens are checked in, so a reviewer sees the format change as a diff
  rather than as an assertion in a test file.
- Someone will regenerate the golden to make a red test go green without
  updating zod — and then the TypeScript test goes red, which is the point.
- The goldens must be deterministic, so timestamps, durations, and absolute
  paths are pinned before serialisation.
