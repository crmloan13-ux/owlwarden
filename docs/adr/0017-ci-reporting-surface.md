# 0017. CI reporting surface: SARIF, JUnit, and the Action

**Status:** Accepted
**Date:** 2026-08-11

## Context

Teams already gate pull requests on SARIF uploads and JUnit test reports.
owlwarden's finding model and exit codes (0 / 1 / 2) are settled; what was
missing is a rendering that GitHub code scanning and CI UIs already understand,
plus a first-party Action that does not invent a second policy layer.

Shipping a second wire schema in TypeScript would drift from the Rust
`Report` (ADR 0010). Softening exit semantics so SARIF "always succeeds" would
teach pipelines the wrong lesson about `Possible` and `truncated` (ADR 0006).

## Decision

**SARIF 2.1.0 and JUnit XML are reporters, not new models.** They implement the
same `Reporter` trait as `pretty` and `json` (ADR 0007). Every field they emit
is copied from `Report` / `Finding`. They do not re-score severity, invent
locations, or change `should_fail`.

**Severity → SARIF level mapping is fixed and documented:** High → `error`,
Medium → `warning`, Low → `note`, Info → `none`. Confidence, OWASP, and CWE
that SARIF levels cannot carry go in `result.properties` so nothing is lost.

**JUnit is one `<testcase>` per finding.** Failures describe the finding; the
suite does not redefine the CLI exit code. Pipelines that want a red build
still read owlwarden's exit code.

**The GitHub Action is a thin composite over the published CLI.** It pins
`npx owlwarden@…`, forwards `--ci` knobs, and preserves exit 0 / 1 / 2. It does
not parse findings to decide success. Optional SARIF upload uses a SHA-pinned
`upload-sarif` action. Allow-flags for project config, suppressions, and
baseline stay off by default on untrusted PRs — same contract as
[docs/how-to/ci.md](../how-to/ci.md).

**Exit codes stay 0 / 1 / 2 with existing meaning.** Document them; do not
renumber. `Possible` alone does not fail; `truncated` always fails.

## Consequences

- `--format sarif` and `--format junit` join `pretty` / `json` everywhere the
  format enum is wired (CLI, napi, config).
- Golden JSON / zod contracts are untouched; SARIF and JUnit get their own
  snapshot tests.
- Stackable multi-format emit and a Markdown reporter remain later work.
- A hosted plugin marketplace is not this ADR — see ADR 0018 for local
  capability preview.
