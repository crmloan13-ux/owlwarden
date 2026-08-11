# 0018. Corpus depth bar and local plugin capability preview

**Status:** Accepted
**Date:** 2026-08-11

## Context

v0.2 made the static matrix square: every offline catalogue rule × every
supported framework fires on a vulnerable twin and stays silent on a clean one.
User and developer feedback after v0.3 was not "add more frameworks" — it was
that the tempting cases and multi-shape contracts were still thin, so a rule
could look green in CI while missing real dialects or flagging lookalikes.

ROADMAP also asked for a "plugin registry that shows capabilities before
install." A signed, curated store is a trust and distribution problem (beyond
1.0). Pretending a local CLI command is that store would overclaim.

## Decision

**Deepen the square; do not dissolve it.** Every framework row still shares the
same expected fire counts (`SHARED_FIRES`). Expanding coverage means richer
`SHAPE_CONTRACTS` and dialect-faithful tempting cases on every clean twin, not
per-framework special-case expectations that make confidence incomparable.

**Dialect tempting is mandatory depth, not optional polish.** Each clean twin's
`*tempting*` surface must exercise the shapes that a naive implementation would
mis-fire on: non-error `.stack` in responses, logged stacks, local-only stack
capture, password-shaped strings that are not secrets, framework-specific
non-route reads, and header names in docs. The shared Next.js
`fixtures/should-not-fire/tempting/` suite remains as a dense regression corpus.

**Generic profile gets fixtures outside the matrix.** Projects with no
framework package still use `generic()` vocabulary. They are tested with
dedicated vulnerable / clean trees so rules cannot hardcode framework names,
without claiming `generic` as a thirteenth supported product framework.

**Plugin "registry" in v0.4 means `owlwarden plugin inspect`.** It reads
`owlwarden.plugin.json`, prints id, rules, and declared capabilities, and does
not instantiate WASM. Operators see what a plugin claims before `--plugin`
loads it. A signed remote registry remains later work.

**Safe autofix may grow only for single-line, non-`Possible` remediations.**
Expanding `--fix` coverage (MD5 password-hash highlight, narrow cookie flag
edits) deepens v0.3 without weakening FixSafety gates.

**Performance: ship a cold-scan baseline harness.** Architecture budgets stay;
incremental watch under 300 ms and a hard CI regression gate remain later.
v0.4 measures; it does not claim an editor loop it does not run.

## Consequences

- Fixture PRs that add a shape update all twelve frameworks or they fail CI.
- Messaging for v0.4 can honestly say CI-ready depth without promising a plugin
  marketplace.
- Active detectors, offline OSV, and signed registries stay explicitly out of
  scope so this bar does not dilute them.
