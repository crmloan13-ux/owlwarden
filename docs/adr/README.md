# Architecture Decision Records

Why things are the way they are. Each record captures one decision that was
genuinely contested — the alternatives, what we chose, and what it costs.

The point is not process. It is that in a year someone will ask "why does the
source provider not just hand me an AST?" and the answer should be a file, not
an archaeology exercise.

| # | Decision | Status |
|---|---|---|
| [0001](0001-dual-engine.md) | Static and dynamic engines over one finding model | Accepted |
| [0002](0002-rust-core-node-distribution.md) | Rust core, distributed as an npm native addon | Accepted |
| [0003](0003-json-boundary.md) | JSON strings across the Rust/Node boundary | Accepted |
| [0004](0004-source-provider-has-no-ast.md) | `SourceProvider` serves bytes, not ASTs | Accepted |
| [0005](0005-pin-oxc-exactly.md) | Pin oxc to an exact version | Accepted |
| [0006](0006-confidence-in-the-model.md) | Confidence in the finding model from v0.0 | Accepted |
| [0007](0007-rendering-lives-in-rust.md) | Reporters are Rust, not TypeScript | Accepted |
| [0008](0008-bound-parser-recursion.md) | Bound parser recursion with a bracket pre-scan | Accepted |
| [0009](0009-minimal-dependencies.md) | Hand-written argument parsing | Accepted |
| [0010](0010-cross-language-contract.md) | Golden files pin the Rust and TypeScript models together | Accepted |
| [0011](0011-framework-profiles.md) | Framework knowledge lives in profiles, not in rules | Accepted |
| [0012](0012-request-origin-not-taint.md) | One-hop request origin, not a taint engine | Accepted |
| [0013](0013-suppressions-and-baseline.md) | Inline suppressions and baseline fingerprints | Accepted |
| [0014](0014-passive-dynamic-and-correlation.md) | Passive dynamic engine and correlation | Accepted |
| [0015](0015-plugin-host-wasmtime.md) | Plugin host on wasmtime, source-only in v0.2 | Accepted |
| [0016](0016-osv-advisory-lookup.md) | Opt-in Google OSV advisory lookup | Accepted |
| [0017](0017-ci-reporting-surface.md) | CI reporting: SARIF, JUnit, GitHub Action | Accepted |
| [0018](0018-corpus-depth-bar.md) | Corpus depth bar and local plugin inspect | Accepted |
| [0019](0019-first-party-active-detector.md) | First-party active detector: csrf-cross-origin-post | Accepted |
| [0020](0020-offline-osv-cache.md) | Offline / cached OSV advisory index | Accepted |
| [0021](0021-plugin-artifact-signing.md) | Plugin artifact integrity and local trust roots | Accepted |
| [0022](0022-stackable-formats.md) | Stackable multi-format emit | Accepted |
| [0023](0023-incremental-watch.md) | Incremental watch invalidation | Accepted |

## Writing one

Short. Context, decision, consequences. If it takes more than a page, the
decision probably contains two decisions.

```markdown
# NNNN. Title in the imperative

**Status:** Accepted | Superseded by NNNN
**Date:** YYYY-MM-DD

## Context
What forced a choice.

## Decision
What we did.

## Consequences
What this costs, and what it rules out.
```
