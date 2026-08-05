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
