# 0005. Pin oxc to an exact version

**Status:** Accepted
**Date:** 2026-01-20

## Context

The static engine's rules match against oxc's AST: node variants, field names,
the shape of a member expression. oxc is pre-1.0 and moves quickly, and its AST
is a data structure rather than a stable API surface.

A normal caret requirement (`oxc_ast = "0.143"`) lets a patch release change the
shape of a node. In an ordinary library that is a compile error. Here it can be
worse: a variant that stops matching means a rule silently stops firing, and a
security scanner that quietly finds less is the failure mode with the highest
cost.

## Decision

Pin every oxc crate to an exact version in the workspace manifest:

```toml
oxc_parser = "=0.143.0"
```

Upgrades are a deliberate PR: bump the pin, run the fixtures, look at the diff
in the snapshot output.

## Consequences

- No surprise parser changes. A rule that stops firing does so because someone
  changed something on purpose.
- We carry the upgrade work ourselves rather than getting it for free. That is
  the intended trade: the fixture corpus makes the upgrade cheap to verify, and
  a broken upgrade is visible before it ships.
- If a downstream crate ever needs a different oxc version, cargo cannot unify
  them. Acceptable — oxc is an internal implementation detail of the static
  engine and is not exposed in any public API.
