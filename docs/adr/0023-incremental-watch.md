# 0023. Incremental watch invalidation

**Status:** Accepted
**Date:** 2026-08-11

## Context

`watch` today debounces and runs a full `scan_project` on every save. The
ARCHITECTURE budget for incremental re-check is under 300 ms; ADR 0018 left
that bar for later. Full rescan is correct but too slow for large trees.

## Decision

**Process-local cache keyed by relative path → content hash (BLAKE3 or SHA-256
of file bytes) plus the finding slice for that path.** Watch keeps the cache
across re-scans in the same process.

**Invalidation:**

- A dirty source file re-runs file-local rules for that file only.
- Changes to `package.json`, lockfiles, `tsconfig*`, or `.owlwarden/**` force a
  **full** rescan (framework detection and project rules).
- Project rules always re-run when any dirty set is non-empty (they are cheap
  relative to re-parsing the whole tree, and wrong cache here is a false
  negative).
- Deleted paths drop their cache entries.

**API:** NAPI / static runner accept optional `dirty_paths: string[]`. Empty /
absent means full scan (MCP and one-shot CLI unchanged).

**Still static-only.** `--target` / `--osv` stay refused in watch (ADR 0014 /
0016). Correctness beats the 300 ms claim: we document measured times; we do
not claim the budget until the perf harness covers a dirty-file path.

## Consequences

- Cross-file taint remains out of scope (ADR 0012); file-local reuse is sound.
- Native CLI watch gains the same dirty-path hint from its fingerprint diff.
- First watch scan is always full (cold cache).
