# Measuring scan performance

Architecture budgets (see [ARCHITECTURE.md](../../ARCHITECTURE.md) §12):

| Metric | Budget |
|---|---|
| Static scan, ~1k-file Next.js project, cold | < 5 s |
| Incremental re-scan of one file | < 300 ms (design target; measure before claiming) |
| Peak memory, same project | < 300 MB |

## Cold-scan baseline harness (v0.4)

```bash
cargo test -p owlwarden-detectors --test perf_baseline -- --ignored --nocapture
```

This times a real fixture scan and prints duration. It is **not** a hard CI
gate yet — numbers vary by host. Use it to catch order-of-magnitude
regressions before claiming a faster release.

Measured at 1.0 on a developer Mac: `fixtures/vulnerable/next-api` (7 files)
was ~9 ms after warmup. That is **not** the 1k-file / 5 s budget; it only
shows the small fixture is not in the wrong order of magnitude.

## Incremental watch (ADR 0023)

`owlwarden watch` keeps a process-local content-hash cache and passes
`dirtyPaths` + the previous report to the engine on re-scan. File-local rules
re-parse only dirty files; project rules always re-run when anything changed.
Changes to `package.json`, lockfiles, `tsconfig*`, or `.owlwarden/**` force a
full rescan. The first watch scan is always full (cold cache).

A hard CI regression gate (±20%) and a dirty-file perf harness remain later
work — document measured re-scan times rather than assuming the 300 ms target.
