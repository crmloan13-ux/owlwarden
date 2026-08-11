# Measuring scan performance

Architecture budgets (see [ARCHITECTURE.md](../../ARCHITECTURE.md) §12):

| Metric | Budget |
|---|---|
| Static scan, ~1k-file Next.js project, cold | < 5 s |
| Incremental re-scan of one file | < 300 ms (design target; watch still re-scans the tree) |
| Peak memory, same project | < 300 MB |

## Cold-scan baseline harness (v0.4)

```bash
cargo test -p owlwarden-detectors --test perf_baseline -- --ignored --nocapture
```

This times a real fixture scan and prints duration. It is **not** a hard CI
gate yet — numbers vary by host. Use it to catch order-of-magnitude
regressions before claiming a faster release.

A hard CI regression gate (±20%) and true incremental watch remain later work.
