# 0006. Confidence in the finding model from v0.0

**Status:** Accepted
**Date:** 2026-01-21

## Context

Static analysis is guessing, and how much it is guessing varies enormously
between findings. `return NextResponse.json({ error: err.stack })` is not a
guess. "This project has no `next.config.js`, so it probably has no security
headers" is very much a guess — the headers may be set by a CDN the scanner
cannot see.

Reporting both at the same volume is how a scanner earns a reputation for noise.
The usual fix is a severity scale, but severity answers a different question:
how bad it is if real, not how likely it is to be real. A `High` finding we are
unsure about and a `Low` finding we are certain of are both badly served by one
number.

Adding confidence later is not a small change. It affects the JSON contract,
exit-code semantics, autofix eligibility, and every rule's metadata.

## Decision

`Confidence` is part of `Finding` from the first release: `Confirmed`, `Likely`,
`Possible`.

- `Confirmed` means observed at runtime. A static rule cannot produce it; only
  correlation with a dynamic probe can. Rules declare this in
  `DetectorMeta::max_confidence`, so the ceiling is documented rather than
  conventional.
- `--min-confidence` filters, and it participates in the exit code: a `Possible`
  finding does not fail a build on its own.
- Autofix will never apply to a `Possible` finding.

## Consequences

- Rule authors have to be honest about how sure they are, and the metadata makes
  overclaiming visible in review.
- The pretty reporter shows confidence next to severity (`HIGH  likely`), which
  costs a little horizontal space and buys the reader the right prior.
- `security-headers-missing` reports `Possible` when it finds no configuration
  at all and `Likely` when it finds a config that sets only some of the headers.
  That distinction is the whole reason this exists.
- Two thresholds to explain instead of one. Worth it.
