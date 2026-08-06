# ADR 0013 — Inline suppressions and baseline fingerprints

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

Adopting a scanner on an existing codebase fails for two separate reasons:
pre-existing findings drown the first report, and legitimate exceptions have no
honest way to be recorded. REVIEW.md H1 moved both mechanisms to v0.1; this
release ships the static half.

Two constraints shaped the design:

1. A suppression without a reason becomes a mute switch. Agents, in particular,
   will take the cheapest path to a green run
   ([docs/explanation/agent-integration.md](../explanation/agent-integration.md)).
2. A baseline keyed on line numbers breaks the first time someone runs a
   formatter. Adoption then means re-accepting the same debt forever.

## Decision

**Suppressions.** The only form that ships is next-line:

```text
// owlwarden-disable-next-line <rule-id> -- <reason>
```

The reason after `--` is mandatory. A directive that names a rule but omits the
reason is recorded as `missingReason` and never hides a finding — so the author
sees why their annotation did nothing. Stale directives (no finding matched)
are listed by `--report-suppressions`. Block and file-wide forms are deferred:
shipping a half-working blanket first would teach people to hide more than they
meant to.

**Baseline.** Entries key on
`fingerprint(rule id | normalised path | whitespace-collapsed code material |
occurrence)`. Line and column are deliberately absent. The code material prefers
`context.evidence`, then the highlighted snippet line, then the title. The
occurrence index (0-based, in report order) stops two identical findings in one
file from collapsing into a single entry. The hash is FNV-1a 64-bit — stable
across platforms, not cryptographic, which is fine because this is a matching
key rather than a security boundary. No new hash dependency.

**Ordering.** Suppressions apply first; `--write-baseline` captures that view;
`--baseline` then filters the displayed report. A baseline is project-level
accepted debt; a suppression is a line-level claim with a reason. The report
keeps both counts separate (`suppressedCount`, `baselineHiddenCount`).

## Consequences

- `suppressedCount` is no longer always zero; the schema field that reserved
  the name in v0.0.1 is now wired.
- Adding `suppressions` and `baselineHiddenCount` to the report is an additive
  change under schema `1.0` ([ADR 0010](0010-cross-language-contract.md)).
- Rule ids remain permanent public API; a rename still breaks baselines and
  suppressions alike.
