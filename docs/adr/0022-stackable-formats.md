# 0022. Stackable multi-format emit

**Status:** Accepted
**Date:** 2026-08-11

## Context

ADR 0017 shipped SARIF and JUnit as alternate `--format` values. Pipelines
often want a human summary and a machine artifact from one scan. Running the
engine twice wastes time and can disagree if the tree changes between runs.

## Decision

**`--format` may be repeated.** Each value is one of `pretty|json|sarif|junit`.
Duplicates are ignored (first wins order). Config keeps a single `format` for
backward compatibility; only the CLI stacks.

**One scan, N renders.** The `Report` is produced once; each format is rendered
from that value.

**Stdout / `--out` pairing:**

- If exactly one machine format (`json`/`sarif`/`junit`) is requested and
  `--out` is set, that format writes to `--out`.
- If several machine formats are requested, `--out` is treated as a **prefix**
  (or directory): files are `\<prefix\>.json`, `\<prefix\>.sarif`,
  `\<prefix\>.xml` (junit). A bare directory gets `report.*` inside it.
- `pretty` always goes to the human stream (stdout when it is the only format,
  otherwise stderr) so machine stdout stays a single parseable document when
  only one machine format is used without `--out`.

**Exit codes unchanged.** Reporters still do not re-score (ADR 0007 / 0017).

## Consequences

- Action / docs examples can emit SARIF file + pretty CI log in one step.
- Markdown reporter remains separate later work.
- NAPI `render` stays single-format; the CLI loops.
