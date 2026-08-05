# 0008. Bound parser recursion with a bracket pre-scan

**Status:** Accepted
**Date:** 2026-01-23

## Context

oxc's parser is recursive descent and does not enforce a nesting limit. A source
file containing several thousand nested brackets overflows the stack and aborts
the process — not a panic that can be caught, an abort.

This is reachable. Someone runs owlwarden on a repository they did not write, or
CI runs it on a pull request from a stranger. "A file in the repo can kill the
scanner" is a denial of service, and the abort takes the Node process with it
when the scan runs through the addon.

Options considered:

1. Run each parse on a thread with a large stack. Costs a thread per file and
   only raises the threshold rather than removing it.
2. Catch the overflow. Not possible; it aborts.
3. Refuse pathological input before parsing it.

## Decision

Before parsing, scan the source once counting bracket depth (`{[(`), ignoring
brackets inside string literals. If the maximum depth exceeds
`MAX_NESTING_DEPTH` (256), skip the file and record it in the report's `errors`.

The limit is deliberately far below where oxc actually breaks. Hand-written code
does not approach 256 levels of nesting, and neither does the output of any
bundler or minifier we tested.

## Consequences

- One extra pass over each file's bytes. Negligible next to parsing.
- A skipped file is visible in the report rather than silently dropped. A scan
  that quietly ignored part of the project would be worse than one that admits
  it.
- The counter is approximate: a file with unmatched closing brackets inside
  strings could under-count. Doing that deliberately still requires real nesting
  above roughly 2048 to reach the actual overflow, so the 8× margin absorbs it.
  Exact counting would mean lexing, which means parsing, which is the thing we
  are trying to avoid doing to untrusted input.
- If a legitimate file is ever rejected, the limit is one constant in
  `crates/core/src/limits.rs`.
