# 0012. One-hop request origin, not a taint engine

**Status:** Accepted
**Date:** 2026-02-08

## Context

`sql-injection`, `ssrf`, and `open-redirect` all turn on the same question: did
this value come from the caller? The answer decides whether a finding is
something to fix today or a style note.

`sql-injection` originally answered it privately, by checking whether the
expression was rooted at an identifier from a hardcoded list. Two problems
showed up immediately when a second rule needed the same answer.

**It was wrong in the common case.** Real handlers park the value in a local
first — `const term = (request.query as { q: string }).q` — and nobody
interpolates `req.body.x` inline twice. A root-identifier check sees `term`,
learns nothing, and downgrades the finding to `Possible`, which never fails CI.
The most damaging bug class went unenforced in exactly the shape it is usually
written.

**It was about to be duplicated.** Three private copies of "what does the
request look like" would drift, and each would be as complete as its author's
memory. One of them already did not know about `getQuery(event)`.

The obvious next step is real taint tracking: inter-procedural, type-aware, with
a call graph. That is a much larger project, it is slow, and — the deciding
point — it makes a claim we cannot honour. A taint engine implies *"if it were
reachable, we would have found it"*, and a partial one that people believe is
more dangerous than a heuristic they can reason about.

## Decision

`crates/static-engine/src/taint.rs` provides `RequestOrigin`: a **one-hop,
intra-procedural, flow-insensitive** origin check, shared by every rule
including plugin rules.

- *One hop* — `const id = req.params.id` marks `id`. `const a = id` does not
  mark `a`.
- *Intra-procedural* — nothing crosses a function boundary.
- *Flow-insensitive* — a later reassignment does not clear the mark.

It recognises three shapes, because the frameworks disagree about how you reach
the request: rooted at a request object (`req.body.email`), reading a
request-bearing property off anything (`input.query.q`), or calling a framework
helper (`getQuery(event).sort`).

**The contract is that this decides confidence, never whether to report.** A
rule fires on its sink either way; the origin separates *"the caller controls
this"* (`Likely`) from *"this is assembled at runtime and might be"*
(`Possible`). A false negative in the origin check costs a confidence level, not
a missed finding.

Tracking is bounded at 256 locals per file, because the input is untrusted.

## Consequences

- **Rules get the answer for free and cannot disagree** about what the request
  looks like. Adding `readValidatedBody` to the helper list improves every rule
  at once.
- **Values assembled across function boundaries are missed**, reported at
  `Possible` rather than `Likely`. This is documented in the module and in each
  rule's "what it will miss" section, rather than left for a user to discover.
- **Destructuring is deliberately not tracked.** Marking every name in
  `const { id } = req.params` is right, and doing the same for
  `const { rows } = await db.query(...)` is wrong; without types the engine
  cannot tell them apart, so it does neither.
- **Growing this into real taint tracking is a decision, not a patch.** It
  changes what a `Likely` finding claims, so it supersedes this ADR rather than
  amending it.
