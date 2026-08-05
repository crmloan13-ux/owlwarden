# 0004. `SourceProvider` serves bytes, not ASTs

**Status:** Accepted
**Date:** 2026-01-20

## Context

The original interface sketch gave `SourceProvider` an `ast()` method, so a
detector could ask for a parsed file the same way it asks for a raw one. It
reads well as an interface.

It cannot be implemented. oxc allocates its AST in an arena, and every node
borrows from that arena. Returning a `Program<'a>` from a trait method means the
allocator has to outlive the return value, which means either the provider owns
an arena per file forever, or the AST is self-referential, or the whole trait
grows a lifetime parameter that infects everything that touches it.

There is a second problem. If each detector asks the provider for an AST, the
provider parses the same file once per detector. With ten static rules that is
ten parses of every file, and parsing dominates the runtime.

## Decision

`SourceProvider` lists files and returns their contents. Nothing more.

Parsing lives in the static engine, which:

1. Parses each file exactly once into an arena on the stack,
2. Builds a `FileUnit` — the AST plus a line index plus framework context,
3. Hands that `FileUnit` to every rule interested in the file,
4. Drops the arena when the file is done.

Rules see a `&FileUnit<'_>` inside a callback. The lifetime never escapes.

## Consequences

- The core stays free of oxc. It knows about files and findings, not about
  syntax trees, which is what keeps it usable for the dynamic engine too.
- `FileRule` and `ProjectRule` live in `crates/static-engine`, not in the core,
  because their signatures mention the AST.
- `FileRule::applies_to` takes a path rather than a parsed unit, so a file no
  rule cares about is never parsed at all.
- Peak memory is one file's AST, not the project's.
- A rule cannot hold onto AST nodes past its own invocation. In practice a rule
  extracts spans and text and is done, so this has not been a constraint.
