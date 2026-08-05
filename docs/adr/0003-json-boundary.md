# 0003. JSON strings across the Rust/Node boundary

**Status:** Accepted
**Date:** 2026-01-18

## Context

napi-rs can mirror Rust structs as JavaScript objects. Doing that for the
`Finding` model would give the TypeScript side native objects with no parsing
cost.

It would also create a second definition of the report format — the napi structs
— alongside the serde one. Two definitions of the same thing drift. Worse, they
drift silently: a field added to the serde model and not to the napi model
simply does not appear on the JavaScript side, and nothing fails.

There is also an ABI question. A prebuilt `.node` from an older release loaded
by a newer CLI exchanging structs is a compatibility problem with undefined
behaviour at the bottom of it.

## Decision

Everything crossing the boundary is a JSON string, in both directions.

```
scan(requestJson: string): string     // JSON ScanRequest → JSON envelope
render(reportJson, optionsJson): string
listRules(): string
```

The envelope carries either a report or a structured `{ code, message, help }`
error. Scan failures are data; only an unparseable request is a thrown
exception, because that is a bug in the caller rather than something the user
can fix.

## Consequences

- One definition of the format (serde), one validator on the other side (zod),
  one thing to document and to fuzz.
- A version mismatch is a schema-version check and a readable error message
  instead of a memory-safety question.
- One serialize/deserialize per scan. Microseconds against an analysis measured
  in hundreds of milliseconds.
- zod strips unknown keys, so the CLI must pass the *original* JSON to `render`,
  never a re-serialised parse result. That is a real footgun; it is called out
  in a comment where it matters and covered by a test that compares key sets.
