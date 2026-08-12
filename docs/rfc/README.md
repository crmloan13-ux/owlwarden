# RFCs

The plugin API is v1 as of owlwarden 1.0. An RFC is required before a change
that would stop a v1 plugin from loading, change `schemaVersion`, or add a
capability class (`network`, `active`, filesystem, …).

Additive optional fields do not need an RFC. They need a changelog note.

## When to write one

Write `docs/rfc/NNNN-slug.md` (next free number) if the change:

- removes or renames a manifest field
- changes the `emit_finding` payload
- widens the sandbox
- bumps `schemaVersion`

## Shape

```markdown
# NNNN. Title

**Status:** Draft | Accepted | Rejected | Superseded by NNNN
**Date:** YYYY-MM-DD

## Problem
What a v1 plugin author cannot do today, and why that matters.

## Proposal
The concrete change to the manifest, host, or SDK.

## Compatibility
What happens to existing `schemaVersion: 1` plugins. If they stop loading,
this RFC is a breaking change and needs a new schema version.

## Alternatives
What we are not doing, in one paragraph each.
```

Accepted RFCs that change a contested design also get an ADR. The RFC is the
proposal; the ADR is the decision that remains after the discussion ends.
