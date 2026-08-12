# 0024. Freeze plugin API v1 at 1.0

**Status:** Accepted
**Date:** 2026-08-12

## Context

ROADMAP v1.0 required a frozen plugin API and a deprecation policy. The host
has spoken `schemaVersion: 1` since 0.2 (ADR 0015); before 1.0 that integer
could still move with a changelog note. Third-party authors cannot target a
surface that might change under them, and owlwarden cannot claim 1.0 while
that is true.

Widening the sandbox (network, active, filesystem) would also be a 1.0
decision. It is still the wrong default: the tool runs on untrusted trees, on
developer machines.

## Decision

**`schemaVersion: 1` is the 1.0 plugin API.** Manifest shape, capability
refusal, `emit_finding` validation, and source-only isolation are frozen.
Breaking changes go through [docs/rfc/](../rfc/README.md) and a new schema
version. `1` is never reused for a different contract.

**Still source-only.** Declaring `network` or `active` remains a load error,
not a downgrade (ADR 0015). A hosted plugin registry remains out of scope
(ADR 0021).

Reference: [docs/reference/plugin-api.md](../reference/plugin-api.md).

## Consequences

- 0.5 manifests that already load continue to load on 1.0.
- New capability classes are an RFC, not a convenient patch.
- The SDK error text no longer says “v0.2”; the integer was always 1.
