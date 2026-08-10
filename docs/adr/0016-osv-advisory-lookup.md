# 0016. Opt-in Google OSV advisory lookup

**Status:** Accepted
**Date:** 2026-08-10

## Context

A06 (Vulnerable and Outdated Components) cannot be answered honestly from
`package.json` ranges alone. The existing `unpinned-dependency` rule covers only
pin hygiene. Known CVEs live in advisory databases; Google's
[OSV](https://osv.dev) is the open, machine-readable one.

Shipping a full offline DB would balloon the npm install. Shelling out to
`osv-scanner` would add a Go toolchain dependency and a second trust boundary.
Calling OSV from the engine needs a network path that is **not** the
`--target` Transport (ADR 0014): advisory traffic must never share the
operator's probe scope, and must never send source code.

## Decision

**Opt-in only (`--osv`).** Default scans stay offline. Enabling the flag is
operator intent, never project config.

**Separate `AdvisoryClient` port in core.** Target probing stays on
`Transport` + scope allowlist. Advisory lookup is a second capability
(`Capabilities.advisory`) with its own allowlisted HTTP adapter that may only
speak to `api.osv.dev` (HTTPS), follows no cross-host redirects, and bounds
request/response size.

**Lockfile → QueryBatch.** Read npm / pnpm / yarn lockfiles through
`SourceProvider`. Send `{ ecosystem, name, version }` batches — never file
contents or source. Cap packages and batches in `limits.rs`.

**New rule `known-vulnerable-dependency`.** Reports GHSA/CVE ids at the
lockfile location. Remediation is `Manual` (upgrade). A06 coverage stays
`Partial` — we do not claim full component intelligence.

**No offline DB and no `osv-scanner` binary in this release.** Document that
teams may still run Google's CLI beside owlwarden in CI.

## Consequences

- CI without `--osv` is unchanged (no network, no new findings).
- Enabling `--osv` reveals package names/versions to Google's API; that is
  disclosed in help and docs.
- Tests mock `AdvisoryClient`; CI never depends on live OSV availability.
- Plugin manifests requesting `network` remain refused (ADR 0015); advisory is
  first-party only until a later ADR.
