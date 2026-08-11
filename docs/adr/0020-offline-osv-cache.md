# 0020. Offline / cached OSV advisory index

**Status:** Accepted
**Date:** 2026-08-11

## Context

ADR 0016 ships opt-in live QueryBatch against `api.osv.dev` and explicitly
refused a full offline DB in the npm tarball (install footprint). Teams still
need air-gapped CI and repeatable scans when Google's API is unreachable.

## Decision

**Do not bundle a vulnerability database in the npm package.** That part of
ADR 0016 stands.

**Add a local index the operator fetches or builds:**

- On-disk format: JSON object `{ "schemaVersion": 1, "ecosystem": "npm",
  "updatedAt": "<RFC3339>", "packages": { "<name>": { "<version>": ["GHSA-…"] } } }`
  capped in `limits::advisory` (file size and package count).
- `owlwarden osv update [project]` reads the project's lockfile, queries OSV
  (same allowlisted client as `--osv`), and writes the index (default
  `.owlwarden/osv-index.json` under the project, or `--out`).
- `--osv-db <path>` makes `known-vulnerable-dependency` use the file-backed
  `AdvisoryClient` with **no network**.
- `--osv` without `--osv-db` keeps today's live client.
- `--osv --offline` is an error unless `--osv-db` is set (fail closed).

**Same rule id.** Online and offline share `known-vulnerable-dependency`; tests
cover the file client with fixtures, never a live API.

## Consequences

- Air-gapped CI commits or caches the index; freshness is the operator's job.
- Index size stays proportional to the lockfile, not the whole npm ecosystem.
- A full ecosystem dump import remains out of scope until a later ADR with an
  explicit size budget.
