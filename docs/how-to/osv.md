# Look up known vulnerable dependencies (OSV)

Optional. Default scans stay offline. Pass `--osv` when you want owlwarden to
ask [Google OSV](https://osv.dev) whether resolved lockfile versions have known
advisories.

```bash
npx owlwarden scan --osv
```

## What it sends

Only `{ ecosystem, name, version }` batches from `package-lock.json`,
`pnpm-lock.yaml`, or `yarn.lock`. Never source code, never file contents.

Traffic goes to `api.osv.dev` over HTTPS on a path separate from `--target`
probing ([ADR 0016](../adr/0016-osv-advisory-lookup.md)).

## Offline / air-gapped CI

We do not ship a vulnerability database in the npm package ([ADR
0020](../adr/0020-offline-osv-cache.md)). On a connected machine, build a
lockfile-scoped index and commit or cache it:

```bash
# default output: .owlwarden/osv-index.json under the project
npx owlwarden osv update

# custom path
npx owlwarden osv update --out ./ci/osv-index.json
```

Then scan without network:

```bash
npx owlwarden scan --osv --osv-db .owlwarden/osv-index.json
```

`--osv-db` alone also enables advisory lookup (you do not need both flags).
`--osv --offline` is an error unless `--osv-db` is set — fail closed.

Index format (schema version 1):

```json
{
  "schemaVersion": 1,
  "ecosystem": "npm",
  "updatedAt": "2026-08-11T12:00:00Z",
  "packages": {
    "lodash": { "4.17.19": ["GHSA-…"] }
  }
}
```

Size is capped in `limits::advisory` (file bytes and package count). Freshness
is the operator's job — re-run `osv update` when the lockfile changes.

## Trust boundary in CI

A committed or cached index is convenient, but it is also a **freshness and
trust boundary**: whoever can update the index file controls which advisories
CI sees. Treat it like any other pinned dependency artifact — review changes,
regenerate when the lockfile moves, and prefer a trusted build job over letting
an untrusted pull request replace the index silently.

## What you get

Findings under the rule id `known-vulnerable-dependency` (High / Likely), with
the GHSA (and CVE when present) at the lockfile location. Remediation is manual:
upgrade and regenerate the lockfile.

A06 coverage stays **Partial** — this is not a full offline component inventory.
Teams that already run Google's `osv-scanner` in CI can keep doing that beside
owlwarden; `--osv` is the in-process alternative when you want one report.

## When not to use it

- Untrusted CI trees where revealing dependency names to a third party is
  unacceptable — omit `--osv` (the default), or use `--osv-db` with a
  pre-built index that never calls the API in CI.
- `watch` mode: the native watcher stays offline so every save does not hammer
  OSV. Run a one-shot `scan --osv` instead.

## Fixtures

| Path | Role |
|---|---|
| [`fixtures/vulnerable/osv-demo/`](../../fixtures/vulnerable/osv-demo/) | Lockfile with a known-vulnerable resolved version (`lodash@4.17.19`). Unit tests drive a mock OSV client against it. |
| [`fixtures/should-not-fire/osv-demo-clean/`](../../fixtures/should-not-fire/osv-demo-clean/) | Lockfile twin that must stay silent when the mock returns no hits. |
| [`fixtures/osv/osv-index-demo.json`](../../fixtures/osv/osv-index-demo.json) | Cached index for `OsvIndexClient` unit tests (no live API). |

These sit **outside** the offline 12 × 12 framework matrix: the rule needs an
advisory client (`--osv` or `--osv-db`), not a framework dialect.
