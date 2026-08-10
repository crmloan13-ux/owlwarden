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

## What you get

Findings under the rule id `known-vulnerable-dependency` (High / Likely), with
the GHSA (and CVE when present) at the lockfile location. Remediation is manual:
upgrade and regenerate the lockfile.

A06 coverage stays **Partial** — this is not a full offline component inventory.
Teams that already run Google's `osv-scanner` in CI can keep doing that beside
owlwarden; `--osv` is the in-process alternative when you want one report.

## When not to use it

- Untrusted CI trees where revealing dependency names to a third party is
  unacceptable — omit `--osv` (the default).
- `watch` mode: the native watcher stays offline so every save does not hammer
  OSV. Run a one-shot `scan --osv` instead.

## Fixtures

| Path | Role |
|---|---|
| [`fixtures/vulnerable/osv-demo/`](../../fixtures/vulnerable/osv-demo/) | Lockfile with a known-vulnerable resolved version (`lodash@4.17.19`). Unit tests drive a mock OSV client against it. |
| [`fixtures/should-not-fire/osv-demo-clean/`](../../fixtures/should-not-fire/osv-demo-clean/) | Lockfile twin that must stay silent when the mock returns no hits. |

These sit **outside** the offline 12 × 12 framework matrix: the rule needs an
advisory client (`--osv`), not a framework dialect.
