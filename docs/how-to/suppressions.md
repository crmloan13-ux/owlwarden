# Suppressions and baselines

Two different tools for two different problems. Mixing them up is how a green
scan stops meaning anything.

| | Suppression | Baseline |
|---|---|---|
| Scope | One line, one rule | Whole project debt |
| Needs a reason | Yes — mandatory | No (the file itself is the record) |
| Survives reformatting | Yes (line must stay adjacent) | Yes (fingerprint ignores line numbers) |
| Flag | inline comment | `--baseline` / `--write-baseline` |

## Inline suppression

```ts
// owlwarden-disable-next-line stack-trace-leak -- gated by NODE_ENV === 'development'
return NextResponse.json({ error: err.stack })
```

Rules that matter:

- The comment must sit on the line **immediately above** the finding. A blank
  line in between means the directive applies to the blank line and goes stale.
- The reason after `--` is mandatory. Without it the finding stays visible and
  `--report-suppressions` labels the comment `missing-reason` (never `active`).
- Forms accepted: `//`, `/* … */`, and `#` (for workflow YAML).
- Block and file-wide forms are not shipped. That is deliberate — a half-working
  blanket teaches people to hide more than they meant to.

List every directive and flag stale or missing-reason ones:

```bash
owlwarden scan --report-suppressions
```

The listing goes to stderr so `--format json` on stdout stays one object. The
JSON report already carries `suppressions` and `suppressedCount`.

## Baseline

For an existing codebase where you cannot clear every finding on day one:

```bash
owlwarden scan --write-baseline .owlwarden-baseline.json
# Trusted pipeline only — --ci refuses --baseline without this opt-in:
owlwarden scan --baseline .owlwarden-baseline.json --ci --fail-on medium \
  --allow-baseline --allow-suppressions
```

Fingerprints key on rule id, path, and whitespace-collapsed code material — not
line numbers — so a prettier pass does not reopen accepted debt. Identical
findings in the same file get distinct fingerprints via an occurrence index
([ADR 0013](../adr/0013-suppressions-and-baseline.md)).

Order of operations: suppressions apply first (when honoured),
`--write-baseline` captures that view, then `--baseline` filters what remains.
A suppressed finding is never written into a new baseline.

## CI defaults

Under `--ci`, owlwarden **lists** inline suppressions but does not hide findings
unless you pass `--allow-suppressions`. `--baseline` is refused unless you pass
`--allow-baseline`. That stops an untrusted PR from silencing the gate with a
comment or a checked-in baseline the pipeline always loads.

owlwarden still does not enforce a net-increase check on `suppressedCount`
across runs — that remains a pipeline decision if you want it.
