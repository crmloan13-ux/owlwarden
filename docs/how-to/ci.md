# Running owlwarden in CI

## The short version

```yaml
- run: npx owlwarden scan --ci --fail-on medium
```

`--ci` is a shorthand for `--format json --quiet --no-color`. It is not a
separate mode: everything it does is reachable with the individual flags, so
there is no CI-only code path that behaves differently from what you see
locally.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | The scan could not run |

Note that `2` is distinct from `1`. A broken install, an unreadable project, or
a typo in a preset name is not the same as a clean scan, and a pipeline that
treats "non-zero" as "found something" will report the wrong thing.

## Choosing a threshold

The defaults fail on anything, which is right for a new project and wrong for an
existing one. Two knobs:

```bash
owlwarden scan --ci --fail-on medium --min-confidence likely
```

- `--fail-on` is about impact: how bad the finding is if it is real.
- `--min-confidence` is about certainty: how sure owlwarden is that it is real.

They are separate because they answer separate questions. A `high` severity
finding at `possible` confidence is worth a human looking at it and is not worth
failing a deploy over. `--min-confidence likely` is the setting most CI
pipelines want.

For an existing codebase with a backlog, start strict on new code rather than
trying to reach zero — baseline support lands in v0.1 and will make that
automatic.

## Reading the output

`--ci` writes JSON to stdout. The shape is typed in `@dointhai/owlwarden-sdk`, whose zod
schemas are checked against the engine on every CI run:

```bash
owlwarden scan --ci | jq -r '.findings[] | "\(.severity)\t\(.id)\t\(.location.path):\(.location.line)"'
```

Two fields deserve attention:

- `suppressedCount` — how many findings a suppression hid. `findings: []` with a
  non-zero `suppressedCount` is not the same as a clean project.
- `errors` — rules that failed and files that were skipped. A scan that could
  not read half your project still exits 0 if the half it read was clean, so
  check this if the numbers look too good.

## GitHub Actions

```yaml
name: security
on: [pull_request]

jobs:
  owlwarden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx owlwarden scan --ci --fail-on medium --min-confidence likely --out report.json
      - if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: owlwarden-report
          path: report.json
```

`--out` writes the report to a file and prints a one-line summary, which keeps
the log readable while preserving the detail as an artifact.

## Speed

v0.0 is static analysis on a bounded file set. A few thousand files takes a
couple of seconds, and there is nothing to cache — no index, no database, no
network. If it is slow, it is reading more files than you expect; check
`target.filesScanned` in the JSON.
