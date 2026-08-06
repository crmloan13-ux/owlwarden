# Running owlwarden in CI

## The short version

```yaml
- run: npx owlwarden scan --ci --fail-on medium
```

`--ci` is a shorthand for `--format json --quiet --no-color`. It is not a
separate mode: everything it does is reachable with the individual flags, so
there is no CI-only code path that behaves differently from what you see
locally.

Do **not** pass `--allow-config-js` on pull requests from outside the team.
Executable config (`owlwarden.config.js` / `.mjs` / `.ts`) is opt-in precisely
so a hostile tree cannot get code execution by being scanned. Prefer
`owlwarden.config.json` (or the `owlwarden` key in `package.json`) in CI.

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
trying to reach zero — run `--write-baseline .owlwarden-baseline.json` once,
then scan with `--baseline .owlwarden-baseline.json` so only new findings fail
the build.

## Reading the output

`--ci` writes JSON to stdout. The shape is typed in `@dointhai/owlwarden-sdk`, whose zod
schemas are checked against the engine on every CI run:

```bash
owlwarden scan --ci | jq -r '.findings[] | "\(.severity)\t\(.id)\t\(.location.path):\(.location.line)"'
```

Two fields deserve attention:

- `suppressedCount` — how many findings a suppression hid. `findings: []` with a
  non-zero `suppressedCount` is not the same as a clean project.
- `baselineHiddenCount` — findings the baseline already accepted. Distinct from
  suppressions: one is project-level debt, the other is a line-level claim with
  a reason.
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
      # Pin full commit SHAs — `ci-unpinned-action` flags moving tags like @v4.
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v4.0.2
        with:
          node-version: 20
      - run: npx owlwarden scan --ci --fail-on medium --min-confidence likely --out report.json
      - if: failure()
        uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3 # v4.3.1
        with:
          name: owlwarden-report
          path: report.json
```

`--out` writes the report to a file and prints a one-line summary, which keeps
the log readable while preserving the detail as an artifact.

## Suppressions in CI

`--report-suppressions` lists every directive on stderr. Prefer reading
`suppressedCount` and `suppressions` from the JSON if you want a pipeline gate —
owlwarden does not fail the build on suppression growth by itself. Details:
[suppressions.md](suppressions.md).

## Speed

v0.0.2 is static analysis on a bounded file set. A few thousand files takes a
couple of seconds, and there is nothing to cache — no index, no database, no
network. If it is slow, it is reading more files than you expect; check
`target.filesScanned` in the JSON.
