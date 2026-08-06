# Running owlwarden in CI

## The short version

```yaml
- run: npx owlwarden scan --ci --fail-on medium
```

`--ci` sets `--format json --quiet --no-color`, and also refuses mute switches
that a hostile PR can plant in the tree:

- project `preset` / `failOn` / `minConfidence` (unless `--allow-project-config`)
- inline suppressions (unless `--allow-suppressions`)
- `--baseline` (unless `--allow-baseline`)

Do **not** pass `--allow-config-js`, `--allow-project-config`,
`--allow-suppressions`, or `--allow-baseline` on pull requests from outside the
team. Pin the gate knobs on the command line:

```bash
npx owlwarden scan --ci --fail-on medium --min-confidence likely
```

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

Fields that deserve attention:

- `truncated` — the findings cap was hit and results were dropped. A truncated
  report is never treated as clean: `--ci` exits 1 even when the retained
  findings are below `--fail-on`.
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

Under `--ci`, inline suppressions are listed in the report but do **not** hide
findings unless you pass `--allow-suppressions`. That stops a PR from silencing
the gate with a comment. On a trusted tree where suppressions are reviewed:

```bash
npx owlwarden scan --ci --fail-on medium --allow-suppressions
```

`--report-suppressions` still lists every directive on stderr. Details:
[suppressions.md](suppressions.md).

## Live probe in CI

Optional. Start (or point at) a staging origin you control, then pass
`--target` on the command line — never from a file in the PR tree:

```bash
npx owlwarden scan --ci --fail-on medium --min-confidence likely \
  --target "$STAGING_URL"
```

Today that correlates `security-headers-missing` only. Details:
[dynamic.md](dynamic.md).

## Speed

Without `--target`, owlwarden is static analysis on a bounded file set. A few
thousand files takes a couple of seconds. With `--target`, add one or two
passive HTTP round-trips — still no crawl. If a static scan is slow, it is
reading more files than you expect; check `target.filesScanned` in the JSON.
