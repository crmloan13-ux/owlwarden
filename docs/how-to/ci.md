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

This table is the **canonical** exit-code contract (ADR 0017). README,
`REPORTERS.md`, and the GitHub Action all mean the same thing:

| Code | Meaning |
|---|---|
| 0 | Nothing at or above `--fail-on` (after `--min-confidence`) |
| 1 | Findings at or above `--fail-on`, **or** the report was `truncated` |
| 2 | The scan could not run (bad args, unreadable project, install failure) |

`Possible` confidence alone never fails the build. `truncated` always fails —
a capped report is not a clean bill of health.

Note that `2` is distinct from `1`. A pipeline that treats every non-zero as
"found something" will file the wrong ticket when the install is broken.

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

Prefer the first-party composite action ([`action/`](../../action/)). It runs
the same CLI flags and **preserves exit 0 / 1 / 2** — it does not re-score
findings.

```yaml
name: security
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  owlwarden:
    runs-on: ubuntu-latest
    steps:
      # Pin full commit SHAs — `ci-unpinned-action` flags moving tags like @v4.
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - uses: suthat/owlwarden/action@v1.1.0
        with:
          preset: quick        # or agent-surface, to scan the agent workspace
          fail-on: medium
          min-confidence: likely
          format: sarif
          out: owlwarden-results.sarif
          # osv: true   # live Google OSV — typed input only (no free-form args)
          # For air-gapped CI, omit osv and call the CLI with --osv-db instead (see osv.md).
      - if: success() || failure()
        uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6
        with:
          sarif_file: owlwarden-results.sarif
```

The Action has **no `args` input** on purpose — unquoted extras were a shell
injection and mute-switch footgun. Need another flag? Call the CLI in a `run:`
step with an argv array, or extend the Action with a typed input.

Every input is validated against an allowlist or a pattern, and **no input may
begin with `-`**. The `path` input is passed after a `--` separator, so a value
that looks like a flag is still a path. This matters when a workflow wires an
input to something a contributor can influence — a `workflow_dispatch` input, a
matrix entry read out of the repository — where `path: --target=http://…` would
otherwise turn a scan step into an outbound request from the runner.

To scan both surfaces, run the Action twice with different `preset` and `out`
values. One job with `preset: agent-surface` is the CI half of what
`owlwarden gate` does during a session.

Without the Action, the equivalent CLI:

```yaml
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v4.0.2
        with:
          node-version: 20
      - run: npx owlwarden scan --ci --fail-on medium --min-confidence likely --format sarif --out owlwarden-results.sarif
```

`--format junit` writes a JUnit XML suite (one failure per finding) for CI UIs
that already render test reports. `--out` writes the report to a file and
prints a one-line summary on stderr.

Repeat `--format` to emit several renderings from one scan — for example a SARIF
file for GitHub Code Scanning and a pretty log for humans:

```bash
npx owlwarden scan --format pretty --format sarif --out owlwarden-results
# → stderr: human summary; owlwarden-results.sarif on disk
```

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

**Active CSRF** (`csrf-cross-origin-post`) needs `--target` and `--allow-active`.
It is for staging you control, not production, and is **not** exposed in the
GitHub Action or MCP. Do not pass `--allow-active` on pull requests from forks.

## Offline OSV

The Action's typed `osv: true` input calls Google OSV at scan time. For
air-gapped or fork-safe CI, build an index on a trusted machine
(`owlwarden osv update`), commit or cache it, and scan with `--osv-db` in a
`run:` step instead. A committed index is a freshness and trust boundary — see
[osv.md](osv.md).

On pull requests from outside the team, keep all `--allow-*` flags off
(including `--allow-plugins`, `--allow-baseline`, and `--allow-suppressions`).
Pin gate knobs on the command line or Action inputs.

## Scoping a pull-request run

A full scan of a large repository on every push is affordable and a full scan of
a monorepo often is not. `--since` narrows what is looked at:

```bash
owlwarden scan --since "${{ github.event.pull_request.base.sha }}" --fail-on medium
```

Three things about it are worth knowing before you rely on it.

**A diff scope is not a baseline.** A baseline suppresses known findings across
a whole scan; `--since` changes which files are read. Using either to imply the
other produces a report that reads clean about code nobody scanned.

**The scope is stated in the output** — in the summary line, and as
`target.diffScope` in the JSON. That is deliberate: a narrowed clean result must
never be mistaken for a clean repository, and a reviewer skimming a green check
has no other way to tell.

**Project-scope rules still run when their own inputs changed.** A commit that
touches only `package.json` still fires `unpinned-dependency`; one that touches
only `.claude/settings.json` still fires the agent-surface rules. Each rule
declares what it reads, so this is a property rather than a heuristic.

For a pre-commit hook, `--staged` is the same idea one step earlier:

```bash
owlwarden scan --staged --fail-on high
```

## Checking a dependency or a template you did not write

`vet` is the posture for a tree that is not yours — a vendored template, a
starter someone linked, a repository a contractor delivered:

```bash
owlwarden vet ./candidate
```

Agent-surface rules only, offline, no plugins, and the target's own config,
baseline, and inline suppressions counted rather than honoured. On your own
repository those mechanisms make adoption realistic; in the hands of the
repository's author they are ways to hide a finding, and on someone else's tree
that is not a trade worth making.

## Speed

Without `--target`, owlwarden is static analysis on a bounded file set. A few
thousand files takes a couple of seconds. With `--target`, add one or two
passive HTTP round-trips — still no crawl. If a static scan is slow, it is
reading more files than you expect; check `target.filesScanned` in the JSON.
