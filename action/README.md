# owlwarden GitHub Action

Composite action that runs the published CLI under `--ci` and preserves exit
codes **0 / 1 / 2** (ADR 0017). It does not re-score findings.

There is **no free-form `args` input**. Extra CLI flags would bypass the
`allow-*` mute-switch model and invite shell injection; use the typed inputs
below (including `osv: true` for `--osv`).

```yaml
permissions:
  contents: read
  # Only if you upload SARIF to code scanning:
  security-events: write

jobs:
  owlwarden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - uses: suthat/owlwarden/action@v1.0.0
        with:
          fail-on: medium
          min-confidence: likely
          format: sarif
          out: owlwarden-results.sarif
      - if: success() || failure()
        uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6
        with:
          sarif_file: owlwarden-results.sarif
```

Do **not** set `allow-baseline`, `allow-suppressions`, or `allow-project-config`
on pull requests from outside the team. Details:
[docs/how-to/ci.md](../docs/how-to/ci.md).
