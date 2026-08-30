# The benchmark corpus

`owlwarden bench` scores the engine against real repositories that two people
have read and labelled by hand. This directory holds those labels.

**The corpus is empty.** That is a statement of fact, not a placeholder to be
ignored: the harness, the schema, the discipline checks, and the threshold gate
all exist and are tested, and no repository has been labelled yet. Until one has,
`owlwarden bench` exits 2 and says so, and **`/benchmark/` must not be
published**. A precision figure computed from this project's own fixtures would
measure the rule authors' model of the world against itself — which is what the
fixture suite already does, and is not what the number is for.

Labelling is the schedule risk on this whole release. It is slow, it is
judgement work, and it cannot be delegated to the person who wrote the rule.

## Adding a repository

```
bench/corpus/<name>/
  ground-truth.json     the labels — committed
  source/               the code — fetched and checksummed, or a submodule
```

```jsonc
{
  "repo": "https://github.com/example/app",
  "commit": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
  "licence": "MIT",
  "framework": "fastify",
  "runtime": "node",
  "labelledBy": ["first-reviewer", "second-reviewer"],
  "labelledAt": "2026-08-27",
  "findings": [
    {
      "rule": "insecure-cookie",
      "path": "src/routes/session.ts",
      "line": 44,
      "verdict": "true-positive",
      "exposure": "internet",
      "note": "session cookie, no httpOnly, unauthenticated login route"
    },
    {
      "rule": "sql-injection",
      "path": "scripts/seed.ts",
      "line": 12,
      "verdict": "false-positive",
      "note": "template literal with no interpolation of external values; build-time seed"
    }
  ],
  "disagreements": [
    {
      "path": "src/lib/redirect.ts",
      "line": 9,
      "note": "reviewers split on whether the allowlist is sufficient; counted as unlabelled"
    }
  ]
}
```

## The rules, and which ones the code enforces

| rule | enforced by |
|---|---|
| Two reviewers, named | `corpus::GroundTruth::validate` — one name, or the same name twice, is refused |
| Pinned by commit SHA | same; a branch name is refused |
| Licence recorded | same |
| Every label carries a note | same; a label nobody can explain is a label nobody can check |
| Disagreements recorded, not resolved | `score::score_entry` — excluded from numerator *and* denominator, and counted in the published output |
| **Chosen before the rules are tuned against it** | **nobody. A reviewer has to catch this.** |
| **Added in its own pull request, separate from any rule change** | **nobody. Same.** |

The last two are the ones that matter most and the two no test can check.
Adding a repository in the same commit as a rule fix is how a benchmark becomes
a rubber stamp, and the only defence is a reviewer who says so.

## Thresholds

`bench/thresholds.toml` holds the precision floors. Raising one is a normal
change. **Lowering one requires a `# note:` line above it explaining what was
traded and why** — the parser refuses the file otherwise, which is the same rule
suppressions live under, applied to our own standards.

Only precision gates the build. Recall is bounded by what has been labelled, so
a recall floor would mostly measure corpus growth rather than the tool. Recall is
published; it does not gate.

See [docs/explanation/benchmark.md](../docs/explanation/benchmark.md) for the
methodology and its limits.
