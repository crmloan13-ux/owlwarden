# 0030 — Publish the false-positive rate on every commit

**Status:** Accepted
**Date:** 2026-08-27
**Related:** [0018](0018-corpus-depth-bar.md) (corpus depth bar), [0012](0012-request-origin-not-taint.md) (honest confidence), [0029](0029-exposure-model.md) (what needs measuring)

---

## Context

Every scanner claims low noise. The claim is unfalsifiable as stated, so nobody believes it, and the first question in every thread about a new security tool is some form of *how noisy is it*. The honest answers available today are anecdotes.

owlwarden's whole positioning rests on a word — honest — used about confidence levels, coverage gaps, and stated limits. That is a strong position and it is currently backed by architecture rather than by evidence. The `coverage` command tells you what is not checked. Nothing tells you how often what *is* checked is wrong.

The project already has the culture. `CONTRIBUTING.md` says the best bug report is a false positive with a small snippet, and [0018](0018-corpus-depth-bar.md) built a should-not-fire corpus with tempting clean twins. That corpus is a pass/fail gate: it is silent or the build is red. It does not produce a number, it is written by the same people who wrote the rules, and it therefore measures internal consistency rather than real-world behaviour.

There is a second reason to build this now and not later. 1.2 adds an exposure classifier ([0029](0029-exposure-model.md)) and a tier resolver ([0028](0028-effective-configuration.md)), both of which will need tuning. Tuning without measurement is guessing with extra steps, and it is how a scanner acquires a reputation that no amount of subsequent work removes.

---

## Decision

### 1. A labelled corpus of real repositories, vendored and pinned

`bench/corpus/` holds a set of open-source repositories pinned by commit SHA, each with a ground-truth file:

```jsonc
// bench/corpus/<repo>/ground-truth.json
{
  "repo": "https://github.com/…",
  "commit": "a1b2c3…",
  "framework": "fastify",
  "runtime": "node",
  "labelledBy": ["…", "…"],
  "labelledAt": "2026-…",
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
    { "path": "src/lib/redirect.ts", "line": 9, "note": "reviewers split on whether the allowlist is sufficient; counted as unlabelled" }
  ]
}
```

Rules for the corpus, because a corpus is only worth what its discipline is worth:

- **Two reviewers per repository**, named in the file. A single-reviewer label is not a label.
- **Disagreements are recorded, not resolved.** They go in `disagreements` and are excluded from both numerator and denominator. A corpus that quietly resolves its hard cases has optimised away exactly the cases that matter.
- **Repositories are pinned by SHA and vendored** — as a git submodule or a fetched-and-checksummed archive — so a result is reproducible in five years and offline.
- **The corpus is chosen before the rules are tuned against it**, and additions are reviewed in their own pull request, separately from any rule change. Adding a repository in the same commit as a rule fix is how a benchmark becomes a rubber stamp.

### 2. `owlwarden bench`

```
owlwarden bench                       # full corpus
owlwarden bench --rule sql-injection
owlwarden bench --compare semgrep     # runs a named alternative through the same harness
owlwarden bench --format json --out bench/latest.json
```

Reports, per rule and overall:

- **precision** — of what we reported, how much was real
- **recall** — of what is labelled, how much we found
- **false positives**, listed with path and line, because a number nobody can inspect is a number nobody trusts
- **`authenticated` precision**, tracked separately per [0029](0029-exposure-model.md) §2 — the metric most likely to be embarrassing and therefore the one that most needs publishing
- **wall time**, per repository and total

Determinism is a hard requirement: same corpus, same commit, byte-identical output on macOS, Linux, and Windows. A benchmark that varies by platform is a benchmark people argue with instead of act on.

### 3. Precision becomes a build invariant

A pull request that drops corpus precision below the threshold fails, exactly as a rule shipping without a remediation cell fails today.

The threshold lives in `bench/thresholds.toml`, per rule and overall. **Raising a threshold is a normal change; lowering one requires a note in the file explaining what was traded and why.** That note is the record — the same pattern as suppressions requiring a mandatory reason, applied to the project's own standards.

This is the mechanism that makes the number mean something over time. Without it, precision is a statistic that drifts down one acceptable increment at a time.

### 4. Published on every commit

CI runs `bench`, writes `bench/latest.json`, and the site renders `/benchmark/`:

- Current precision and recall, overall and per rule
- The `authenticated` precision, called out separately
- Corpus size, repository count, label count, and disagreement count — stated next to the numbers, because a precision figure without a denominator is marketing
- The exact command to reproduce, and the exact command used for any comparison run
- History, so a regression is visible rather than only reported

### 5. Comparison runs, done fairly or not at all

`--compare` runs a named alternative over the same corpus through the same harness. The rules for it:

- The alternative's exact invocation and version are published.
- The alternative is run in a **configuration its own documentation recommends**, not one that flatters us.
- Where owlwarden does worse, the page says so in the same font size.
- We do not claim their false positives are false positives against *their* intent — a rule we do not have is not a rule we beat. Scope differences are stated, not scored.

If those constraints cannot be met for a given tool, no comparison is published for that tool. A dishonest benchmark on a project whose entire positioning is honesty is not a marketing risk, it is a category error.

---

## Alternatives considered

**Extend the existing should-not-fire corpus and call it done.** Cheapest, and it measures the wrong thing: fixtures written by the rule author test the author's model of the world. Real repositories test the world.

**Use an academic benchmark suite.** Reproducible and comparable, and mostly synthetic, mostly not Node web applications, and entirely silent on the agent surface — where the interesting half of this tool lives, and where no benchmark exists at all.

**Publish only when the numbers are good.** The version of this that everyone does. It converts the artefact from evidence into a claim, and a reader can tell the difference immediately. The value of `/benchmark/` is precisely that it updates whether or not the update is flattering.

**Threshold on recall as well as precision.** Attractive and premature. Recall is bounded by what has been labelled, so a recall threshold mostly measures corpus growth. Recall is published; only precision gates the build. Revisit when the corpus is large enough that the bound is the tool's rather than the corpus's.

---

## Consequences

**Good**

- The one-line claim — *publishes its own false-positive rate on every commit* — is checkable in thirty seconds by a stranger who has installed nothing, and no competitor in this lane can copy it quickly, because copying it means publishing their own number.
- Tuning the exposure classifier and the tier resolver becomes measurable instead of intuitive, which is the difference between 1.2 landing well and 1.2 landing.
- A false-positive bug report now has somewhere to go: it becomes a corpus entry, and the fix is verified by a number rather than by an opinion.
- `/benchmark/` is the correct page to link from a launch post, because it answers the first question rather than deferring it.

**Costs**

- **Labelling is the schedule risk for the whole release.** It is slow, it is judgement work, and it cannot be delegated to the person who wrote the rule. Budget for it explicitly and start it in phase 3, before the tuning work in phase 4 depends on it.
- A published number invites argument about methodology. That is a healthy cost and it consumes maintainer time. Publishing the harness and the corpus is what keeps the argument technical.
- Vendoring repositories has licence implications. Prefer fetch-and-checksum over vendoring source where licences allow, and record each repository's licence in its corpus file.
- The precision gate will, at some point, block a rule someone wants to ship. That is the invariant working. It will not feel like it at the time.

---

## Exit criteria

1. `owlwarden bench` produces byte-identical output for the same corpus and commit on macOS, Linux, and Windows.
2. Every corpus repository is pinned by SHA, has two named reviewers, and records its licence.
3. Disagreements are excluded from precision and recall, and their count is published.
4. `bench/thresholds.toml` gates CI; a deliberately noisy rule on a test branch fails the build.
5. Lowering a threshold without a note in the file fails the build.
6. `/benchmark/` renders the latest run, including corpus size, disagreement count, per-rule false positives, and `authenticated` precision as its own figure.
7. A comparison run publishes the alternative's exact version and invocation, and at least one row where owlwarden does worse — if there is genuinely no such row, the corpus is too small and the page says that instead.
8. `docs/explanation/benchmark.md` states the methodology, its limits, and how to add a repository.
9. The false-positive list is reproducible from the published artefacts by someone with no access to the maintainers.
