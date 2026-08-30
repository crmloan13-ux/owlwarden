# How noisy is it?

Every scanner claims low noise. The claim is unfalsifiable as stated, so nobody
believes it, and the first question in every thread about a new security tool is
some form of *how noisy is it*. The honest answers available today are
anecdotes.

owlwarden's whole positioning rests on a word — honest — used about confidence
levels, coverage gaps, and stated limits. That is a strong position and it was
backed by architecture rather than by evidence. `coverage` tells you what is not
checked. Nothing told you how often what *is* checked is wrong.

```bash
npx owlwarden bench
```

```
precision 93.4% · recall 71.2% · `authenticated` precision 88.9%
over 6 repositories, 214 labels, 9 disagreement(s) excluded · 12.40s

  rule                            prec  recall    fp    fn
  insecure-cookie                97.1%   82.4%     1     6
  …

  false positives
    sql-injection scripts/seed.ts:12
```

## The current state, stated plainly

**The corpus is empty.** The harness, the schema, the discipline checks, and the
threshold gate exist and are tested. No repository has been labelled yet.

Until one has, `owlwarden bench` exits 2 and says so, and **`/benchmark/` is not
published**. A number computed from this project's own fixtures would measure
the rule authors' model of the world against itself — which is what the fixture
suite already does, and is precisely not what this number is for.

Labelling is the schedule risk on the whole release. It is slow, it is judgement
work, and it cannot be delegated to the person who wrote the rule.

## Why not just use the fixture suite

`fixtures/` is a pass/fail gate: it is silent or the build is red. It does not
produce a number, it is written by the same people who wrote the rules, and it
therefore measures internal consistency.

Fixtures written by a rule's author test the author's model of the world. Real
repositories test the world. Both are necessary; neither substitutes.

## The discipline

A corpus is only worth what its discipline is worth.

- **Two reviewers per repository, named in the file.** A single-reviewer label
  is not a label, and the loader refuses one — including the same name twice.
- **Disagreements are recorded, not resolved.** They go in `disagreements` and
  are excluded from *both* numerator and denominator, and their count is
  published. A corpus that quietly resolved its hard cases would have optimised
  away exactly the cases that matter.
- **Repositories are pinned by commit SHA**, so a result is reproducible in five
  years and offline. A branch name is refused.
- **Each repository records its licence.** Vendoring somebody's code to measure
  ourselves against is a thing with terms.
- **Every label carries a note** in the reviewers' own words. A label nobody can
  explain is a label nobody can check.
- **The corpus is chosen before the rules are tuned against it, and additions
  are reviewed in their own pull request.** No test can enforce this. Adding a
  repository in the same commit as a rule fix is how a benchmark becomes a
  rubber stamp, and the only defence is a reviewer who says so.

## What the numbers mean

**Precision** — of what we reported *and somebody reviewed*, how much was real.
Findings nobody has reviewed are counted as unlabelled and excluded, and their
count is published: a precision figure over a tenth of the output is a statistic
about a tenth of the output.

Precision over nothing is `n/a`, not 100%. A scanner that reported nothing would
otherwise publish the most flattering possible number.

**Recall** — of what is labelled real, how much we found. Published, and it does
not gate the build: recall is bounded by what has been labelled, so a recall
floor would mostly measure corpus growth.

**`authenticated` precision** — precision restricted to findings the exposure
classifier called "behind auth". Tracked and published on its own because a
finding wrongly marked as behind auth is a finding somebody deprioritises. It is
the number this project is most embarrassed to publish, which is exactly why it
is not folded into the headline.

**The denominator travels with the number.** Corpus size, repository count,
label count, and disagreement count are on the same object as the rate, because
a precision figure without a denominator is marketing.

## Precision as a build invariant

A pull request that drops corpus precision below the floor in
`bench/thresholds.toml` fails, in the same family as "a rule cannot ship without
a fix for every framework".

**Raising a threshold is a normal change. Lowering one requires a `# note:` line
above it** explaining what was traded and why — the parser refuses the file
otherwise. That is the same rule suppressions live under, applied to the
project's own standards, and it is the mechanism that makes the number mean
something over time.

The gate will, at some point, block a rule someone wants to ship. That is the
invariant working. It will not feel like it at the time.

## Reproducibility

Same corpus, same commit, byte-identical output on macOS, Linux, and Windows. A
benchmark that varies by platform is a benchmark people argue with instead of
act on.

Every collection is ordered by a total key, and every published rate is rounded
to four decimal places — a float printed at full precision differs in its last
digit between platforms and would make the artefact churn on every run.

Corpus scans run `--preset deep` with suppressions **reported and not honoured**
and no baseline. The measured tree is somebody else's code; a scanner that let
it silence its own findings would publish a number about its comments.

## Comparison runs

`--compare` is not implemented, and passing it is an error rather than a no-op.

A comparison is publishable only under conditions that are not yet met:

- the alternative's exact version and invocation published,
- run in a configuration **its own documentation recommends**, not one that
  flatters us,
- every row where owlwarden does worse shown in the same font size,
- scope differences stated rather than scored — a rule we do not have is not a
  rule we beat.

If those constraints cannot be met for a tool, no comparison is published for
that tool. A dishonest benchmark on a project whose entire positioning is
honesty is not a marketing risk. It is a category error.

See [ADR 0030](../adr/0030-published-benchmark.md) for the decision.
