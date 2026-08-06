# False positives, and why findings have a confidence

## The problem with being right most of the time

A scanner that is right 90% of the time sounds good until you run it on a real
codebase and get forty findings, four of which are wrong. Someone spends an
afternoon on those four, concludes the tool does not understand their code, and
adds it to the list of things that are ignored in CI. The thirty-six real
findings go with it.

This is the normal fate of security tooling, and it is not caused by missing
rules. It is caused by presenting a guess and a fact at the same volume.

## Two separate questions

Most tools have one number: severity. Severity answers *how bad is this if it is
real*. It does not answer *how likely is it to be real*, and conflating the two
is how a scanner ends up shouting.

owlwarden reports both.

| Confidence | What it means |
|---|---|
| `confirmed` | Observed at runtime. The dynamic engine saw the server do it. |
| `likely` | The code says so. A static rule's ceiling. |
| `possible` | Consistent with a problem, but there are innocent explanations. |

A static rule cannot produce `confirmed` on its own. Correlation with a live
probe can — today for `security-headers-missing` when you pass `--target`
([ADR 0014](../adr/0014-passive-dynamic-and-correlation.md)). Each rule declares
its solo ceiling in `maxConfidence` so the limit is documented rather than
implied.

## What this looks like in practice

**`stack-trace-leak`** fires on `return NextResponse.json({ error: err.stack })`.
The stack is in the response body; there is no reading of that code where it is
not. It reports `likely` — not `confirmed`, because a middleware could in
principle rewrite the body before it leaves, and no live body probe for this
rule ships yet — we have not actually watched the response leave.

**`security-headers-missing`** fires when it finds no header configuration. But
the headers may be set by a CDN, an ingress controller, or a reverse proxy —
none of which are in your repository. So when the rule finds no configuration at
all, it reports `possible`. When it finds a `next.config.js` that sets three of
the five headers, it reports `likely`: someone decided to manage headers in the
application, and two are missing from that decision. Pass `--target` and the
live response settles it: matching gaps become `confirmed`; headers that are
actually present clear the static finding.

**`sql-injection`, `ssrf`, and `open-redirect`** all ask the same question — did
this value come from the caller? — and all answer it with the same shared
analysis, [`RequestOrigin`](../adr/0012-request-origin-not-taint.md). It follows
a value one hop from `req.query`, `req.body`, or the framework's event object
into a local variable, and no further. When it can see that link, the finding is
`likely`. When it sees an interpolated query but cannot trace where the value
came from, the finding is `possible` and says so, because a template literal
built entirely from constants is a perfectly ordinary thing to write.

Deliberately not a taint engine. A full inter-procedural analysis would raise
some of those `possible` findings to `likely`, and would also produce confident
claims about paths it had reasoned about incorrectly. One hop is the amount of
certainty the analysis actually has.

**`hardcoded-secret`** is the rule most likely to be wrong, so it is the most
conservative: it skips test files and fixtures, ignores anything that reads from
the environment, and drops known documentation placeholders such as AWS's own
`AKIAIOSFODNN7EXAMPLE`. A recognised token prefix with the right shape reports
`likely`; a variable merely *named* `apiKey` reports `possible`.

That distinction — same rule, different confidence, depending on what the
evidence supports — is the whole point.

## What this means for you

- **`--min-confidence likely`** is the setting most CI pipelines want. It
  reports `possible` findings but does not fail on them.
- **Autofix never touches a `possible` finding.** Low confidence plus automatic
  edits is how a tool destroys a codebase and its own reputation in one command.
- **Suppression requires a reason.** Not to make it inconvenient, but because
  the reason is what a reviewer reads in the diff — and because an agent that
  "fixes" a finding by suppressing it has to write down what it is claiming.

## If we get it wrong

A false positive is a bug, and a higher-priority one than a missing rule. The
fixture corpus at `fixtures/should-not-fire/` exists for exactly this: it is
full of code that looks like it should fire and must not — `console.error(err.stack)`,
a `.stack` property on something that is not an error, a stack captured into a
variable and never returned. CI fails if any of it produces a finding.

If owlwarden flags correct code, open an issue with the smallest snippet that
reproduces it. That snippet becomes a permanent test.
