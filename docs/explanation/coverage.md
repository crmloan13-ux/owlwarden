# What owlwarden covers, and what it does not

Run `owlwarden coverage` and you get a table with holes in it. That is
deliberate. This page explains how to read it and why it is shaped this way.

## Why publish the gaps at all

A security scanner's most dangerous output is a clean report. Someone reads
"0 findings" and concludes the code is secure, when what it actually means is
"none of the checks this tool has found anything". Those are very different
statements, and the distance between them is exactly the size of the gaps in
the coverage table.

So the table lists all ten OWASP categories, whether or not owlwarden checks
them, and the numbers are computed from the rules compiled into the binary you
are running. There is no hand-maintained claim to go stale, and no way for the
tool to advertise a category it does not check.

## The three states

| State | Meaning |
| --- | --- |
| **covered** | At least one rule maps to this category. |
| **gap** | No rule yet, and source analysis could see this. Backlog. |
| **out of reach** | No rule, and none is coming from a static engine. |

The third state is the one that matters most, and it is why the table has a
*reach* column rather than just a rule count.

**A04:2021 Insecure Design** is the clearest example. It covers threats that
come from what the system does, not from how a line is written: a password
reset flow that skips verification, a checkout that trusts a price sent by the
client, a tenant model with no isolation. Nothing in the AST distinguishes a
correct design from a broken one. Listing A04 as "0 rules" alongside the
categories we simply have not written yet would imply a future release fixes
it. It will not. That work needs a threat model and a human, and pretending
otherwise is worse than admitting it.

*Partial* reach means part of the category is visible. A02 Cryptographic
Failures is partial because `weak-crypto` sees a bad primitive in the source,
but whether TLS terminates correctly at your load balancer is a property of a
deployment this tool never sees.

## Why a category with one rule is not "covered"

It is covered in the table's sense — a rule maps to it — and that is all the
word claims. A03 Injection has one rule, `sql-injection`, and injection is a
much larger family than SQL: command injection, template injection, LDAP,
XPath, NoSQL operators. The table says a rule exists, not that the category is
exhausted.

Read the rule list in each row, not the tick.

## Static analysis only, for now

Everything above describes the static engine, which reads source and never
touches the network. The dynamic engine (see
[ADR 0001](../adr/0001-dual-engine.md)) will reach some of what static analysis
cannot: response headers as actually served, authentication that is enforced at
runtime, redirects that actually happen. When it lands, the reach column gains
a second dimension. Until then, "out of reach" means out of reach of this
release.

## Frameworks

The second half of the table counts rules whose remediation is written
specifically for each framework, rather than falling back to generic advice.

This is a real distinction and not a vanity metric. A Fastify user told "add
security headers" has to go and find out that the answer is
`@fastify/helmet`, that it is registered rather than `use`d, and that the
registration must be awaited. A rule that knows the framework skips all three
steps. `rulesFallingBack` is 0 for every supported framework and a test fails
the build if it ever is not, so a new rule cannot ship serving four frameworks
well and the fifth badly.

Adding a sixth framework is a
[framework profile](../adr/0011-framework-profiles.md) plus a remediation entry
on each rule — and the test tells you exactly which rules still need one.

## Using it in CI

`owlwarden coverage --json` emits the same table as machine-readable JSON. Two
things it is genuinely useful for:

- Recording what your pipeline checked at the time of a release, so an audit
  later has an honest answer rather than a guess.
- Failing a build when an upgrade *reduces* coverage — a plugin that stopped
  loading, or a preset that no longer selects a rule you relied on.

What it is not useful for is a percentage on a dashboard. Nine of ten categories
is not ninety percent of your risk, and treating it that way is how a number
starts driving decisions it cannot support.
