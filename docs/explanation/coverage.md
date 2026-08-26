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

Since v1.1 there are **two** tables, and keeping them apart is the same
argument one level up. The OWASP Top 10 (2021) is about the web application in
your repository. [OWASP ASI 2026](../adr/0025-agent-surface-and-supply-chain.md)
is about the agent that works in it. Merging them would let an agent rule appear
to raise your Top 10 coverage, and the `owasp-top10` preset — which means
"rules mapped to an OWASP Top 10 (2021) category" — would stop meaning anything.

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
deployment this tool never sees. A06 is partial because
`unpinned-dependency` covers pin hygiene offline, and
`known-vulnerable-dependency` answers known CVEs only when you opt into
`--osv` ([how-to/osv.md](../how-to/osv.md)) — we do not ship an offline
advisory database.

## Why a category with one rule is not "covered"

It is covered in the table's sense — a rule maps to it — and that is all the
word claims. A03 Injection has one rule, `sql-injection`, and injection is a
much larger family than SQL: command injection, template injection, LDAP,
XPath, NoSQL operators. The table says a rule exists, not that the category is
exhausted.

Read the rule list in each row, not the tick.

## Static first; dynamic is opt-in

The coverage table is computed from the **static** rules. Those read source and
never open a socket on their own.

Pass `--target` and the passive dynamic engine can confirm or clear
`security-headers-missing` against a live response
([how-to/dynamic.md](../how-to/dynamic.md),
[ADR 0014](../adr/0014-passive-dynamic-and-correlation.md)). That does not add
rows to this table: the rule was already mapped; correlation only changes
confidence. Broader runtime coverage (auth, redirects as served, active checks)
is still later work — see [ROADMAP.md](../../ROADMAP.md).

## The agentic table, and why it has more holes

The ASI table is shaped the same way and reads the same way, with one
difference worth stating: it has proportionally more `out of reach` rows.

Instruction files, hooks, permissions, and tool declarations are checked into
the repository, so a scanner can see them. Memory poisoning, tool misuse at run
time, and multi-agent orchestration failures are properties of a *running*
agent. No amount of parsing `.claude/settings.json` reaches them, and the table
says so rather than leaving those rows looking like a backlog.

The edition is pinned in the engine, so moving to a later ASI list is a
reviewed change with a visible diff rather than a drift. Every rule in the
family declares a CWE as its primary mapping for the same reason: CWE ids are
stable across decades, this edition is new enough that it will be renumbered,
and a renumbering should cost a table edit rather than invalidating the taxonomy
on findings already in someone's baseline.

`owlwarden coverage` also prints **the closed path allowlist** the agent surface
reads. That is the honest answer to "what do you not look at?" on this surface:
not a category with no rule, but a file that is not on the list. A reader can
tell in one glance whether their host's configuration is even in scope.

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

## Agent hosts

The same invariant, one surface over. A rule reading agent configuration owes a
fix for each of the seven supported hosts, and `rulesFallingBack` is 0 there
too.

The two profile sets are never checked against each other, and that is the whole
reason `Surface` exists. `.claude/settings.json` has nothing to do with whether
the application is Next.js or Koa; writing the same paragraph twelve times to
satisfy the framework list would have made `RULES.md` dishonest, and exempting
the new rules would have put a hole in the invariant. Generalising it cost one
enum and kept the property.

`generic` is in the host set and is not a placeholder. It is the fix for a host
we have never heard of, and keeping it mandatory is what stops this family from
becoming an advertisement for the four vendors we happen to know about.

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
