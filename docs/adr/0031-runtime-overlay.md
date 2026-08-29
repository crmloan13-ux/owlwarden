# 0031 — Runtime is an overlay, not a dimension

**Status:** Accepted
**Date:** 2026-08-27
**Related:** v0.0 (the `FrameworkProfile` registry and the remediation matrix), [0018](0018-corpus-depth-bar.md) (no padding), [0025](0025-agent-surface-and-supply-chain.md) (`Surface`, and the precedent for generalising the matrix)

---

## Context

`weak-crypto` tells a Hono user to `import { randomBytes } from 'node:crypto'`. On Cloudflare Workers there is no `node:crypto` import to make. The advice is not merely less good on that runtime; **it does not run**.

The same failure appears in four other places already in the catalogue:

| rule | what changes with the runtime |
|---|---|
| `weak-crypto` | `node:crypto` vs Web Crypto; `scrypt` unavailable on edge |
| `insecure-cookie` | `Set-Cookie` construction differs between the Node adapter and the fetch-API adapter |
| `security-headers-missing` | headers set in edge middleware, not in a Node config block |
| `hardcoded-secret` | `process.env` vs `c.env` on Workers vs `Deno.env.get` |
| `ssrf` | `fetch` redirect semantics and the availability of `redirect: 'error'` |

Several supported frameworks are runtime-polymorphic by design. Hono targets Node, Bun, Deno, and Workers. Nuxt's Nitro has presets for all of them. Astro, Remix, and SvelteKit each ship adapters that change the runtime under the same source. The framework is not enough information to write a fix that executes, and the catalogue currently pretends otherwise. Some of the existing remediation text already hedges — "on a worker preset use the Web Crypto API" — which is the honest workaround for a model that cannot express the distinction, and it is a workaround.

The project's own standard makes this a defect rather than a nicety. A rule may not ship without a fix for every supported framework, and the point of that invariant is that the fix is real. A fix that throws at import time is not a fix; it is a cell that satisfies a test.

### Why the obvious solution is wrong

Add `Runtime` as a second profile dimension and the matrix goes from 25 × 16 to 25 × 16 × 4 — about 1 600 cells. Most of them would be identical. `sql-injection` does not care whether the process is Bun or Node; parameter binding is parameter binding.

Filling 1 600 cells where 400 carry information is exactly the padding [0018](0018-corpus-depth-bar.md) rejected for fixtures, and it would degrade `RULES.md` from a reference into a permutation dump. It also makes adding a runtime a 400-cell change, which means no runtime ever gets added.

---

## Decision

### 1. A framework profile declares its runtimes

```rust
pub enum Runtime { Node, Bun, Deno, WebWorker }   // WebWorker covers Workers / edge / fetch-API hosts

impl FrameworkProfile {
    fn runtimes(&self) -> &[Runtime];   // e.g. Hono: all four; Sails: [Node]
    fn default_runtime(&self) -> Runtime;
}
```

Detection is evidence-based and ordered, and reports what it used:

1. An explicit runtime declaration — `wrangler.toml` / `wrangler.jsonc`, `deno.json`, `bunfig.toml`, a `runtime` export in a route or `next.config`, a Nitro preset, a framework adapter in the config.
2. The lockfile and `engines`.
3. Framework default.

The pretty reporter states it on the summary line — `41 files · next · node · quick · 0.3s` — because a fix chosen from an inferred runtime should say what it inferred. A finding whose fix depends on the runtime and whose runtime was guessed from a default says so in one word.

Mixed-runtime repositories are normal: a Next application with three edge routes, or a monorepo with a Workers API next to a Node worker. Runtime is therefore resolved **per file**, not per project, from the nearest evidence upward.

### 2. Remediation stays keyed by framework. Runtimes are deltas.

```rust
pub struct Remediation {
    base: FixText,                              // the framework fix
    deltas: BTreeMap<Runtime, FixText>,         // only where the runtime changes it
}
```

- The base fix is what ships today, unchanged.
- A delta exists only where the base genuinely does not run or is genuinely wrong.
- Five rules carry deltas. Twenty carry none and are not asked to.

Five rules × the polymorphic frameworks × the runtimes that differ is roughly 60 additional cells, all of them carrying information. Not 1 200.

### 3. The invariant that keeps this honest

The naive version of this design lets a rule silently claim its base fix works everywhere. The build must not allow that.

**For every framework × runtime pair a profile declares, a rule either has a delta, or its base fix is executed on that runtime in the fixture suite and passes.**

Executed, not parsed. The fixture matrix gains a runtime axis for the five deltaed rules and, for the other twenty, an execution smoke test that runs the fix snippet under each declared runtime and asserts it does not throw. A fix that does not run is a build failure, in the same class as a missing remediation cell.

This is the entire load-bearing decision. Without it, "runtime is an overlay" becomes "runtime is ignored, with extra types". With it, the absence of a delta is a positive assertion that the tests checked.

### 4. `Surface` composes; it does not multiply

[0025](0025-agent-surface-and-supply-chain.md) made the remediation matrix generic over `Surface`. Runtime applies to `Surface::WebApp` only. `AgentHostProfile` has no runtime axis — a `SessionStart` hook is the host's concern, and the fix does not change because the application runs on Bun.

So the shape is: **surface selects the profile set; runtime overlays one of them.** Two orthogonal mechanisms, neither nested inside the other, and the matrix test iterates the pair it is given.

### 5. Four new frameworks in the same release

SvelteKit, TanStack Start, SolidStart, and Elysia join, taking the set to sixteen. They are added now rather than later because they are the frameworks most likely to be on a non-Node runtime, so the overlay and the new profiles exercise each other. Each ships the full square matrix — vulnerable, clean twin, tempting — per [0018](0018-corpus-depth-bar.md).

Adding a framework remains a `FrameworkProfile` and [docs/how-to/extend.md](https://github.com/suthat/owlwarden/blob/main/docs/how-to/extend.md) remains the whole procedure, with one paragraph added: declare your runtimes, and expect the execution test to tell you where your base fixes do not run.

---

## Alternatives considered

**Runtime as a full second dimension.** Complete, uniform, and 1 200 cells of padding. Rejected on the same grounds as every other padding proposal in this repository.

**Keep hedging in prose.** What the catalogue does today — "on a worker preset use the Web Crypto API". It is honest and it is not a fix. The entire differentiator is that the fix is pasteable; a fix with a conditional in it is a paragraph, and the tool already lost to a search engine at that point.

**Detect the runtime and refuse to advise when unsure.** Safest, and it turns the most common configuration — an ordinary Node project with no explicit declaration — into a degraded experience in service of an uncommon one. The default-with-disclosure in §1 gets the same safety at a fraction of the cost.

**A `Runtime` profile parallel to `FrameworkProfile`, with rules keyed by whichever is more specific.** Considered seriously. It handles the framework-agnostic runtime cases cleanly, and it makes the resolution order — which profile wins for a given rule — a thing every rule author has to reason about. The overlay keeps a single obvious answer: framework first, runtime patches it.

---

## Consequences

**Good**

- Fixes execute on the runtime the reader is actually using, which is the difference between a catalogue and a reference.
- Roughly 60 informative cells instead of 1 200 empty ones. `RULES.md` stays readable and the rule pages gain a real axis rather than a permutation explosion.
- The execution smoke test is a new class of correctness guarantee: the project now asserts that its advice *runs*, not merely that it exists. As far as we know no comparable scanner does this, and it is a claim worth making.
- Separating *what the code is* from *where it runs* rehearses the separation a second language will need, which is the standing precondition for calling the parsing layer generic.

**Costs**

- CI now needs Bun, Deno, and a Workers-compatible runtime alongside Node, on three operating systems. That is real infrastructure and it slows the build. It is also the only way §3 means anything.
- Runtime detection is inference, and inference is wrong sometimes. The summary line disclosing the inferred runtime is the mitigation, and it must not be droppable in quiet modes.
- Per-file runtime resolution is more work than per-project and is required by real monorepos. It needs a cache or it shows up in the cold-scan budget.
- Every rule author now has one more thing to consider. The execution test is what stops that consideration from being optional, and the extend guide has to say so plainly.

---

## Exit criteria

1. Runtime detection is asserted for every framework × runtime pair a profile declares, from explicit declaration, from lockfile evidence, and from default — with the source of the determination recorded in the finding.
2. Per-file resolution is correct in a mixed-runtime fixture: a Next application with edge and Node routes classifies each correctly.
3. The five deltaed rules have runtime fixtures for every pair their frameworks declare.
4. **For the twenty rules with no delta, the base fix snippet executes without throwing under every declared runtime**, in CI, on all three operating systems. Removing a needed delta turns the build red.
5. SvelteKit, TanStack Start, SolidStart, and Elysia pass the full square matrix including tempting fixtures.
6. The summary line states the runtime and whether it was detected or defaulted, in every non-machine format.
7. `RULES.md` regenerates with the runtime axis; the "a rule shipped without an entry" test still fails when it should.
8. `AgentHostProfile` has no runtime axis, and a test asserts that agent-surface remediation is not asked for one.
9. Cold-scan time stays within a recorded budget with per-file runtime resolution enabled.
