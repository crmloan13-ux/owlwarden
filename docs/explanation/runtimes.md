# Does this fix work on Bun, Deno, or Workers?

`weak-crypto` used to tell a Hono user to `import { randomBytes } from
'node:crypto'`. On Cloudflare Workers there is no `node:crypto` import to make.
The advice was not merely less good on that runtime — **it did not run**, and a
fix that throws at import time is not a fix. It is a cell that satisfies a test.

Since 1.2, every finding carries the runtime its file runs on, and a rule may
carry a *delta*: a replacement fix for the runtimes where its base advice would
not execute.

```
◉ᴥ◉ 41 files · quick · edge (detected) · 0.3s
```

```
 ↳  fix (Hono · edge)  There is no node:crypto on this runtime. Use the Web
                       Crypto API, which is global. scrypt has no equivalent;
                       PBKDF2 with a high iteration count is the replacement.
```

## Why an overlay and not a dimension

The obvious design is a second profile axis, and it is wrong. The remediation
matrix would go from 25 × 16 to 25 × 16 × 4 — about 1 600 cells, most of them
identical, because `sql-injection` does not care whether the process is Bun or
Node. Parameter binding is parameter binding.

Filling 1 600 cells where 400 carry information is exactly the padding
[ADR 0018](../adr/0018-corpus-depth-bar.md) rejected for fixtures, and it makes
adding a runtime a 400-cell change — which means no runtime ever gets added.

So remediation stays keyed by framework, and a runtime is a **delta**: a rule
declares one only where the base fix genuinely does not run.

**Five rules carry deltas.** `weak-crypto`, `insecure-cookie`,
`security-headers-missing`, `hardcoded-secret`, and `ssrf`. The other twenty
carry none.

## The invariant that makes silence mean something

The naive version of this design lets a rule silently claim its base fix works
everywhere. The build does not allow that:

> For every framework × runtime pair a profile declares, a rule either has a
> delta, or its base fix is checked against that runtime in the fixture suite.

So the *absence* of a delta is a positive assertion the tests made, not an
oversight nobody noticed. Adding a framework that declares Workers support and
forgetting a delta turns the build red, with the offending API named:

```
weak-crypto on sveltekit × webWorker: the base fix uses `node:crypto`,
which does not exist there, and the rule declares no delta
```

That message is from a real failure during this release: the four frameworks
added in 1.2 needed five deltas each, and the invariant is how we found out
rather than a user.

The check runs everywhere. Bun, Deno, and workerd are not on most developer
machines, so a local run reports which runtimes it could not execute on by name,
and CI sets `OWLWARDEN_REQUIRE_RUNTIMES=1` to make a missing one a failure. A
suite that silently skipped the interesting half would be worse than no suite.

## How the runtime is decided

Evidence, in order, and the answer says which was used:

1. **An explicit declaration** — `wrangler.toml`, `deno.json`, `bunfig.toml`, an
   `export const runtime = 'edge'` in a route, a Nitro preset, a framework
   adapter in the config. Reported as `detected`.
2. **The lockfile** — `bun.lockb`, `deno.lock`. Also `detected`: it is evidence,
   not a guess.
3. **The framework default.** Reported as `defaulted`, because it is an
   inference and a fix chosen from an inference should say so.

That word is on the summary line in every non-machine format and is **not
droppable in quiet modes**. Detection is inference; a report whose fixes were
chosen from an inferred runtime has to say what it inferred.

### Per file, not per project

Mixed-runtime repositories are normal — a Next application with three edge
routes, a monorepo with a Workers API next to a Node worker — so resolution
walks upward from each file to the nearest evidence:

```
apps/api/wrangler.toml      → everything under apps/api/ is edge
apps/jobs/                  → no declaration, so the framework default
app/api/stream/route.ts     → export const runtime = 'edge', so just this route
```

An in-file declaration beats every directory-level one, because it is per route
and that is the whole point of it.

## What a delta is not for

**Only where the base fix does not run, or is genuinely wrong.** A delta added
because it reads better is the padding this design exists to avoid, and the
build cannot tell the two apart — that discipline is the reviewer's.

The rule of thumb: if you cannot name the API that is absent, you do not have a
delta. You have a rewrite of advice that already worked.

## The agent surface has no runtime axis

`Surface` selects the profile set; runtime overlays one of them. A `SessionStart`
hook is the host's concern, and the fix for it does not change because the
application runs on Bun. A test asserts that agent-surface remediation is never
asked for a runtime.

See [ADR 0031](../adr/0031-runtime-overlay.md) for the decision and the
alternatives that were rejected.
