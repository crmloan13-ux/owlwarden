# Exposure: which finding do I fix first

Run owlwarden on a six-month-old application and it returns somewhere between
fifteen and eighty findings, correctly, with a fix for each. You now have a
problem the tool has not helped with: you have an afternoon, and the report is a
list.

Severity does not answer it. Severity is a property of the *rule* —
`insecure-cookie` is medium on the public login route and medium on the internal
admin tool behind a VPN. Confidence does not answer it either; confidence is a
property of the *evidence*. Neither says whether an attacker can reach the code.

`exposure` is that fourth field.

| value | meaning |
|---|---|
| `internet` | on a request-handling path, and no authentication gate was identified on that path |
| `authenticated` | on a request-handling path with a positively identified authentication gate |
| `internal` | not on a request-handling path — a build script, a worker, a CLI, a migration |
| `unknown` | the framework profile could not place it |

```
◉ᴥ◉ 412 files · quick · 1.4s
23 findings (10 high, 11 medium, 2 low)
3 internet-reachable, 8 behind auth, 9 internal, 3 unclassified
```

Three findings is an afternoon. Twenty-three is a backlog. Same scan.

## Absence of evidence yields `internet`

**A finding is classified `authenticated` only when a gate is positively
identified. Absence of evidence yields `internet`.**

This is the one thing about the design that is not negotiable, and it runs
against the grain of everything else in the tool.

Everywhere else, uncertainty resolves downward. A rule that cannot prove a value
came from the request reports `possible` rather than guessing, because the cost
of a false `likely` is a wasted hour.

Exposure inverts that cost. A finding wrongly marked `authenticated` is a
finding somebody deprioritises — and the tool would have reassured them about
something it never checked. That is the only way this release could make a
reader *less* safe, so the design is shaped around it rather than caveated
afterwards.

Concretely:

- A middleware module that does not resolve to a file in the tree **is not a
  gate**. `import { requireAuth } from './middleware/auth'` gates nothing if
  `src/middleware/auth.ts` was deleted or renamed.
- A name that does not read as an authentication check **is not a gate**.
  `app.use(logger)` mounts something; it does not gate anything.
- A session call whose result is never checked **is not a gate**. `const session
  = await getServerSession()` with nothing done about the answer gates nothing,
  and the classifier requires a branch that returns or throws.
- A `config.matcher` we could not read **covers nothing**, rather than
  everything. An unparseable matcher would otherwise mark every route in the
  application as behind auth on the strength of a file we failed to parse.

The fixtures assert the *direction*, not only the value: for every framework,
deleting the gate and re-running must never produce `authenticated`.

## What it does not claim

**It does not judge whether the gate is correct.** A broken auth check
classifies as `authenticated`. Verifying authentication logic is a different
tool, and pretending otherwise would be the same overreach as calling one-hop
origin a taint engine.

**It is not reachability analysis.** There is no call graph. The question
answered is "does this file sit on a declared request path, and is that path
guarded", from route resolution and middleware declaration — the things a
`FrameworkProfile` already models. A finding in a library called only from a
guarded handler classifies as `unknown`, not `authenticated`.

**`unknown` is not a quiet `internal`.** `internal` is a claim that nothing
reaches the file. `unknown` means the question was not answered. They are
counted separately for that reason, and `coverage` reports the unclassified rate
so it is visible rather than felt.

## Exposure never raises severity

A medium on an internet-reachable route is still a medium. It sorts first, and
it can trip its own gate, and that is all.

Severity means *how bad is this class of bug* and has to keep meaning that, or
SARIF output and every downstream consumer become incomparable between versions.

## Gating on it

```bash
owlwarden scan --fail-on-exposure internet
```

```bash
owlwarden scan --fail-on medium --fail-on-exposure internet
```

The two compose as an **OR**, because they express different policies —
*nothing worse than medium* and *nothing an anonymous caller can reach* — and a
team should be able to hold both. Exit codes are unchanged.

The confidence floor applies to each. A `possible` finding on an
internet-reachable route is still a guess, and failing a build on a guess is how
a tool gets removed from a pipeline.

## What counts as a gate, per framework

Gate recognition is declared in `FrameworkProfile` alongside route resolution,
so adding a framework adds exposure support by construction.

| framework | what is recognised |
|---|---|
| Express, Koa, Connect | middleware mounted on a path prefix covering the route, where the middleware is recognised as an auth gate |
| Fastify | `onRequest` / `preHandler` at instance or route level |
| Nest | a guard on the controller or handler, or `useGlobalGuards` at bootstrap |
| Hapi | the route's `auth` option, or a default strategy on the server |
| Next | `middleware.ts` with a matcher covering the route, or an enforcing call in the handler |
| Nuxt | server middleware under `server/middleware/` |
| Hono | `app.use()` on a path pattern covering the route |
| Astro | `src/middleware.ts` |
| Remix | an enforcing session call in the loader or action |
| Sails | a policy mapped to the action in `config/policies.js` |
| Gatsby | an enforcing session call in the function |

"Is this middleware an auth gate" is answered from a declared set — the common
packages, plus a shape rule for a local module whose name reads as an auth
check. `express-session` is deliberately absent: it attaches a session store to
every request and gates nothing, and treating it as a gate would mark every
route in a very large number of applications as behind auth.

## Where it appears

- `pretty` — a word on the header line beside severity and confidence, and the
  distribution on the summary line.
- `json` — an `exposure` field, plus `exposureEvidence` naming the route and,
  when `authenticated`, the gate that was identified and where.
- `sarif` — a result property. It does not touch `level`.
- `md` — grouped by exposure, because a pull-request comment is read top-down.
- `agent` — included, and it earns its tokens: an agent that knows which finding
  is reachable fixes the right one first for the same budget.

See [ADR 0029](../adr/0029-exposure-model.md) for the decision and the
alternatives that were rejected.
