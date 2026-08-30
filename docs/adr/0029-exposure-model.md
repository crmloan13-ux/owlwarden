# 0029 — Exposure: a third axis, and it fails loud

**Status:** Accepted
**Date:** 2026-08-27
**Related:** [0012](0012-request-origin-not-taint.md) (one-hop origin, not taint), [0014](0014-passive-dynamic-and-correlation.md) (confidence), [0018](0018-corpus-depth-bar.md) (corpus depth), [0030](0030-published-benchmark.md) (how this gets measured)

---

## Context

Run 1.1 on a six-month-old application and it returns somewhere between fifteen and eighty findings, correctly, with a fix for each. The tool has done what it promised. The person reading the output now has a problem the tool did not help with: they have an afternoon, and the report is a flat list sorted by severity.

Severity is a property of the *rule*, not of the finding. `insecure-cookie` is medium everywhere — on the public login route and on the internal admin tool that only runs behind a VPN. Confidence is a property of the *evidence*. Neither answers the question every reader actually has, which is *if I fix one thing today, which one*.

The answer, in practice, is the one an attacker can reach. A missing `httpOnly` on a session cookie set by an unauthenticated login handler and the same cookie set by a script that runs at build time are not the same finding, and every experienced reviewer triages on that distinction before any other.

The engine already knows most of what is needed. `FrameworkProfile` resolves `app/api/users/route.ts` to `GET /api/users` and the pretty reporter prints it. What is missing is whether anything guards that route, and a place to put the answer.

Commercial scanners approach this with reachability analysis over a call graph and a lot of infrastructure. That is not available here and is not the point: the useful ninety per cent of the question is answerable from route resolution and middleware declaration, which are exactly the things a framework profile already models.

---

## Decision

### 1. `exposure` is a fourth field on every finding, orthogonal to severity and confidence

| value | meaning |
|---|---|
| `internet` | the finding is on a request-handling path, and no authentication gate was identified on that path |
| `authenticated` | the finding is on a request-handling path with a positively identified authentication gate |
| `internal` | the finding is not on a request-handling path — a build script, a worker, a CLI, a migration |
| `unknown` | the framework profile could not place it |

`exposure` is a fourth axis because it is a fourth question. Severity asks *how bad is this class of bug*. Confidence asks *how sure are we it is here*. `runtime_scope` asks *is this declaration in effect*. Exposure asks *can anyone reach it*. Collapsing any two of those into one number is how scanners become unreadable.

### 2. It fails loud, always

**A finding is classified `authenticated` only when a gate is positively identified. Absence of evidence yields `internet`.**

This is the single most important sentence in this ADR and it is the one thing about the design that is non-negotiable.

Everywhere else in owlwarden, uncertainty resolves downward: an injection-shaped rule that cannot prove origin reports `possible` rather than guessing. That is correct, because the cost of a false `likely` is a wasted hour.

Exposure inverts the cost. A finding wrongly marked `authenticated` is a finding somebody deprioritises. The tool would be reassuring the reader about something it did not check. That is the only new failure mode 1.2 introduces that could make a user *less* safe, and the design has to be shaped around it rather than caveated afterwards.

So the direction is asserted, not just the values: fixtures verify that removing a gate never produces `authenticated`, and that an unrecognised gate produces `internet` rather than `unknown`. When the classifier does not understand something on a request path, it says the scary thing.

### 3. What counts as a gate, per framework

Gate recognition is declared in `FrameworkProfile`, alongside route resolution, and is per-framework by construction:

- **Nest** — a guard on the controller or handler, or applied globally at bootstrap.
- **Express / Koa / Connect** — middleware mounted on a path prefix that covers the route, where the middleware is recognised as an auth gate.
- **Fastify** — `onRequest` / `preHandler` at the instance or route level, including within a registered plugin's encapsulation scope.
- **Hapi** — the route's `auth` option, or a default strategy on the server.
- **Next** — `middleware.ts` with a matcher covering the route, or an in-handler session check on a recognised session API.
- **Nuxt** — server middleware, or route rules.
- **Hono** — `app.use()` on a path pattern covering the route.
- **Remix / TanStack Start / SvelteKit / SolidStart** — a session or auth call in the loader or action, or a hook that runs before it.
- **Astro** — middleware.
- **Sails** — a policy mapped to the action.
- **Gatsby / Elysia** — as their handler models require.

Recognition of "is this middleware an auth gate" is a declared set per profile — the common libraries, plus a shape rule for a local module whose name or export matches an auth pattern. **A local module that cannot be resolved is not a gate.** That is the loud direction again.

The engine does not attempt to determine whether the gate is *correct*. A broken auth check is `authenticated` here. Verifying auth logic is a different tool, and pretending otherwise would be the same overreach as calling one-hop origin a taint engine.

### 4. Sorting, gating, and the summary line

Default sort becomes `exposure → severity → confidence`. The summary line states the distribution:

```
◉ᴥ◉ 412 files · quick · 1.4s
23 findings · 3 internet-reachable, 8 behind auth, 9 internal, 3 unclassified
```

A new independent gate:

```
owlwarden scan --fail-on-exposure internet
owlwarden scan --fail-on medium --fail-on-exposure internet   # either trips it
```

`--fail-on-exposure` composes with `--fail-on` rather than replacing it, because they express different policies: *nothing worse than medium* and *nothing an anonymous caller can reach*. A team should be able to hold both.

**Exposure never raises severity.** A medium on an internet route is still a medium; it just sorts first and can trip its own gate. Severity means *how bad is this class of bug* and must keep meaning that, or the SARIF output and every downstream consumer become incomparable across versions.

### 5. Output

- `pretty` — a word on the header line next to severity and confidence.
- `json` — an `exposure` field, plus `exposureEvidence` naming the route and, when `authenticated`, the gate that was identified and where.
- `sarif` — a result property; `--fail-on-exposure` maps to the existing exit-code contract without touching it.
- `md` — grouped by exposure, because a pull-request comment is read top-down and the top is where the reachable ones belong.
- `agent` — included, and it earns its tokens: an agent that knows which finding is reachable fixes the right one first at no extra cost.

### 6. Relationship to `RequestOrigin`

They look adjacent and are not. `RequestOrigin` ([0012](0012-request-origin-not-taint.md)) asks whether a *value* came from the request, one hop. Exposure asks whether the *code* sits on a request path at all, and whether that path is guarded.

They compose usefully — an `ssrf` finding with request-origin and `internet` exposure is the worst cell in the report — and neither is evidence for the other. A handler can be internet-reachable with no request-derived values anywhere in it.

Keeping them separate also keeps the one-hop limit honest. Nothing in this ADR extends taint analysis, and the roadmap should not imply that it does.

---

## Alternatives considered

**Fold exposure into severity.** One number, easier to read, and it destroys comparability: the same rule would report differently across files, SARIF consumers could not compare across runs, and "high" would stop meaning anything specific.

**Fold it into confidence.** Worse. Confidence is about evidence for the finding's existence. Reachability is a property of the finding's context. Merging them means a reachable false positive outranks an unreachable true positive.

**Build real reachability over a call graph.** More accurate and a different project. It needs whole-program analysis, resolution through dynamic imports and DI containers, and a runtime model per framework. The declared-route-and-middleware approach captures most of the value at a fraction of the cost, and — importantly — is explainable in one line to the person reading the finding, which a call-graph result is not.

**Ask the dynamic engine.** `--target` could confirm a route responds without credentials, which is stronger evidence than any static classification. It also requires a running application, which most scans do not have. Deferred as a correlation source for a later ADR; if it lands, it belongs in the `Confirmed` machinery from [0014](0014-passive-dynamic-and-correlation.md), not here.

**Default the unclassifiable to `internal`.** Quieter output, and it is the reassuring direction. Rejected on the §2 principle.

---

## Consequences

**Good**

- The existing 25 rules become substantially more useful without adding one. This is a better return than new rules and it is the axis on which owlwarden differentiates rather than competes.
- The summary line changes how the tool feels on a legacy repository, from a backlog to an afternoon.
- `--fail-on-exposure internet` is a policy teams actually want and currently cannot express in any open-source scanner.
- Gate recognition is a `FrameworkProfile` concern, so adding a framework still adds exposure support by construction — the same property that made framework fixes cheap.

**Costs**

- Classification is not free. Resolving middleware mounting and encapsulation scopes costs time on a cold scan, and the performance budget in the harness must absorb it before the number goes in the changelog.
- `unknown` will be common at first, on generic-profile projects and unusual layouts. That is honest and it is also a worse experience than a confident wrong answer, which is exactly the trade this project keeps making on purpose. `coverage` should report the unclassified rate so it is visible rather than felt.
- A new axis is new surface for a security tool to be wrong on, in the one direction that matters. The benchmark from [0030](0030-published-benchmark.md) must track `authenticated` precision separately from overall precision, and it should be the number the project is most embarrassed to publish.

---

## Exit criteria

1. Every rule that can attach to a route emits an exposure value. A test asserts that no rule silently emits `unknown` for a framework whose profile claims route resolution.
2. Auth-gate fixtures for all sixteen frameworks: gated route → `authenticated`; ungated route → `internet`; **gate removed → never `authenticated`**.
3. An unresolvable local middleware module produces `internet`, not `authenticated` and not `unknown`.
4. A finding in a build script, a worker, and a migration each produce `internal`.
5. `--fail-on-exposure internet` trips independently of `--fail-on`, and both together behave as an OR. Exit codes unchanged.
6. Exposure appears in pretty, json, sarif, md, and agent output; `exposureEvidence` names the route and the gate.
7. The summary line states the distribution, and `coverage` reports the unclassified rate.
8. `authenticated` precision is tracked as its own metric in `owlwarden bench` and published separately.
9. Cold-scan time on the 10 000-file harness stays within a recorded budget with classification enabled.
10. `docs/explanation/exposure.md` states, in the same words as §2, that absence of evidence yields `internet`, and why.
