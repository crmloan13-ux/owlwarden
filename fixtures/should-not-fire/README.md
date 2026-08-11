# `fixtures/should-not-fire/` — the false-positive corpus

Every project in this tree is **correct code**. CI scans all of them and fails
if any rule produces a single finding.

This is the test that keeps the tool installable. A security scanner is judged
on precision long before it is judged on coverage: a developer who sees three
wrong findings stops reading the fourth, and the tool is gone within a week.

## What belongs here

Not "code with no bugs" — code that is *tempting* to a rule and still correct.

Each supported framework has a clean twin of its vulnerable fixture, so every
rule is exercised in both directions in the same dialect.

## Rule × framework grid (vulnerable must fire / clean must stay silent)

Pinned by `SHARED_FIRES` in `crates/detectors/tests/fixtures.rs` — 12 rules ×
12 frameworks = **144 cells**. CI fails if any cell is missing.

Multi-fire counts are locked to named shapes (`SHAPE_CONTRACTS` in the same
file): `ssrf` = fetch/$fetch + axios + `got.get` + `https.get`/`http.get`;
`open-redirect` = redirect helper + `Location` header + extra/status-first
redirect; `weak-crypto` = MD5-password + `Math.random` + AES-ECB;
`sensitive-data-logged` = password + accessToken. Each clean twin must also
ship a `*tempting*` file (dialect depth from v0.4) and a `*safe-redirect*`
helper (filename check in CI).

Generic-profile fixtures (`generic-api` / `generic-api-clean`) live **outside**
this 144-cell grid — see ADR 0018.

| rule | next | nuxt | nest | express | fastify | hono | koa | hapi | sails | astro | remix | gatsby |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| stack-trace-leak | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| sql-injection | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| cors-permissive | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| insecure-cookie | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| hardcoded-secret | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| security-headers-missing | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| ssrf | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| open-redirect | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| weak-crypto (×3 shapes) | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| unpinned-dependency | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| ci-unpinned-action | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| sensitive-data-logged | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |

Clean twins:

| | Corrects |
|---|---|
| `next-api-clean/` | bound queries, cookie flags, allowlisted CORS/SSRF/redirect, headers in `next.config`, `randomUUID` |
| `nest-api-clean/` | the same, with `helmet` + allowlisted `enableCors` in `main.ts` |
| `express-api-clean/` | parameterised queries, cookie flags, origin-comparing redirect, SSRF host allowlist |
| `fastify-api-clean/` | the Fastify spelling, with `randomUUID` for session tokens |
| `nuxt-api-clean/` | the Nitro spelling, with `routeRules` headers and a checked `sendRedirect` |
| `hono-api-clean/` | `hono/cors` allowlist, `setCookie` attrs, `secureHeaders`, allowlisted fetch/redirect |
| `koa-api-clean/` | `koa-helmet`, `@koa/cors` allowlist, `ctx.cookies.set` attrs |
| `hapi-api-clean/` | `h.state` attrs, explicit CORS origin header, allowlisted fetch/redirect |
| `sails-api-clean/` | `helmet` in `config/http.js`, bound queries, cookie flags |
| `astro-api-clean/` | headers in `astro.config`, `cookies.set` attrs, allowlisted fetch/redirect |
| `remix-api-clean/` | `helmet` in `entry.server`, `serialize` with attrs, allowlisted fetch/redirect |
| `gatsby-api-clean/` | headers in `gatsby-config`, Express-shaped cookie flags and allowlists |

Alongside them, `tempting/` holds the cases that break naive rules: a `.stack`
property that is a technology list, a logger call shaped like a response, a
header name inside a comment, `md5` used for a cache key, `Math.random()` used
to jitter a retry. Each clean twin also has a `tempting.ts` (or equivalent)
and a `safe-redirect.ts` origin-comparing helper — both filenames are required.

The clean twins matter more than they look. A rule that fires on the vulnerable
fixture proves it can detect *something*; only the twin proves it detected the
vulnerability rather than the framework.

## Opt-in OSV corpus (outside the 144)

`known-vulnerable-dependency` needs `--osv` and an advisory client, so it is
**not** part of `SHARED_FIRES`. Its silent twin lives here:

| Path | Role |
|---|---|
| `osv-demo-clean/` | Lockfile with a non-matching package; mock OSV returning no hits must stay silent |

The vulnerable counterpart is `fixtures/vulnerable/osv-demo/`.

## Adding to it

Every new rule ships with at least one entry here, and every false positive
reported by a user becomes a new file here in the same PR as the fix. That is
how the corpus stays a real regression suite instead of a snapshot of the day it
was written.
