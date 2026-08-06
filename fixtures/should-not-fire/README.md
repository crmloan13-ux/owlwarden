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
5 frameworks = **60 cells**. CI fails if any cell is missing.

| rule | next | nuxt | nest | express | fastify |
|---|:---:|:---:|:---:|:---:|:---:|
| stack-trace-leak | yes | yes | yes | yes | yes |
| sql-injection | yes | yes | yes | yes | yes |
| cors-permissive | yes | yes | yes | yes | yes |
| insecure-cookie | yes | yes | yes | yes | yes |
| hardcoded-secret | yes | yes | yes | yes | yes |
| security-headers-missing | yes | yes | yes | yes | yes |
| ssrf | yes | yes | yes | yes | yes |
| open-redirect | yes | yes | yes | yes | yes |
| weak-crypto (×3 shapes) | yes | yes | yes | yes | yes |
| unpinned-dependency | yes | yes | yes | yes | yes |
| ci-unpinned-action | yes | yes | yes | yes | yes |
| sensitive-data-logged | yes | yes | yes | yes | yes |

Clean twins:

| | Corrects |
|---|---|
| `next-api-clean/` | bound queries, cookie flags, allowlisted CORS/SSRF/redirect, headers in `next.config`, `randomUUID` |
| `nest-api-clean/` | the same, with `helmet` + allowlisted `enableCors` in `main.ts` |
| `express-api-clean/` | parameterised queries, cookie flags, origin-comparing redirect, SSRF host allowlist |
| `fastify-api-clean/` | the Fastify spelling, with `randomUUID` for session tokens |
| `nuxt-api-clean/` | the Nitro spelling, with `routeRules` headers and a checked `sendRedirect` |

Alongside them, `tempting/` holds the cases that break naive rules: a `.stack`
property that is a technology list, a logger call shaped like a response, a
header name inside a comment, `md5` used for a cache key, `Math.random()` used
to jitter a retry.

The clean twins matter more than they look. A rule that fires on the vulnerable
fixture proves it can detect *something*; only the twin proves it detected the
vulnerability rather than the framework.

## Adding to it

Every new rule ships with at least one entry here, and every false positive
reported by a user becomes a new file here in the same PR as the fix. That is
how the corpus stays a real regression suite instead of a snapshot of the day it
was written.
