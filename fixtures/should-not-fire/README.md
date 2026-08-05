# `fixtures/should-not-fire/` — the false-positive corpus

Every project in this tree is **correct code**. CI scans all of them and fails
if any rule produces a single finding.

This is the test that keeps the tool installable. A security scanner is judged
on precision long before it is judged on coverage: a developer who sees three
wrong findings stops reading the fourth, and the tool is gone within a week.

## What belongs here

Not "code with no bugs" — code that is *tempting* to a rule and still correct.

Each supported framework has a clean twin of its vulnerable fixture, so every
rule is exercised in both directions in the same dialect:

| | Corrects |
|---|---|
| `next-api-clean/` | logs the stack server-side, returns a generic body, sets every required header |
| `nest-api-clean/` | the same, with `helmet` registered in `main.ts` |
| `express-api-clean/` | parameterised queries, cookie flags set, an origin-comparing redirect helper, an SSRF host allowlist |
| `fastify-api-clean/` | the Fastify spelling of the same, with `randomUUID` for session tokens |
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
