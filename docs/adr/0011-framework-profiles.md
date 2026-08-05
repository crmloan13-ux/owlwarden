# 0011. Framework knowledge lives in profiles, not in rules

**Status:** Accepted
**Date:** 2026-02-08

## Context

The first two rules were written against Next.js and NestJS, and each one grew
its own private list of what those frameworks look like: `stack-trace-leak` had
a `RESPONSE_OBJECTS` constant naming `res` and `reply`, `security-headers-missing`
had a hardcoded `next.config.js` path, and both had a `match framework { ... }`
for remediation. `Framework` itself was a closed enum.

That is fine for two rules and two frameworks. It does not survive contact with
five frameworks and nine rules, for three separate reasons.

**It is O(rules x frameworks) edits.** Adding Fastify meant touching every rule.
The failure mode is not a compile error — it is a rule that still builds, still
passes its tests, and quietly never fires on Fastify. That is the worst kind of
bug for a security tool, because the output is a clean report.

**Rules disagreed with each other.** `stack-trace-leak` knew `reply.send` was a
response sink; `sql-injection` did not know `searchParams` was request data.
Each rule was as good as whichever list its author happened to remember.

**A closed enum cannot be extended by a plugin.** The plugin system is a stated
goal (`ARCHITECTURE.md` §6). A plugin author who supports Hono or Elysia would
have had to get a variant merged into the core enum first, which is not a plugin
system — it is a patch queue.

## Decision

**`Framework` is an open type.** A newtype over `Cow<'static, str>` with
validated shape (lowercase, digits, hyphens, ≤32 bytes) and constants for the
built-ins. Anyone can mint one; nobody has to edit an enum. The zod schema in
`packages/sdk` mirrors this — a string with a shape constraint, not
`z.enum([...])` — so a plugin's findings still parse in a consumer built against
an older SDK.

**Framework knowledge lives in a `FrameworkProfile` registry** in
`crates/static-engine/src/framework/`. One profile per framework, holding:

| Field | What it answers |
| --- | --- |
| `packages` | How to detect it from `package.json`. |
| `specificity` | Who wins when several match. |
| `config_files`, `bootstrap_files` | Where configuration lives. |
| `http` | Its dialect: response objects, body methods, cookie setters, CORS enablers, bare response helpers. |
| `handlers` | How routes are declared. |
| `route_for_path` | File-based routing, where it has any. |

Rules ask questions of the profile — `is_response_sink`, `is_cookie_setter` —
instead of matching names themselves.

**Detection returns a set, not one answer.** A NestJS project genuinely is an
Express project underneath, and a monorepo genuinely has several. `specificity`
resolves the primary for remediation; the set is what rules match against.

**Remediation is a declarative table.** `Remediation` in `crates/core` holds a
fix per framework plus a generic fallback, and `framework_coverage()` reports
every (rule, framework) pair with no specific advice. A test fails the build
when that list is non-empty, so a rule cannot ship serving four frameworks and
neglecting the fifth.

## Consequences

- **Adding a framework is one profile plus one remediation entry per rule**, and
  the coverage test names the rules still missing one. The work is visible and
  bounded instead of discovered a bug report at a time.
- **A plugin can register a profile** through `Project::discover_with`, which
  makes plugin frameworks first-class rather than second-class.
- **A profile is a single point of failure across every rule.** A wrong entry
  is now wrong everywhere at once. That is the trade — and it is the right one,
  because it is also *fixable* everywhere at once, and the fixture matrix in
  `crates/detectors/tests/fixtures.rs` exercises each framework end to end.
- **Detection is dependency-based and can be wrong** for a project that lists a
  framework it does not use. Findings carry the detected framework so a reader
  can see the assumption rather than having to infer it.
- The `FrameworkSet` threads through `UnitMeta` behind an `Arc`, so per-file
  metadata construction stays cheap.
