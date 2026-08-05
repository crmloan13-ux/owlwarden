# AGENTS.md

Instructions for AI coding agents working in this repository. Humans should read
[CONTRIBUTING.md](CONTRIBUTING.md) instead — it covers the same ground with more
context.

If you are looking for how owlwarden supports agents *as users* — the MCP
server, editor hooks, machine-readable output — that is
[docs/explanation/agent-integration.md](docs/explanation/agent-integration.md).

---

## What this project is

A security auditor for web applications. A Rust engine behind a TypeScript CLI,
distributed on npm. It reads source code and reports problems with the fix
inline.

Two consequences follow from it being a security tool, and they drive most of
the rules below:

1. **A false positive costs more than a missed finding.** A tool that flags
   correct code gets switched off, and everything it would have caught goes with
   it.
2. **The tool must not become the vulnerability it hunts.** It runs on
   developer machines and CI runners, against repositories nobody vetted.

## Before you write code

```bash
pnpm i
pnpm build      # native addon, then TypeScript
pnpm check      # fmt, clippy, typecheck, eslint, all tests
```

`pnpm check` is the gate. It must pass with zero warnings before you propose a
change. It takes about a minute.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the structure, and the relevant
[ADR](docs/adr/) if you are about to change something an ADR covers. If your
change contradicts an ADR, that is a conversation to have before writing code,
not after.

## Always

- **Write the interface, its doc comment, and a test before the
  implementation.** Not as ceremony — an interface written after the fact
  describes what happened to get built rather than what was needed.
- **Bound every loop over external data.** An explicit `.take(N)` or a documented
  cap. Limits live in `crates/core/src/limits.rs`.
- **Validate at the boundary.** Any function taking input from outside the
  process checks it first.
- **Return typed errors.** `thiserror` in Rust, discriminated unions in
  TypeScript. Propagate with `?`; do not swallow.
- **Keep functions under about 60 lines.** Longer means extract.
- **Add a fixture for the case you fixed.** If a rule was wrong, the input that
  proved it belongs in `fixtures/`, where it becomes permanent.

## Never

- **No `unwrap`, `expect`, or `panic!` in library paths.** Tests may.
- **No unawaited promises.**
- **No new dependency without justifying it in the description of the change.**
  A security tool's install footprint is part of its argument. `cargo-deny`
  checks licences and advisories; it cannot tell anyone whether the dependency
  was worth it.
- **No check that changes the target's state** without `--allow-active` and
  scope enforcement.
- **No weakening of the plugin sandbox for convenience.**
- **No network or exploit capability** without an ADR and maintainer approval.

## Comments

Comments explain why, not what. If a comment restates the line under it, delete
it — it is noise the moment someone edits the line and not the comment.

Worth writing: a constraint the code cannot express, a trade-off someone will
otherwise try to "fix", the reason a limit is the number it is. Not worth
writing: what a function does when its name already says so, or a note
explaining that your change is correct.

## Writing a rule

A rule is a `FileRule` (one parsed file) or a `ProjectRule` (the whole tree),
both in `crates/detectors`. Start from `cors.rs`, the shortest complete example.
The full walkthrough, including adding a framework instead of a rule, is
[docs/how-to/extend.md](docs/how-to/extend.md).

In order:

1. **`DetectorMeta`.** A permanent id, a severity, and an honest
   `max_confidence`. A static rule cannot reach `Confirmed` — only correlation
   with a live probe can. Overclaiming here is visible in review, which is the
   point of the field.
2. **`Remediation`.** A declarative table, not a `match` on the framework.
   Every framework in `SUPPORTED_FRAMEWORKS` needs a fix that compiles, because
   someone will paste it, and a test fails if one is missing. It has to be
   complete inline; the reader may have no browser.
3. **Fixtures.** One under `fixtures/vulnerable/` that must fire, and at least
   one under `fixtures/should-not-fire/` that must not — ideally the tempting
   case a naive implementation would flag. Register both in the matrix in
   `crates/detectors/tests/fixtures.rs`, which pins the expected count of each
   finding, not merely its presence.
4. **The rule.** Then run it against the whole corpus and regenerate the
   catalogue: `node scripts/generate-rules-md.mjs`.

### Use the shared infrastructure, do not re-invent it

This is the instruction most likely to be ignored, and the one that costs most
when it is. Two rules that answer the same question differently produce
findings whose confidence levels are not comparable, and nobody notices until a
user asks why the same code is `likely` under one rule and `possible` under
another.

- **Framework vocabulary.** Never hardcode `res.json`, `reply.send`, or a config
  path. Ask `owlwarden_static::http` (`is_response_sink`, `is_cookie_setter`,
  `is_cors_enabler`, `route_registration`), which answers from the profiles of
  the frameworks the scanned project actually uses. Teaching the engine a new
  spelling means editing one profile in
  `crates/static-engine/src/framework/profiles.rs`, and every rule gains it at
  once. See [ADR 0011](docs/adr/0011-framework-profiles.md).
- **Request origin.** Never write your own "did this value come from the user"
  check. `owlwarden_static::taint::RequestOrigin` is that check. It is one hop
  and intra-procedural on purpose — see
  [ADR 0012](docs/adr/0012-request-origin-not-taint.md) — and making it
  cleverer for one rule is a change to every rule's confidence.
- **Finding construction.** `crates/detectors/src/build.rs` seeds a builder from
  the rule's own metadata, so a finding cannot disagree with the catalogue about
  its own severity or OWASP mapping.

Rule ids are permanent. They appear in suppressions, in other people's CI
configuration, and in agent rules files. Renaming one is a breaking change, goes
through a deprecation cycle, and is recorded in
[CHANGELOG.md](CHANGELOG.md).

## If you add a rule, say what it does not reach

`owlwarden coverage` is computed from the compiled-in rules, so it updates
itself. What it cannot do is judge whether a rule's `owasp` mapping is honest.
Mapping a narrow check to a broad category makes the coverage table claim
ground the rule does not hold, which is worse than an empty cell — the whole
point of publishing the gaps is that a reader can trust them. See
[docs/explanation/coverage.md](docs/explanation/coverage.md).

## If you change the report format

The format is declared twice, in serde and in zod, and golden files hold them
together:

```bash
OWLWARDEN_UPDATE_GOLDEN=1 cargo test -p owlwarden-reporters
pnpm test:ts   # will fail until packages/sdk/src/report.ts matches
```

Regenerating the golden to make a red test go green, without updating the zod
schema, will simply turn a different test red. That is deliberate. See
[ADR 0010](docs/adr/0010-cross-language-contract.md).

## Definition of done

- [ ] Interface defined and documented.
- [ ] Implementation with bounded loops and boundary checks.
- [ ] Tests: the happy path, and at least one malicious or oversized input.
- [ ] `pnpm check` passes with zero warnings.
- [ ] Public API has doc comments; user-facing behaviour is noted in `docs/`.
- [ ] An ADR added or updated if a design decision was made.

## When to stop and ask

Some changes are not yours to make unilaterally. Stop and raise it if the task
requires:

- adding a network or exploitation capability,
- a check that modifies the target's state,
- weakening the sandbox, the scope model, or a resource limit,
- renaming a rule id or changing the report schema incompatibly,
- contradicting an accepted ADR.

Surfacing the conflict is the correct outcome in these cases. Working around it
is not.
