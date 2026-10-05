# Contributing to owlwarden

## The contribution we want most

**A false positive.** If owlwarden flags correct code, that is a higher-priority
bug than any missing rule. A scanner that cries wolf gets uninstalled, and every
false positive spends trust the project does not have much of yet.

Open an issue with the smallest snippet that reproduces it. If you can, add the
snippet to `fixtures/should-not-fire/` in a PR — that directory is a test
corpus, and CI fails if anything in it produces a finding.

## Setup

```bash
# Rust 1.88+, Node 22.13+, pnpm
pnpm i
pnpm build        # native addon, then TypeScript
pnpm check        # what CI runs
```

`pnpm check` is `cargo fmt --check`, `cargo clippy -D warnings`, `tsc`,
`cargo test`, and `vitest`. Run it before you push; it takes about a minute.

Building needs a newer Node than running does, because pnpm 11 does. The
published CLI supports Node 20, and CI runs it on Node 20 after building on 22
so that the `engines` field is a tested claim rather than a hopeful one.

Useful during development:

```bash
cargo run -p owlwarden-cli -- scan fixtures/vulnerable/next-api
cargo test -p owlwarden-detectors
pnpm vitest
```

## Layout

```
crates/core           ports (traits), the finding model, the OWASP catalogue. No I/O.
crates/static-engine  filesystem provider, oxc parsing, rule plumbing,
                      framework profiles, shared AST and request-origin helpers
crates/detectors      the rules themselves
crates/reporters      pretty, json, sarif, junit, md output
crates/napi           the Node bridge
crates/cli-native     standalone binary, no Node required
packages/sdk          report types + zod schemas
packages/config       config schema and resolver
packages/cli          the `owlwarden` command
fixtures/             vulnerable projects and the false-positive corpus
```

`ARCHITECTURE.md` explains why it is arranged this way. `docs/adr/` records the
decisions that were genuinely contested.

## Writing a rule

A rule is a `FileRule` (sees one parsed file) or a `ProjectRule` (sees the whole
tree). Both live in `crates/detectors`. Start from `cors.rs` — it is the
shortest complete example of the shape.

[docs/how-to/extend.md](docs/how-to/extend.md) is the full walkthrough, including
how to add a framework rather than a rule. The short version:

1. The `DetectorMeta`: a permanent id, a severity, and the honest `max_confidence`.
   A static rule cannot reach `Confirmed`; only correlation with a live probe can.
2. The `Remediation` table. Every framework in `SUPPORTED_FRAMEWORKS` needs a fix
   that compiles, because someone will paste it. A test enforces this, so a rule
   cannot ship with a framework silently falling through to generic advice.
3. Fixtures on **every** supported framework: a vulnerable project that must
   fire, and a clean twin that must stay silent — ideally the tempting case a
   naive implementation would flag. Counts live in `SHARED_FIRES` /
   `crates/detectors/tests/fixtures.rs` (12 × 12 cells today). CI fails if a
   catalogue rule is missing from any framework row.

Then the rule. Then run it against the whole corpus, and regenerate the
catalogue with `node scripts/generate-rules-md.mjs`.

Two pieces of shared infrastructure exist so that rules do not each invent their
own answer. Use them:

- **Framework vocabulary.** Never hardcode `res.json` or `reply.send`. Ask
  `owlwarden_static::http` — `is_response_sink`, `is_cookie_setter`,
  `is_cors_enabler` — which answers from the profiles of whichever frameworks
  the project actually uses.
- **Request origin.** Never write your own "did this come from the user" check.
  `owlwarden_static::taint::RequestOrigin` is that check, and it is what keeps
  confidence levels comparable between rules.

**Rule ids are permanent.** They appear in suppressions, agent rules files, and
other people's CI configs. Choose one you can live with; renaming is a breaking
change and goes in the changelog.

## Code standards

The full list is in `ARCHITECTURE.md`. The parts that come up in review most
often:

- No `unwrap`, `expect`, or `panic!` outside tests. Errors are typed and
  propagate.
- Every loop over external data has an explicit bound.
- Validate input at the top of any function that takes it from outside.
- Functions under about 60 lines.
- Zero warnings. `clippy -D warnings` is the gate, not a suggestion.

Comments explain *why*, not *what*. If a comment restates the line below it,
delete it.

## Commits and PRs

- Sign off your commits (`git commit -s`). We use the
  [DCO](https://developercertificate.org/), not a CLA.
- One logical change per PR.
- If you change the report format, regenerate the cross-language goldens:
  `OWLWARDEN_UPDATE_GOLDEN=1 cargo test -p owlwarden-reporters`, then update the
  zod schema in `packages/sdk` until the vitest passes again.
- If you make a design decision, add an ADR in `docs/adr/`. Not every PR needs
  one; the ones that change how something works do.

## Adding a dependency

Say why in the PR. `cargo-deny` runs in CI and checks the licence and the
advisory database, but it cannot tell us whether the dependency was worth it. A
security tool's install footprint is part of its argument.

## Releasing

Maintainers only, but written down so it is not folklore.

owlwarden is eleven npm packages: the four in this repo, plus one prebuilt
binary package per platform. They are built and published by
`.github/workflows/release.yml`, never from a laptop — a laptop can only produce
its own platform's binary, and it cannot generate
[provenance](https://docs.npmjs.com/generating-provenance-statements), which is
an attestation signed by the CI system that did the build.

1. Bump the version in all five manifests — `Cargo.toml`, `packages/*/package.json`,
   `crates/napi/package.json` — and check with `node scripts/check-version.mjs`.
2. Update `CHANGELOG.md`.
3. Exercise the pipeline without publishing:
   `gh workflow run release.yml -f dry_run=true`. It builds all seven targets and
   verifies every platform package has its binary.
4. Merge, then tag: `git tag -s vX.Y.Z && git push origin vX.Y.Z`.

The tag must match the manifests or the release fails before anything is built.
That check exists because npm publishes are immutable: a wrong version cannot be
replaced, only deprecated and superseded.

Publishing needs an `NPM_TOKEN` repository secret — a granular automation token
with write access to `owlwarden` and the `@dointhai` scope.

## Code of conduct

Be decent. Disagree about the code, not about the person. Maintainers will
remove comments and contributors that make this an unpleasant place to work.
