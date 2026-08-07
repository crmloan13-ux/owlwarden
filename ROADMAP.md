# Roadmap

What is built, what is next, and what each release has to be true for it to
ship. Dates are absent on purpose — this is an ordering, not a schedule.

SemVer. Before 1.0 the plugin API may change, with a migration note in each
release. It freezes at 1.0 and changes only through the RFC process after that.

---

## v0.0 — Static spine — **shipped**

**Goal:** a working thread from `npx owlwarden scan` to a code frame in the
terminal, with nothing faked in between.

Delivered:

- Cargo and pnpm workspaces; the napi bridge; a standalone binary.
- Config loader with zod, presets, and useful zero-config defaults.
- Static engine: sandboxed `SourceProvider`, oxc parsing, and a
  `FrameworkProfile` registry that keeps framework knowledge out of the rules.
- Five frameworks: Next.js, Nuxt, NestJS, Express, and Fastify.
- Nine rules across six OWASP Top 10 categories, each with a `Remediation`
  table that must cover every supported framework. See [RULES.md](RULES.md).
- `RequestOrigin`, a shared one-hop origin analysis that the injection-shaped
  rules use to set confidence honestly ([ADR 0012](docs/adr/0012-request-origin-not-taint.md)).
- `pretty` reporter with code frames, and `json`, both behind the `Reporter`
  trait; `owlwarden coverage` publishes what the rules reach and what they miss.
- Vulnerable and should-not-fire fixtures for all five frameworks, both wired
  into CI.
- Linux, macOS, and Windows in CI. Zero-warning build.

**Exit criteria, all met:** every fixture issue found with code frames; `--ci`
emits JSON with a non-zero exit; the false-positive corpus is silent.

The rule count grew past the original two during v0.0 because two rules could
not answer the question the tool exists to answer. A scanner that reports one
category and stays silent on the rest reads as a clean bill of health, which is
worse than no scan at all — hence `owlwarden coverage`, which states the gaps
in the same breath as the findings.

## v0.0.2 — Trust without the network — **shipped**

**Goal:** make adoption realistic on a legacy repo *before* the dynamic engine
lands. SemVer patch because the plugin API and the network surface are
untouched; the work is a slice of what v0.1 still owns.

Delivered:

- Inline suppressions with a mandatory reason, and `--report-suppressions`.
- Baseline mode (`--baseline` / `--write-baseline`) with reformatting-stable
  fingerprints ([ADR 0013](docs/adr/0013-suppressions-and-baseline.md)).
- Rules for the three static-reachable OWASP gaps: A06 (`unpinned-dependency`),
  A08 (`ci-unpinned-action`), A09 (`sensitive-data-logged`). A04 stays out of
  reach on purpose.
- `watch`, static-only.

**Exit criteria, met for this slice:** baseline survives reformatting; the
false-positive corpus stays silent at twelve rules; every new rule covers all
five frameworks.

## v0.1 — Trust and the dynamic engine — **shipped**

**Goal:** a tool you can point at a real codebase without drowning in output,
including runtime confirmation.

Delivered:

- Dynamic engine: bounded `Transport`, scoped, passive — and correlation with
  the static engine, which is what makes `Confirmed` reachable
  ([ADR 0014](docs/adr/0014-passive-dynamic-and-correlation.md)).
- First correlated rule: `security-headers-missing` (the case static analysis
  cannot settle alone, because CDN/ingress headers are invisible to it).
- Square static matrix: every catalogue rule × every supported framework
  (vulnerable fires, clean twin silent), including three `weak-crypto` shapes
  on each framework.
- CLI live e2e through the npm package (`--target`) on all five frameworks;
  napi `scan` runs off the event loop so probes do not deadlock Node.
- Rule catalogue remains generated `RULES.md` plus offline `explain` — a hosted
  docs site is not this release; inventing one without content infrastructure
  would be ceremony.

**Exit criteria, met:** correlated findings report as `Confirmed`; the
false-positive corpus stays silent; the 12 × 5 static cells and CLI live
correlation tests are green. (Suppressions, baseline, `watch`, and the
A06/A08/A09 rules shipped in 0.0.2.) Active checks, deeper dynamic rules, and
a hosted docs site remain later work — stated here so 0.1.0 does not overclaim.

## v0.2 — Plugins and the agent surface — **shipped**

**Goal:** extensibility that does not require trusting the extension, on top of
broad Node framework coverage developers already use.

Delivered:

- Twelve first-party frameworks (Hono, Koa, Hapi, Sails.js, Astro, Remix,
  Gatsby on top of the original five), with a square fixture matrix. Adding
  another Node framework remains a `FrameworkProfile` — see
  [docs/how-to/extend.md](docs/how-to/extend.md).
- `plugin-host` on wasmtime, source-only capability model, sandbox-escape suite
  ([ADR 0015](docs/adr/0015-plugin-host-wasmtime.md)).
- Plugin-authoring types in `@dointhai/owlwarden-sdk`, and
  `owlwarden plugin scaffold`.
- `owlwarden mcp` (stdio, static, read-only) and `init --agent-rules`. See
  [docs/explanation/agent-integration.md](docs/explanation/agent-integration.md).

**Exit criteria, met:** an external plugin loads sandboxed and can contribute
findings; malicious samples in the escape suite are contained; an MCP-capable
agent can scan and pull remediations in one loop. Autofix (`--fix`) and
polished editor post-edit hooks remain later work — stated so 0.2.0 does not
overclaim.

## v0.3 — Autofix and active checks

**Goal:** close the loop from finding to fix, without breaking anyone's code.

- `--fix`: `Safe` fixes only, never on a `Possible` finding, clean git tree by
  default, and a re-scan afterwards to verify rather than assume.
- `--allow-active` gating for state-changing checks, with a scope-escape test
  suite, rate limiting, and a request audit log.

**Exit criteria:** safe autofix verified across the fixture corpus with no
behaviour changes; active checks unreachable without the flag; the scope-escape
suite passes.

## v0.4 — Pipelines and reporting

**Goal:** fits into the tooling teams already run.

- SARIF reporter for GitHub code scanning, and a JUnit reporter.
- A GitHub Action.
- A documented exit-code contract.
- A plugin registry that shows an extension's capabilities before install.

**Exit criteria:** a demonstration repository gates pull requests on owlwarden
through the Action, with a baseline suppressing pre-existing findings.

## v0.5 — Release assurance

**Goal:** releases you can verify rather than trust.

- Signed releases (cosign) and an SBOM per artifact.
- `cargo-deny` and `cargo-audit` as blocking gates.
- `cargo-fuzz` targets on the parsing and response-handling boundaries.
- Reproducible builds where feasible.

**Exit criteria:** the release pipeline produces signed artifacts with an
attached SBOM, and supply-chain checks block CI rather than warn.

## v1.0 — Stable

**Goal:** stable, documented, plugin API frozen.

- Complete documentation across all four Diátaxis types.
- Plugin API v1, with a deprecation policy.
- A performance pass against the budgets in
  [ARCHITECTURE.md](ARCHITECTURE.md) §12.

**Exit criteria:** every gate green; documentation complete; third-party plugins
exist; a changelog and an upgrade guide.

## Beyond 1.0

Candidate directions, in no particular order: GraphQL and gRPC awareness;
authenticated scan flows; frameworks outside the Node ecosystem, which needs a
second language before the parsing layer can honestly be called generic; an LSP
mode; a curated, signed plugin registry.

Adding another Node framework is no longer a roadmap item, because it is no
longer a change to the engine — it is a `FrameworkProfile`, and
[docs/how-to/extend.md](docs/how-to/extend.md) is the whole procedure.

---

## Documentation

The [Diátaxis](https://diataxis.fr) model — four kinds of document, never mixed:

| Kind | Location | Answers | Today |
|---|---|---|---|
| Tutorials | `docs/tutorials/` | I am new and want to learn by doing | the README walkthrough only |
| How-to guides | `docs/how-to/` | I have a specific task | CI, extending the engine |
| Reference | `docs/reference/` | I need the exact flag, field, or code | error codes; `RULES.md` |
| Explanation | `docs/explanation/` | I want to understand why | coverage, false positives, agents |

Reference material is generated from source where possible — `RULES.md` already
is, and a test fails if a rule ships without its entry — so it cannot drift from
the code it describes.

Alongside those:

- **ADRs** (`docs/adr/`) — one file per contested decision, numbered
  sequentially, never deleted, only superseded. This is the durable record of
  why something is the way it is.
- **CHANGELOG.md** — Keep a Changelog format. Every user-visible change.
- **RFCs** (`docs/rfc/`) — not yet, and deliberately so: the plugin API is v0.2,
  and an RFC process with nothing to decide is ceremony. The directory appears
  with the first proposal that touches the public plugin API.

Documentation is part of the definition of done. A feature is not finished until
its reference entry exists and, if it is user-facing, a how-to note as well.

## Governance and release

- Trunk-based development. Short-lived branches. Every pull request runs the
  full `pnpm check` gate.
- Conventional Commits, feeding an automated changelog and version bumps.
- Release: tag, build every platform package in CI, sign, attach an SBOM,
  publish to npm and GitHub Releases. Platform packages live under the
  `@dointhai` scope, so `npx owlwarden` resolves the right binary without the
  user thinking about it.
- Two-person review for anything in `plugin-host` or the release pipeline.
- DCO sign-off on commits. No CLA.
