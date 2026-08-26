# Roadmap

What is built, what is next, and what each release has to be true for it to
ship. Dates are absent on purpose — this is an ordering, not a schedule.

SemVer. The plugin API is frozen at 1.0 and changes only through the RFC
process after that.

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

Each of those now has a test that fails when the bug is reintroduced, and where
a mechanism exists in two languages — signature verification, text
sanitisation — both sides are held to one fixture that neither of them
generates.

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

## v0.3 — Autofix, active gate, and OSV — **shipped**

**Goal:** close the loop from finding to fix, without breaking anyone's code;
open the active-check gate safely; cover known lockfile advisories opt-in.

Delivered:

- `--fix` / `--fix-unsafe` / `--dry-run` / `--allow-dirty`: `Safe` highlight
  replacements only, never on `Possible`, clean git tree by default, re-scan
  after apply. First Safe remediations on `stack-trace-leak` and
  `weak-crypto` (GuessableToken).
- `--allow-active` wired through CLI/napi, rate limit, request audit log,
  existing scope-escape suite. No first-party active detector yet.
- `--osv` + rule `known-vulnerable-dependency` via allowlisted OSV QueryBatch
  ([ADR 0016](docs/adr/0016-osv-advisory-lookup.md)).
- 0.2.1 polish: npm homepage → GitHub Pages, token/frontier narrative, MCP
  stderr how-to.

**Exit criteria, met for this slice:** Safe autofix gated and tested; active
methods unreachable without the flag; scope-escape and OSV mock suites pass.
Active detectors, offline OSV DB, and editor hooks remain later work.

## v0.4 — CI-ready depth — **shipped**

**Goal:** fit the pipelines teams already run, and make the findings those
pipelines gate on deep enough to trust — not a thin matrix with a SARIF coat of
paint.

Delivered:

- **Pipelines** ([ADR 0017](docs/adr/0017-ci-reporting-surface.md)): `--format
  sarif` (SARIF 2.1.0) and `--format junit`; composite GitHub Action under
  `action/`; exit-code contract documented as canonical in
  [docs/how-to/ci.md](docs/how-to/ci.md) (still 0 / 1 / 2).
- **Corpus depth** ([ADR 0018](docs/adr/0018-corpus-depth-bar.md)): dialect
  tempting on every clean twin; richer `ssrf` / `open-redirect` shape
  contracts; generic-profile fixtures outside the square matrix.
- **Capability deepen from 0.3:** more `Safe` autofix remediations; `owlwarden
  plugin inspect` for capabilities-before-load (local preview, not a signed
  store); cold-scan performance baseline harness.

**Exit criteria, met for this slice:** Action smoke against a clean fixture
exits 0; SARIF/JUnit snapshots green; square matrix still silent on clean /
tempting; shape contracts expanded without per-framework expectation drift.

## v0.5 — Depth beyond CI — **shipped**

**Goal:** close the later-work gaps that 0.3/0.4 left named: active probes,
air-gapped OSV, plugin integrity, multi-format emit, incremental watch.

Delivered:

- **Active detector** ([ADR 0019](docs/adr/0019-first-party-active-detector.md)):
  `csrf-cross-origin-post` behind `--allow-active`.
- **Offline OSV** ([ADR 0020](docs/adr/0020-offline-osv-cache.md)):
  `owlwarden osv update`, `--osv-db`, fail-closed `--osv --offline`.
- **Plugin integrity** ([ADR 0021](docs/adr/0021-plugin-artifact-signing.md)):
  manifest `artifact.sha256`, optional ed25519 `.sig`, `--require-signed-plugins`
  (local trust roots — not a hosted registry).
- **Stackable formats** ([ADR 0022](docs/adr/0022-stackable-formats.md)):
  repeated `--format` from one scan.
- **Incremental watch** ([ADR 0023](docs/adr/0023-incremental-watch.md)):
  dirty-path re-parse + finding merge (no <300 ms claim until measured).

**Exit criteria, met for this slice:** active canary suite green; offline OSV
fixture client green; digest/signature host tests green; multi-format CLI tests
green; incremental merge unit tests green. Markdown reporter, hosted plugin
store, and signed npm releases remain later.

## v0.6 — Release assurance — **folded into 1.0 where it already existed**

**Goal:** releases you can verify rather than trust.

Already true before 1.0 (kept, not re-litigated):

- `cargo-deny` as a blocking CI job (advisories + licences).
- npm publish with `--provenance`.
- Committed lockfiles.

**Not in 1.0** (still later): cosign-signed GitHub artifacts, an SBOM attached
to a GitHub Release, `cargo-fuzz` on parser/response boundaries. Those do not
unblock adoption; the plugin freeze and the first-run path do.

## v1.0 — Stable — **shipped**

**Goal:** stable, documented, plugin API frozen, and a first run that lands
in CI and in an agent without a scavenger hunt.

Delivered:

- Plugin API v1 frozen (`schemaVersion: 1`). Breaking changes go through
  [docs/rfc/](docs/rfc/README.md). See
  [ADR 0024](docs/adr/0024-plugin-api-v1.md).
- Diátaxis filled in: tutorials (first scan, agents), CLI and plugin-API
  reference, upgrade guide, comparison, maintainer discoverability checklist.
- `owlwarden init` writes the adoption kit: agent-rules, GitHub Action
  workflow, Cursor MCP config.
- `--format md` for PR comments (ADR 0022 extended).
- MCP registry descriptor at [`mcp/server.json`](mcp/server.json).

**Exit criteria, met for this slice:** documentation covers all four Diátaxis
kinds; plugin API has a freeze + RFC path; `init` and `md` are tested;
changelog and upgrade guide exist. Third-party plugins in the wild are a
consequence of the freeze, not a file we can commit. Hard CI perf gates and
cosign remain later — stated so 1.0.0 does not overclaim.

## v1.1 — The agent surface and the gate — **this release**

**Goal:** answer the second question the same repository now raises — *is the
coding agent that works in it being told to do something hostile?* — and turn a
tool the model may call into a control that always runs
([ADR 0025](docs/adr/0025-agent-surface-and-supply-chain.md),
[ADR 0026](docs/adr/0026-deterministic-agent-gate.md)).

Delivered:

- `Surface`, and the remediation matrix generalised over it. Twelve frameworks
  for `webApp`, seven agent hosts for `agentWorkspace`, neither checked against
  the other's rules, and a missing cell still fails the build.
- Eleven rules on the new surface, all capped at `likely`, all carrying a
  `runtimeScope`, all mapped to CWE with OWASP ASI 2026 as a secondary
  reference. The catalogue is 25 rules.
- A closed path allowlist that overrides `.gitignore` and nothing else, a
  bounded JSONC parser that keeps spans and duplicate keys, command-string
  analysis with a documented benign twin per signal, and hidden-text detection
  that folds homoglyphs for matching and reports from the original bytes.
- `owlwarden vet`, `owlwarden gate` with three host adapters, `owlwarden verify`,
  `--since` / `--staged` / `--paths`, `--format agent`, and
  `init --claude-code | --cursor | --generic`.
- A generated documentation site: 213 pages, one per rule and one per
  (rule, profile) cell that has a verified example, built from the same source
  that generates `RULES.md`, with a changelog and an Atom feed.
- **A pentest pass over the pre-existing code, not only the new.** It found more
  than the new work did, and the pattern is worth writing down: every one of the
  six failed *silently and safely*, which is why they survived a release. The
  Action rejected every input it was ever given. `plugin inspect` could never
  report `verified`. A plugin supplied the key that vouched for it. An unknown
  config key was stripped rather than refused, so `failon` read as tightening
  and did nothing. A `--since` that could not resolve widened the scan instead
  of failing it. And of two mirrored sanitisers, each was missing something the
  other had.

  Nothing here was found by looking harder at code. Four of the six were found
  by *running* something that had never been run: the Action's script, the
  signature path, the suppression listing on a terminal. The rule that came out
  of it, and the one this project should keep: a check that has never failed on
  purpose is not known to work.

**Exit criteria, all met:** every ADR 0025 and 0026 criterion; a tempting
fixture per agent host that stays silent in `quick`; a standing corpus of real
repository configurations that stays silent; a hostile-input suite that
terminates within budget and executes nothing; and an evasion suite with one
test per technique per rule.

The number that is not a target: rule count. Twenty-five is not a step toward
five thousand, and the second surface exists because nothing else reads it —
not to make the first number larger.

## Beyond 1.1

Candidate directions, in no particular order: GraphQL and gRPC awareness;
authenticated scan flows; frameworks outside the Node ecosystem, which needs a
second language before the parsing layer can honestly be called generic; an LSP
mode; a long-lived gate daemon, if cold-start cost turns out to dominate — a
measured problem with its own ADR, not an assumption to design around now; host
adapters beyond the three; a hosted curated plugin registry (local
digest/signature trust shipped in v0.5).

Named as out of scope so a later release does not quietly claim them: scanning
agent configuration inside `node_modules`; resolving effective configuration
across a host's managed, user, project, and local tiers; plugin-authored rules
on the agent surface, which needs an RFC because it adds a type to the frozen
plugin API; and any enforcement at the model layer rather than the process
layer.

Adding another Node framework is no longer a roadmap item, because it is no
longer a change to the engine — it is a `FrameworkProfile`, and
[docs/how-to/extend.md](docs/how-to/extend.md) is the whole procedure. The same
is now true of an agent host: an `AgentHostProfile` and a fixture pair.

---

## Documentation

The [Diátaxis](https://diataxis.fr) model — four kinds of document, never mixed:

| Kind | Location | Answers | Today |
|---|---|---|---|
| Tutorials | `docs/tutorials/` | I am new and want to learn by doing | first scan; agent/MCP |
| How-to guides | `docs/how-to/` | I have a specific task | CI, upgrade, plugins, discover |
| Reference | `docs/reference/` | I need the exact flag, field, or code | CLI; plugin API v1; error codes; `RULES.md` |
| Explanation | `docs/explanation/` | I want to understand why | coverage, false positives, agents, compared |

The generated documentation site (`site/`) is built from the same catalogue as
`RULES.md`, and its examples are harvested by scanning the fixtures — so a page
cannot describe behaviour the tool no longer has. `pnpm site:check` fails when
the committed site is stale or when any page breaks the head-tag, link-graph, or
no-external-host contracts.

Reference material is generated from source where possible — `RULES.md` already
is, and a test fails if a rule ships without its entry — so it cannot drift from
the code it describes.

Alongside those:

- **ADRs** (`docs/adr/`) — one file per contested decision, numbered
  sequentially, never deleted, only superseded. This is the durable record of
  why something is the way it is.
- **CHANGELOG.md** — Keep a Changelog format. Every user-visible change.
- **RFCs** (`docs/rfc/`) — required for a breaking plugin-API change after 1.0.
  See [docs/rfc/README.md](docs/rfc/README.md).

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
