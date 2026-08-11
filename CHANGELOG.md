# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

**Rule ids are public API.** A rule id, once released, is never reused for a
different check and never silently renamed — CI configs, suppressions, and
agent rules files all reference them. Renames go through a deprecation cycle and
are listed here under Changed.

## [Unreleased]

## [0.4.0] — 2026-08-11

CI-ready depth: pipelines teams already run, plus a deeper fixture corpus so
those pipelines gate on findings worth trusting
([ADR 0017](docs/adr/0017-ci-reporting-surface.md),
[ADR 0018](docs/adr/0018-corpus-depth-bar.md)).

### Added

- **`--format sarif`** — SARIF 2.1.0 rendering of the existing `Report` (ADR
  0017). For GitHub code scanning and similar consumers.
- **`--format junit`** — JUnit XML, one failure per finding. Exit codes stay on
  the CLI.
- **GitHub Action** at [`action/`](action/) — composite over the published CLI;
  preserves exit 0 / 1 / 2. See [docs/how-to/ci.md](docs/how-to/ci.md).
- **Corpus depth** — dialect tempting on every clean twin; `ssrf` shapes now
  include `got.get` and `https.get`/`http.get` (4); `open-redirect` adds an
  extra/status-first shape (3); generic-profile fixtures outside the 144-cell
  matrix.
- **More Safe autofix** — `weak-crypto` HashedSecret (algorithm literal
  `'md5'`/`'sha1'` → `'sha256'`, keeping `createHmac` keys and `crypto.`
  receivers) and `insecure-cookie` options objects that only carry security
  keys (or `{}`).
- **`owlwarden plugin inspect <path>`** — print capabilities from
  `owlwarden.plugin.json` without loading WASM (local preview, not a signed
  registry).
- Cold-scan performance baseline harness
  ([docs/how-to/performance.md](docs/how-to/performance.md)).

### Security

- GitHub Action drops free-form `args` (shell injection + `--allow-*` bypass);
  typed `osv` input replaces ad-hoc flags; path/out/version reject CR/LF/`..`;
  `GITHUB_OUTPUT` uses a heredoc delimiter.
- `plugin inspect` confines paths under cwd, requires `realpath` under the
  working tree, and reads via `readFileBounded` (no symlink leaf).
- Action smoke workflow pins upstream actions by full commit SHA.
- SARIF endpoint URIs strip control characters; `plugin inspect` bounds JSON
  nesting depth after parse.

### Fixed

- MCP `scan_project` / `scan_file` send the flat NAPI request shape (nested
  `settings` was rejected by `deny_unknown_fields`, so agent scans failed).
- NAPI rejects `--allow-active` without `--target`, matching the CLI gate.
- `--fix` refuses to apply when highlight text drifted since the scan (TOCTOU /
  dirty-tree safety).
- Active request pacing reserves the next slot under a lock so concurrent
  detectors cannot bypass `ACTIVE_MIN_INTERVAL`.
- OSV advisory summaries strip control / ANSI characters before they enter
  findings; package-lock line lookup is O(lines) not O(packages × lines).
- `weak-crypto` Safe autofix no longer rewrites the whole `createHash` /
  `createHmac` call (which truncated HMAC keys and stripped `crypto.`).

## [0.3.0] — 2026-08-10

Autofix (`--fix`), `--allow-active` scaffold, and opt-in Google OSV lookup.
Folded in the 0.2.1 docs/MCP polish so one publish updates npm `homepage`.

### Added

- **`owlwarden scan --fix`** — applies `Safe`, single-line highlight
  replacements only. Never on `Possible`. Clean git tree by default
  (`--allow-dirty` to override). `--dry-run` and `--fix-unsafe`. Re-scans
  after writes. First Safe remediations: `stack-trace-leak` and `weak-crypto`
  (GuessableToken / `Math.random()`).
- **`--allow-active`** — with `--target`, permits state-changing HTTP methods.
  Rate-limited, request audit log (method/URL/status). No first-party active
  detector yet. MCP cannot set the flag.
- **`--osv`** — opt-in Google OSV QueryBatch for lockfile dependencies
  ([ADR 0016](docs/adr/0016-osv-advisory-lookup.md)). New rule
  `known-vulnerable-dependency` (A06 / CWE-1395). See
  [docs/how-to/osv.md](docs/how-to/osv.md).
- `AdvisoryClient` port and `Capabilities.advisory`, distinct from target
  `Transport` scope.

### Changed

- npm `homepage` → `https://suthat.github.io/owlwarden/`.
- Token narrative: save tokens with local baseline scans; spend frontier models
  on hard judgment (site, README, npm README, agent-integration).
- `owlwarden mcp` stderr ready banner / TTY how-to; stdout remains JSON-RPC-only.

## [0.2.0] — 2026-08-08

Plugins (source-only WASM), MCP for agents, and twelve Node frameworks. The
formal v0.2 bar from [ROADMAP.md](ROADMAP.md). Autofix and active checks stay
later work.

### Added

- **`owlwarden-plugin-host`** — sandboxed WASM plugin host (ROADMAP v0.2),
  ships partial: source-only. A plugin is a `.wasm` module plus an
  `owlwarden.plugin.json` manifest, loaded with `--plugin <path>` (repeatable)
  and refused under `--ci` unless `--allow-plugins` is also passed. Every
  invocation runs in a fresh `wasmtime` store bounded by fuel, a 64 MiB
  `StoreLimits` memory cap, and a wall-clock deadline via epoch interruption;
  the only host function wired is `emit_finding`, and every claim it receives
  is re-validated against the plugin's own manifest before it becomes a
  finding. A manifest declaring `network` or `active` is refused at load
  time rather than silently downgraded — see
  [ADR 0015](docs/adr/0015-plugin-host-wasmtime.md). `wasmtime` is a new
  dependency, confined to this one crate with default features disabled
  (only `cranelift`/`runtime`/`std`); every other crate keeps
  `#![forbid(unsafe_code)]`. Floored at 36.0.13 — every earlier release has
  an open RUSTSEC advisory, several of them sandbox escapes.
- Sandbox-escape test suite (`crates/plugin-host/tests/sandbox_escape.rs`):
  fuel exhaustion, oversized `memory.grow` / `table.grow`, a finding flood, an
  undeclared rule id, an oversized `why`, and a benign positive control.
- Error code **`E_PLUGIN_INVALID`** for a plugin that could not be loaded.
- **`owlwarden mcp`** — stdio MCP server with `scan_project`, `scan_file`,
  `explain_rule`, and `list_rules`. Static and read-only; no `--target`, no
  file writes, paths sandboxed to the workspace root.
- **`owlwarden init --agent-rules`** — writes `.owlwarden/agent-rules.md` from
  the compiled catalogue.
- **`owlwarden plugin scaffold <name>`** — guest stub (`plugin.wat`) plus a
  valid `owlwarden.plugin.json`.
- Plugin-authoring schemas in `@dointhai/owlwarden-sdk` (`pluginManifestSchema`).
- **Seven more Node frameworks** with first-class profiles, remediation on every
  catalogue rule, and square fixture coverage: Hono, Koa, Hapi, Sails.js, Astro,
  Remix, and Gatsby. Supported set is now twelve stacks (12 rules × 12
  frameworks, locked in CI).
- **Richer fixture corpus** — each framework exercises two real-world shapes for
  `ssrf` (fetch + axios), `open-redirect` (redirect helper + `Location`
  header), and `sensitive-data-logged` (password + accessToken), plus tempting
  false-positive twins on every clean project.
- **File-route mapping** for Astro (`src/pages/api`), Remix flat routes, and
  Gatsby Functions (`src/api`).
- Request-origin recognition for Hono’s `c` context and Astro’s `Astro.request`.

### Changed

- `DetectorMeta.title` / `.category` / `.description` are now
  `Cow<'static, str>` (were `&'static str`), so a `WasmDetector` built from a
  parsed plugin manifest can own its strings. No change to the JSON wire
  shape or to first-party rules, which still write string literals.
- README and npm package text rewritten in plain language: what it does, that
  it stays local, which frameworks it knows, and what v0.2 actually ships
  (plugins source-only, MCP read-only). States that local scans cover baseline
  checks without burning LLM tokens, and that deeper AI security review still
  belongs on high-impact work.
- Plugin hardening after whitebox review: `O_NOFOLLOW` + bounded reads for
  manifest/WASM load; `StoreLimits` on tables; plugin rule ids must be
  namespaced under the plugin id; source-only plugins cannot declare
  `confirmed`; `why` capped; MCP JSON-RPC lines capped; `init` /
  `plugin scaffold` use symlink-safe writes under the working directory; napi
  re-checks `--ci` + `--allow-plugins`.
- Fixture matrix tightened: every clean twin ships `*tempting*` and
  `*safe-redirect*` files; multi-fire rules are locked to named source shapes
  (fetch/axios, redirect/Location, …); the TypeScript e2e path asserts
  `SHARED_FIRES` counts on all twelve frameworks, not only Next.js.
- Cookie detection: nested setters (`ctx.cookies.set`), Hapi `isHttpOnly` /
  `isSecure` / `isSameSite`, and dropped false cookie matches on
  `c.header` / `res.setHeader` / bare `serialize`.
- Stack-trace rule recognises Koa-style `ctx.body = …` assignments.
- `secureHeaders` counts as header middleware for Hono.

### Fixed

- `cargo deny` CI gate: allow `CDLA-Permissive-2.0` for `webpki-roots` (Mozilla
  CA data via rustls/reqwest), and give the dynamic-engine dev-dep on
  `owlwarden-transport` a workspace version so it is not a path-only wildcard.

### Security

- **Prompt-injection hardening for MCP / agents / plugins.** MCP tool results
  are wrapped in an `OWLWARDEN_TOOL_RESULT` trust-boundary envelope; free text
  is stripped of control/invisible characters and common chat role markers.
  Plugin `why` is sanitised at emit time; `init --agent-rules` tells agents to
  treat findings as evidence, not instructions.

## [0.1.0]

Passive dynamic engine and correlation. `Confirmed` is reachable for the first
time, without opening active (state-changing) checks.

### Added

- **`--target <URL>`** — probe a live origin with passive methods only
  (GET/HEAD/OPTIONS). Operator intent from the command line; never read from
  project config, so a hostile PR cannot point CI at an internal host
  ([ADR 0014](docs/adr/0014-passive-dynamic-and-correlation.md)).
- **`--scope <URL>`** (repeatable) — deny-by-default allowlist. When omitted,
  the allowlist is exactly the origin of `--target`. Localhost is not special.
- **`owlwarden-transport`** — `ReqwestTransport` that enforces scope on every
  redirect hop, streams body bytes under the cap, and refuses state-changing
  methods without `--allow-active` (no active detectors ship yet).
- **`owlwarden-dynamic`** — passive header probe for `security-headers-missing`
  and a correlation post-pass that raises agreeing static+dynamic findings to
  `confirmed`, or clears a static gap when the live response already sets the
  headers.
- Error code **`E_TARGET_INVALID`** for bad target/scope.
- **Square static fixture matrix** — every catalogue rule has a vulnerable
  fixture and a silent clean twin on all five frameworks (12 × 5 = 60 cells).
  `weak-crypto` fires three shapes on every framework. Locked by
  `SHARED_FIRES` in `crates/detectors/tests/fixtures.rs`.
- **Framework dynamic matrix** — `crates/dynamic-engine/tests/framework_matrix.rs`
  correlates `security-headers-missing` against each framework's fixture plus a
  live header probe (confirmed / cleared / clean stays silent).
- **CLI live e2e** — `packages/cli/test/run.test.ts` drives `--target` through
  the npm CLI against an in-process server on all five frameworks.

### Changed

- Confidence filtering runs **after** correlation, so a `possible` static
  finding can still become `confirmed`.
- `watch` refuses `--target` / `--scope` (static-only; re-probing on save is
  hostile to the developer's own server).
- Help text no longer claims every scan is offline — only scans without
  `--target`.
- **napi `scan` is async** (`spawn_blocking`) so a live probe cannot deadlock
  the Node event loop while an in-process test (or user) server is accepting
  connections. The TypeScript CLI awaits the Promise.

### Security

- Scope deny-by-default, including redirect hops (SSRF-bait case).
- Credentials in `--target` / `--scope` URLs are refused.
- Automatic response decompression is off; body caps apply while streaming.
- No path from scanned-tree config to the request URL.
- Redirect `Location` re-validated as a target (blocks `user@host` confusion,
  non-http(s) schemes, control characters, oversized URLs).
- Headers-only probes (`max_body_bytes = 0`) do not pull a response body into
  memory — a hostile HEAD payload cannot inflate the scanner.
- Oversized response header values are dropped, not truncated; outbound request
  headers reject CRLF/NUL (request-smuggling footgun for future detectors).

## [0.0.2]

Static slice of the trust-and-noise work planned for v0.1: suppressions,
baseline, three gap-closing rules, and `watch`. Still no network — the dynamic
engine that makes `Confirmed` reachable remains later.

### Added

- **Inline suppressions** with a mandatory reason:
  `// owlwarden-disable-next-line <rule> -- <reason>`. Directives without a
  reason never hide a finding. `--report-suppressions` lists every directive
  and flags stale or missing-reason ones. `suppressedCount` in the JSON report
  is now wired for real.
- **Baseline mode.** `--baseline <file>` reports only findings new since the
  file was written; `--write-baseline <file>` records current debt. Fingerprints
  key on rule id, normalised path, whitespace-collapsed evidence, and an
  occurrence index so a formatter pass does not reopen accepted findings and
  two identical findings in one file stay distinct
  ([ADR 0013](docs/adr/0013-suppressions-and-baseline.md)).
- **Three rules** closing the static-reachable OWASP gaps:
  - `unpinned-dependency` (A06) — `*` / `latest` in `package.json`
  - `ci-unpinned-action` (A08) — GitHub Actions not pinned to a commit SHA
  - `sensitive-data-logged` (A09) — passwords/tokens written to a log sink  
  Each ships remediation for all five frameworks, with vulnerable and
  should-not-fire fixtures.
- **`owlwarden watch`** — re-scan on change, static only. Never opens a network
  path.

### Changed

- The filesystem walker now reads `.github/` (still skips other hidden
  directories), so CI integrity rules can see workflow files.
- Report JSON gains `suppressions` and `baselineHiddenCount` (additive under
  schema `1.0`).
- **Security hardening (hostile scan target):** executable project config
  (`owlwarden.config.{js,mjs,ts,mts}`) is opt-in via `--allow-config-js`
  (default loads JSON only); `--ci` ignores project `preset` / `failOn` /
  `minConfidence` unless `--allow-project-config`, ignores inline suppressions
  unless `--allow-suppressions`, and refuses `--baseline` unless
  `--allow-baseline`; truncated reports fail CI; `--out` / `--write-baseline`
  refuse symlinked parent directories and write via temp+rename
  (`create_new` / `wx`); source reads are bounded and use `O_NOFOLLOW` on Unix;
  parser nesting guard skips comments/strings and counts generics/JSX and
  brackets inside templates; `hardcoded-secret` redacts values in snippets
  before line truncation; baseline/config loads refuse symlinks and oversized
  inputs; CI workflow evidence is length-capped. See [SECURITY.md](SECURITY.md).

## [0.0.1]

First release. A static engine, a rule set, and honest reporting about what it
does and does not reach.

### Added

- **Static engine.** Sandboxed `SourceProvider`, oxc parsing with bounded
  recursion, and per-file and whole-project rule traits.
- **Five frameworks** via the `FrameworkProfile` registry: Next.js, Nuxt,
  NestJS, Express, and Fastify. Detection is package-based with specificity
  tie-breaking, so a NestJS project that also depends on Express is treated as
  NestJS.
- **Nine rules** across six OWASP Top 10 (2021) categories:
  `open-redirect`, `weak-crypto`, `sql-injection`, `cors-permissive`,
  `insecure-cookie`, `security-headers-missing`, `stack-trace-leak`,
  `hardcoded-secret`, and `ssrf`. Full catalogue in [RULES.md](RULES.md).
- **`owlwarden coverage`** — what the rules reach, and what they do not,
  computed from the compiled-in rules rather than maintained by hand.
- **Confidence on every finding**, and a `RequestOrigin` analysis that the
  injection-shaped rules use to distinguish `Likely` from `Possible`.
- **Remediation tables**, so every rule ships a framework-specific fix for each
  supported framework rather than generic advice.
- **`pretty` and `json` reporters**, with code frames, ASCII and no-colour
  fallbacks, and a stable JSON contract validated against zod schemas in CI.
- **`owlwarden explain <id>`** — the full write-up for a rule with no network
  access, because the reader may be an agent with no browser.
- npm CLI plus a standalone Rust binary, on Linux, macOS, and Windows.

### Security

- Passive only. v0.0 reads source and sends no requests, so it cannot change
  the state of anything it scans.
- No telemetry, of any kind, opt-in or otherwise.
- `#![forbid(unsafe_code)]` in every crate.
- Bounded file count, file size, total bytes, and parser recursion depth, so a
  hostile repository cannot exhaust memory or the stack.

[Unreleased]: https://github.com/suthat/owlwarden/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/suthat/owlwarden/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/suthat/owlwarden/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/suthat/owlwarden/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/suthat/owlwarden/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/suthat/owlwarden/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/suthat/owlwarden/releases/tag/v0.0.1
