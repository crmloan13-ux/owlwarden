# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

**Rule ids are public API.** A rule id, once released, is never reused for a
different check and never silently renamed — CI configs, suppressions, and
agent rules files all reference them. Renames go through a deprecation cycle and
are listed here under Changed.

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/suthat/owlwarden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/suthat/owlwarden/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/suthat/owlwarden/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/suthat/owlwarden/releases/tag/v0.0.1
