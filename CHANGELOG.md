# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

**Rule ids are public API.** A rule id, once released, is never reused for a
different check and never silently renamed — CI configs, suppressions, and
agent rules files all reference them. Renames go through a deprecation cycle and
are listed here under Changed.

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/suthat/owlwarden/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/suthat/owlwarden/releases/tag/v0.0.1
