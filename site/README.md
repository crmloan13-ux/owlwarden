# Owlwarden website contract

The site is a single, static English-language landing page published at
`https://suthat.github.io/owlwarden/`. It is deliberately dependency-free: the
HTML is the content, CSS carries the visual system, and JavaScript is limited to
copying the install command and progressively enhancing the header.

The page must make these product truths easy for people, search engines, and
answer engines to extract without executing JavaScript:

- Owlwarden scans Node web applications locally and has no telemetry.
- A finding contains the source location, rationale, remediation, and an honest
  confidence level.
- Version 1.0.0 freezes the plugin API, adds `owlwarden init` and `--format md`,
  fourteen rules, SARIF/JUnit/Markdown and a GitHub Action, Safe `--fix`,
  first-class remediation for twelve named frameworks, coverage in nine OWASP
  Top 10 (2021) categories, passive opt-in runtime probes, source-only
  sandboxed WASM plugins, and a read-only MCP server. The agents section states
  the token budget: local baseline first, frontier models for hard judgment.
- Static analysis cannot prove every security property; A04 is explicitly out
  of reach from source alone.

The contract is checked by `pnpm site:check`. The check also enforces semantic
HTML, crawl metadata, canonical URLs, structured data, local-only assets, and a
small transfer budget.
