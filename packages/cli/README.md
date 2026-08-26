# owlwarden

[![npm](https://img.shields.io/npm/v/owlwarden)](https://www.npmjs.com/package/owlwarden)

Security scanner for Node web apps and AI coding agents. Finds OWASP Top 10
issues in Next.js, Nuxt, NestJS, Express, Fastify, Hono, Koa, Hapi, Sails.js,
Astro, Remix, and Gatsby — and scans the agent configuration in your repository
(`.claude/`, `.cursor/`, `.vscode/`, `CLAUDE.md`) that no dependency scanner
reads. Runs entirely on your machine. No account, no telemetry, no network
unless you ask.

```bash
npx owlwarden scan          # your app
npx owlwarden vet .         # your agent's config
```

## Install

```bash
npm i -D owlwarden
```

Node 20+. Prebuilt native addon for macOS, Linux, and Windows — no compiler
needed. Published with npm provenance.

## Why

Your agent writes the code, and it also reads configuration out of your working
tree and executes it. `.claude/settings.json`, `.vscode/tasks.json`,
`.cursor/hooks.json`, `.devcontainer/devcontainer.json`. Those files are not in
your lockfile, so no software composition analysis tool reads them. They are not
application source, so no SAST rule parses them. They are checked in, so review
treats them like a `.prettierrc`.

That is the gap the August 2026 npm worm used for persistence: it wrote a
session hook into `.claude/settings.json` and a task into `.vscode/tasks.json`,
then committed them everywhere it could reach. Pulling the poisoned package
versions did not remove the foothold, because nothing was looking at it.

owlwarden covers both surfaces in one pass, with one exit code.

## What it finds

25 rules across nine of the ten OWASP Top 10 (2021) categories, plus an
agent-surface family mapped to OWASP ASI 2026: SQL injection, SSRF, open
redirect, hardcoded secrets, weak crypto, permissive CORS, insecure cookies,
missing security headers, leaked stack traces, sensitive data in logs, unpinned
dependencies and actions, known-vulnerable dependencies via OSV, install-time
lifecycle scripts, auto-executing agent hooks, wildcard tool permissions,
unpinned MCP servers, hidden text in instruction files, and more.

Every rule carries a fix written for your framework — or, on the agent surface,
for your host. A rule cannot ship without one: the build fails on an empty cell.

`owlwarden coverage` prints what it does **not** look at, next to what it does.

Full catalogue: https://github.com/suthat/owlwarden/blob/main/RULES.md

## Usage

```bash
owlwarden scan                      # zero-config
owlwarden scan --since origin/main  # only what changed
owlwarden scan --staged             # pre-commit
owlwarden vet ./cloned-repo         # check a repo before you open it
owlwarden gate --host claude-code   # agent hook entry point
owlwarden verify --patch fix.diff   # did that fix actually fix it?
owlwarden mcp                       # stdio MCP server
owlwarden init --claude-code        # hooks, MCP entry, CI workflow
owlwarden coverage
owlwarden explain sql-injection
```

Output formats: `pretty`, `json`, `sarif`, `junit`, `md`, `agent`. Stackable in
one run.

Exit codes: `0` clean · `1` findings at or above `--fail-on` · `2` could not run.

## In the agent loop

An MCP tool is called when the model decides to call it. A hook runs every time.
owlwarden ships both and says which is which.

```bash
owlwarden init --claude-code   # hooks + MCP entry
owlwarden init --cursor
owlwarden init --generic       # a shell wrapper, for any host
```

`init` never writes a `SessionStart` hook. Repository config that runs when you
open the folder is what `agent-hook-autoexec` reports at high severity, and a
tool that ships that rule while generating the shape would have `owlwarden scan`
reporting its own output.

`--format agent` puts the report on a token budget — rule id, line, patch,
nothing else — so the deterministic checks stop costing frontier tokens.

Guide: https://github.com/suthat/owlwarden/blob/main/docs/explanation/agent-integration.md

## In CI

```yaml
- uses: suthat/owlwarden/action@v1
  with:
    fail-on: medium
    format: sarif
```

Guide: https://github.com/suthat/owlwarden/blob/main/docs/how-to/ci.md

## Config

Optional.

```ts
import { defineConfig } from "@dointhai/owlwarden-config";

export default defineConfig({
  preset: "owasp-top10",
  failOn: "medium",
  minConfidence: "likely",
});
```

Flags win over the file. Config is never loaded from above the scan root — and
in `vet` and `gate`, the scanned project cannot loosen the posture at all, only
tighten it.

## Limits

Stated because a clean report you cannot calibrate is worse than no report.

- Not all of OWASP. A04 (Insecure Design) is out of reach from source, on
  purpose — no parser finds a design flaw.
- Origin tracking is one hop, not a full taint engine. Injection-shaped rules
  cap their confidence accordingly instead of guessing.
- `confirmed` means confirmed: reachable only when a static finding is
  corroborated against a running target. Nothing else in the tool uses the word.
- Twelve frameworks get tailored fixes; everything else gets a generic scan.
- Agent-config rules cap at `likely` and carry a `runtime_scope`, so a hook in a
  tutorial is not reported like a hook in your settings.
- Active probes require `--target` and `--allow-active`. Staging only.

## Links

- Docs: https://suthat.github.io/owlwarden/
- Repository: https://github.com/suthat/owlwarden
- Rules: https://github.com/suthat/owlwarden/blob/main/RULES.md
- Security policy: https://github.com/suthat/owlwarden/blob/main/SECURITY.md
- Changelog: https://github.com/suthat/owlwarden/blob/main/CHANGELOG.md

## Licence

MIT OR Apache-2.0, at your option.
