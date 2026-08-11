# owlwarden

Local-first security floor for Node web apps — built so coding agents and humans
get the same answer: the line, a fix, and an honest confidence level. Rust
engine, TypeScript CLI on npm. Nothing leaves your machine unless you opt in.

**v0.5.0** — fourteen rules, CI-ready SARIF/JUnit and a first-party GitHub
Action, active CSRF canary (staging + `--allow-active`), offline OSV indexes,
plugin artifact integrity, stackable `--format`, incremental `watch`, read-only
MCP for agents. Site:
[https://suthat.github.io/owlwarden/](https://suthat.github.io/owlwarden/).
See [ROADMAP.md](ROADMAP.md).

```bash
npx owlwarden scan
npx owlwarden mcp    # stdio MCP for Cursor, Claude, and other MCP hosts
```

## Agents and MCP (first-class)

**Save tokens first, then spend a frontier model on the hard parts.** Run the
scanner locally for baseline checks (fast, offline, same rules every time) so
the agent does not burn tokens re-asking “did we leak a stack?” on every edit.
Keep frontier models for architecture, auth, payments, personal data, and
judgments a parser cannot make. Floor first; judgment on top.

Wire it into an agent loop instead of pasting terminal output by hand:

```bash
owlwarden mcp                  # tools: scan_project, scan_file, explain_rule, list_rules
owlwarden scan --format json   # same report shape agents already parse
owlwarden init --agent-rules   # writes .owlwarden/agent-rules.md from the catalogue
```

MCP is read-only and static-only — no live `--target`, no file writes, paths
stay under the workspace. On a TTY, `owlwarden mcp` prints a short how-to on
stderr and then waits; silence means it is waiting for a host, not hung.
Schemas live in `@dointhai/owlwarden-sdk` and are checked against the Rust
output in CI.

More: [docs/explanation/agent-integration.md](docs/explanation/agent-integration.md).

Fourteen rules, nine of the OWASP Top 10 categories. First-class fixes for
Next.js, Nuxt, NestJS, Express, Fastify, Hono, Koa, Hapi, Sails.js, Astro,
Remix, and Gatsby. Gaps are listed by `owlwarden coverage`.

---

## Sample output

```
◉ᴥ◉ 2 files · quick · 0.31s
2 findings (1 high, 1 medium)

────────────────────────────────────────────────────────────────────────
HIGH  likely  Stack trace leaked in error response  A05:2021
────────────────────────────────────────────────────────────────────────
 app/api/users/route.ts:13:16  (GET /api/users)

  11 │   } catch (err) {
  12 │     return NextResponse.json(
  13 │       { error: err.stack },
     │                ~~~~~~~~~ leaks internal stack trace to the client
  14 │       { status: 500 }
  15 │     )

 ↳  fix (Next.js)   Return a generic message; log the error server-side.
                    console.error(err)
                    return NextResponse.json(
                      { error: 'Internal Server Error' },
                      { status: 500 },
                    )
 ↳  why             Stack traces expose absolute file paths, dependency
                    versions, and internal call structure — enough to
                    fingerprint the stack and locate other weaknesses.
 ⓘ  ref             OWASP A05:2021 · CWE-209 · RULES.md#stack-trace-leak
```

The fix is in the finding. You should not need another browser tab. CI and
agents use the same JSON.

## Install

```bash
npm i -D owlwarden
npx owlwarden scan
# or for an MCP-capable editor / agent:
npx owlwarden mcp
```

Node 20+. Prebuilt addon for macOS, Linux, and Windows — no compiler on the
user machine.

```json
{
  "scripts": {
    "security-check": "owlwarden scan"
  }
}
```

### From source

Rust 1.88+, Node 22.13+ (for pnpm; the published CLI still runs on 20), and pnpm.

```bash
git clone https://github.com/suthat/owlwarden
cd owlwarden
pnpm install
pnpm build
node packages/cli/dist/bin.js scan /path/to/project
```

`pnpm check` runs the full gate (fmt, clippy, tests, typecheck, eslint).

## Usage

```bash
owlwarden scan
owlwarden mcp
owlwarden init --agent-rules
owlwarden scan --format json
owlwarden scan ./apps/api
owlwarden scan --preset owasp-top10
owlwarden scan --ci
owlwarden scan --fail-on medium
owlwarden scan --baseline .owlwarden-baseline.json
owlwarden scan --write-baseline .owlwarden-baseline.json
owlwarden scan --target http://127.0.0.1:3000/
owlwarden scan --plugin ./my-plugin
owlwarden watch
owlwarden rules
owlwarden coverage
owlwarden explain stack-trace-leak
owlwarden plugin scaffold my-rules
```

`--target` is optional. It only probes what you allow — see
[docs/how-to/dynamic.md](docs/how-to/dynamic.md).

Exit codes: `0` clean · `1` findings at or above `--fail-on` · `2` could not run.

## Config

Optional. Defaults are fine for most repos.

```ts
import { defineConfig } from "@dointhai/owlwarden-config";

export default defineConfig({
  preset: "owasp-top10",
  failOn: "medium",
  minConfidence: "likely",
});
```

Also: `.mts` / `.mjs` / `.js` / `.json`, or an `owlwarden` key in `package.json`.
Flags win over the file. Config is never loaded from above the scan root.

## Safety

- No network without `--target` or `--osv`. With `--target`, scope is deny-by-default.
- Reads stay inside the project root; outbound symlinks are refused;
  `node_modules` and `.gitignore` are respected; size caps apply.
- No telemetry.
- `#![forbid(unsafe_code)]` in library crates. The WASM host is the exception
  (`plugin-host` / wasmtime).

Details: [SECURITY.md](SECURITY.md).

## Limits (honest ones)

- Not all of OWASP. `coverage` lists the gaps. A04 is out of reach on purpose.
- Dynamic checks are passive by default. Active probes (`csrf-cross-origin-post`)
  need `--target` and `--allow-active` — staging only, not in CI Action.
- Other stacks get a generic scan; the twelve named frameworks get tailored
  fixes. The matrix is locked in CI.
- Origin tracking is one hop, not a full taint engine
  ([ADR 0012](docs/adr/0012-request-origin-not-taint.md)).
- Plugins are source-only WASM. No hosted plugin store. MCP is read-only /
  static. `--fix` applies Safe highlight replacements only (never `Possible`).

[ROADMAP.md](ROADMAP.md) has the order.

## Contributing

Best bug report: a false positive with a small snippet.

[CONTRIBUTING.md](CONTRIBUTING.md) · [AGENTS.md](AGENTS.md) for coding agents.

## Docs

| | |
|---|---|
| [RULES.md](RULES.md) | What it can find |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How it is built |
| [REPORTERS.md](REPORTERS.md) | Output formats and exit codes |
| [docs/](docs/) | How-tos, explanations, ADRs |
| [SECURITY.md](SECURITY.md) | Threat model |
| [ROADMAP.md](ROADMAP.md) | What is next |

## Licence

MIT OR Apache-2.0, at your option.
