# owlwarden

Scanner for common security mistakes in Node web apps. Install from npm, run
it on your repo, get the line and a fix. The engine is Rust; the CLI is what
you type.

It does not send your code anywhere. No account, no telemetry, no “phone home”.
Offline unless you pass `--target`.

```bash
npx owlwarden scan
```

**v0.1.0** (plus unreleased work on more frameworks). Twelve rules covering
nine of the OWASP Top 10. First-class fixes for Next.js, Nuxt, NestJS, Express,
Fastify, Hono, Koa, Hapi, Sails.js, Astro, Remix, and Gatsby. Run
`owlwarden coverage` to see what it still does not look for.

---

## What you get

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

The fix is in the finding. You should not need another tab — useful for people
and for agents that only see the terminal.

## Install

```bash
npm i -D owlwarden
npx owlwarden scan
```

Needs Node 20+. Prebuilt native addon for macOS, Linux, and Windows — no
compiler, no download in `postinstall`.

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

`pnpm check` is the full gate (fmt, clippy, tests, typecheck, eslint).

## Usage

```bash
owlwarden scan
owlwarden scan ./apps/api
owlwarden scan --preset owasp-top10
owlwarden scan --ci
owlwarden scan --fail-on medium
owlwarden scan --baseline .owlwarden-baseline.json
owlwarden scan --write-baseline .owlwarden-baseline.json
owlwarden scan --target http://127.0.0.1:3000/
owlwarden watch
owlwarden rules
owlwarden coverage
owlwarden explain stack-trace-leak
```

`--target` is optional and only probes what you allow — see
[docs/how-to/dynamic.md](docs/how-to/dynamic.md).

Exit codes: `0` clean · `1` findings at or above `--fail-on` · `2` could not run.

## Config

Optional. Defaults are fine for most repos. When you need more:

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

- No network without `--target`. With `--target`, scope is deny-by-default.
- Reads stay inside the project root; symlinks out are refused; `node_modules`
  and `.gitignore` are respected; size caps apply.
- No telemetry.
- `#![forbid(unsafe_code)]` in library crates.

Details: [SECURITY.md](SECURITY.md).

## What it does not do yet

- Not all of OWASP. `coverage` lists the gaps. A04 is out of reach on purpose.
- Dynamic checks are passive and opt-in. No active (state-changing) probes yet.
- Other stacks get a generic scan; the twelve named frameworks get tailored
  fixes. Matrix is locked in CI.
- Origin tracking is one hop, not a full taint engine
  ([ADR 0012](docs/adr/0012-request-origin-not-taint.md)).
- Plugins and `owlwarden mcp` are next on the roadmap. Today agents use
  `--format json` and `explain`.

[ROADMAP.md](ROADMAP.md) has the order.

## Agents / editor loops

```bash
owlwarden scan --format json
```

Schemas live in `@dointhai/owlwarden-sdk` and are checked against the Rust
output in CI. Each finding carries a fix and a confidence level so a bot is
less likely to “fix” noise.

More: [docs/explanation/agent-integration.md](docs/explanation/agent-integration.md).

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
