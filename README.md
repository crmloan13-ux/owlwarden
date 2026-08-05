# owlwarden

A keen-eyed security auditor for web apps and APIs. Rust engine, npm install,
passive by default.

```bash
npx owlwarden scan
```

**Status: v0.0.** Nine rules across six of the OWASP Top 10, static analysis
only, with first-class support for Next.js, Nuxt, NestJS, Express, and Fastify.
It works and it is honest about what it does not do yet — run
`owlwarden coverage`, or see [Scope](#what-it-does-not-do-yet).

---

## What it does

owlwarden reads your source, finds a small set of security problems that are
easy to introduce and easy to miss, and shows you where they are and how to fix
them:

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

Every finding carries the fix inline. There is no "see the docs for details":
the reader might be an AI agent with no browser, and even a human should not
have to open a tab to act on a scanner.

## Install

```bash
npm i -D owlwarden          # or pnpm add -D owlwarden
npx owlwarden scan
```

Node 20 or newer. The engine ships as a prebuilt native addon for macOS, Linux,
and Windows — there is no compiler step and no `postinstall` that downloads
anything.

Add it to your project:

```json
{
  "scripts": {
    "security-check": "owlwarden scan"
  }
}
```

### Building from source

Only needed on a platform with no prebuilt addon, or to work on owlwarden
itself. Requires Rust 1.88+, Node 20+, and pnpm.

```bash
git clone https://github.com/suthat/owlwarden
cd owlwarden
pnpm install
pnpm build          # cargo build + napi + tsc
node packages/cli/dist/bin.js scan /path/to/project
```

`pnpm check` runs the whole gate: clippy with warnings denied, `cargo test`,
`tsc --noEmit`, eslint, and the vitest suites.

## Usage

```bash
owlwarden scan                          # zero config
owlwarden scan ./apps/api               # a specific directory
owlwarden scan --preset owasp-top10     # a named rule bundle
owlwarden scan --ci                     # JSON on stdout, no colour, exit code
owlwarden scan --fail-on medium         # only medium and worse fail the build
owlwarden rules                         # what it can find
owlwarden coverage                      # what it cannot find, gaps included
owlwarden explain stack-trace-leak      # the full write-up, offline
```

**Exit codes:** `0` clean · `1` findings at or above `--fail-on` · `2` the scan
could not run. CI can branch on these.

## Configuration

Zero config is the intended way to run it. When you need more, put an
`owlwarden.config.ts` next to your `package.json`:

```ts
import { defineConfig } from "@owlwarden/config";

export default defineConfig({
  preset: "owasp-top10",
  failOn: "medium",
  minConfidence: "likely",
});
```

`.mts`, `.mjs`, `.js`, `.json`, and an `owlwarden` key in `package.json` also
work. Flags beat the config file; the config file beats the defaults. owlwarden
does not look for config outside the directory being scanned.

## Safety

This is a security tool, so it is worth being precise about what it does to your
machine and your systems.

- **It does not touch the network.** v0.0 is static analysis: it reads files and
  parses them. No requests are sent to your app or to us.
- **It stays inside the project.** The file provider is rooted at the directory
  you point it at, resolves symlinks, and refuses anything that escapes. It
  skips `node_modules`, respects `.gitignore`, and caps file size and total
  bytes read.
- **It has no telemetry.** Not off-by-default-but-present — absent.
- **It is bounded.** Every loop over your files has a limit, and a pathological
  input (a 50 MB minified bundle, a file nested 10,000 brackets deep) is skipped
  and reported, not crashed on.

`#![forbid(unsafe_code)]` in every crate. See [SECURITY.md](SECURITY.md) for the
threat model and how to report a vulnerability.

## What it does not do yet

Being clear about this matters more than looking complete.

- **Six of the ten OWASP categories.** `owlwarden coverage` prints the table,
  gaps included, computed from the rules compiled into the binary you have.
  A04 Insecure Design is marked out of reach rather than pending, because no
  parser finds a design flaw —
  [docs/explanation/coverage.md](docs/explanation/coverage.md) explains how to
  read that distinction.
- **Static only.** The dynamic engine — the one that probes a running app and
  raises a finding's confidence to `confirmed` — is designed
  ([ARCHITECTURE.md](ARCHITECTURE.md) §2) and not built.
- **Five frameworks with specific advice.** Next.js, Nuxt, NestJS, Express, and
  Fastify each get remediation written for them; anything else is scanned
  generically, which means less context in the finding rather than fewer
  findings. Adding a sixth is a profile plus a remediation entry per rule —
  [docs/how-to/extend.md](docs/how-to/extend.md).
- **Origin analysis is one hop, not a taint engine.** A value that reaches a
  sink through two locals or a function call is reported at `possible` rather
  than `likely`. Stated in every rule and in
  [ADR 0012](docs/adr/0012-request-origin-not-taint.md), because a scanner that
  overstates its reach is worse than one that admits it.
- **No plugins yet.** The sandbox design is settled; the host is v0.2. The
  extension points the plugins will use are already in place and documented.
- **No `--fix`, no MCP server, no baseline.** All planned, none shipped.

See [ROADMAP.md](ROADMAP.md) for the order.

## Using it from an agent

Machine-readable output is not an afterthought here — when an agent is in the
loop, the agent is the one reading the report and editing the code.

```bash
owlwarden scan --format json
```

`@owlwarden/sdk` ships zod schemas for the report, checked against the Rust
engine on every CI run, so the types cannot drift from what the tool emits. Two
things most tools do not carry travel with each finding: the fix, inline and
complete, and an honest `confidence`.

[docs/explanation/agent-integration.md](docs/explanation/agent-integration.md)
covers the design, including the parts that are not built yet.

## Contributing

The most useful contribution is a false positive. If owlwarden flags correct
code, that is a bug with a higher priority than a missing rule — open an issue
with the smallest snippet that reproduces it.

[CONTRIBUTING.md](CONTRIBUTING.md) has the development setup;
[AGENTS.md](AGENTS.md) is the same ground condensed for AI coding agents.

```bash
pnpm i
pnpm build      # native addon + TypeScript
pnpm check      # fmt, clippy, typecheck, eslint, all tests
```

## Documentation

| | |
|---|---|
| [RULES.md](RULES.md) | What it can find. Generated from the engine. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How it is built, and the constraints. |
| [REPORTERS.md](REPORTERS.md) | What every output format promises, and the exit codes. |
| [docs/](docs/) | How-to guides, explanations, and the decision records. |
| [SECURITY.md](SECURITY.md) | Threat model and how to report a vulnerability. |
| [ROADMAP.md](ROADMAP.md) | What is next, and in what order. |
| [REVIEW.md](REVIEW.md) | The pre-implementation audit, and what it changed. |

## Licence

MIT OR Apache-2.0, at your option.
