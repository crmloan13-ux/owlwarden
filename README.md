<div align="center">

# ◉ᴥ◉ owlwarden

**The deterministic security floor for Node code — including the code your agent
just wrote, and the config your agent reads.**

Runs on your machine. No account, no telemetry, no network unless you ask for it.

[![npm](https://img.shields.io/npm/v/owlwarden?color=%23111)](https://www.npmjs.com/package/owlwarden)
[![npm downloads](https://img.shields.io/npm/dm/owlwarden)](https://www.npmjs.com/package/owlwarden)
[![CI](https://github.com/suthat/owlwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/suthat/owlwarden/actions)
[![licence](https://img.shields.io/badge/licence-MIT%20OR%20Apache--2.0-blue)](#licence)
[![provenance](https://img.shields.io/badge/npm-provenance-green)](https://www.npmjs.com/package/owlwarden)

[Docs](https://suthat.github.io/owlwarden/) · [Rules](RULES.md) · [Compare](docs/explanation/compared.md) · [Roadmap](ROADMAP.md)

</div>

---

```bash
npx owlwarden scan          # your app
npx owlwarden vet .         # your agent's config — the part nothing else reads
```

## Why this exists

An agent writes most of the code in a lot of repositories now. Two things
follow, and most tooling has only caught up with the first.

**One.** Generated code is confident and wrong in patterns, not one-offs. A
stack trace returned to the client, a redirect target taken from the caller,
`Math.random()` producing a session id. Fast to write, easy to miss in review,
and identical across a thousand repositories.

**Two — and this is the part with a gap in it.** The agent reads configuration
out of your working tree and executes it. `.claude/settings.json`.
`.vscode/tasks.json`. `.cursor/hooks.json`. `.devcontainer/devcontainer.json`.
`CLAUDE.md`. Your lockfile does not record those files. Your SCA tool does not
read them. Your review process treats them like a `.prettierrc`.

In August 2026 an npm worm used exactly that gap: it planted a session hook in
`.claude/settings.json` and a task in `.vscode/tasks.json`, then committed them
into every repository it could reach. The poisoned package versions were pulled
within hours. The foothold in the config was not, because nothing was looking at
it. Opening the folder was enough to start the payload again.

owlwarden scans both surfaces, in one pass, with one exit code.

## What a finding looks like

```
◉ᴥ◉ 41 files · 3 config · since HEAD · 0.09s
2 findings (2 high)

────────────────────────────────────────────────────────────────────────
HIGH  likely  Stack trace leaked in error response                A05:2021
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

────────────────────────────────────────────────────────────────────────
HIGH  likely  active  Repository config executes on open              ASI05
────────────────────────────────────────────────────────────────────────
 .claude/settings.json:4:24

   3 │   "hooks": {
   4 │     "SessionStart": [{ "command": "node .claude/setup.mjs" }]
     │                                    ~~~~~~~~~~~~~~~~~~~~~~ runs on open
   5 │   }

 ↳  fix (Claude Code)  Remove the SessionStart entry, or move the hook to
                       user-level settings where the repository cannot
                       define it. Platform teams: allowManagedHooksOnly.
 ↳  why                Anyone who clones this repository and opens it runs
                       this command. .claude/setup.mjs is not tracked in git.
 ⓘ  ref                CWE-829 · ASI05 · RULES.md#agent-hook-autoexec
```

The fix is in the finding. You should not need another browser tab. CI, hooks,
and agents read the same JSON.

## How it compares

|  | owlwarden | Cloud SAST (Semgrep, Snyk, Sonar…) | LLM code reviewers | `.claude/`-only scanners |
|---|---|---|---|---|
| Runs offline, no account | **yes** | no | depends | yes |
| Deterministic — same input, same output | **yes** | yes | no | usually |
| Rule breadth | 25 rules, Node web | thousands, many languages | unbounded | config only |
| Fix written for *your* framework | **enforced by CI, per surface** | generic message + link | varies per run | n/a |
| Scans agent + editor config | **yes** | no | no | yes |
| Both surfaces, one exit code | **yes** | no | no | no |
| Telemetry | none, ever | varies | varies | varies |

We are not trying to out-rule Semgrep and will not pretend otherwise. Run both.
owlwarden is the part that runs in the agent loop with no network, states what
it cannot see, and gives you a fix you can paste.

The vendors' own model-based scanners say the same thing about themselves — that
they are non-deterministic and do not replace static analysis. This is the
static analysis they mean.

## Limits, stated up front

Most scanners bury this. It is on the first screen because a clean report you
cannot calibrate is worse than no report.

- **Not all of OWASP.** `owlwarden coverage` prints the gaps next to the
  findings. A04 (Insecure Design) is out of reach from source, on purpose — no
  parser finds a design flaw.
- **Origin tracking is one hop**, not a full taint engine
  ([ADR 0012](docs/adr/0012-request-origin-not-taint.md)). Injection-shaped
  rules cap their confidence accordingly instead of guessing.
- **`Confirmed` means confirmed.** It is reachable only when a static finding is
  corroborated against a running target. Nothing else in the tool uses that word,
  and nothing on the agent surface can reach it at all.
- **Agent-config rules cap at `likely`** and carry a `runtime_scope`, so a hook
  in a tutorial is not reported like a hook in your settings.
- **Twelve frameworks and seven agent hosts get tailored fixes.** Everything else
  gets a generic scan. Both matrices are locked in CI.
- **Dynamic checks are passive by default.** Active probes need `--target` and
  `--allow-active`, staging only, never in the CI Action.
- **Plugins are source-only WASM.** No hosted store. MCP is read-only and static,
  and is not loaded by `gate` or `vet` at all.

## In the agent loop

**A tool the model *may* call is not a control that *always* runs.** owlwarden
ships both, and is clear about which is which.

```bash
owlwarden init --claude-code   # hooks + MCP entry
owlwarden init --cursor        # hooks + MCP entry + rules file
owlwarden init --generic       # a shell wrapper, for any host
```

| surface | when it runs | what it does |
|---|---|---|
| **gate (hooks)** | after every edit, before a shell command, at the turn boundary | blocks, with the rule and the fix as the reason. Runs outside the model, so nothing in the prompt argues with it. |
| **MCP** | when the model asks | `scan_project`, `scan_file`, `explain_rule`, `list_rules`. Read-only, static-only, paths stay under the workspace. |
| **`--format agent`** | either | the report on a token budget: rule, line, patch. No prose. |
| **`verify`** | after a fix | applies a patch to a scratch copy, re-scans, and exits 0 only if the finding is gone *and* nothing new appeared. |

`init` never writes a `SessionStart` hook, and its MCP entry is
`node_modules/.bin/owlwarden` rather than `npx -y`. Those are the two shapes
`agent-hook-autoexec` and `agent-mcp-unpinned-remote` report — a tool that ships
the rules and generates the shapes would have `owlwarden scan` reporting its own
output. A test asserts everything `init` writes passes `owlwarden vet` clean.

Run the deterministic floor locally so the agent stops burning tokens re-asking
*did we leak a stack?* on every edit. Keep the frontier model for architecture,
auth, payments, personal data — the judgements a parser cannot make. Floor
first; judgement on top.

More: [docs/explanation/agent-integration.md](docs/explanation/agent-integration.md).

## Install

```bash
npm i -D owlwarden
npx owlwarden scan
```

Node 20+. Prebuilt native addon for macOS, Linux, and Windows — no compiler on
your machine. Published with npm provenance.

```json
{
  "scripts": {
    "security-check": "owlwarden scan --since origin/main --fail-on medium"
  }
}
```

<details>
<summary>From source</summary>

Rust 1.88+, Node 22.13+ (for pnpm; the published CLI still runs on 20), pnpm.

```bash
git clone https://github.com/suthat/owlwarden
cd owlwarden && pnpm install && pnpm build
node packages/cli/dist/bin.js scan /path/to/project
```

`pnpm check` runs the full gate: fmt, clippy, tests, typecheck, eslint, site,
and the docs contracts.
</details>

## Usage

```bash
owlwarden scan                      # zero-config
owlwarden scan --since origin/main  # only what changed
owlwarden scan --staged             # pre-commit
owlwarden vet ./cloned-repo         # agent config, before you open it
owlwarden gate --host claude-code   # hook entry point
owlwarden verify --patch fix.diff   # did that fix actually fix it?
owlwarden watch
owlwarden coverage                  # what it finds, and what it misses
owlwarden explain stack-trace-leak
owlwarden rules
owlwarden plugin scaffold my-rules

owlwarden scan --format sarif --out owlwarden.sarif
owlwarden scan --format md --out report.md      # PR comments
owlwarden scan --format agent --budget 1500     # for the model
owlwarden scan --preset owasp-top10
owlwarden scan --preset agent-surface
owlwarden scan --baseline .owlwarden-baseline.json
owlwarden scan --osv                            # OSV advisories, opt-in
owlwarden scan --target http://127.0.0.1:3000/  # passive, scoped
```

Exit codes: `0` clean · `1` findings at or above `--fail-on` · `2` could not
run. The contract is canonical in [docs/how-to/ci.md](docs/how-to/ci.md).

## In CI

```yaml
- uses: suthat/owlwarden@v1
  with:
    fail-on: medium
    format: sarif
    since: ${{ github.event.pull_request.base.sha }}
```

SARIF 2.1.0 uploads to code scanning. JUnit for anything that reads it. Markdown
for PR comments.

## Config

Optional. Defaults are fine for most repositories.

```ts
import { defineConfig } from "@dointhai/owlwarden-config";

export default defineConfig({
  preset: "owasp-top10",
  failOn: "medium",
  minConfidence: "likely",
});
```

Also `.mts` / `.mjs` / `.js` / `.json`, or an `owlwarden` key in
`package.json`. Flags win over the file. Config is never loaded from above the
scan root — and in `vet` and `gate`, the scanned project cannot loosen the
posture at all, only tighten it.

## Safety

- No network without `--target` or `--osv`. With `--target`, scope is
  deny-by-default.
- Reads stay inside the project root. Outbound symlinks refused, size caps,
  `node_modules` and `.gitignore` respected — with one documented exception for
  the agent-config path allowlist, which is why `.claude/settings.local.json` is
  not invisible ([ADR 0025](docs/adr/0025-agent-surface-and-supply-chain.md)).
- Agent config is parsed, never executed. `$schema` is never fetched.
- No telemetry. There is no opt-in switch, because there is nothing to switch on.
- `#![forbid(unsafe_code)]` in library crates; the WASM host is the documented
  exception.
- `cargo-deny` blocks the build on advisories and licences. Releases carry npm
  provenance.

Details: [SECURITY.md](SECURITY.md).

## Contributing

The best bug report is a false positive with a small snippet.

[CONTRIBUTING.md](CONTRIBUTING.md) · [AGENTS.md](AGENTS.md) for coding agents ·
[docs/adr/](docs/adr/) for why anything is the way it is.

## Docs

| | |
|---|---|
| [RULES.md](RULES.md) | Every rule, every fix, generated from source |
| [docs/tutorials/](docs/tutorials/) | First scan · agents and hooks |
| [docs/how-to/](docs/how-to/) | CI · plugins · extending to a new framework |
| [docs/reference/](docs/reference/) | CLI · plugin API v1 · error codes |
| [docs/explanation/](docs/explanation/) | Coverage · false positives · agents · compared |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How it is built |
| [SECURITY.md](SECURITY.md) | Threat model |
| [ROADMAP.md](ROADMAP.md) | What is next, and in what order |

## Licence

MIT OR Apache-2.0, at your option.
