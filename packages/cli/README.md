# owlwarden

Security review for code still in motion.

Owlwarden scans Node web applications and returns the vulnerable line, why it
matters, a fix written for the framework it found, and a confidence level you
can act on. The Rust engine runs locally behind an npm CLI. No telemetry, no
account, and no source upload.

```bash
npx owlwarden scan
```

**Version 0.3.0** ships thirteen rules (including opt-in
`known-vulnerable-dependency` via `--osv`), Safe `--fix`, an `--allow-active`
scaffold, first-class remediation for twelve Node frameworks, a read-only MCP
server, passive opt-in runtime confirmation, and sandboxed source-only WASM
plugins.

[Website](https://suthat.github.io/owlwarden/) ·
[Rule catalogue](https://github.com/suthat/owlwarden/blob/main/RULES.md) ·
[Documentation](https://github.com/suthat/owlwarden/blob/main/docs/README.md) ·
[Source](https://github.com/suthat/owlwarden)

## Why Owlwarden

Most security reports stop at a category name. Owlwarden is built to finish the
thought.

- **The fix is part of the finding.** Source findings include the location, a
  focused code frame, the impact, references, and remediation written for the
  detected framework. You should not need another browser tab to understand the
  result.
- **Confidence and severity are separate.** `high` describes the impact if a
  finding is real. `confirmed`, `likely`, and `possible` describe how strong the
  evidence is. Static analysis cannot claim `confirmed`; runtime evidence has
  to agree with the source.
- **False positives are treated as product failures.** Shared framework
  profiles and request-origin analysis keep rules consistent. Clean twins in
  the fixture corpus must remain silent across every supported framework.
- **Local is the default, not a privacy setting.** A normal scan reads the
  project and makes no network requests. Nothing leaves your machine. No
  telemetry. Runtime probing only begins when you explicitly pass `--target`.
- **People and tools receive the same truth.** The terminal reporter, JSON
  output, TypeScript SDK, and MCP tools all use one finding model. Cross-language
  golden tests keep the Rust output and zod schemas aligned.
- **Fast enough for the edit loop.** The engine is Rust; the interface is npm.
  Prebuilt native packages mean users do not need a Rust compiler or a
  postinstall binary fetch.

Owlwarden is a repeatable security floor. Authentication, authorization,
payments, personal data, and product design still deserve deeper human and
AI-assisted review.

## One finding, the whole answer

```text
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
                    versions, and internal call structure.
 ⓘ  ref             OWASP A05:2021 · CWE-209
```

The human report and `--format json` are two renderings of the same finding.
Agents do not receive a simplified second version with different claims.

## What it catches

The catalogue has thirteen rules mapped across nine OWASP Top 10 (2021)
categories. Zero-config stays offline; pass `--osv` for lockfile CVE lookup.

| Area | Rules |
|---|---|
| Request and data flow | `sql-injection`, `ssrf`, `open-redirect` |
| Secrets and cryptography | `hardcoded-secret`, `weak-crypto` |
| Browser and response boundaries | `cors-permissive`, `insecure-cookie`, `security-headers-missing`, `stack-trace-leak` |
| Supply chain and observability | `unpinned-dependency`, `known-vulnerable-dependency` (needs `--osv`), `ci-unpinned-action`, `sensitive-data-logged` |

```bash
owlwarden rules                 # the compiled rule catalogue
owlwarden explain ssrf          # rationale and every framework-specific fix
owlwarden coverage              # covered categories and published gaps
```

Rule IDs are permanent because they appear in suppressions, baselines, CI
configuration, and agent rules files. The complete catalogue—including severity,
confidence ceilings, OWASP/CWE mappings, and remediation—is published in
[RULES.md](https://github.com/suthat/owlwarden/blob/main/RULES.md).

## Coding agents and MCP

**Save tokens first. Spend frontier models on the hard parts.** Baseline
security checks should not consume model tokens on every edit. Run them
locally, deterministically, and cheaply — then keep a frontier model for
architecture, auth boundaries, payments, personal data, and the judgments a
parser cannot make.

```bash
npx owlwarden mcp
```

Running that command in a normal terminal looks quiet on purpose: the process
speaks MCP over stdio and waits for a host. On a TTY it prints a short how-to
on stderr (ready line under a host). Silence means “waiting,” not “hung.”

The stdio MCP server exposes four tools:

| Tool | Purpose |
|---|---|
| `scan_project` | Scan the workspace and return typed JSON |
| `scan_file` | Run the project scan and filter it to one edited file |
| `explain_rule` | Return the full rationale and all framework fixes for a rule |
| `list_rules` | Return the catalogue compiled into the installed engine |

A typical MCP host entry looks like this:

```json
{
  "mcpServers": {
    "owlwarden": {
      "command": "npx",
      "args": ["owlwarden", "mcp", "."]
    }
  }
}
```

Host configuration formats vary, but the command is ordinary stdio. The MCP
surface is **static-only, read-only**, and workspace-scoped: it cannot use
`--target`, trigger active probes, or write a fix. Tool results are wrapped as
untrusted evidence and common prompt-role markers are neutralised before scan
or plugin prose reaches the model.

Generate a short project-local rules file from the installed catalogue:

```bash
owlwarden init --agent-rules
# writes .owlwarden/agent-rules.md
```

See the full
[agent integration guide](https://github.com/suthat/owlwarden/blob/main/docs/explanation/agent-integration.md).

## Framework support

Every offline catalogue rule carries specific remediation for every framework
below. A release test fails if any cell in that **12 rules × 12 frameworks**
fixture matrix is missing. The opt-in OSV rule
(`known-vulnerable-dependency`) is outside that offline matrix — it has
remediation for all twelve frameworks and is covered by
`fixtures/vulnerable/osv-demo/` plus a clean twin.

| | | | |
|---|---|---|---|
| Next.js | Nuxt | NestJS | Express |
| Fastify | Hono | Koa | Hapi |
| Sails.js | Astro | Remix | Gatsby |

Owlwarden understands each framework's request origins, response sinks, cookie
setters, CORS helpers, route registration, and configuration conventions.
Unrecognised Node stacks still receive the generic rules that do not require
framework context; they do not receive invented framework-specific advice.

## Install

```bash
npm install --save-dev owlwarden
npx owlwarden scan
```

Node.js 20 or later is required. Prebuilt packages ship for:

- macOS: Intel and Apple Silicon
- Linux: x64 and arm64 on glibc; x64 on musl/Alpine
- Windows: x64 and arm64

Add a repeatable local command:

```json
{
  "scripts": {
    "security-check": "owlwarden scan"
  }
}
```

## Commands

| Command | What it does |
|---|---|
| `owlwarden scan [PATH]` | Run the zero-config static scan |
| `owlwarden watch [PATH]` | Re-scan when source changes; always static-only |
| `owlwarden mcp [PATH]` | Start the read-only stdio MCP server |
| `owlwarden rules` | Print the compiled rule catalogue |
| `owlwarden coverage` | Show OWASP reach and explicit gaps |
| `owlwarden explain <RULE_ID>` | Print a rule's rationale and fixes offline |
| `owlwarden init --agent-rules` | Write agent guidance from the compiled catalogue |
| `owlwarden plugin scaffold <NAME>` | Create a source-only WASM plugin stub and manifest |

Common scans:

```bash
owlwarden scan ./apps/api
owlwarden scan --preset owasp-top10
owlwarden scan --format json
owlwarden scan --fail-on medium --min-confidence likely
owlwarden scan --out owlwarden-report.json
```

Presets: `quick` is the high-signal default, `owasp-top10` selects mapped rules,
and `deep` enables every compiled rule, including noisier heuristics.

## CI without greenwashing

```bash
npx owlwarden scan --ci --fail-on medium --min-confidence likely
```

`--ci` emits quiet JSON and also refuses controls that an untrusted pull request
could plant in the scanned tree. Unless the workflow explicitly opts in, it
ignores project gate settings, does not apply inline suppressions, refuses a
baseline, and refuses plugins.

Severity and confidence remain separate in CI. A high-impact heuristic at
`possible` confidence remains visible but does not fail CI on its own. A
truncated report always fails; partial evidence is never presented as a clean
scan.

| Exit code | Meaning |
|---|---|
| `0` | Nothing at or above the configured gate |
| `1` | Findings reached the gate, or the report was truncated |
| `2` | The scan could not run |

For a complete workflow, artifact handling, and guidance for external pull
requests, see
[Running Owlwarden in CI](https://github.com/suthat/owlwarden/blob/main/docs/how-to/ci.md).

## Configuration

Zero configuration is fine. When a project needs shared defaults, use JSON:

```json
{
  "preset": "owasp-top10",
  "failOn": "medium",
  "minConfidence": "likely"
}
```

Save it as `owlwarden.config.json`, or place the same object under an
`owlwarden` key in `package.json`. Command-line flags win.

JavaScript and TypeScript configs are supported, but loading executable project
configuration requires `--allow-config-js`. Do not enable it when scanning an
untrusted tree. `--target` and `--scope` are never loaded from project config.

## Adopting it in an existing codebase

A security gate is useful when it stops new debt, even if old debt cannot be
cleared in one pull request.

Create a baseline once on a trusted tree:

```bash
owlwarden scan --write-baseline .owlwarden-baseline.json
owlwarden scan --baseline .owlwarden-baseline.json
```

In CI, baseline use requires an explicit `--allow-baseline`; that prevents a
hostile pull request from checking in its own green result.

Suppress one line only when a human owns the reason:

```ts
// owlwarden-disable-next-line stack-trace-leak -- gated by NODE_ENV === 'development'
return NextResponse.json({ error: err.stack })
```

The reason is mandatory. Missing, stale, and active directives can all be
listed with `--report-suppressions`. Details:
[Suppressions and baselines](https://github.com/suthat/owlwarden/blob/main/docs/how-to/suppressions.md).

## Optional runtime confirmation

Most scans stay static and offline. Pass `--osv` to query Google OSV for known
CVEs in lockfile versions
([OSV lookup](https://github.com/suthat/owlwarden/blob/main/docs/how-to/osv.md)).
If a local or staging server is running, you can also compare source with a
passive response:

```bash
npx owlwarden scan --target http://127.0.0.1:3000/
```

The current runtime correlation covers `security-headers-missing`. Owlwarden
sends a passive `HEAD` request, falling back to `GET`, and either confirms the
missing headers, clears a false static gap, or keeps disagreement visible. It
does not crawl the application.

Scope is deny-by-default. With no `--scope`, the allowlist is exactly the target
origin; every redirect is checked again. Target and scope come from the command
line only, so a hostile repository cannot turn a CI scan into a request to an
internal host.

Read [Probe a running app](https://github.com/suthat/owlwarden/blob/main/docs/how-to/dynamic.md)
before pointing a runner at a network target.

## Source-only WASM plugins

Version 0.2.0 can load third-party source rules:

```bash
owlwarden plugin scaffold company-rules
owlwarden scan --plugin ./company-rules
```

Each invocation gets a fresh wasmtime store with fuel, memory, table, finding,
and wall-clock limits. There is no WASI, filesystem, network, or clock. A
manifest that asks for network or active capabilities is refused rather than
silently downgraded. Under `--ci`, plugins require `--allow-plugins`.

Plugins are still code you chose to run. Review their source and provenance.
The authoring walkthrough is in
[Extending Owlwarden](https://github.com/suthat/owlwarden/blob/main/docs/how-to/extend.md#plugins).

## Safety model

- Static scans make no network requests and have No telemetry.
- Reads stay inside the project root. Outbound symlinks are refused;
  `node_modules` and `.gitignore` are respected.
- File sizes, file counts, findings, parser nesting, redirects, MCP lines, and
  plugin resources all have explicit caps.
- Executable project config is opt-in. CI mute switches are off by default.
- Hardcoded credentials are redacted in evidence and source snippets.
- Native packages are prebuilt with npm provenance. Nothing downloads an
  executable in a postinstall script.
- Library crates use `#![forbid(unsafe_code)]`; wasmtime integration is isolated
  in the plugin host.

Read the complete threat model and vulnerability reporting policy in
[SECURITY.md](https://github.com/suthat/owlwarden/blob/main/SECURITY.md).

## Honest limits

- Owlwarden does not prove an application is secure. It publishes both the
  rules it has and the gaps it cannot reach.
- Nine of ten OWASP Top 10 (2021) categories have at least one rule; that is not
  a claim of complete category coverage. **A04:2021 Insecure Design** is out of
  reach from source alone and needs product intent or a threat model.
- Request-origin tracking is one hop and intra-procedural, not a full taint
  engine. A miss lowers confidence rather than hiding a finding.
- Runtime correlation currently covers security headers only. Probes are
  passive and opt-in; no active detector ships.
- Plugins are source-only. MCP is static-only and read-only.
- `--fix` applies only `Safe`, single-line highlight replacements (never on
  `Possible`), requires a clean git tree unless `--allow-dirty`, and re-scans
  afterwards. Most remediations stay `Manual` on purpose.
- `--osv` opts into Google OSV lockfile lookups (name+version only). See
  [docs/how-to/osv.md](https://github.com/suthat/owlwarden/blob/main/docs/how-to/osv.md).
- `--allow-active` opens state-changing HTTP methods under `--target`; no
  first-party detector uses them yet.
- Unrecognised stacks receive generic checks, not tailored framework fixes.

`owlwarden coverage` computes reach from the rules in the engine you actually
installed. The rationale behind the published gaps is in
[Coverage is a map, not a percentage](https://github.com/suthat/owlwarden/blob/main/docs/explanation/coverage.md).

## Licence

MIT OR Apache-2.0, at your option.
