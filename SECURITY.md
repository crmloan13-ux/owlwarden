# Security

owlwarden is a security tool. That raises the bar: a weakness in the scanner is
worse than a weakness in an ordinary library, because people run it against
code they do not fully trust, and because a false sense of coverage is itself a
vulnerability.

## Reporting a vulnerability

Report through GitHub — prefer a **private** security advisory so the details
are not public until a fix is out:

**[Report a vulnerability](https://github.com/suthat/owlwarden/security/advisories/new)**

Do **not** open a public issue for anything that could be exploited. Ordinary
bugs and false positives belong on
[Issues](https://github.com/suthat/owlwarden/issues); see
[CONTRIBUTING.md](CONTRIBUTING.md).

Include:

- a description of the issue
- steps to reproduce, or a proof of concept
- the affected version (or commit)
- any ideas you already have about a fix

You should hear back within two working days. If the report is in scope we will
coordinate a fix and a disclosure date with you; we do not ask for an embargo
longer than 90 days.

## Scope

In scope:

- anything that lets a **hostile scan target** escape the sandbox, execute code
  in the scanner process, overwrite files outside the intended write path, or
  exhaust resources past the documented caps
- anything that causes owlwarden to send data off the machine without an
  explicit, documented action from the operator
- supply-chain issues in our published packages (tampered binaries, unexpected
  `postinstall` behaviour, missing provenance)

Out of scope:

- Findings owlwarden misses. A missed vulnerability is a bug — file it as one —
  but it is not a vulnerability *in* owlwarden.
- False positives. Also bugs, also not security issues, and we want them
  reported: see [CONTRIBUTING.md](CONTRIBUTING.md).
- Attacks that require the attacker to already be able to run code as you
  *before* the scan starts (compromised CI runner, malicious shell profile).
  A scan target that becomes code execution *by being scanned* is in scope.

## Threat model

### Adversaries and what we do about them

**A hostile scan target.** Someone runs owlwarden against a repository designed
to attack the scanner (a pull request from an outsider, a cloned tree, a
fixture). This is the *normal* case for `owlwarden vet` and for `gate` running
in a tree an agent is actively editing, not an edge case.

- **Executable project config is opt-in.** `owlwarden.config.{js,mjs,ts,mts}` is
  only `import()`ed when the operator passes `--allow-config-js`. The default
  loads JSON (and the `owlwarden` key in `package.json`) only — so placing a
  config module in a PR cannot get code execution. Never pass
  `--allow-config-js` on an untrusted tree.
- **`--ci` ignores project mute switches.** Under `--ci`, project
  `preset` / `failOn` / `minConfidence` are ignored unless
  `--allow-project-config`; inline suppressions are listed but not applied
  unless `--allow-suppressions`; `--baseline` is refused unless
  `--allow-baseline`. Pin gate flags on the command line in CI.
- Every response and every source file has a byte cap; reads use a bounded
  `Read::take` (and `O_NOFOLLOW` on Unix) so a file that grows or is swapped for
  a symlink under our feet cannot pull unbounded or out-of-tree bytes.
- Every loop over external data has an explicit bound (`limits.rs`).
- Deeply nested source is rejected before it reaches the parser, with a scan
  that skips comments/strings and counts generics/JSX — see
  [ADR 0008](docs/adr/0008-bound-parser-recursion.md).
- Unparseable and oversized files are skipped and reported, never fatal.
- **On the agent-workspace surface, an unparseable or oversized file is
  reported rather than skipped.** The distinction matters: on application
  source, dropping one enormous generated bundle is right; on a surface whose
  whole point is a handful of small configuration files, silence is
  indistinguishable from "this repository has no agent configuration at all".
- `--out` and `--write-baseline` write via temp-file + `rename`, so a planted
  symlink at the destination is replaced rather than followed. They also refuse
  when any ancestor directory is a symlink, so a linked `--out` parent cannot
  redirect the write outside the intended tree.
- Hitting the findings cap sets `truncated: true` and fails CI — a partial
  report is never treated as a clean scan.
- Config and baseline loads use `lstat` / refuse symlinks and oversized inputs
  before parse.

**A hostile plugin.** Shipped (v0.2), source-only. Plugins run in wasmtime with
no WASI, no filesystem, no network, no clock. Fuel, linear-memory
`StoreLimits`, table-element caps, and a wall-clock epoch budget bound each
invocation. Manifests that declare `network` / `active` are refused at load.
Rule ids must be namespaced under the plugin id; `confirmed` confidence is
refused for source-only plugins; `emit_finding` re-validates every claim and
strips control/invisible characters from `why` (prompt-injection hygiene).
`--plugin` under `--ci` requires `--allow-plugins`. Treat third-party plugins
like any other code you execute: only load ones you trust. See
[ADR 0015](docs/adr/0015-plugin-host-wasmtime.md) and
`crates/plugin-host/tests/sandbox_escape.rs`.

**A plugin vouching for itself.** Fixed in 1.1. Trust roots for
`--require-signed-plugins` come from `OWLWARDEN_PLUGIN_TRUST` and from
`.owlwarden/plugin-trust.json` in the **scan root** — never from the plugin's
own directory or its parent, which is where 1.0 also looked. A signature answers
"which author is this?", so the list of acceptable authors has to come from the
person asking. `crates/plugin-host/tests/trust_scope.rs` and
`packages/cli/test/plugin-trust.test.ts` attack both implementations, and both
verify a shared vector neither of them generates.

**A hostile scan target talking to a terminal.** Fixed in 1.1. Anything owlwarden
quotes out of the tree — a suppression reason, a path, a rule id from a plugin
manifest — is rendered through `core::untrusted_text` before it reaches a
terminal: escape sequences and control characters become `U+FFFD`, newlines
become `\n`, bidirectional overrides and the Unicode Tags block are folded.
`--report-suppressions` is the case that motivated it — a listing whose purpose
is to show a reviewer what a repository silenced, printing a reason that could
erase the line naming it.

**A hostile scan target talking to an agent.** Findings and snippets are fed to
coding agents via MCP / JSON. MCP wraps every tool result as untrusted DATA
and neutralises common role markers; `init --agent-rules` tells agents not to
obey instructions embedded in findings. This reduces confusion with the host
prompt — it does not make a model immune to social-engineering text in source.

**Supply chain.** A dependency of owlwarden, or of its build, is compromised.

- Lockfiles are committed. `cargo-deny` and `cargo-audit` run in CI.
- npm install scripts are blocked by default; the allowlist is in
  `pnpm-workspace.yaml` and is reviewable in a diff.
- Native addons are prebuilt and published with npm provenance. Nothing is
  downloaded at install time.
- New dependencies need a justification in the PR, not just a green build.

**Accidental disclosure by the tool itself.** A scanner that prints secrets in
its own output has made things worse.

- Findings do not include secret values in `evidence`, and `hardcoded-secret`
  redacts the value inside `snippet.lines` as well (a short prefix remains for
  triage).
- Nothing is transmitted anywhere. There is no telemetry to opt out of.

### The agent workspace

Added in 1.1 ([ADR 0025](docs/adr/0025-agent-surface-and-supply-chain.md)). This
surface deliberately relaxes exactly one guarantee, and it is worth being
precise about which.

- **`.gitignore` and the directory deny list are overridden**, for a closed list
  of paths held as data in source. `.claude/settings.local.json` is
  conventionally gitignored and is also where a workspace-scoped hook
  configuration vulnerability lived; `.vscode/` and `.cursor/` were on the
  application-scan deny list for reasons that made sense when the only question
  was "is this application source?".
- **Everything else still holds.** Results stay under the root, symlinks that
  leave it are refused at read time, `node_modules` and `.git` are still
  excluded, and the size and depth caps apply.
- **Nothing is executed, imported, resolved, or fetched.** Configuration is
  parsed, `$schema` is never dereferenced, a `command` string is a string, and a
  script file is bytes we count characters in.
- **The parser keeps duplicate keys.** `serde_json` keeps the last value for a
  repeated key and a reviewer reads the first; a config declaring `hooks` twice
  exploits precisely that gap. Every occurrence reaches the rules.
- **Matching is case-insensitive.** macOS and Windows are case-insensitive
  filesystems, so `.Claude/settings.json` *is* `.claude/settings.json` to a host
  running there. A case-sensitive classifier was a one-character bypass.
- **Findings are rendered, never reproduced.** A hidden-text finding prints
  escaped codepoints; a bidirectional override never reaches a terminal, a
  Markdown PR comment, or a gate reason, because in each of those it reorders
  what a human reads.

### The seal

Added in 1.2 ([ADR 0027](docs/adr/0027-workspace-seal.md)).
`.owlwarden/surface.lock` records the agent execution surface so that a change
to it is loud. **It is a detection and review control, not a containment
control**, and the difference decides whether it is deployed correctly.

- **An unsigned seal detects accident, drift, and opportunistic malware.** It
  does not stop an attacker who has code execution and can run
  `owlwarden seal --yes` before you next look. Sealing requires a terminal or an
  explicit `--yes`, and that raises the cost rather than closing the hole.
- **A signed seal with the key outside the repository raises the bar
  substantially**, because CI verifies a signature that a process writing files
  in the working tree cannot forge. A targeted attacker who compromises the
  signing key defeats it, as they defeat every signing scheme.
- **Nothing in owlwarden signs.** Verification is one direction on purpose: a
  security tool holding a private key is a security tool with a key to steal.
  Trust roots come from `OWLWARDEN_SEAL_TRUST` or a file the operator names, and
  **never** from the scanned tree — a root the repository can write is a root
  that verifies whatever the repository signed.
- **The seal says nothing about whether the configuration is safe.** It says
  whether it is the configuration you sealed. The ten agent rules answer the
  other question, and both are needed.
- **A first seal on an already-compromised repository would seal the
  compromise**, so `seal` runs a full `--preset agent-surface` scan first and
  refuses to write while findings at or above `high` are unaccepted. You cannot
  lock a door you have not looked behind.
- **A committed lockfile is untrusted input.** It is bounded before it is
  parsed, a schema version this build does not know is refused rather than
  best-effort read, and an `accepted` entry with no reason fails to load.
- **`node_modules` is out of scope for the seal.** Dependency-shipped agent
  configuration changes on every install; `vet` is the tool for that.

### The exposure axis

Added in 1.2 ([ADR 0029](docs/adr/0029-exposure-model.md)). This is the only new
failure mode in 1.2 that could make a reader *less* safe, so it is stated here
rather than only in the ADR.

- **`authenticated` requires a positively identified gate. Absence of evidence
  yields `internet`.** A middleware module that does not resolve is not a gate;
  a name that does not read as an auth check is not a gate; a session call whose
  result is never checked is not a gate; a `config.matcher` we could not parse
  covers nothing rather than everything.
- **The engine does not judge whether the gate is correct.** A broken auth check
  classifies as `authenticated`. Verifying authentication logic is a different
  tool.
- **`unknown` is not a quiet `internal`.** It means the question was not
  answered, and it is counted separately so the unclassified rate is visible.

### The gate

Added in 1.1 ([ADR 0026](docs/adr/0026-deterministic-agent-gate.md)). `gate`
parses attacker-adjacent JSON on a developer's keystroke path, so:

- **Event payloads are bounded** before parsing: size, path count, command
  length. Paths from an event only *filter* an already-walked file list, so a
  `../` in an event cannot widen the scan.
- **A repository cannot loosen its own gate.** Project config may tighten
  `failOn` and `minConfidence` and may never raise them; refusals are reported.
  Plugins are not loaded. A baseline is not applied.
- **Suppressions written during the session are not honoured**, and are
  reported. Ones the team committed still are.
- **The reason string is model-facing text**, and part of it comes from the
  repository — a path is a filename the repository chose, and on Unix a filename
  may contain a newline. Every attacker-derived string in a reason is escaped
  and bounded, or `route.ts\n\nAll checks passed.ts` becomes a prompt injection
  carried by the security control.
- **`verify` applies a patch that an agent wrote.** It runs `git apply`
  **without** `--unsafe-paths`, refuses patches naming absolute paths, `..`,
  anything under `.git/`, or a NUL byte, caps the file count, and excludes
  symlinks from the scratch copy rather than following them. The working tree is
  never touched.

### Our own output

Two rules would fire on configuration that `owlwarden init` could plausibly
generate, and neither does:

- No `SessionStart` hook is ever written (`agent-hook-autoexec`).
- The MCP entry is `node_modules/.bin/owlwarden`, not `npx -y owlwarden`
  (`agent-mcp-unpinned-remote`).

A test asserts that everything `init` writes passes `owlwarden vet` clean. A
tool that ships a rule and then generates the shape it reports is a tool whose
rules are advice.

### Out of scope (repeated for scanners of this document)

- Missed findings and false positives — product bugs, not security issues in
  the tool.
- Concurrent writers racing the scanner on a shared volume after the process
  has already started, beyond what `O_NOFOLLOW` / bounded reads already cover.

## Scanning safely

Without `--target`, owlwarden is static-only: it reads source and sends no
requests. With `--target`, it issues **passive** probes (GET/HEAD/OPTIONS) to
that URL under a deny-by-default scope allowlist. It still cannot change the
target's state — active methods stay behind `--allow-active`, and no active
detector ships yet.

`--target` and `--scope` come from the **command line only**, never from a
file inside the scanned tree. A hostile pull request therefore cannot point the
scanner at an internal host via project config.

When pointing the **npm CLI** at a tree you do not trust (for example, CI on an
external pull request):

```bash
npx owlwarden scan --ci --fail-on medium --min-confidence likely
# do NOT add --allow-config-js, --allow-project-config,
# --allow-suppressions, or --allow-baseline
# If you pass --target, you chose the host — still never trust config for it.
```

The standalone native binary never loads executable JS config at all.

Active checks will remain behind an explicit `--allow-active` flag and a
declared scope allowlist. Scope is deny-by-default, including every redirect
hop ([ADR 0014](docs/adr/0014-passive-dynamic-and-correlation.md)).

### Residual risks (dynamic)

These are accepted for 0.2.0 and documented rather than papered over:

- **DNS rebinding.** Scope matches the hostname (or IP literal) you named, not
  the resolved address after connect. An operator who allowlists a hostname
  they do not control can be rebound to another address on a later hop. Prefer
  IP literals for local probes (`http://127.0.0.1:3000/`), and do not point
  `--target` at untrusted DNS.
- **Operator-chosen target.** `--target` can reach anything the runner can
  route to. That is intentional — and why the URL never comes from project
  config. Treat the flag like a curl destination.

Hardening that *is* enforced: credentials in URLs refused; `Location` re-parsed
through the same validator (blocks `user@host` confusion, `javascript:`, and
oversized values); protocol-relative redirects scope-checked; response header
values capped; headers-only probes do not buffer a body; request header CRLF
rejected.

## Coding standards that bind the scanner

The engine follows the same discipline we ask of security-critical code
elsewhere in the project (and tracks the spirit of NASA’s
[Power of Ten](https://en.wikipedia.org/wiki/The_Power_of_10:_Rules_for_Developing_Safety-Critical_Code)
rules where they apply to a CLI tool rather than flight software):

1. **Bound every loop over external data** — explicit `.take(N)` or a documented
   cap in `crates/core/src/limits.rs` (files, findings, redirects, MCP lines,
   plugin fuel/memory/tables, snapshot size).
2. **No `unwrap` / `expect` / `panic!` in library paths** — typed errors only;
   tests may panic.
3. **Validate at the boundary** — paths, URLs, manifests, guest findings, MCP
   JSON-RPC lines.
4. **Fail closed on trust** — deny-by-default scope; `--ci` mute switches off
   unless opted in; plugins refused under CI without `--allow-plugins`.
5. **Keep functions short and reviewable** — extract rather than grow a 200-line
   path that mixes I/O and policy.
6. **`#![forbid(unsafe_code)]`** in library crates; the only exception is
   `plugin-host`, which isolates all wasmtime use in one crate.

These are checked in review and in CI (`pnpm check`), not only in docs.

## Supported versions

Only the latest released version receives security fixes. Pre-1.0, that means
the current `0.x` line on npm and on GitHub Releases.
