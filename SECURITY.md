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
fixture).

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
