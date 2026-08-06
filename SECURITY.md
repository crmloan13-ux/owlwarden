# Security

owlwarden is a security tool. That raises the bar: a weakness in the scanner is
worse than a weakness in an ordinary library, because people run it against
code they do not fully trust, and because a false sense of coverage is itself a
vulnerability.

## Reporting a vulnerability

Email **security@dointhai.com**. Please do not open a public issue for anything
that could be exploited.

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
- **`--ci` ignores project gate knobs.** `preset` / `failOn` / `minConfidence`
  from the scan target are ignored under `--ci` unless
  `--allow-project-config` is set, so a PR cannot silence findings with JSON
  alone. Pin those flags on the command line in CI.
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

**A hostile plugin.** Not yet applicable — the plugin host is v0.2. When it
lands, plugins run in WASM with no ambient authority: no filesystem, no network,
no clock, unless the run grants that capability explicitly.

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

owlwarden v0.0.2 is passive: it reads source and sends no requests. It cannot
change your application's state because it never contacts it.

When pointing the **npm CLI** at a tree you do not trust (for example, CI on an
external pull request):

```bash
npx owlwarden scan --ci --fail-on medium --min-confidence likely
# do NOT add --allow-config-js or --allow-project-config
```

The standalone native binary never loads executable JS config at all.

When the dynamic engine lands, active checks will remain behind an explicit
`--allow-active` flag and a declared scope allowlist, and will be denied by
default. That is enforced today by the `ScopeResolver` in the core, which
denies every target unless configured otherwise.

## Supported versions

Only the latest released version receives security fixes. Pre-1.0, that means
the current `0.x` line on npm and on GitHub Releases.
