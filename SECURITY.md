# Security policy

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/suthat/owlwarden/security/advisories/new)
on this repository. Please do not open a public issue first.

There is deliberately no email address here. A published contact address that
nobody is watching is worse than none at all — a reporter waits, assumes they
have been ignored, and eventually discloses publicly. Private advisories are
routed to the maintainers and cannot be quietly missed.

Include what you would want to receive: what you did, what happened, and what
you expected. A proof of concept helps; a patch is welcome but not expected.

What to expect:

| | |
|---|---|
| Acknowledgement | within 3 working days |
| First assessment | within 10 working days |
| Fix or a plan with dates | within 30 days for High and Critical |
| Credit | in the release notes, unless you would rather not |

We have no bug bounty. We will not threaten you with legal action for research
conducted in good faith against your own systems or against this repository's
fixtures.

## Threat model

owlwarden is a security tool, which means the interesting question is not only
"what does it find" but "what happens when it is pointed at something hostile".

### Assets

1. The developer's machine and the CI runner it executes on.
2. The source code it reads — which must not leave the machine.
3. The scanned target, which must not be damaged by the act of scanning.

### Adversaries and what we do about them

**A hostile scan target.** Someone runs owlwarden against a repository or a
server designed to attack the scanner.

- Every response and every file has a byte cap; decompression has a ratio cap.
- Every loop over external data has an explicit bound.
- Deeply nested source is rejected before it reaches the parser, so a crafted
  file cannot exhaust the stack.
- Unparseable and oversized files are skipped and reported, never fatal.

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

- Findings never include secret values; evidence is truncated code, not data.
- Nothing is transmitted anywhere. There is no telemetry to opt out of.

### Out of scope

- Findings owlwarden misses. A missed vulnerability is a bug — file it as one —
  but it is not a vulnerability *in* owlwarden.
- False positives. Also bugs, also not security issues, and we want them
  reported: see [CONTRIBUTING.md](CONTRIBUTING.md).
- Attacks that require the attacker to already be able to run code as you.

## Scanning safely

owlwarden v0.0 is passive: it reads source and sends no requests. It cannot
change your application's state because it never contacts it.

When the dynamic engine lands, active checks will remain behind an explicit
`--allow-active` flag and a declared scope allowlist, and will be denied by
default. That is not a promise about the future — it is enforced today by the
`ScopeResolver` in the core, which denies every target unless configured
otherwise.
