# 0027 — A lockfile for the agent execution surface

**Status:** Accepted
**Date:** 2026-08-27
**Related:** [0013](0013-suppressions-and-baseline.md) (reformatting-stable fingerprints), [0021](0021-plugin-artifact-signing.md) (ed25519, trust roots), [0025](0025-agent-surface-and-supply-chain.md) (the surface), [0026](0026-deterministic-agent-gate.md) (the gate that enforces it)

---

## Context

[0025](0025-agent-surface-and-supply-chain.md) established that agent and editor configuration is executable and that nothing else reads it. 1.1 shipped ten rules and `owlwarden vet` against that surface, and both are point-in-time: they answer *is this configuration dangerous right now*.

The attack they were written for is not point-in-time. The August 2026 worm's second infection route worked by *writing* into `.claude/settings.json` and `.vscode/tasks.json` — using stolen credentials to commit them into branches of repositories it never otherwise touched. The dangerous property was not that the configuration was malformed. It was that it appeared, in a file nobody diffs, in a directory reviewers skim, between one session and the next.

A rule catches that only if the injected configuration happens to match a shape we enumerated. Ten rules is a good net and it is a net. A `SessionStart` hook that runs `node ./scripts/warm-cache.mjs` is indistinguishable from a legitimate one by inspection, and both `agent-hook-autoexec` and a human reviewer will treat it as ordinary.

What is *not* ambiguous is that it was not there yesterday.

The Node ecosystem already solved this problem once, for dependencies. `package-lock.json` does not judge whether a package is malicious. It records what was resolved, and it makes a change loud. That is the whole mechanism, and it works because the diff is reviewable even when the content is not.

There is no equivalent for the set of files an agent loads and executes out of the working tree.

### Why a rule cannot do this job

Rules answer *is this shape dangerous*. Integrity answers *is this the same as what we agreed to*. They compose, and neither substitutes:

- A rule with no knowledge of history cannot flag a benign-looking hook that appeared overnight.
- An integrity check with no rules flags every legitimate edit equally and gets muted in a week.

1.1 has the first. 1.2 needs the second, and the two together are what makes the surface reviewable.

### Why the existing baseline is not it

[0013](0013-suppressions-and-baseline.md)'s baseline records *findings* so that a legacy repository can adopt the tool without drowning. It is a suppression mechanism. It is silent about a file that produces no finding, which is precisely the case here.

The fingerprinting work from 0013 is reusable, though, and is the reason this is cheap to build: reformatting-stable digests already exist, and the same idea applied to a parsed config is what stops the lock from churning on every `prettier` run.

---

## Decision

### 1. `.owlwarden/surface.lock`

A committed file recording the agent execution surface by semantic digest.

```jsonc
{
  "schemaVersion": 1,
  "sealedAt": "2026-08-27T09:14:02Z",
  "engine": { "version": "1.2.0", "catalogueDigest": "sha256:9f2c…" },
  "surface": {
    "files": [
      {
        "path": ".claude/settings.json",
        "sha256": "sha256:1a4b…",
        "semantic": "sha256:c771…",
        "tier": "project"
      },
      { "path": "CLAUDE.md", "sha256": "sha256:88de…", "semantic": "sha256:88de…" }
    ],
    "hooks": [
      {
        "host": "claude-code",
        "event": "PostToolUse",
        "matcher": "Edit|Write",
        "commandDigest": "sha256:4e19…",
        "target": "pnpm exec prettier --write"
      }
    ],
    "mcpServers": [
      { "name": "owlwarden", "command": "owlwarden mcp", "pin": "workspace" },
      { "name": "docs", "transport": "stdio", "package": "some-mcp@2.4.1", "pin": "exact" }
    ],
    "permissions": { "allowDigest": "sha256:07bb…", "denyDigest": "sha256:5c30…" },
    "marketplaces": [],
    "instructionFiles": [".claude/agents/reviewer.md", "AGENTS.md"]
  },
  "accepted": [
    { "fingerprint": "…", "rule": "agent-hook-autoexec", "reason": "devcontainer bootstrap, reviewed 2026-08-20" }
  ]
}
```

Design notes that matter:

- **Two digests per file.** `sha256` over the bytes, and `semantic` over the parsed and canonicalised structure. Comparison uses `semantic`; `sha256` is recorded so an investigator can tell a reformat from an edit without re-running anything. For Markdown instruction files the two are the same, because in a file whose whole purpose is to be read by a model, whitespace is content.
- **Hooks, MCP servers, and permissions are extracted, not just hashed.** A file digest tells you *something* changed. A structured record tells you *a `SessionStart` hook was added*, which is the sentence a reviewer needs. This is the difference between a lockfile that gets read and one that gets `--force`d.
- **`accepted` carries reasons, matching the mandatory-reason rule from 0013.** A seal is where you write down that the bootstrap hook is deliberate. An entry with no reason fails to write.
- **`engine.catalogueDigest`** means a seal knows which rule set it was taken under. Verifying a seal written by an older catalogue reports that fact rather than pretending the comparison is clean.

### 2. Commands

```
owlwarden seal                    # write or update; interactive
owlwarden seal --verify           # exit 0 if unchanged, 1 on drift, 2 if it could not run
owlwarden seal --sign             # detached ed25519, reusing 0021's trust roots
owlwarden seal --diff             # show what changed without writing
owlwarden seal --accept <fp> --reason "…"
```

`--verify` prints a diff in the surface's own vocabulary, not a file diff:

```
◉ᴥ◉ surface drift · 2 changes

  + hook          claude-code  SessionStart   node .claude/setup.mjs
                  .claude/settings.json:4  · not present in the seal
                  · .claude/setup.mjs is untracked in git

  ~ mcp server    docs         pin: exact 2.4.1 → npx -y (unpinned)
                  .claude/settings.json:31

  seal taken 2026-08-20 by <key 4e19…>, engine 1.2.0, catalogue 9f2c…
```

### 3. Where it is enforced

| point | behaviour |
|---|---|
| `gate --event session-start` | verify; on drift return `ask` with the diff, or `deny` under `--seal strict` |
| `gate --event config-change` | verify the changed file only; drift written *during a session* is `deny`, always |
| CI (`seal --verify`) | exit 1 on drift; the Action posts the surface diff as a comment and stays silent otherwise |
| `scan` | reports drift as an informational line, never changes the exit code |

The mid-session case is the strict one and should be. Configuration that changes while an agent is running was written by something in the session, and nothing in a normal workflow does that.

### 4. Sealing is never unattended

`owlwarden seal` requires a TTY, or an explicit `--yes`. It is not run by `gate`, not run by `scan`, and `init` does not add it to a hook.

This is the whole defence against the obvious objection — that whatever wrote the drift can also run `seal`. It is a partial defence and §"Limits" says so.

### 5. Signing

Reuses [0021](0021-plugin-artifact-signing.md) unchanged: detached ed25519 signature at `.owlwarden/surface.lock.sig`, local trust roots, `--require-signed-seal` to make an unsigned or badly-signed seal a failure.

The signing key lives outside the repository — a developer's keychain, or a CI secret. That is the property that matters: a process that can write files in the working tree cannot produce a valid signature, so CI's verification is meaningful even when the developer's machine is compromised.

### 6. The seal file is itself in the protected surface

`.owlwarden/surface.lock` and its signature are in the [0025](0025-agent-surface-and-supply-chain.md) path allowlist. Modifying them is therefore a tracked event, and `gate --event config-change` fires on a mid-session rewrite of the seal exactly as it does on a mid-session rewrite of a hook. Per the precedent set by CVE-2026-25725, **creating a protected file that did not previously exist counts as mutation.**

---

## Limits, stated in the document rather than in a footnote

This is a detection and review control. It is not a containment control, and the difference decides whether someone deploys it correctly.

- **An unsigned seal detects accident, drift, and opportunistic malware.** It does not stop an attacker who has code execution and can run `owlwarden seal --yes` before you next look. The TTY requirement raises the cost; it does not close the hole.
- **A signed seal with the key outside the repository raises the bar substantially**, because CI verifies a signature the attacker cannot forge from inside the working tree. A targeted attacker who compromises the signing key defeats it, as they defeat every signing scheme.
- **The seal says nothing about whether the configuration is safe.** It says whether it is the configuration you sealed. `vet` and the ten rules answer the other question, and both are needed.
- **A first seal on an already-compromised repository seals the compromise.** `seal` therefore runs a full `--preset agent-surface` scan first and refuses to write while findings at or above `high` are unaccepted, printing them. You cannot lock a door you have not looked behind.
- **`node_modules` is out of scope for the seal.** Dependency-shipped agent configuration changes on every install and is covered by `vet --deep` instead. Sealing it would produce a file that churns and therefore a file nobody reads.

---

## Alternatives considered

**Rely on git.** The configuration is committed, so `git diff` already shows it. True, and it is what nobody does — the files are small, they sit in a dot-directory alongside editor preferences, and the semantic weight of a line in `settings.json` is invisible in a diff that also contains 400 lines of application change. The value here is not detection of the byte change; it is a check that fails the build and a comment that says *a `SessionStart` hook was added* in words. Also: the worm's whole method was committing to branches, which means the change was in git and passed review anyway.

**Extend the existing baseline to cover files rather than findings.** Conflates two jobs with opposite defaults. A baseline exists to make findings quieter; a seal exists to make changes louder. Overloading one file with both would guarantee that someone `--write-baseline`s away a foothold while suppressing a medium.

**Hash the files and nothing else.** Half the cost, a tenth of the value. `surface.lock changed` is a message people learn to re-run past. `a SessionStart hook was added` is not.

**A hosted attestation service.** Solves the resealing problem properly, by putting the record somewhere the attacker cannot write. Also introduces an account, a network dependency, and a trust relationship — three things this project does not have and sells not having. If a team needs that property, they already have a mechanism: a signed seal verified in CI by a key the developer machine does not hold.

**Watch the files continuously, as a daemon.** Better detection latency, worse everything else: a long-lived process, platform-specific file watching, and a new attack surface in a security tool. `gate --event config-change` gets most of the benefit at the moment it matters, for the cost of a hook.

---

## Consequences

**Good**

- The agent's execution surface becomes reviewable by the same mechanism the ecosystem already trusts for dependencies, with a vocabulary that makes the review four seconds rather than an investigation.
- The CI comment — silent unless the surface moved — is the highest signal-to-noise artefact the project has produced. It is also the thing most likely to spread it, because it lands in pull requests where people who never installed owlwarden will read it.
- It composes with the rules instead of competing: rules judge shape, the seal judges change, and `coverage` can now state both.

**Costs**

- A new committed file is a new thing to merge-conflict. Conflicts will be common on branches that both touch agent config. The resolution is `owlwarden seal --diff` and a re-seal, and it needs to be documented before the first user hits it, not after.
- Structured extraction of hooks, MCP servers, and permissions means the seal format tracks host schemas, which change faster than anything else in this codebase. `schemaVersion` and a documented migration path are not optional.
- Yet another concept in a tool that already asks the user to hold severity, confidence, `runtime_scope`, presets, baselines, and suppressions. The mitigation is the framing: it is a lockfile, and everyone already knows what a lockfile is. If the docs need more than that sentence, the design is wrong.

---

## Exit criteria

1. `seal` → edit a config → `seal --verify` exits 1 and names the changed hook, MCP server, or permission by key.
2. Reformatting a config without semantic change does not break the seal. Changing one character of a hook command does.
3. `seal` refuses to write on an unaccepted `high` finding, and prints it.
4. `seal` refuses to run without a TTY unless `--yes` is passed. Asserted in CI.
5. A signed seal verifies against a trust root outside the repository; a re-sealed drift without a valid signature fails under `--require-signed-seal`.
6. `gate --event session-start` returns `ask` on drift and `deny` under `--seal strict`; `gate --event config-change` returns `deny` on any drift.
7. The GitHub Action posts a surface diff on change and posts nothing otherwise. Both asserted against fixtures.
8. Creating `.owlwarden/surface.lock` where none existed is reported as mutation by `gate --event config-change`.
9. A seal written under an older `catalogueDigest` verifies with an explicit note rather than silently.
10. `SECURITY.md` carries the limits above, in the same words.

Later work, named so 1.2 does not overclaim: sealing dependency-shipped configuration, cross-repository seal policy, and any form of remote attestation.
