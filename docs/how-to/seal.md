# Lock the agent's execution surface

Your dependencies have a lockfile. The set of files your coding agent loads and
executes out of the working tree does not.

```bash
npx owlwarden seal
```

That writes `.owlwarden/surface.lock` — a committed record of every file on the
agent surface by semantic digest, with the hooks, MCP servers, permission set,
marketplace sources, and instruction files extracted rather than merely hashed.
Commit it.

```bash
npx owlwarden seal --verify
```

Exit 0 if the surface is unchanged, 1 on drift, 2 if it could not run.

## What a drift report looks like

```
◉ᴥ◉ surface drift · 2 changes

  + hook          claude-code SessionStart  node .claude/setup.mjs · not present in the seal
                  .claude/settings.json:19
  ~ mcp server    claude-code docs  pin: exact npx -y some-mcp@2.4.1 → unpinned npx -y some-mcp
                  .claude/settings.json:31

  seal taken 2026-08-27T09:14:02Z by engine 1.2.0 · no signature beside the seal
```

That is the whole point. `settings.json changed` is a line people learn to
re-run past. *A `SessionStart` hook was added* is a review a human can do in
four seconds, and currently cannot do at all.

## Reformatting does not break it

Every file carries two digests: one over the bytes, one over the parsed and
canonicalised structure. Comparison uses the second, so running `prettier` over
your dot-directory does not fail the build. The byte digest is still recorded,
and the report says `reformatted; no semantic change` — an investigator wants to
know the file was rewritten even when its meaning did not move.

Instruction files are the exception and seal byte-for-byte. In a file whose
whole purpose is to be read by a model, whitespace is content: a reordered
paragraph in `CLAUDE.md` is a different instruction.

## The first seal

`seal` refuses to write while an unaccepted `high` finding sits on the agent
surface, and prints each one with its fingerprint:

```
refusing to seal: 1 unaccepted finding(s) at or above high on the agent surface.
Sealing now would record the compromise as the agreed state.

  high agent-hook-autoexec  .devcontainer/devcontainer.json:7
    fingerprint 0e4834ac2ef19d65
```

You cannot lock a door you have not looked behind. Fix it, or write down the
decision:

```bash
npx owlwarden seal --accept 0e4834ac2ef19d65 --reason "devcontainer bootstrap, reviewed 2026-08-20"
```

`--accept` is repeatable — pass `--accept` and `--reason` in pairs — and the
reason is mandatory, the same rule inline suppressions live under. An acceptance
nobody can explain is an acceptance nobody decided.

Acceptances survive a re-seal. They are decisions the team made, not
observations of the tree.

## In CI

```yaml
- uses: suthat/owlwarden@v1
  with:
    seal: verify              # or `report` to summarise without failing
    require-signed-seal: true # optional; see below
```

The surface diff goes to the job summary and the `seal-diff` output. It is
**silent when the surface has not moved**, because a comment that appears on
every pull request is a comment nobody reads.

The Action does not post a comment itself. Writing one needs a token with
`pull-requests: write`, and an Action that asked for one to say something it can
say without it would have widened your blast radius for a convenience. Read
`seal-diff` and post it with your own permissions if you want that.

## In the gate

```bash
owlwarden gate --host claude-code --seal advisory .
```

| event | behaviour |
|---|---|
| `session-start` | drift returns `ask` with the diff, or `deny` under `--seal strict` |
| `config-change` | drift returns `deny`, always, under any posture |
| everything else | drift returns `ask`, or `deny` under `--seal strict` |

Mid-session drift is the strict case and should be. Configuration that changes
*while an agent is running* was written by something in the session, and nothing
in a normal workflow does that.

## Signing

```bash
# once, outside the repository
owlwarden seal
ssh-keygen -Y sign …   # or any ed25519 signer; owlwarden never holds a key
```

Put the base64 signature in `.owlwarden/surface.lock.sig`, the public key in
`OWLWARDEN_SEAL_TRUST` (colon-separated hex) or a trust file you pass with
`--trust`, and add `--require-signed-seal`.

owlwarden verifies and never signs. That is deliberate: the key belongs in a
developer's keychain or a CI secret, where this process cannot reach it, and
that is the property that makes CI's verification meaningful even when a
developer's machine is compromised. A trust root inside the scanned tree is
never read — a root the repository can write is a root that verifies whatever
the repository signed.

## Merge conflicts

Common on branches that both touch agent configuration, and the resolution is
not a manual merge:

```bash
git checkout --ours .owlwarden/surface.lock
npx owlwarden seal --diff      # read what actually moved
npx owlwarden seal             # re-seal
```

## What it does not protect against

Stated here rather than in a footnote, because it decides whether you have
deployed it correctly.

An **unsigned** seal detects accident, drift, and opportunistic malware. It does
not stop an attacker who already has code execution and can run
`owlwarden seal --yes` before you next look. Sealing requires a terminal or an
explicit `--yes`; that raises the cost and does not close the hole.

A **signed** seal with the key outside the repository raises the bar
substantially, because CI verifies a signature that a process writing files in
the working tree cannot forge. A targeted attacker who compromises the signing
key defeats it, as they defeat every signing scheme.

And the seal says nothing about whether your configuration is *safe*. It says
whether it is the configuration you sealed. `owlwarden vet` answers the other
question, and you want both.

See [ADR 0027](../adr/0027-workspace-seal.md) for the decision and the
alternatives that were rejected.
