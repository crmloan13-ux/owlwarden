# Which file is deciding my agent's behaviour?

Four files can set the same key. `git config --show-origin` exists because that
question is unanswerable by inspection, and `npm config ls -l` exists for the
same reason. Agent hosts have the same problem and no such command, so people
debug it by deleting files.

```bash
npx owlwarden effective --host claude-code
```

```
◉ᴥ◉ effective configuration · claude-code  (order verified against claude-code 2.x)

  hooks                       2 keys
                              ✓ .claude/settings.json  (project)

  permissions                 2 keys
                              ✓ .claude/settings.json  (project)

  not opened: managed, user — pass --include-user-config to resolve against them
```

`--key permissions` narrows it to one key. `--format json` gives the same answer
with provenance per key, for a script.

## `--include-user-config`, and what it changes

**Without it, nothing outside the project root is opened.** That is the flat
statement, and it is the whole default: the project sells an invariant that
reads stay inside the project root, and every scan that has not explicitly opted
out of it still holds that invariant exactly.

With it, owlwarden reads a **closed allowlist** of user- and managed-tier paths
for the host you named — read-only, never executed, with the same size caps,
symlink refusal, and hostile-input handling the project tier gets.

```
◉ᴥ◉ effective configuration · claude-code  (order verified against claude-code 2.x)

  hooks                       (set by user settings)
                              ✓ user settings  (user)
                              ✗ .claude/settings.json  (project, shadowed)

  permissions                 (set by user settings)
                              ✓ user settings  (user)
                              ✗ .claude/settings.json  (project, lost)

  1 key(s) set only above this project, not listed
```

Two things in that output are deliberate and worth reading twice.

`hooks` says **shadowed** and `permissions` says **lost**. Permission lists
concatenate across tiers, so the project's entries still take effect; hooks
replace, so the project's are inert. A tool that called both "overridden" would
be telling you your permissions do not apply, which is the opposite of true.

`1 key(s) set only above this project, not listed` is not coyness. A key name is
contents: your user settings may hold a key named after an internal project, and
this output is a file people paste into tickets. Keys the project also declares
are listed, because their names are already in your repository.

## What never leaves your machine

**The contents of user-tier files never enter any output.** Not `pretty`, not
`json`, not SARIF, not a Markdown report, not `--format agent`. A finding may
say *shadowed by user settings*; it may not say what those settings contain. A
value that won from outside the scan root renders as `(set by user settings)`,
and the path it came from renders as the tier's name rather than a location —
your home directory layout names you.

This is asserted rather than intended. A test plants a sentinel string in every
position of a fixture user config — a key, a value, a nested value, an array
element, a command — and greps every byte of every format for it. A future
reporter that starts echoing a resolved value fails there rather than in
somebody's issue tracker.

## `shadowed` in a scan

```bash
npx owlwarden scan --preset agent-surface --include-user-config
```

A project key a higher tier overrides reports `runtime_scope: shadowed`, capped
at `possible` — which, combined with the rule that `possible` never fails CI on
its own, means it stops interrupting you.

**It is reported, not suppressed.** A repository that ships a dangerous hook
which happens to be inert on *your* machine is still shipping it to the next
person, whose tiers differ. The finding stays in the report and says which tier
shadowed it.

The mirror case is the reason to run this at all, and no other tool checks it: a
project key that is **not** overridden, in an environment where you assumed it
was. Silence there is worse than noise.

## `vet` refuses the flag

```
$ owlwarden vet --include-user-config ./someones-repo
error: vet takes none of these
```

Not for a privacy reason — tier contents never reach any output either way — but
because the answer would be wrong in the reassuring direction. `vet` reads a
repository somebody else wrote. Downgrading its dangerous hook to `shadowed`
because *your* settings happen to override it says nothing about the next
reader, who is the person `vet` exists to warn.

## When a host changes its precedence

Each profile records the host version its order was checked against, and a test
asserts the order. Tier precedence is host-specific behaviour that changes
without notice; recording the version is what turns "the host changed its mind"
from your bug report into a failing test in our CI.

If the order is wrong for the host version you are on, that is a bug worth
filing — with the version, which is the field the fix keys off.

See [ADR 0028](../adr/0028-effective-configuration.md) for the decision and the
alternatives that were rejected.
