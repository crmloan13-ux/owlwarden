# 0028 — Effective configuration, and the `shadowed` scope

**Status:** Accepted
**Date:** 2026-08-27
**Related:** [0014](0014-passive-dynamic-and-correlation.md) (what `Confirmed` means), [0025](0025-agent-surface-and-supply-chain.md) §5–6 (`runtime_scope`, and why `Confirmed` is unreachable on this surface)

---

## Context

[0025](0025-agent-surface-and-supply-chain.md) introduced `runtime_scope` to stop a hook in a tutorial being reported like a hook in your settings. It is a path heuristic: under `docs/`, `examples/`, `templates/`, `fixtures/`, or inside a fenced Markdown block, a finding is capped at `possible`; everywhere else it is `active`.

That heuristic is right for the case it was designed for and wrong for the case that generates the most irritation in practice. Agent hosts resolve configuration across several tiers — an administrator-managed tier, the user's own settings, the project's settings, and a local per-machine override — with a defined precedence. A key present in the project tier may be entirely inert because a higher tier overrides it.

Reporting an inert key as `active` is not a small inaccuracy. It is the specific failure that teaches a team the agent rules are noisy, because the person triaging it *knows* their platform team disabled project hooks org-wide, and the tool is telling them otherwise with a confident label.

The mirror case matters too, and nobody is checking it: a project key that is *not* overridden, in an environment where the reader assumed it was. Silence there is worse than noise.

There is a second, unrelated demand for the same machinery. Asking *which of these four files is actually deciding my agent's behaviour* has no good answer today, in any tool. Developers debug this by deleting files. `git config --show-origin` and `npm config ls -l` exist because the same question is unanswerable by inspection in those ecosystems too, and both are among the most-used diagnostic commands in their tools.

---

## Decision

### 1. Resolve tiers as the host does

Each `AgentHostProfile` gains a declared resolution order and merge semantics — which tiers exist, in what precedence, and for each key kind whether a higher tier replaces, merges, or is forbidden from being set by a lower one.

The profile records the host version it was verified against, and a test asserts the order against a pinned host. When a host changes its precedence, the failing test is the notification.

Resolution is data in the profile, not logic in the rules. Framework knowledge stayed out of rules in v0.0; host knowledge stays out of them here for the same reason.

### 2. A fourth `runtime_scope`: `shadowed`

| value | meaning | confidence |
|---|---|---|
| `active` | this key wins the resolution order | as declared |
| `shadowed` | present, but overridden by a higher tier | capped at `possible` |
| `project-optional` | loadable, not on the default resolution path | as declared |
| `template` | under a template, example, or fixture path | capped at `possible` |
| `documentation` | inside a fenced block in a Markdown file | capped at `possible` |

`shadowed` is reported, not suppressed. A repository that ships a dangerous hook which happens to be inert on *your* machine is still shipping it to the next person, whose tiers differ. The finding says which tier shadowed it and stops there.

### 3. `owlwarden effective`

```
owlwarden effective --host claude-code
owlwarden effective --host cursor --key permissions.allow
owlwarden effective --format json
```

Prints the resolved configuration with provenance per key: the winning value, the file and line it came from, and the tiers that lost.

```
◉ᴥ◉ effective configuration · claude-code

  hooks.SessionStart          (none)
                              ✗ .claude/settings.json:4       shadowed by managed
                              ✓ managed                        hooks disabled

  permissions.allow           4 entries
                              ✓ .claude/settings.json:12
                              ✗ ~/… (user)                     merged, 2 entries

  mcpServers.docs             some-mcp@2.4.1
                              ✓ .claude/settings.json:31
```

This is a diagnostic, and it is the kind of small tool that gets a project mentioned. It costs almost nothing once the resolver exists.

### 4. The user tier is read only under an explicit flag, and never reported

The project sells an invariant: reads stay inside the project root. Tier resolution requires reading files outside it. That contradiction is resolved deliberately rather than eroded quietly.

- Without `--include-user-config`, behaviour is **identical to 1.1**: only project-root tiers are resolved, and a project key is `active` unless a path heuristic says otherwise. This is the default everywhere, including CI, where a user tier does not exist anyway.
- With the flag, owlwarden reads a **closed allowlist** of user- and managed-tier paths per host. Read-only. Never executed. Same size caps and hostile-input handling as [0025](0025-agent-surface-and-supply-chain.md) §4.
- **The contents of user-tier files never enter any output.** Not in `pretty`, not in `json`, not in SARIF, not in a Markdown report, not in `--format agent`. A finding may say *shadowed by user settings*; it may not say what those settings contain. `effective` renders the winning value only when it came from inside the scan root; a value that won from a user or managed tier renders as `(set by user settings)`.

That last rule is the one to hold. A security report is a file people paste into tickets and pull requests, and a scanner that leaks a developer's personal configuration into a shared channel has caused an incident, not prevented one.

### 5. This does not unlock `Confirmed`

[0014](0014-passive-dynamic-and-correlation.md) defines `Confirmed` as static corroborated against a running target. Resolution is not corroboration — it establishes *which declaration applies*, not *that the declared thing happens*. A resolved `SessionStart` hook is still a claim about what a host will do, not an observation of it doing so.

So: `Surface::AgentWorkspace` stays capped at `likely`, exactly as 0025 §6 decided, and resolution improves `runtime_scope` instead. The vocabulary keeps its meaning.

The tempting move here is to promote resolution to a confidence signal because it feels like stronger evidence. It is stronger evidence about a different proposition. Keeping the two apart is the reason anyone believes the labels.

---

## Alternatives considered

**Leave the heuristic alone.** The cheapest option, and it means the largest false-positive class in the newest rule family stays. `shadowed` findings are the ones users will report first, and the answer "that is by design" is not one that survives contact.

**Read the user tier by default.** Better accuracy, and it breaks the invariant silently. A security scanner that starts reading `$HOME` after an upgrade, without being asked, has spent trust it needed for something else.

**Ask the host.** Some hosts can print their own resolved configuration. Shelling out to whichever agent CLI is installed makes the scanner depend on a moving external binary, in a hot path, in a tool whose defining property is that it does not depend on anything. Rejected on determinism grounds, not on effort.

**Make resolution a confidence input.** Discussed at length. Rejected in §5.

---

## Consequences

**Good**

- The largest false-positive class in the agent family is removed by construction rather than by tuning.
- `shadowed` also catches the inverse case, which no tool currently reports: a dangerous key that the reader assumed was overridden and is not.
- `owlwarden effective` is a genuinely useful standalone command, and standalone useful commands are how tools get recommended.
- The resolver is the honest prerequisite for any future host-state correlation, if that is ever built.

**Costs**

- Tier precedence is host-specific behaviour that changes without notice. Every profile now carries a pinned-version test, and a host release can turn CI red for reasons unrelated to our code. That is the correct trade — we would rather learn from a failing test than from a user — but it is ongoing maintenance, and it belongs in the same quarterly review as the rest of `AgentHostProfile`.
- A flag that changes what the scanner reads is a flag people will misunderstand. The documentation has to be blunt: without it, nothing outside the project is opened.
- Five `runtime_scope` values is at the edge of what a person will hold in their head. If a sixth is ever proposed, that is the signal the axis needs redesigning rather than extending.

---

## Exit criteria

1. Every `AgentHostProfile` declares a resolution order, and a test asserts it against a pinned host version.
2. A project key overridden by a higher tier reports `shadowed`, capped at `possible`, and names the shadowing tier.
3. A project key not overridden reports `active`, with `--include-user-config` on and a user tier present.
4. Without `--include-user-config`, output is byte-identical to 1.1 on the full fixture suite.
5. No output format, at any verbosity, contains the contents of a user- or managed-tier file. Asserted by a test that greps every reporter's output for a sentinel string planted in a fixture user config.
6. `owlwarden effective` prints provenance per key and renders out-of-root winning values as `(set by user settings)`.
7. No rule on `Surface::AgentWorkspace` can produce `Confirmed`. The 0025 test still passes unchanged.
8. Hostile input in a user-tier file — malformed, oversized, deeply nested, symlinked — is handled by the same bounded path as project-tier input.
