# 0025 — The agent workspace is a second scan surface

**Status:** Accepted — shipped in 1.1.0
**Date:** 2026-08-25
**Supersedes:** nothing
**Superseded by:** nothing
**Related:** [0012](0012-request-origin-not-taint.md) (confidence), [0013](0013-suppressions-and-baseline.md) (suppressions), [0014](0014-passive-dynamic-and-correlation.md) (`Confirmed`), [0016](0016-osv-advisory-lookup.md) (OSV), [0018](0018-corpus-depth-bar.md) (corpus), [0024](0024-plugin-api-v1.md) (plugin API freeze), [0026](0026-deterministic-agent-gate.md) (the gate that consumes this surface)

---

## Context

owlwarden currently answers one question: *is the web application in this repository written safely?* Fourteen rules, twelve `FrameworkProfile`s, one remediation table per rule per framework, enforced by a build that fails when a cell is empty.

There is a second question the same repository now raises, and no rule in the catalogue touches it: *is the coding agent that works in this repository itself being told to do something hostile?*

This is not a hypothetical extension. It is the attack that happened.

On 4 August 2026 a self-propagating npm worm known as ChainDrop poisoned several hundred packages in under four hours, starting from a compromised maintainer account in the `keyv` monorepo. The dependency half of that incident is already inside our reach — `known-vulnerable-dependency` and `unpinned-dependency` cover it as well as any lockfile rule can. The half that is not in our reach is the persistence mechanism: the payload wrote itself into `.claude/settings.json`, `.claude/setup.mjs`, `.vscode/tasks.json`, and `.vscode/setup.mjs`, and used stolen credentials to commit those files into branches of every repository it could reach. Removing the poisoned package version does not remove that foothold. Regenerating the lockfile does not remove it. The next developer who opens the folder in an editor, or starts an agent session in it, re-executes the dropper.

The property that makes this class of file dangerous is simple and general: **agent and editor configuration is executable, is read from the working tree, and is not read by any software composition analysis tool.** It is not a dependency, so no lockfile records it. It is not application source, so no SAST rule parses it. It is checked in, so it passes review as "config" the way a `.prettierrc` does.

The same property has already produced CVEs independent of the worm. Repository-controlled session hooks that execute on open, repository-controlled environment that redirects an agent's API traffic, and a desktop editor that executed workspace-defined hook commands out of a file that had not previously existed — all of these are the same category error, which one write-up phrased precisely: workspace-sourced hook configuration was treated as project *state* rather than as *execution* state.

Point tools for this exist. There are npm packages and GitHub Actions that scan `.claude/` alone, and agent skills that audit instruction files. They are useful and they are also a separate silo: a second report shape, a second exit code, a second CI job, a second suppression syntax, and no relationship to the application findings sitting next to them in the same pull request. A team ends up gating on two tools that disagree about what "high" means.

owlwarden is already in the working tree, already parses `.github/workflows` for `ci-unpinned-action`, already parses `package.json` for `unpinned-dependency`, already has a fingerprinted baseline, a suppression syntax with mandatory reasons, SARIF output, and an exit-code contract. Adding this surface is cheaper for us than adding a second tool is for the user, and the result is one gate.

### The design tension that makes this an ADR

Two invariants collide.

**Invariant A (from v0.0):** every rule ships remediation for every supported framework, and the build fails otherwise. This is the reason the framework column in `RULES.md` cannot silently drift to zero.

**Invariant B (the new rules):** `.claude/settings.json` has nothing to do with whether the application is Next.js or Koa. The fix for a hostile `SessionStart` hook is identical across all twelve frameworks and different across agent hosts.

Satisfying A naively means writing the same remediation string twelve times — padding, of exactly the kind [0018](0018-corpus-depth-bar.md) rejected for fixtures. Exempting the new rules from A means the invariant now has a hole in it, and a hole in an invariant is how it dies.

Neither is acceptable. That is the decision this document exists to make.

---

## Decision

### 1. Introduce `Surface`, and make the remediation invariant generic over it

A rule declares which surface it examines. A surface owns a profile set. The build asserts remediation completeness *per surface*, not against one hard-coded framework list.

```rust
/// What kind of artefact a rule reads. Determines which profile set its
/// remediation table must cover.
pub enum Surface {
    /// Application source. Profiles: FrameworkProfile (12 today).
    WebApp,
    /// Agent and editor configuration in the working tree.
    /// Profiles: AgentHostProfile (7 today).
    AgentWorkspace,
}

pub enum AgentHostProfile {
    ClaudeCode,
    Cursor,
    VsCode,
    Copilot,
    Codex,
    GeminiCli,
    Generic,
}
```

The matrix test becomes:

```rust
for rule in catalogue() {
    for profile in rule.surface().profiles() {
        assert!(rule.remediation(profile).is_some(), "{} has no fix for {profile:?}", rule.id());
    }
}
```

Invariant A survives unchanged in spirit — a rule still cannot ship without a concrete fix for every environment it claims to serve — and Invariant B is honoured, because the environment that matters for an agent-config rule is the agent host, not the web framework.

`owlwarden coverage` grows a second table. `RULES.md` grows a `Surface` column and a second framework-support table. Both are generated; neither can drift.

### 2. The catalogue: eleven rules

All eleven are `Surface::AgentWorkspace` unless noted. Severity and maximum confidence follow the existing scale. Primary taxonomy is CWE, because CWE is stable; the secondary mapping is OWASP Top 10 for Agentic Applications (ASI) 2026, with the edition pinned in `taxonomy.rs` so a new edition is a deliberate, reviewed change rather than a drift.

| id | severity | max conf. | CWE | ASI 2026 |
|---|---|---|---|---|
| `agent-hook-autoexec` | high | likely | CWE-829 | ASI05 |
| `agent-hook-untrusted-command` | high | likely | CWE-78 | ASI05 |
| `agent-config-loader-script` | high | likely | CWE-506 | ASI04 |
| `agent-config-env-redirect` | high | likely | CWE-15 | ASI03 |
| `agent-config-secret-reachable` | high | likely | CWE-522 | ASI03 |
| `agent-permission-wildcard` | medium | likely | CWE-732 | ASI03 |
| `agent-mcp-unpinned-remote` | medium | likely | CWE-1357 | ASI04 |
| `agent-marketplace-untrusted` | medium | likely | CWE-1357 | ASI04 |
| `agent-instructions-hidden-text` | high | likely | CWE-838 | ASI01 |
| `agent-instructions-directive` | medium | possible | CWE-77 | ASI01 |
| `install-lifecycle-script` (`WebApp`) | medium | likely | CWE-829 | ASI04 |

Rule ids are permanent from the moment they ship, per the existing policy. They appear in suppressions, agent rules files, and other people's CI configs.

---

#### `agent-hook-autoexec` — Repository config executes a command when the workspace is opened

**Fires on:** a hook or task declared in a tracked or untracked repository-local config that runs without a further user action. Concretely: any `SessionStart` entry in `.claude/settings.json` or `.claude/settings.local.json`; any `.vscode/tasks.json` task with `runOptions.runOn: "folderOpen"`; a `postCreateCommand` / `postStartCommand` / `initializeCommand` in `.devcontainer/devcontainer.json`; the equivalent open-time entries in `.cursor/hooks.json`.

**Does not fire on:** hooks bound to an explicit user action (`PostToolUse`, `PreToolUse`, `Stop`) — those are covered by `agent-hook-untrusted-command`, which judges the command instead of the trigger. A `tasks.json` task with no `runOn`, or `runOn: "default"`, is silent.

**Why it is high:** the finding describes a repository that runs code on the machine of anyone who clones it and opens it. That is remote code execution with a social step so small it does not count as one.

**Remediation shape:** per host, name the file and the key, and give the safe replacement — a task the developer runs by hand, or the host's managed-settings tier where the platform team, not the repository, owns hooks.

---

#### `agent-hook-untrusted-command` — Hook command reaches outside the project

Fires when the *command string* in any hook, of any trigger, does something a formatter would not: pipes a network fetch into a shell (`curl … | sh`, `wget … | bash`), decodes and evaluates (`base64 -d | …`, `node -e`, `eval`), writes outside the project root (`~`, `$HOME`, absolute paths outside the scan root), reads `.env`, `.npmrc`, `~/.ssh`, or credential stores, or launches a package resolved at run time (`npx -y`, `bunx`, `uvx`, `pipx run`) rather than a script committed in the repository.

Silent on the common legitimate shape: a hook that invokes a project-local script, an installed binary from `devDependencies`, or a package manager script defined in `package.json`.

This rule is where most of the family's value lives and most of its false-positive risk lives with it. See *False positives* below.

---

#### `agent-config-loader-script` — Executable script inside an agent or editor config directory

Fires on a `.js`, `.mjs`, `.cjs`, `.ts`, `.sh`, or `.py` file inside `.claude/`, `.vscode/`, `.cursor/`, `.gemini/`, or `.codex/` that is referenced by a hook or task, or that matches the loader shape those directories are not supposed to contain. `.claude/setup.mjs` and `.vscode/setup.mjs` are the ChainDrop artefacts by name; the rule matches the shape, not the names, and the names go in the fixtures.

Silent on hook scripts under a documented, conventional path (`.claude/hooks/`, `.cursor/hooks/`) that are tracked in git — a real team's real hook. The finding text says which of those two facts was missing.

---

#### `agent-config-env-redirect` — Repository config redirects the agent's API traffic

Fires when repository-local config sets `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `GOOGLE_GEMINI_BASE_URL`, an `HTTPS_PROXY` pointing at a non-loopback host, or `NODE_EXTRA_CA_CERTS`, in an `env` block that the host applies to the session.

A repository that decides where your agent's traffic goes decides who reads your prompts and your source. There is a legitimate case — a company gateway — and the fix text says so: put it in user or managed settings, not in the repository, so that cloning a project does not silently change it.

---

#### `agent-config-secret-reachable` — Repository config puts credentials in reach of a repository-controlled command

Fires when a hook command, MCP server `env` block, or task references a credential-shaped variable (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `NPM_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `*_SECRET`, `*_TOKEN`), or when an MCP server declaration inherits the full process environment rather than an explicit allowlist.

Distinct from `hardcoded-secret`: nothing is hardcoded here. The credential is correctly stored in the environment and then handed to a command the repository controls.

---

#### `agent-permission-wildcard` — Repository config pre-approves a broad tool permission

Fires on `permissions.allow` entries that are unbounded (`Bash`, `Bash(*)`, `Bash(*:*)`, `WebFetch`, `Write(*)`, `mcp__*`) or that pre-approve a shell with an argument wildcard in a position that makes the constraint meaningless (`Bash(git *)` allows `git … -c core.pager='sh -c …'`; the finding says so). Also fires when a repository disables a permission gate wholesale.

Medium, not high: on its own it is a widened blast radius, not an execution. Combined with `agent-hook-autoexec` in the same file it is the full chain, and the reporter says that in the correlation note.

---

#### `agent-mcp-unpinned-remote` — MCP server declaration resolves code at run time

Fires on an MCP server entry whose command is `npx -y <pkg>`, `uvx <pkg>`, `bunx <pkg>`, or `docker run <image>` without an exact version or digest, or whose transport is a remote URL under a domain not in an allowlist. Each of these means the code that gets a tool call today is not necessarily the code that got one yesterday.

Fix: pin the version or the digest; prefer a dependency in `devDependencies` over a run-time resolve; for remote transports, state the trust decision in the config rather than leaving it implicit.

---

#### `agent-marketplace-untrusted` — Repository config adds a third-party plugin or skill source

Fires when repository-local config registers an additional plugin marketplace, skill directory, or extension source, or auto-installs from one. A marketplace reference is a delegation of trust that the repository is making on the developer's behalf.

---

#### `agent-instructions-hidden-text` — Instruction file contains text a human reader cannot see

Fires on zero-width characters (`U+200B`–`U+200F`, `U+2060`–`U+2064`, `U+FEFF`), bidirectional overrides (`U+202A`–`U+202E`, `U+2066`–`U+2069`), tag characters (`U+E0000`–`U+E007F`), or non-ASCII homoglyph runs inside `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/**`, `.github/copilot-instructions.md`, agent/subagent frontmatter, or skill definitions.

The model reads the bytes; the reviewer reads the rendering. When those disagree, review is not review. This one is high and near-unambiguous: a bidi override in a Markdown instruction file has no legitimate use we have found, and the false-positive corpus will say so if we are wrong.

The finding renders the offending run as escaped codepoints. It never echoes the raw sequence into the terminal or into a Markdown report.

---

#### `agent-instructions-directive` — Instruction file tells the agent to bypass its own controls

Fires on instruction text matching a small, explicitly enumerated set of shapes: disregarding prior or system instructions, disabling or skipping the permission prompt, exfiltrating environment variables or credentials, or fetching and executing remote content.

**Medium, and capped at `possible` — the only rule in the family that is.** This is a heuristic over prose. It belongs in `deep`, not in `quick`. It exists because leaving it out means the family looks at every mechanism except the one an attacker reaches for first, but it is honest about being a heuristic, and [ADR 0012](0012-request-origin-not-taint.md)'s principle applies: state the confidence the method actually earns.

---

#### `install-lifecycle-script` — Package declares an install-time script

`Surface::WebApp`, because it reads `package.json` and its fix is a package-manager fix. Fires on `preinstall`, `install`, or `postinstall` in the scanned project's own manifest. Medium: legitimate for native addons — and we ship one, so the fixture set includes our own shape as a clean twin — and it is also the mechanism a worm reaches for when it republishes a package.

---

### 3. Path discovery, and the `.gitignore` exception

The existing `SourceProvider` respects `.gitignore`, skips `node_modules`, refuses outbound symlinks, and caps file size. Two of those four are wrong for this surface.

`.claude/settings.local.json` is conventionally gitignored. It is also where a workspace-scoped hook configuration vulnerability lived. Respecting `.gitignore` here means the rule is silent on exactly the file the CVE was about.

**Decision:** `Surface::AgentWorkspace` reads from an explicit, closed path allowlist that overrides `.gitignore`. Everything else stays: paths remain under the scan root, symlinks that leave it are refused, size caps apply, and nothing is executed.

The allowlist, in full, is data — not a glob the user can widen:

```
.claude/settings.json
.claude/settings.local.json
.claude/hooks/**
.claude/agents/**
.claude/skills/**
.claude/*.{js,mjs,cjs,ts,sh,py}
.claude-plugin/**
.cursor/mcp.json
.cursor/hooks.json
.cursor/hooks/**
.cursor/*.{js,mjs,cjs,ts,sh,py}
.cursor/rules/**
.cursorrules
.vscode/tasks.json
.vscode/settings.json
.vscode/extensions.json
.vscode/*.{js,mjs,cjs,ts,sh,py}
.devcontainer/devcontainer.json
.devcontainer/**/devcontainer.json
.github/copilot-instructions.md
.gemini/**
.codex/**
.mcp.json
mcp.json
CLAUDE.md
AGENTS.md
```

The two `.cursor/` script entries were added during implementation. Without
them `agent-config-loader-script` was structurally blind to the ChainDrop shape
one host over — which is the shape the rule exists for — and the closed list
would have been a list of the places we happened to think of rather than the
places a dropper goes. Extending it is a reviewed change; the module comment
and a verbatim-list test in `crates/static-engine/src/agentws/paths.rs` are the
review record.

Two further properties, both learned by attacking the implementation and both
now asserted:

**Matching is case-insensitive.** macOS and Windows ship case-insensitive
filesystems. `.Claude/settings.json` *is* `.claude/settings.json` to a host
running there — it opens it and executes what is in it — so a case-sensitive
classifier was a one-character bypass of the entire surface. On Linux the cost
is scanning a file the host would not load, which is the safe direction.

**A file that is too large is reported, not skipped.** The application-source
walker drops a file over the size cap, which is right for one enormous generated
bundle. On this surface it would have made a 5 MB `.claude/settings.json`
invisible: not scanned, not reported, and indistinguishable from a repository
with no agent configuration at all. Silence is the one answer this surface must
never give by accident.

A closed list is deliberate. A user-extensible glob would let a repository point owlwarden at a file the engine has no parser for, and the honest answer to "we found nothing in a file we do not understand" is not one we want to give.

`node_modules` stays excluded on this surface too, with one exception under discussion for a later ADR: an agent config *inside* a dependency is a real vector and a very large scan.

### 4. Parsing hostile input

Every file on this surface is attacker-controlled whenever `vet` is the intent. Therefore:

- **Never execute, never import, never resolve.** Config is parsed, not loaded. `$schema` is never fetched. No `require`, no dynamic `import`, no shell.
- **JSONC-tolerant parse.** These files carry comments and trailing commas in the wild. A parse failure is reported, never treated as "clean" — through the scan's `errors` channel rather than as a catalogue rule, so the rule count stays a count of *security* rules and the exit code is unaffected. `owlwarden scan` prints them; `report.errors` carries them.
- **Duplicate keys are all kept**, in source order. `serde_json` keeps the last value for a repeated key; a reviewer reading top-down sees the first. A config that says `"hooks": {}` and then `"hooks": { "SessionStart": … }` is exactly the shape that exploits the difference, and a rule reading only one of them saw nothing while the host loaded the other. Every occurrence reaches the rules.
- **Fold for matching, report the original.** Byte offsets, the code frame, and the escaped rendering all come from the original bytes; only the matcher sees the folded copy.

  The draft of this ADR said "normalised to NFKC". That would not have worked, and saying it would have left the hole open while sounding rigorous: **NFKC does not map Cyrillic `а` (U+0430) to Latin `a`**, because they are genuinely different letters. It normalises compatibility forms — fullwidth, circled, ligatures — and leaves the actual homoglyph attack untouched. So the implementation does both jobs explicitly: a compatibility fold for the ranges that matter, a confusable fold for the scripts an attacker reaches for, invisible characters removed, and whitespace runs collapsed so that a line break in the middle of a sentence is not an evasion either.

  `crates/static-engine/src/agentws/text.rs` carries the reasoning and the table.
- **Bounded work.** Size caps, a nesting depth cap, a node-count cap, and a match-time budget per file. A config file is not a place where a scanner should be able to spend a second.

  One bound was missing and mattered. The string scanner validated the whole remaining input to read one character, once per character — so a single 1.5 MB string, well inside the size cap, in a file an attacker fully controls, on the gate's keystroke path, took the scanner out of service. The size cap does not help when the work is the square of the length. `hostile_workspace.rs` asserts the timing.
- `#![forbid(unsafe_code)]` continues to hold; nothing here needs the `plugin-host` exception.

### 5. `runtime_scope`: the field that keeps this family from being noise

A `.claude/settings.json` under `docs/`, `examples/`, `templates/`, `fixtures/`, or `test/` is documentation. A fenced code block in a Markdown tutorial showing a hook is documentation. Reporting those at the same weight as a live config is how a rule family gets turned off in week two.

Findings on this surface carry an orthogonal `runtime_scope`:

| value | meaning | effect on confidence |
|---|---|---|
| `active` | in a path the host actually loads | as declared |
| `project-optional` | loadable but not the default resolution path | as declared |
| `template` | under a template/example/fixture path | capped at `possible` |
| `documentation` | inside a fenced block in a Markdown file | capped at `possible` |

`runtime_scope` appears in the JSON, in SARIF as a property, and as a word in the pretty reporter. It is not a severity multiplier and it is not a suppression — the finding is still reported, because a repository that *ships* a risky template is still telling its readers to do the risky thing. It changes what the reader is being told.

### 6. `Confirmed` is not reachable on this surface

[ADR 0014](0014-passive-dynamic-and-correlation.md) defines `Confirmed` as a static finding corroborated by the dynamic engine against a running target. There is no running target for a config file, and inventing a second meaning for the word would quietly break the one property this project sells.

**Decision:** `Surface::AgentWorkspace` caps every rule at `likely`. If we later build a host-state probe — resolving the effective configuration the way the host itself would, across managed, user, project, and local tiers — that is a correlation source and it gets its own ADR, its own transport bound, and its own exit criteria. Not this one.

### 7. `owlwarden vet` — the same engine, a different intent

```
owlwarden vet ./freshly-cloned-repo
```

`vet` is `scan` with a fixed posture for the case where the target is not yours:

- preset `agent-surface`, `--fail-on high`, `--min-confidence likely`
- `--offline`: no OSV, no `--target`, no network, no exceptions
- **plugins are not loaded**, even signed ones, and even if the invoking user has a trust root configured
- **the target's owlwarden config is not read, its baseline is not applied, and its inline suppressions are not honoured** — they are counted and reported, and a non-zero count is itself printed on the summary line

That last point is the one worth being loud about. Every mechanism we built in [0013](0013-suppressions-and-baseline.md) to make adoption realistic on a legacy repo is, in the hands of the repository's author, a mechanism for hiding a finding. On your own repository that trade is correct and deliberate. On someone else's it is not a trade at all. `vet` therefore treats the target's suppression surface as evidence rather than as instruction.

`scan` is unchanged: it reads your config, honours your baseline, and includes the agent-surface rules in `quick` and `deep` at their declared severities.

### 8. Presets

| preset | change |
|---|---|
| `quick` | gains ten of the eleven; `agent-instructions-directive` is excluded |
| `owasp-top10` | gains `install-lifecycle-script` only (it is the one with an OWASP Top 10 (2021) mapping — A08) |
| `deep` | gains all eleven |
| `agent-surface` *(new)* | the eleven, alone — for a config-only gate or a `vet` |

The `owasp-top10` preset deliberately does not absorb the family. That preset means "rules mapped to an OWASP Top 10 (2021) category" and the ASI list is a different document. Blurring the two would make the preset a marketing word.

### 9. Plugin API

Adding `surface` to rule metadata is an additive optional field defaulting to `Surface::WebApp`. A plugin built against `schemaVersion: 1` continues to load and continues to be checked against the twelve `FrameworkProfile`s. No break, no RFC.

**Exposing `AgentHostProfile` to plugin authors is a different matter** and does require an RFC per [0024](0024-plugin-api-v1.md), because it adds a type to the frozen surface. Until that RFC lands, third-party rules cannot target `Surface::AgentWorkspace`. Stated here so 1.1 does not overclaim an extensibility it has not shipped.

---

## False positives

This family will produce more false positives than anything currently in the catalogue, because it judges intent from a command string rather than from a language construct. The corpus bar from [0018](0018-corpus-depth-bar.md) is raised accordingly.

Three fixture kinds per rule per host profile, not two:

1. **Vulnerable** — fires, at the declared severity and confidence.
2. **Clean twin** — the same file, benign. Silent.
3. **Tempting** — a *legitimate* configuration that shares surface features with the vulnerable one. A `PostToolUse` hook that runs `pnpm exec prettier --write`. A `tasks.json` build task with no `runOn`. An MCP server pinned to an exact version. A `devcontainer.json` whose `postCreateCommand` is `pnpm install`. Silent, and its silence is the assertion.

Plus a standing corpus: the agent and editor configuration of a set of well-known open-source repositories, vendored as fixtures, which must stay silent in `quick`. When it does not, either the rule is wrong or the repository is, and finding out which is the work.

The pretty reporter states, for every finding on this surface, the specific fact that fired it — which key, which trigger, which token in the command — so that a false positive is a one-line bug report rather than an argument. Per `CONTRIBUTING.md`: the best bug report is a false positive with a small snippet.

---

## Alternatives considered

**Ship a separate binary.** Cleanest boundary, and it loses the whole reason to do this: one report shape, one exit code, one baseline, one CI job. The user's problem is not that the checks do not exist; it is that they exist in four tools that do not agree.

**Write the same remediation twelve times to satisfy the framework matrix.** Would have shipped in a day and would have made `RULES.md` dishonest, which is the one thing the project has consistently refused. It also would have taught the matrix test to accept padding.

**Exempt the new rules from the remediation invariant.** A hole in an invariant is a hole in the invariant. Generalising it over `Surface` costs one enum and keeps the property.

**Detect ChainDrop specifically — IOCs, hashes, the Ethereum C2 contract, the known domains.** Tempting, dated on arrival, and outside the method: the campaign rotated its C2 through a smart contract precisely so that domain blocklists would not work. We match shapes, not incidents. The incident goes in the fixtures.

**Put the whole thing in the dynamic engine, by resolving effective host configuration.** More accurate, requires modelling four settings tiers per host, and would make `Confirmed` mean two different things. Deferred, with §6 as the placeholder.

**Score the config with a model.** Would raise recall on `agent-instructions-directive` substantially. It also makes the answer non-deterministic and requires either a network call or a local model, which are the two properties this tool does not have and sells not having. If a user wants a model's opinion, they have one — the whole `AGENTS.md` narrative is that the deterministic floor runs first so the model's budget goes somewhere it earns its keep.

---

## Consequences

**Good**

- One `owlwarden scan` covers application code and the agent's own execution surface, with one `--fail-on` and one exit code.
- `owlwarden vet` is a genuinely new capability with a one-line pitch: check a repository before you open it in an agent.
- The `Surface` abstraction is the mechanism by which any future non-application surface (IaC, container manifests) enters the catalogue without another argument about the matrix.

**Costs, stated plainly**

- The catalogue goes from 14 rules to 25 and `RULES.md` roughly doubles. The generated-reference machinery absorbs it; the review burden is real.
- A second profile set is a second thing that can drift. The matrix test is what stops it, and it must be extended before the first rule lands, not after.
- The false-positive surface is the highest in the project's history. If the standing corpus is not built alongside the rules, this family will make the tool feel noisy and it will take the rest of the catalogue's reputation with it.
- Agent hosts change their configuration schemas faster than web frameworks change theirs. This family carries maintenance that `sql-injection` does not. `AgentHostProfile` needs an owner and a quarterly review, and that is a governance change, not a code change.
- We are now shipping rules about the tooling of specific vendors. The profile set must stay open to any host that reads project-local config, or the rule family becomes an advertisement.

---

## Exit criteria

This ADR is satisfied when all of the following hold:

1. `Surface` exists, the remediation matrix test is generic over it, and removing a single remediation cell from any rule in either surface fails the build.
2. All eleven rules ship, with vulnerable / clean-twin / tempting fixtures for every rule × every `AgentHostProfile`, wired into CI.
3. The standing real-world config corpus is silent in `quick`.
4. `runtime_scope` is present in JSON, SARIF, Markdown, and pretty output, and a fixture proves a `template`-scoped finding is capped at `possible`.
5. No rule on `Surface::AgentWorkspace` can produce `Confirmed`; a test asserts it.
6. `owlwarden vet` refuses to load plugins, refuses the network, and reports — not honours — the target's suppressions. A fixture repository that attempts to suppress its own hostile hook still exits non-zero.
7. A hostile-input suite covering malformed JSON, 10 MB config files, 10 000-deep nesting, symlinks pointing outside the root, and bidi/zero-width payloads terminates within budget and never executes anything.
8. `owlwarden coverage` prints the ASI table with its gaps stated, in the same voice as the OWASP Top 10 table: what we do not look at, alongside what we do.
9. `RULES.md` regenerates and the "rule ships without an entry" test still fails when it should.

All nine hold. Beyond them, two suites exist that this document did not ask for and should have:

- `crates/static-engine/tests/hostile_workspace.rs` — availability, containment, and honesty as three named properties, including a test that the path allowlist and the walker's globs agree on every pattern. Two lists that have to match is two lists that can drift, and the drift is silent in both directions.
- `crates/detectors/tests/evasion.rs` — one test per evasion technique per rule, and a meta-test that fails when a rule is added without one. A rule nobody has tried to get past is a rule nobody has tested.

Not in scope, and stated here so the release does not overclaim: scanning agent configuration inside `node_modules`; resolving effective configuration across managed/user/project/local tiers; plugin-authored rules on this surface; any runtime enforcement — that is [0026](0026-deterministic-agent-gate.md).

---

## References

- OWASP Top 10 for Agentic Applications (ASI) 2026 — ASI01 Agent Goal Hijack, ASI03 Agent Identity & Privilege Abuse, ASI04 Agentic Supply Chain Compromise, ASI05 Unexpected Code Execution.
- OWASP Top 10 for LLM Applications, 2026 edition (published 4 August 2026) — for the framing that the job is bounding the blast radius, not preventing the model from being fooled.
- ChainDrop / Shai-Hulud npm worm, 4 August 2026 — vendor analyses from Microsoft Threat Intelligence, Elastic Security Labs, Zscaler ThreatLabz, and StepSecurity, for the `.claude/settings.json`, `.claude/setup.mjs`, `.vscode/tasks.json`, `.vscode/setup.mjs` persistence path and the smart-contract C2 that defeats domain blocklists.
- CVE-2025-59536 — repository-controlled session hook executing on open.
- CVE-2026-21852 — repository config redirecting agent API traffic and reaching a provider key.
- CVE-2026-48124 — desktop editor executing workspace-defined hook commands from a local settings file without a dedicated approval step.
- CVE-2026-25725 — hook injection into a settings file that did not previously exist, which is why creating a protected file counts as mutation.

Incident references are the reason the fixtures exist. They are not detection logic.
