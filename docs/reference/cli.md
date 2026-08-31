# CLI reference

Values and defaults. Task-oriented steps live in [how-to](../how-to/) and
[tutorials](../tutorials/).

```
owlwarden turn [PATH] [--base REF] [--hook HOST] [--record] [--fail-on LEVEL]
owlwarden scan [PATH] [OPTIONS]
owlwarden vet [PATH] [--fail-on LEVEL] [--format FORMAT]
owlwarden gate --host <HOST> [PATH] [--since REF] [--fail-on LEVEL]
owlwarden verify --patch <FILE> [PATH] [--rule ID] [--fail-on LEVEL]
owlwarden watch [PATH] [OPTIONS]
owlwarden mcp [PATH]
owlwarden init [--claude-code] [--cursor] [--generic] [--force]
owlwarden init [--agent-rules] [--workflow] [--mcp] [--out FILE]
owlwarden rules [--json]
owlwarden coverage [--json]
owlwarden explain <RULE_ID> [--json]
owlwarden plugin scaffold <NAME>
owlwarden plugin inspect <PATH>
owlwarden osv update [PATH] [--out FILE]
```

`owlwarden --help` prints the four commands a first run needs;
`owlwarden help --all` prints this whole list with the presets compiled into
this build. `owlwarden --version` prints the engine version.

The standalone binary carries `scan`, `vet`, `gate`, `watch`, and the read-only
commands. `init`, `turn`, `verify`, `mcp`, and `plugin` are npm-CLI only — they need a
JavaScript runtime for reasons that are theirs, not the engine's.

## `turn`

*What did this turn change?* Scans the paths that differ from `--base`, scans
the same paths at that commit, and diffs the two by the baseline fingerprint
([ADR 0032](../adr/0032-turn-verdict.md)).

| Flag | Default | Notes |
|---|---|---|
| `--base <REF>` | `HEAD` | One ref, not a range |
| `--preset <NAME>` | `quick` | This runs after every turn |
| `--fail-on <LEVEL>` | `high` | Not `scan`'s `info`: see below |
| `--min-confidence <L>` | `likely` | `possible` never blocks, at any setting |
| `--fail-on-exposure <R>` | unset | Composes with `--fail-on` as an OR |
| `--hook <HOST>` | unset | `claude-code`, `cursor`, `generic` |
| `--record` | off | Append to `.owlwarden/turns.jsonl` |
| `--no-surface` | off | Skip the agent-execution-surface read |
| `--format <F>` | `pretty` | `pretty` or `json` only |

Every finding is one of three states:

| state | meaning | can fail the turn |
|---|---|---|
| `introduced` | present now, absent at the base | **yes** |
| `carried` | present in both | no, at any threshold |
| `fixed` | present at the base, absent now | no |

**Carried findings never fail a turn.** Everything introduced is reported
whether or not it blocks; `blocking` in the JSON is the subset that met the
gate, and the verdict is `blocked` exactly when it is non-zero.

The defaults are stricter than `scan`'s because the command runs in a different
place. `scan --fail-on info` is a report you read; `turn --fail-on high` is a
control that interrupts someone.

Exit codes are the usual `0` / `1` / `2`. Under `--hook` the exit code is the
host's, and stdout carries the host's JSON and nothing else.

**Requires a git repository.** The verdict is a comparison and the base of the
comparison is a commit; outside a repository the command refuses rather than
inventing one. Over 400 changed files it also refuses — that is a merge or a
reformat, not a turn.

**Your index and working tree are never touched.** The base tree is laid out
with `read-tree` into a private `GIT_INDEX_FILE` and `checkout-index` into a
temporary directory, so `git status` is byte-identical across a run.

## `scan` / `watch`

| Flag | Default | Notes |
|---|---|---|
| `--preset` | `quick` | `quick`, `owasp-top10`, `deep`, `agent-surface` |
| `--format` | `pretty` (`json` under `--ci`) | Repeatable: `pretty`, `json`, `sarif`, `junit`, `md`, `agent` |
| `--out` | stdout | File, or prefix/directory when several machine formats |
| `--fail-on` | `info` | `high` / `medium` / `low` / `info` |
| `--min-confidence` | `possible` | `confirmed` / `likely` / `possible` |
| `--since <REF>` | off | Scan only what changed since a git ref, plus untracked files |
| `--staged` | off | Scan only what is staged |
| `--paths <A,B>` | off | Scan only these paths. Repeatable, comma-separated |
| `--budget <N>` | 1500 | `--format agent` only: the token ceiling |
| `--max-findings <N>` | none | `--format agent` only: a cap applied before the budget |
| `--ci` | off | JSON + quiet; ignores project mute switches unless `allow-*` |
| `--target` | off | Passive probes. Operator-only; never from config |
| `--allow-active` | off | Requires `--target`. Staging only |
| `--osv` / `--osv-db` / `--offline` | off | Lockfile advisories; `--offline` needs `--osv-db` |
| `--fix` | off | Safe highlight replacements only. Not with `--ci` |
| `--plugin` | none | Repeatable. `--ci` also needs `--allow-plugins` |

`--since`, `--staged`, and `--paths` each narrow the scan a different way;
passing more than one is an error rather than a guess.

**A narrowing flag that cannot narrow is an error, not a full scan.** A
`--since` naming a ref git cannot resolve exits `2`. It used to print a note and
scan everything, which in CI on a shallow clone turns "three new findings" into
a red job full of pre-existing debt — the usual cause is `actions/checkout`
defaulting to `fetch-depth: 1`, and the error says so. `--since` takes one ref;
a range like `main..HEAD` is refused, because it would widen the scope the flag
was asked to cut. `gate` degrades instead of failing, on purpose: a hook that
bricks a session over a git hiccup gets uninstalled.

**A diff scope is not a baseline.** A baseline suppresses known findings across
a full scan; `--since` narrows what is looked at. Using either to imply the
other is a bug, and there is a fixture for it. The scope is stated in every
format — `12 files · 3 config · since HEAD` in the summary line,
`target.diffScope` in the JSON — so a narrowed clean result can never be
mistaken for a clean repository.

Project-scope rules run when **their own declared inputs** changed, whatever
else did. A commit touching only `package.json` still fires
`unpinned-dependency`; a commit touching only `.claude/settings.json` still
fires the agent rules.

`watch` is static-only: it refuses `--target` and `--osv`, and it owns its own
incrementality, so it ignores the diff-scope flags.

Exit codes: `0` clean · `1` findings at or above `--fail-on` (or truncated) ·
`2` could not run. Canonical table: [ci.md](../how-to/ci.md).

## `vet`

`scan` with a fixed posture, for a repository you did not write.

| Setting | Under `vet` |
|---|---|
| Preset | `agent-surface` |
| `--fail-on` | `high` (the one knob left; it is the operator's call) |
| `--min-confidence` | `likely` |
| Network | none — no OSV, no `--target`, no exceptions |
| Plugins | not loaded, even signed ones, even with a trust root configured |
| The target's config file | **not read at all** |
| The target's baseline | not applied |
| Inline suppressions | counted and reported, never honoured |

`--plugin`, `--target`, `--osv`, `--baseline`, `--allow-suppressions`,
`--allow-project-config`, and `--allow-config-js` are **errors** under `vet`,
not no-ops. A flag that appears to work and does not is worse than one that is
rejected.

A non-zero suppression count is printed on the summary line. "This repository
carries four inline suppressions, which vet counted and did not honour" is the
most useful sentence `vet` can produce about a tree nobody has read.

## `gate`

The hook entry point. Reads the host's event JSON on **stdin**.

| Flag | Default | Notes |
|---|---|---|
| `--host` | required | `claude-code`, `cursor`, `generic` |
| `--since <REF>` | off | At a turn boundary, scan what changed since this ref |
| `--fail-on` | `high` | A gate that blocks on everything gets removed in week one |
| `--min-confidence` | `likely` | A gate that blocks on a heuristic gets removed in week two |
| `--event <FILE>` | stdin | Read the event from a file instead. For tests and for hosts that pass a path |

| Environment | Effect |
|---|---|
| `OWLWARDEN_GATE_FAIL=closed` | A gate failure *after* an edit denies instead of allowing. Off by default |
| `OWLWARDEN_GATE_TIMEOUT_MS` | The gate's own ceiling. Default 5000 |

**Exit codes with `--host generic`:** `0` allow · `1` deny · `2` ask, or the
gate could not run. The vendor adapters carry the verdict in their JSON and
always exit `0`, because a non-zero exit means something else to those hosts.

**The failure posture is not configurable in one direction.** Before a command
executes, a gate that fails returns `ask` — nothing runs on a coin flip. After
an edit or at a turn boundary it returns `allow` and writes to stderr, because
nothing has executed, CI is still behind it, and bricking a session over a
scanner timeout is how the hook gets uninstalled.

**Posture is tighten-only.** Project-level owlwarden config may lower `failOn`
or `minConfidence`; an attempt to raise either is refused and reported. A
repository cannot disable its own gate by editing a file in the repository.

**Suppressions written during the session are not honoured**, and are reported.
Ones the team committed still work.

## `verify`

| Flag | Default | Notes |
|---|---|---|
| `--patch <FILE>` | required | A unified diff |
| `--rule <ID>` | any | The finding the patch is supposed to resolve |
| `--fail-on` | `medium` | Severity at or above which a *new* finding fails the verification |

Exits `0` only if the originating finding is gone **and** no new finding at or
above the threshold appeared. A patch that trades a `stack-trace-leak` for an
`open-redirect` fails.

The patch is applied to a scratch copy; your working tree is never touched.
Paths naming `..`, an absolute location, anything under `.git/`, or a NUL byte
are refused before `git apply` sees them, and symlinks are excluded from the
copy rather than followed.

## `init`

With a host flag, wires the gate into that host. With no flags, writes the
adoption kit. The two sets are independent.

| Flag | Writes |
|---|---|
| `--claude-code` | `.claude/settings.json` hooks, `.mcp.json` entry |
| `--cursor` | `.cursor/hooks.json`, `.cursor/mcp.json`, `.cursor/rules/owlwarden.mdc` |
| `--generic` | `.owlwarden/gate.sh` |
| `--agent-rules` | `.owlwarden/agent-rules.md` (`--out` overrides) |
| `--workflow` | `.github/workflows/owlwarden.yml` |
| `--mcp` | `.cursor/mcp.json` (merges `mcpServers.owlwarden`) |
| `--force` | Replace files owlwarden did not generate |

Existing files are shown as a diff and left alone unless `--force`. Paths must
stay under the working directory, and symlinked destinations are refused.

**No `SessionStart` hook is ever written**, and the MCP entry is
`node_modules/.bin/owlwarden` rather than `npx -y`. Those are the two shapes
`agent-hook-autoexec` and `agent-mcp-unpinned-remote` report; generating them
would have `owlwarden scan` reporting its own output.

## Config file

`owlwarden.config.json` in the scan root, or an `owlwarden` key in
`package.json`. With `--allow-config-js`, also `.ts` / `.mts` / `.mjs` / `.js`.

| Key | Default | Notes |
|---|---|---|
| `preset` | `quick` | `quick`, `owasp-top10`, `deep`, `agent-surface` |
| `failOn` | `info` | `high` / `medium` / `low` / `info` |
| `minConfidence` | `possible` | `confirmed` / `likely` / `possible` |
| `format` | `pretty` | `pretty`, `json`, `sarif`, `junit`, `md` |
| `rules.<id>.enabled` | on | Turn one rule off |
| `rules.<id>.severity` | the rule's | Report at a different severity |

**Unknown keys are refused.** They used to be stripped, which meant `failon:
"high"` parsed and the run used `info` — a config that reads as if it tightens
and does not, with nothing printed anywhere. A near miss is named in the error.

**Config is never read through a symlink**, and a symlink found where a config
would be is reported rather than skipped in silence. Config is never read from
above the scan root; `vet` does not read it at all.

## `mcp`

Stdio JSON-RPC. Tools: `scan_project`, `scan_file`, `explain_rule`,
`list_rules`. Read-only, static, workspace-scoped. Not loaded by `gate` or
`vet` at all.
