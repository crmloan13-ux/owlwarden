# CLI reference

Values and defaults. Task-oriented steps live in [how-to](../how-to/) and
[tutorials](../tutorials/).

```
owlwarden scan [PATH] [OPTIONS]
owlwarden watch [PATH] [OPTIONS]
owlwarden mcp [PATH]
owlwarden init [--agent-rules] [--workflow] [--mcp] [--force] [--out FILE]
owlwarden rules [--json]
owlwarden coverage [--json]
owlwarden explain <RULE_ID> [--json]
owlwarden plugin scaffold <NAME>
owlwarden plugin inspect <PATH>
owlwarden osv update [PATH] [--out FILE]
```

`owlwarden --help` prints the same list with the presets compiled into this
build. `owlwarden --version` prints the engine version.

## `scan` / `watch`

| Flag | Default | Notes |
|---|---|---|
| `--preset` | `quick` | `quick`, `owasp-top10`, `deep` |
| `--format` | `pretty` (`json` under `--ci`) | Repeatable: `pretty`, `json`, `sarif`, `junit`, `md` |
| `--out` | stdout | File, or prefix/directory when several machine formats |
| `--fail-on` | `info` | `high` / `medium` / `low` / `info` |
| `--min-confidence` | `possible` | `confirmed` / `likely` / `possible` |
| `--ci` | off | JSON + quiet; ignores project mute switches unless `allow-*` |
| `--target` | off | Passive probes. Operator-only; never from config |
| `--allow-active` | off | Requires `--target`. Staging only |
| `--osv` / `--osv-db` / `--offline` | off | Lockfile advisories; `--offline` needs `--osv-db` |
| `--fix` | off | Safe highlight replacements only. Not with `--ci` |
| `--plugin` | none | Repeatable. `--ci` also needs `--allow-plugins` |

`watch` is static-only: it refuses `--target` and `--osv`.

Exit codes: `0` clean · `1` findings at or above `--fail-on` (or truncated) ·
`2` could not run. Canonical table: [ci.md](../how-to/ci.md).

## `init`

No flags writes all three files. A flag selects a subset.

| Flag | File |
|---|---|
| `--agent-rules` | `.owlwarden/agent-rules.md` (`--out` overrides) |
| `--workflow` | `.github/workflows/owlwarden.yml` |
| `--mcp` | `.cursor/mcp.json` (merges `mcpServers.owlwarden`) |
| `--force` | Replace files owlwarden did not generate |

Paths must stay under the working directory. Symlinked destinations are
refused.

## `mcp`

Stdio JSON-RPC. Tools: `scan_project`, `scan_file`, `explain_rule`,
`list_rules`. Read-only, static, workspace-scoped.
