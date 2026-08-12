# Serving AI agents as users

**Status:** v1.0 surface is shipped. `--format json` / `sarif` / `junit` / `md`,
`explain`, `owlwarden mcp`, `init` (adoption kit), `--fix` (CLI only), opt-in
`--osv`, and `plugin inspect` work today. Editor post-edit hooks remain later.
Each section below says what is live.

If you are an agent working *on* this repository rather than using it, read
[AGENTS.md](../../AGENTS.md).

---

## Save tokens first; spend frontier models on the hard parts

Baseline security checks are a poor use of model tokens. Run owlwarden locally
(fast, offline, same rules every time) so an agent does not re-ask “did we leak
a stack?” on every edit. Keep a frontier model for architecture, authorization
boundaries, payments, personal data, and the decisions a parser cannot make.
Floor first; judgment on top.

---

## Why the output format is not an afterthought

Traditional security tooling assumes a human reads a report, thinks, and edits.
When an agent is in the loop, the agent reads the report and edits. That changes
what good output is:

| Written for a human | Written for an agent |
|---|---|
| Colour, box drawing, alignment | Deterministic, parseable, no ANSI |
| "See the docs for details" | The remediation, complete and inline |
| Prose explanation | A precise location and the replacement text |
| A prioritised list to read | A prioritised list with an applicable fix |

owlwarden serves both from one finding model. The agent path is `--format json`,
plus two things that most tools do not carry: an inline fix and an honest
confidence.

The second matters more than it looks. An agent cannot judge whether a finding
is a guess — it has no prior about the codebase and no reason to doubt a
confident-sounding report. If `confidence` is inflated, an agent will act on
noise, and the resulting damage is attributed to the tool that reported it. See
[false-positives.md](false-positives.md).

## Machine-readable output — shipped

```bash
owlwarden scan --format json
```

`@dointhai/owlwarden-sdk` publishes zod schemas for that output, checked against the Rust
engine on every CI run, so the types cannot describe a format the tool does not
emit.

Two fields are easy to overlook and worth reading:

- `suppressedCount` — findings a suppression hid. `findings: []` with a non-zero
  count is not a clean project.
- `errors` — rules that failed and files that were skipped. A scan that could
  not read half a project still exits 0 if the half it read was clean.

## `owlwarden explain <rule>` — shipped

The complete write-up for a rule: what it looks for, why it matters, and every
framework's fix, printed to the terminal. No network access, because the reader
may not have any.

```bash
owlwarden explain stack-trace-leak
owlwarden explain stack-trace-leak --json
```

## `owlwarden mcp` — shipped (v0.2)

```bash
owlwarden mcp [PATH]
```

JSON-RPC over stdio. Hand-rolled subset (initialize, tools/list, tools/call) —
no MCP SDK dependency. Wire it into an MCP-capable host the same way you would
any other stdio server.

**If you run it in a terminal and it looks hung:** that is expected. stdout is
the protocol channel; the process waits for the host. On a TTY, stderr prints a
short how-to (host config snippet, tools, Ctrl+C). Under a host, stderr gets a
one-line ready notice. Never put human logs on stdout — that breaks JSON-RPC.

Example host entry:

```json
{
  "mcpServers": {
    "owlwarden": {
      "command": "npx",
      "args": ["owlwarden", "mcp", "."]
    }
  }
}
```

| Tool | Purpose |
|---|---|
| `scan_project` | Scan the workspace; return findings as JSON |
| `scan_file` | Full project scan, filtered to one file — for edit loops |
| `explain_rule` | Full rationale and every framework's fix, for one rule |
| `list_rules` | The catalogue |

Hard limits, because an agent drives it:

- **Read-only.** Never writes files. Applying fixes is outside MCP.
- **Static only.** No `--target`. An agent cannot trigger network probes.
- **`--allow-active` unreachable.**
- **Project-scoped.** Paths outside the workspace root are refused.
- **Prompt-injection hardened.** Every tool result is wrapped in an
  `OWLWARDEN_TOOL_RESULT` envelope that states the payload is DATA, not
  instructions. Strings are stripped of control / invisible characters and
  common chat role markers (`<|im_start|>`, `[INST]`, …). Plugin `why` text
  is sanitised again inside `plugin-host` before it enters a finding. This
  does not make a model immune — it makes scan/plugin prose harder to mistake
  for the host system prompt.

## `owlwarden init` — shipped (v1.0)

```bash
owlwarden init                 # agent-rules + GitHub Action + Cursor MCP
owlwarden init --agent-rules   # → .owlwarden/agent-rules.md
owlwarden init --mcp           # → .cursor/mcp.json (merges mcpServers.owlwarden)
owlwarden init --workflow      # → .github/workflows/owlwarden.yml
```

`--agent-rules` writes a short markdown file from the compiled-in catalogue so
agents load the same rule ids `scan` actually enforces. The file includes an
explicit note that findings / snippets / plugin text are untrusted evidence —
not instructions. Re-run after upgrading the tool. `--force` replaces files
owlwarden did not generate.

## Editor hooks — later

- A documented post-edit hook that runs a single-file check on what changed.
- `owlwarden watch --format json` already streams findings; a thin editor
  wrapper around it is the remaining piece.
- An LSP mode is a candidate after v1.

## `--fix` — shipped (v0.3)

Many findings have one obvious correct patch, and applying it should be one
command.

```bash
owlwarden scan --fix           # safe fixes only
owlwarden scan --fix --dry-run # show the change, write nothing
```

The rules around it exist because this is the feature most able to do harm:

- Every `Fix` declares `safety: Safe | Unsafe | Manual`. Only `Safe` applies
  without `--fix-unsafe`, and `Safe` means a single-line highlight replacement
  that cannot change behaviour beyond removing the vulnerability.
- Multi-line educational patches stay `Manual` and are never auto-applied.
- **Never on a `Possible` finding.** Low confidence plus automatic edits is how
  a tool destroys a codebase and its own reputation in one command.
- Fixes apply to a clean git tree by default, so every change is trivially
  reversible (`--allow-dirty` to override).
- After applying, re-scan and report what remains. Never claim success without
  checking.

## The failure mode this design guards against

There is an obvious way agent-driven security tooling goes wrong: the agent sees
findings, "fixes" them by suppressing them, and reports success. Nothing about
that is malicious — suppression is the cheapest path to a green run.

So:

- **Suppression requires a reason string.** An agent has to state a
  justification, and a human reads it in the diff.
- **`--report-suppressions`** lists every suppression. `suppressedCount` is in
  the JSON so a pipeline *can* fail on a net increase; owlwarden itself does
  not enforce that policy (see [how-to/suppressions.md](../how-to/suppressions.md)).
- **`suppressedCount` is in the JSON**, so "0 findings" is never mistaken for
  "0 problems".
- The documentation says plainly, to humans and agents alike: suppression is a
  judgement call that a human owns.

## What this asks of the rest of the tool

Three constraints elsewhere in the codebase exist because of this design:

- **Remediation must be complete offline and inline.** An agent has no browser.
- **`confidence` must be honest**, or both autofix and agent trust collapse.
  This is why `DetectorMeta::max_confidence` is a declared field.
- **Single-file scans must be fast enough for an edit loop.** Architecture
  §12 targets 300 ms; 1.0 has incremental watch, not a measured CI claim.
  See [docs/how-to/performance.md](../how-to/performance.md).
