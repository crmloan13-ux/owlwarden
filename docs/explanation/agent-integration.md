# Serving AI agents as users

**Status:** partly shipped. `--format json` and `explain` work today. The MCP
server, editor hooks, and `--fix` are designed and scheduled for v0.2 and v0.3
(see [ROADMAP.md](../../ROADMAP.md)). This document describes the whole design
so the parts that exist can be understood in context; each section says where it
stands.

If you are an agent working *on* this repository rather than using it, read
[AGENTS.md](../../AGENTS.md).

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

`@owlwarden/sdk` publishes zod schemas for that output, checked against the Rust
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

## `owlwarden mcp` — planned, v0.2

An MCP server, so an agent can call owlwarden mid-task instead of shelling out
and parsing text.

| Tool | Purpose |
|---|---|
| `scan_project` | Scan the workspace; return findings as JSON |
| `scan_file` | Scan one file — cheap enough for an edit loop |
| `explain_rule` | Full rationale and every framework's fix, for one rule |
| `list_rules` | The catalogue, so an agent can check itself before writing |

The surface is deliberately narrow, because an autonomous process drives it:

- **Read-only.** The MCP server never writes files. Applying fixes is a separate
  action a person takes.
- **Static engine only**, unless the user has explicitly enabled dynamic
  scanning for the project. An agent must not be able to cause network probes as
  a side effect of asking a question.
- **`--allow-active` is unreachable.** State-changing checks cannot be triggered
  through MCP at all.
- **Project-scoped.** Paths outside the workspace root are refused.

## Editor and agent hooks — planned, v0.2

- A documented post-edit hook that runs a single-file scan on what changed and
  feeds the findings back into the agent's context, so a problem is caught in
  the same turn it was written.
- `owlwarden watch --format json`, a stream of findings for any tool to consume.
- `owlwarden init --agent-rules`, which writes a short rules file describing the
  security conventions of *this* codebase — "never return `err.stack`; use the
  shared `apiError()` helper" — derived from the enabled rule set. Prevention is
  cheaper than detection.
- An LSP mode is a candidate after v1, for people not working with agents.

## `--fix` — planned, v0.3

Many findings have one obvious correct patch, and applying it should be one
command.

```bash
owlwarden scan --fix           # safe fixes only
owlwarden scan --fix --dry-run # show the diff, change nothing
```

The rules around it exist because this is the feature most able to do harm:

- Every `Fix` declares `safety: Safe | Unsafe | Manual`. Only `Safe` applies
  without `--fix-unsafe`, and `Safe` means it cannot change behaviour beyond
  removing the vulnerability.
- **Never on a `Possible` finding.** Low confidence plus automatic edits is how
  a tool destroys a codebase and its own reputation in one command.
- Fixes apply to a clean git tree by default, so every change is trivially
  reversible.
- After applying, re-scan and report what remains. Never claim success without
  checking.

## The failure mode this design guards against

There is an obvious way agent-driven security tooling goes wrong: the agent sees
findings, "fixes" them by suppressing them, and reports success. Nothing about
that is malicious — suppression is the cheapest path to a green run.

So:

- **Suppression requires a reason string.** An agent has to state a
  justification, and a human reads it in the diff.
- **`--report-suppressions`** lists every suppression, and CI can fail on a net
  increase.
- **`suppressedCount` is in the JSON**, so "0 findings" is never mistaken for
  "0 problems".
- The documentation says plainly, to humans and agents alike: suppression is a
  judgement call that a human owns.

## What this asks of the rest of the tool

Three constraints elsewhere in the codebase exist because of this design:

- **Remediation must be complete offline and inline.** An agent has no browser.
- **`confidence` must be honest**, or both autofix and agent trust collapse.
  This is why `DetectorMeta::max_confidence` is a declared field.
- **Single-file scans must be fast** — under 300 ms — or they do not fit an edit
  loop. That is where the performance budget in
  [ARCHITECTURE.md](../../ARCHITECTURE.md) §12 comes from.
