import { presetInfoListSchema } from "@dointhai/owlwarden-sdk";

import type { NativeEngine } from "./native.js";

/**
 * The help text, in two tiers.
 *
 * # Why two
 *
 * The full listing is eleven commands and sixty flags, and every one of them is
 * there because somebody needed it. Printed all at once it is a wall, and the
 * cost lands on exactly the wrong person: someone who has run `npx owlwarden`
 * for the first time and is looking for the one command that answers their
 * question. Everything a first run needs is in the default text; `help --all`
 * has the rest, and nothing was removed.
 *
 * Presets come from the engine so the list is never stale. If the engine cannot
 * be loaded, help still prints — someone whose install is broken needs the help
 * text more than most, not less.
 */
export function helpText(native: NativeEngine | undefined, all = false): string {
  return all ? fullHelp(native) : shortHelp(native);
}

/** The default: what a first run needs, and where the rest is. */
function shortHelp(native: NativeEngine | undefined): string {
  return `owlwarden ${native?.engineVersion() ?? ""} — the deterministic security floor for Node
and for the coding agent working in your repository.

USAGE
  owlwarden turn                    what did this turn change?   ← start here
  owlwarden scan [PATH]             every rule, the whole repository
  owlwarden vet [PATH]              someone else's repo, before you open it
  owlwarden init --claude-code      wire it into the agent loop

  Runs on your machine. No account, no telemetry, no network unless you ask.

  turn — scans the files this turn touched, scans the same files at the last
        commit, and reports only what you just introduced. Findings that
        were already there are counted on one line and never printed: a gate
        that blocks on debt the turn did not create is a gate that gets
        removed, and everything it would have caught goes with it.
        --base <REF>       compare against this instead of HEAD
        --hook <HOST>      answer in a host's hook shape (claude-code, cursor,
                           generic) instead of on a terminal
        --record           append the verdict to .owlwarden/turns.jsonl
        --fail-on <LEVEL>  what blocks a turn. Default: high
  scan — the whole repository, both surfaces, one exit code. Every finding
        carries a fix written for your framework, and an \`exposure\` saying
        whether an anonymous caller can reach it.
        --since <REF>  --staged  --fix  --format <F>  --fail-on <LEVEL>
  vet  — a repository you did not write, before you open it in an editor.
        Agent-surface rules only, offline, and the target's own config,
        baseline, and suppressions are counted rather than honoured.
  init — writes the hooks and the MCP entry for one host. Never a SessionStart
        hook: repository config that runs on open is what this tool reports.

EXIT CODES
  0  clean        1  findings at or above --fail-on        2  could not run

MORE
  owlwarden help --all        every command and every flag
  owlwarden explain <RULE>    one rule, in full, offline
  owlwarden coverage          what it finds — and what it does not
  owlwarden rules             the whole catalogue

  Docs: https://suthat.github.io/owlwarden/
`;
}

/** Everything. Reached by \`owlwarden help --all\`. */
function fullHelp(native: NativeEngine | undefined): string {
  return `owlwarden ${native?.engineVersion() ?? ""} — security scanner for Node apps (MCP-ready)

USAGE
  owlwarden turn [PATH] [OPTIONS]      what did this turn change?
  owlwarden scan [PATH] [OPTIONS]
  owlwarden vet [PATH]                 check a repo before you open it
  owlwarden gate --host <HOST> [PATH]  hook entry point; event JSON on stdin
  owlwarden seal [PATH] [OPTIONS]      lock the agent's execution surface
  owlwarden effective [PATH] --host <HOST>   which file is deciding this?
  owlwarden verify --patch <FILE>      did this fix actually fix it?
  owlwarden mcp [PATH]
  owlwarden init [--claude-code|--cursor|--generic] [--force]
  owlwarden init [--agent-rules] [--workflow] [--mcp] [--out FILE]
  owlwarden watch [PATH] [OPTIONS]
  owlwarden rules [--json]
  owlwarden coverage [--json] [--no-color] [--ascii]
  owlwarden explain <RULE_ID> [--json]
  owlwarden plugin scaffold <NAME>
  owlwarden plugin inspect <PATH>
  owlwarden osv update [PATH] [--out FILE]

  Local only. No telemetry. --target is opt-in (scoped; deny by default).

  turn — the loop-closer. Scans the paths that changed since --base (default
        HEAD), scans the same paths at that commit, and diffs the two by the
        baseline fingerprint. Introduced findings are reported in full and are
        the only ones that can fail the turn; carried findings are counted;
        fixed findings are named, because that is the only line in this tool
        that reports something going right.
        --base <REF>            what to measure against. Default: HEAD
        --hook <HOST>           answer in claude-code / cursor / generic hook
                                shape, through the same adapters \`gate\` uses
        --record                append to .owlwarden/turns.jsonl (last 200)
        --no-surface            skip the agent-execution-surface read
        --format pretty|json    not sarif: a SARIF upload describing seven
                                files would overwrite the repository's findings
        --fail-on <LEVEL>       default high, not scan's info: this runs after
                                every turn, and a gate that stops an agent on a
                                passing medium is a gate somebody disables
        The base is a commit, so the verdict is exactly as trustworthy as the
        commit is. An agent that can commit can move the anchor; the base is
        printed on every line for that reason.
  vet — scan a repository you did not write. Agent-surface rules only, offline,
        no plugins, and the target's own config, baseline, and suppressions are
        counted and reported rather than honoured. Every mechanism that makes
        adoption realistic on your repository is, on someone else's, a way to
        hide a finding.
  gate — the deterministic control. Reads the host's event on stdin, scans what
        it names, and returns a verdict the model cannot argue with, because the
        prompt is not this process's input. A tool the model *may* call is not a
        control that *always* runs.
        --host claude-code | cursor | generic. \`generic\` is owlwarden's own
        event and decision JSON and works with anything that runs a process.
  seal — records .owlwarden/surface.lock: every file the agent loads out of the
        working tree, by semantic digest, with its hooks, MCP servers, and
        permission set extracted so the diff reads as a sentence rather than as
        "settings.json changed". Your dependencies have a lockfile; your agent's
        execution surface did not.
        --verify   exit 0 if unchanged, 1 on drift, 2 if it could not run
        --diff     show what changed without writing, and never exit non-zero
        --accept <FINGERPRINT> --reason <TEXT>   repeatable, in pairs
        --trust <FILE>          trust roots for the detached signature
        --require-signed-seal   an unsigned or untrusted seal fails --verify
        --yes      proceed without a terminal
        Sealing is never unattended, and that raises the cost for whatever wrote
        the drift rather than closing the hole. SECURITY.md says which.
  effective — \`git config --show-origin\` for your agent. Prints the resolved
        configuration with provenance per key: which file won, and which lost.
        --host <HOST>  --key <KEY>  --include-user-config
        A value that won from outside the project root renders as
        \`(set by user settings)\`; it is never printed. Nor are the names of
        keys only a higher tier sets — a key name is contents too.
  verify — apply a patch to a scratch copy, re-scan, and exit 0 only if the
        finding is gone AND nothing new appeared at or above the threshold.
        A fix that trades a stack-trace-leak for an open-redirect fails.
  mcp — stdio MCP for coding agents (scan / explain / list rules; static, read-only).
        On a TTY it prints a how-to on stderr and then waits; silence means it
        is waiting for a host, not hung. Under a host, stderr gets a ready line.
  init — with a host flag, wires the gate into that host's lifecycle events.
        With no flags, writes the adoption kit (agent-rules, GitHub Action
        workflow, Cursor MCP). Existing files are shown as a diff and left
        alone unless --force.
        No SessionStart hook is ever written: repository config that runs on
        open is what \`agent-hook-autoexec\` reports, and shipping the rule while
        writing the entry would be indefensible.
  Prefer --format json for CI and agents. Repeat --format to emit several
  renderings from one scan (e.g. --format pretty --format sarif --out results).
  plugin scaffold writes a WASM guest stub + manifest.
  plugin inspect prints capabilities from owlwarden.plugin.json (no WASM load).

  coverage shows which OWASP categories have rules, and which do not.

  watch re-scans on change. Static only — never opens a network path.

SCAN OPTIONS
  --preset <NAME>       Rule bundle to run
${presetLines(native)}
  --format <FORMAT>     Output format (repeatable): pretty, json, sarif, junit,
                        md, agent
  --since <REF>         Scan only what changed since this git ref
  --staged              Scan only what is staged
  --paths <A,B>         Scan only these paths (repeatable, comma-separated)
  --budget <N>          With --format agent, the token ceiling (default 1500)
  --max-findings <N>    With --format agent, a hard cap applied before the budget
  --out <FILE|DIR>      Write machine output to a file, or a prefix / directory
                        when several machine formats are requested
  --baseline <FILE>     Report only findings new since this baseline
  --write-baseline <F>  Write current findings to a baseline file
  --report-suppressions List every inline suppression; flag stale ones
  --allow-config-js     Load owlwarden.config.{js,mjs,ts,mts} via import()
  --allow-project-config  Under --ci, honour project preset/fail-on/min-confidence
  --allow-suppressions  Under --ci, honour inline suppressions (off by default)
  --allow-baseline      Under --ci, permit --baseline (off by default)
  --fail-on <LEVEL>     Exit 1 at this severity or above. Default: info
  --fail-on-exposure <REACH>
                        Exit 1 at this reachability or above: internet,
                        authenticated, internal, unknown. Composes with
                        --fail-on as an OR.
  --min-confidence <L>  Drop findings below this confidence. Default: possible
  --target <URL>        Probe this URL (passive GET/HEAD). Operator-only —
                        never read from project config
  --scope <URL>         Allowlist entry (repeatable). Default: origin of --target
  --plugin <PATH>       Load a WASM detector (repeatable). Directory with
                        owlwarden.plugin.json + plugin.wasm, or a bare .wasm
                        with a sidecar manifest. Sandboxed; source-only
  --allow-plugins       Under --ci, permit --plugin (off by default)
  --require-signed-plugins  Refuse plugins without a verified .sig (ADR 0021)
  --fix                 Apply Safe highlight replacements (never on Possible).
                        Requires a clean git tree unless --allow-dirty
  --fix-unsafe          With --fix, also apply Unsafe remediations
  --dry-run             With --fix, show changes without writing
  --allow-dirty         With --fix, allow a dirty working tree
  --allow-active        With --target, permit state-changing HTTP methods.
                        Staging only. Enables csrf-cross-origin-post.
  --osv                 Opt into Google OSV lockfile advisory lookup
                        (sends name+version to api.osv.dev; never source)
  --osv-db <PATH>       Use a cached OSV index file (no network)
  --offline             With --osv, require --osv-db (fail closed)
  --ci                  JSON + quiet + no-color; also ignores project gates,
                        suppressions, and --baseline unless allow-* is set
  --no-color            Disable colour (NO_COLOR is honoured too)
  --ascii               ASCII output for terminals without reliable UTF-8
  --hyperlinks          Emit OSC-8 links, if your terminal supports them
  -q, --quiet           No banner, no progress

CONFIG
  owlwarden.config.json, or an "owlwarden" key in package.json. Executable
  configs (.js/.mjs/.ts/.mts) need --allow-config-js — scanning an untrusted
  tree must not execute attacker code. Flags override the config file. Zero
  config is fine. --target / --scope are never taken from config.

EXIT CODES
  0  nothing at or above --fail-on
  1  findings at or above --fail-on
  2  the scan could not run

Without --target, scans are static-only and never touch the network.
With --target, only passive methods are used; scope is deny-by-default.
`;
}

function presetLines(native: NativeEngine | undefined): string {
  if (!native) return "                        (engine not loaded)";
  try {
    const presets = presetInfoListSchema.parse(JSON.parse(native.listPresets()));
    return presets
      .map((preset) => `      ${preset.name.padEnd(16)}${preset.description}`)
      .join("\n");
  } catch {
    return "                        (engine not loaded)";
  }
}
