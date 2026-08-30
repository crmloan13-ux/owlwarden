import { presetInfoListSchema } from "@dointhai/owlwarden-sdk";

import type { NativeEngine } from "./native.js";

/**
 * The help text.
 *
 * Presets come from the engine so the list is never stale. If the engine cannot
 * be loaded, help still prints — someone whose install is broken needs the help
 * text more than most, not less.
 */
export function helpText(native: NativeEngine | undefined): string {
  return `owlwarden ${native?.engineVersion() ?? ""} — security scanner for Node apps (MCP-ready)

USAGE
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
