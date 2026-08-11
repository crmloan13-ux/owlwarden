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
  owlwarden mcp [PATH]
  owlwarden init --agent-rules [--out FILE]
  owlwarden watch [PATH] [OPTIONS]
  owlwarden rules [--json]
  owlwarden coverage [--json] [--no-color] [--ascii]
  owlwarden explain <RULE_ID> [--json]
  owlwarden plugin scaffold <NAME>
  owlwarden plugin inspect <PATH>

  Local only. No telemetry. --target is opt-in (scoped; deny by default).

  mcp — stdio MCP for coding agents (scan / explain / list rules; static, read-only).
        On a TTY it prints a how-to on stderr and then waits; silence means it
        is waiting for a host, not hung. Under a host, stderr gets a ready line.
  init --agent-rules — writes .owlwarden/agent-rules.md from the catalogue.
  Prefer --format json for CI and agents.
  plugin scaffold writes a WASM guest stub + manifest.
  plugin inspect prints capabilities from owlwarden.plugin.json (no WASM load).

  coverage shows which OWASP categories have rules, and which do not.

  watch re-scans on change. Static only — never opens a network path.

SCAN OPTIONS
  --preset <NAME>       Rule bundle to run
${presetLines(native)}
  --format <FORMAT>     pretty (default), json, sarif, or junit
  --out <FILE>          Write the report to a file instead of stdout
  --baseline <FILE>     Report only findings new since this baseline
  --write-baseline <F>  Write current findings to a baseline file
  --report-suppressions List every inline suppression; flag stale ones
  --allow-config-js     Load owlwarden.config.{js,mjs,ts,mts} via import()
  --allow-project-config  Under --ci, honour project preset/fail-on/min-confidence
  --allow-suppressions  Under --ci, honour inline suppressions (off by default)
  --allow-baseline      Under --ci, permit --baseline (off by default)
  --fail-on <LEVEL>     Exit 1 at this severity or above. Default: info
  --min-confidence <L>  Drop findings below this confidence. Default: possible
  --target <URL>        Probe this URL (passive GET/HEAD). Operator-only —
                        never read from project config
  --scope <URL>         Allowlist entry (repeatable). Default: origin of --target
  --plugin <PATH>       Load a WASM detector (repeatable). Directory with
                        owlwarden.plugin.json + plugin.wasm, or a bare .wasm
                        with a sidecar manifest. Sandboxed; source-only in v0.2
  --allow-plugins       Under --ci, permit --plugin (off by default)
  --fix                 Apply Safe highlight replacements (never on Possible).
                        Requires a clean git tree unless --allow-dirty
  --fix-unsafe          With --fix, also apply Unsafe remediations
  --dry-run             With --fix, show changes without writing
  --allow-dirty         With --fix, allow a dirty working tree
  --allow-active        With --target, permit state-changing HTTP methods.
                        No first-party detector uses this yet
  --osv                 Opt into Google OSV lockfile advisory lookup
                        (sends name+version to api.osv.dev; never source)
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
