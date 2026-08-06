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
  return `owlwarden ${native?.engineVersion() ?? ""} — keen-eyed security auditor

USAGE
  owlwarden scan [PATH] [OPTIONS]
  owlwarden watch [PATH] [OPTIONS]
  owlwarden rules [--json]
  owlwarden coverage [--json] [--no-color] [--ascii]
  owlwarden explain <RULE_ID> [--json]

  coverage reports which OWASP categories the rules reach, and which they do
  not. A gap is stated rather than left blank, because "no findings" and "not
  looked for" are different answers.

  watch re-scans on change. Static only — it never opens a network path.

SCAN OPTIONS
  --preset <NAME>       Rule bundle to run
${presetLines(native)}
  --format <FORMAT>     pretty (default) or json
  --out <FILE>          Write the report to a file instead of stdout
  --baseline <FILE>     Report only findings new since this baseline
  --write-baseline <F>  Write current findings to a baseline file
  --report-suppressions List every inline suppression; flag stale ones
  --allow-config-js     Load owlwarden.config.{js,mjs,ts,mts} via import()
  --allow-project-config  Under --ci, honour project preset/fail-on/min-confidence
  --fail-on <LEVEL>     Exit 1 at this severity or above. Default: info
  --min-confidence <L>  Drop findings below this confidence. Default: possible
  --ci                  Shorthand for --format json --quiet --no-color
                        (also ignores project gate knobs unless --allow-project-config)
  --no-color            Disable colour (NO_COLOR is honoured too)
  --ascii               ASCII output for terminals without reliable UTF-8
  --hyperlinks          Emit OSC-8 links, if your terminal supports them
  -q, --quiet           No banner, no progress

CONFIG
  owlwarden.config.json, or an "owlwarden" key in package.json. Executable
  configs (.js/.mjs/.ts/.mts) need --allow-config-js — scanning an untrusted
  tree must not execute attacker code. Flags override the config file. Zero
  config is fine.

EXIT CODES
  0  nothing at or above --fail-on
  1  findings at or above --fail-on
  2  the scan could not run

Scans are passive: owlwarden reads your source and never touches the network.
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
