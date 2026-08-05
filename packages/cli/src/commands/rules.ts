import { ruleMetaListSchema, type RuleMeta } from "@dointhai/owlwarden-sdk";

import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";

/**
 * Prints the rule catalogue.
 *
 * The list comes from the engine, not from a table maintained here, so it
 * cannot describe rules the installed engine does not have.
 */
export function runRules(
  native: NativeEngine,
  json: boolean,
  stdout: NodeJS.WritableStream,
): number {
  const raw = native.listRules();
  if (json) {
    stdout.write(`${raw}\n`);
    return EXIT.CLEAN;
  }

  const rules = ruleMetaListSchema.parse(JSON.parse(raw));
  stdout.write(`${rules.length} rule${rules.length === 1 ? "" : "s"}\n\n`);
  for (const rule of rules) {
    stdout.write(`${formatRule(rule)}\n`);
  }
  return EXIT.CLEAN;
}

function formatRule(rule: RuleMeta): string {
  const tags = [rule.severity, rule.category, rule.owasp].filter(Boolean).join("  ");
  return `${rule.id}\n  ${rule.title}\n  ${tags}\n`;
}
