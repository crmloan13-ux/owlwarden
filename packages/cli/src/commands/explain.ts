import { ruleExplanationSchema } from "@dointhai/owlwarden-sdk";

import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";

/**
 * Prints everything known about one rule.
 *
 * Complete and offline, by design: the reader may be an agent with no browser
 * (`AGENTS.md` §6), so "see the docs" is not an acceptable answer here.
 */
export function runExplain(
  native: NativeEngine,
  ruleId: string,
  json: boolean,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): number {
  const raw = native.explainRule(ruleId);
  if (raw === null) {
    stderr.write(`error: no rule ${JSON.stringify(ruleId)}. Run \`owlwarden rules\`.\n`);
    return EXIT.ERROR;
  }

  if (json) {
    stdout.write(`${raw}\n`);
    return EXIT.CLEAN;
  }

  const { meta, fixes, references } = ruleExplanationSchema.parse(JSON.parse(raw));

  const lines: string[] = [
    `${meta.title}  (${meta.id})`,
    "",
    `severity    ${meta.severity}`,
    `confidence  at most ${meta.maxConfidence}`,
    `category    ${meta.category}`,
  ];
  if (meta.owasp !== undefined) lines.push(`owasp       ${meta.owasp}`);
  if (meta.cwe !== undefined) lines.push(`cwe         CWE-${meta.cwe}`);
  lines.push("", meta.description, "", "FIXES");

  for (const fix of fixes) {
    lines.push("", `  [${fix.framework ?? "any"}] ${fix.summary}`);
    if (fix.patch !== undefined) {
      for (const line of fix.patch.split("\n")) lines.push(`      ${line}`);
    }
  }

  lines.push("", "REFERENCES");
  for (const reference of references) {
    lines.push(`  ${reference.id}  ${reference.url}`);
  }

  stdout.write(`${lines.join("\n")}\n`);
  return EXIT.CLEAN;
}
