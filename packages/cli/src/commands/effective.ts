import type { EffectiveCliOptions } from "../args.js";
import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";

/** One key, as the engine resolved it. */
interface ResolvedKey {
  key: string;
  value: string;
  winner: string;
  winnerSource: string;
  shadowsProject: boolean;
  losers: { tier: string; source: string }[];
}

/** The engine's answer. */
interface EffectiveResponse {
  ok: boolean;
  error?: string;
  host: string;
  verifiedAgainst: string;
  includeUserConfig: boolean;
  keys: ResolvedKey[];
  keysOnlyAboveRoot: number;
  tiersRead: { tier: string; source: string }[];
  tiersSkipped: string[];
}

/**
 * Runs `owlwarden effective`.
 *
 * A diagnostic, not a check: it exits 0 whenever it could run at all. "Which of
 * these four files is deciding my agent's behaviour" has no good answer in any
 * tool today — developers debug it by deleting files — and the answer is not a
 * pass or a fail.
 */
export function runEffective(
  native: NativeEngine,
  options: EffectiveCliOptions,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): number {
  let response: EffectiveResponse;
  try {
    response = JSON.parse(
      native.effective(
        JSON.stringify({
          projectRoot: options.path,
          host: options.host,
          ...(options.key === undefined ? {} : { key: options.key }),
          includeUserConfig: options.includeUserConfig,
        }),
      ),
    ) as EffectiveResponse;
  } catch (error) {
    stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
    return EXIT.ERROR;
  }

  if (!response.ok) {
    stderr.write(`error: ${response.error ?? "could not resolve the configuration"}\n`);
    return EXIT.ERROR;
  }

  if (options.json) {
    stdout.write(`${JSON.stringify(response, null, 2)}\n`);
    return EXIT.CLEAN;
  }

  stdout.write(
    `\n${options.unicode ? "◉ᴥ◉" : "(o.o)"} effective configuration · ${response.host}` +
      `  (order verified against ${response.verifiedAgainst})\n\n`,
  );
  if (response.keys.length === 0) {
    stdout.write("  (nothing resolved)\n");
  }
  for (const entry of response.keys) {
    stdout.write(`  ${entry.key.padEnd(28)}${entry.value}\n`);
    stdout.write(`  ${"".padEnd(28)}✓ ${entry.winnerSource}  (${entry.winner})\n`);
    for (const loser of entry.losers) {
      const note = entry.shadowsProject && loser.tier === "project" ? "shadowed" : "lost";
      stdout.write(`  ${"".padEnd(28)}✗ ${loser.source}  (${loser.tier}, ${note})\n`);
    }
    stdout.write("\n");
  }
  if (response.keysOnlyAboveRoot > 0) {
    // Counted, never named: a key only a tier above the root sets is a line of
    // the developer's own configuration, not this repository's.
    stdout.write(
      `  ${response.keysOnlyAboveRoot} key(s) set only above this project, not listed\n`,
    );
  }
  if (response.tiersSkipped.length > 0) {
    stdout.write(
      `  not opened: ${response.tiersSkipped.join(", ")} — pass --include-user-config ` +
        "to resolve against them\n",
    );
  }
  return EXIT.CLEAN;
}
