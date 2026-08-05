import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";

/**
 * Prints what the shipped rules reach, and what they do not.
 *
 * The table is computed by the engine from the rules compiled into it and
 * rendered there too, so this command cannot flatter the tool and cannot
 * disagree with the native binary's version of the same output.
 */
export function runCoverage(
  native: NativeEngine,
  options: { json: boolean; color: boolean; unicode: boolean },
  stdout: NodeJS.WritableStream,
): number {
  if (options.json) {
    stdout.write(`${native.coverage()}\n`);
    return EXIT.CLEAN;
  }

  stdout.write(
    native.renderCoverage(
      JSON.stringify({ color: options.color, unicode: options.unicode }),
    ),
  );
  return EXIT.CLEAN;
}
