import { ArgError, parse } from "./args.js";
import { runCoverage } from "./commands/coverage.js";
import { runExplain } from "./commands/explain.js";
import { runRules } from "./commands/rules.js";
import { runScan } from "./commands/scan.js";
import { EXIT } from "./exit.js";
import { helpText } from "./help.js";
import { loadNative, NativeLoadError, type NativeEngine } from "./native.js";

/** Streams the CLI writes to. Injected so tests do not have to touch `process`. */
export interface Streams {
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
}

/**
 * Runs one command and returns its exit code.
 *
 * Nothing here calls `process.exit`; `bin.ts` owns that. Every path returns a
 * code, which is what makes the whole CLI testable in-process.
 */
export async function run(argv: string[], streams: Streams): Promise<number> {
  const { stdout, stderr } = streams;

  let cli: ReturnType<typeof parse>;
  try {
    cli = parse(argv);
  } catch (error) {
    if (error instanceof ArgError) {
      stderr.write(`error: ${error.message}\n\nRun \`owlwarden --help\`.\n`);
      return EXIT.ERROR;
    }
    throw error;
  }

  // Help is the one command that must work on a broken install.
  let native: NativeEngine | undefined;
  try {
    native = loadNative();
  } catch (error) {
    if (!(error instanceof NativeLoadError)) throw error;
    if (cli.command !== "help") {
      stderr.write(`error: ${error.message}\n`);
      return EXIT.ERROR;
    }
  }

  switch (cli.command) {
    case "help":
      stdout.write(helpText(native));
      return EXIT.CLEAN;
    case "version":
      stdout.write(`owlwarden ${native?.engineVersion() ?? "unknown"}\n`);
      return EXIT.CLEAN;
    case "rules":
      return runRules(mustLoad(native), cli.json, stdout);
    case "coverage":
      return runCoverage(
        mustLoad(native),
        { json: cli.json, color: cli.color, unicode: cli.unicode },
        stdout,
      );
    case "explain":
      return runExplain(mustLoad(native), cli.rule, cli.json, stdout, stderr);
    case "scan":
      return runScan(mustLoad(native), cli.options, stderr, stdout);
  }
}

/**
 * Asserts the engine loaded.
 *
 * Only `help` tolerates a missing engine, and the branch above has already
 * returned in that case; this narrows the type without a second error path that
 * would never run.
 */
function mustLoad(native: NativeEngine | undefined): NativeEngine {
  if (!native) throw new NativeLoadError("the owlwarden engine is not available");
  return native;
}
