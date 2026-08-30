import { ArgError, parse } from "./args.js";
import { runCoverage } from "./commands/coverage.js";
import { runEffective } from "./commands/effective.js";
import { runExplain } from "./commands/explain.js";
import { runInit } from "./commands/init.js";
import { runMcp } from "./commands/mcp.js";
import { runOsvUpdate } from "./commands/osv-update.js";
import { runPluginInspect } from "./commands/plugin-inspect.js";
import { runPluginScaffold } from "./commands/plugin-scaffold.js";
import { runRules } from "./commands/rules.js";
import { runGate } from "./commands/gate.js";
import { runScan } from "./commands/scan.js";
import { runSeal } from "./commands/seal.js";
import { runVerify } from "./commands/verify.js";
import { runWatch } from "./commands/watch.js";
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
    case "watch":
      return runWatch(mustLoad(native), cli.options, stderr, stdout);
    case "vet":
      return runScan(mustLoad(native), cli.options, stderr, stdout);
    case "gate":
      return runGate(mustLoad(native), cli.options, {
        stdin: process.stdin,
        stdout,
        stderr,
      });
    case "seal":
      return runSeal(mustLoad(native), cli.options, stdout, stderr);
    case "effective":
      return runEffective(mustLoad(native), cli.options, stdout, stderr);
    case "verify":
      return runVerify(mustLoad(native), cli.options, stdout, stderr);
    case "mcp":
      return runMcp(mustLoad(native), cli.path);
    case "init":
      return runInit(
        mustLoad(native),
        {
          hosts: cli.hosts,
          agentRules: cli.agentRules,
          workflow: cli.workflow,
          mcp: cli.mcp,
          force: cli.force,
          ...(cli.out === undefined ? {} : { out: cli.out }),
        },
        process.cwd(),
        stderr,
      );
    case "plugin-scaffold":
      return runPluginScaffold(cli.name, process.cwd(), stderr);
    case "plugin-inspect":
      return runPluginInspect(cli.path, process.cwd(), stdout, stderr);
    case "osv-update":
      return runOsvUpdate(mustLoad(native), cli.path, cli.out, stderr);
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
