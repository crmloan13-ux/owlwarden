#!/usr/bin/env node
/**
 * The `owlwarden` executable.
 *
 * Thin on purpose: everything worth testing is in `run.ts`, which returns an
 * exit code instead of calling `process.exit`.
 */
import { EXIT } from "./exit.js";
import { run } from "./run.js";

const code = await run(process.argv.slice(2), {
  stdout: process.stdout,
  stderr: process.stderr,
}).catch((error: unknown) => {
  // An unexpected throw is a bug in owlwarden, not something the user did.
  // Print enough to file an issue with, and nothing that pretends it was their
  // fault.
  process.stderr.write(
    `owlwarden crashed. This is a bug — please report it at\n` +
      `  https://github.com/suthat/owlwarden/issues\n\n` +
      `${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
  );
  return EXIT.ERROR;
});

// `exitCode` rather than `exit()`: it lets stdout drain, which matters when the
// report is being piped somewhere.
process.exitCode = code;
