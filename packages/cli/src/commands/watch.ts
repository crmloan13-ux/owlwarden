import { watch as fsWatch } from "node:fs";

import type { ScanOptions } from "../args.js";
import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";

import { runScan } from "./scan.js";

/** How long to wait after a change before re-scanning. */
const DEBOUNCE_MS = 200;

/**
 * Re-scans on change. Static only — watch never opens a network path, so an
 * editor save cannot trigger a probe (`ARCHITECTURE.md` §8).
 *
 * Returns only when the process is signalled; the exit code of the *last*
 * completed scan is what a caller would see if they stopped it.
 */
export async function runWatch(
  native: NativeEngine,
  options: ScanOptions,
  stderr: NodeJS.WritableStream,
  stdout: NodeJS.WritableStream,
): Promise<number> {
  if (options.target !== undefined || options.scope.length > 0) {
    stderr.write(
      "error: watch is static-only; omit --target / --scope\n" +
        "  re-probing on every save is hostile to the developer's own server\n",
    );
    return EXIT.ERROR;
  }

  // Watch wants a readable stream of findings, not a banner on every keystroke.
  // `--write-baseline` runs once on the first scan only — rewriting on every
  // keystroke would amplify a symlink write gadget and thrash the disk.
  const watchOptions: ScanOptions = {
    ...options,
    quiet: true,
    format: options.format ?? "pretty",
  };

  let lastExit = await runScan(native, watchOptions, stderr, stdout);
  delete watchOptions.writeBaseline;
  let timer: NodeJS.Timeout | undefined;
  let inFlight: Promise<void> | undefined;
  let pending = false;

  const kick = (): void => {
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(() => {
      void enqueue();
    }, DEBOUNCE_MS);
  };

  const enqueue = async (): Promise<void> => {
    if (inFlight !== undefined) {
      pending = true;
      return;
    }
    inFlight = (async () => {
      do {
        pending = false;
        stderr.write("\n— re-scan —\n");
        lastExit = await runScan(native, watchOptions, stderr, stdout);
      } while (pending);
      inFlight = undefined;
    })();
    await inFlight;
  };
  stderr.write(`watching ${watchOptions.path} — press Ctrl+C to stop\n`);

  let watcher: ReturnType<typeof fsWatch>;
  try {
    watcher = fsWatch(watchOptions.path, { recursive: true }, (_event, filename) => {
      // Ignore our own baseline writes and editor swap files.
      if (filename !== null && shouldIgnore(filename)) return;
      kick();
    });
  } catch (error) {
    stderr.write(
      `error: could not watch ${watchOptions.path}: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    return EXIT.ERROR;
  }

  await new Promise<void>((resolve) => {
    const stop = (): void => {
      watcher.close();
      if (timer !== undefined) clearTimeout(timer);
      resolve();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });

  return lastExit;
}

function shouldIgnore(filename: string): boolean {
  const base = filename.replace(/\\/g, "/");
  return (
    base.endsWith(".owlwarden-baseline.json") ||
    base.includes("node_modules/") ||
    base.endsWith("~") ||
    base.endsWith(".swp") ||
    base.endsWith(".tmp")
  );
}
