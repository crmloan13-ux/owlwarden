import { createHash } from "node:crypto";
import { watch as fsWatch } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";

import type { Report } from "@dointhai/owlwarden-sdk";

import type { ScanOptions } from "../args.js";
import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";

import { type ScanCapture, runScan } from "./scan.js";

/** How long to wait after a change before re-scanning. */
const DEBOUNCE_MS = 200;

/** Max dirty paths forwarded per incremental request (matches Rust cap). */
const MAX_DIRTY_PATHS = 1_000;

/** Matches `limits::source::MAX_FILE_BYTES` — never hash a giant blob into RAM. */
const MAX_HASH_FILE_BYTES = 2 * 1024 * 1024;

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
  const { osvDb: _ignoredOsvDb, ...rest } = options;
  const watchOptions: ScanOptions = {
    ...rest,
    quiet: true,
    format: options.format ?? "pretty",
    osv: false,
    offline: false,
  };
  if (options.osv || options.osvDb !== undefined) {
    stderr.write(
      "note: watch ignores --osv / --osv-db; run `owlwarden scan --osv` instead\n",
    );
  }

  const contentHashes = new Map<string, string>();
  const pendingDirty = new Set<string>();
  let lastReport: Report | undefined;

  const capture: ScanCapture = {};
  let lastExit = await runScan(native, watchOptions, stderr, stdout, capture);
  lastReport = capture.report;
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
        const dirtyPaths = [...pendingDirty].slice(0, MAX_DIRTY_PATHS);
        pendingDirty.clear();

        const incrementalOptions: ScanOptions =
          dirtyPaths.length > 0 && lastReport !== undefined
            ? {
                ...watchOptions,
                dirtyPaths,
                previousReportJson: JSON.stringify(lastReport),
              }
            : watchOptions;

        stderr.write("\n— re-scan —\n");
        const scanCapture: ScanCapture = {};
        lastExit = await runScan(native, incrementalOptions, stderr, stdout, scanCapture);
        if (scanCapture.report !== undefined) {
          lastReport = scanCapture.report;
        }
      } while (pending);
      inFlight = undefined;
    })();
    await inFlight;
  };

const noteChange = (filename: string | Buffer | null): void => {
  if (filename === null) {
    kick();
    return;
  }
  const name = typeof filename === "string" ? filename : filename.toString("utf8");
  void (async () => {
    const rel = name.replace(/\\/g, "/");
    if (shouldIgnore(rel)) return;

      const absolute = join(watchOptions.path, rel);
      const hash = await hashFile(absolute);
      if (hash === undefined) {
        contentHashes.delete(rel);
        pendingDirty.add(rel);
        kick();
        return;
      }

      const previous = contentHashes.get(rel);
      if (previous === hash) {
        return;
      }
      contentHashes.set(rel, hash);
      pendingDirty.add(rel);
      kick();
    })();
  };

  stderr.write(`watching ${watchOptions.path} — press Ctrl+C to stop\n`);

  let watcher: ReturnType<typeof fsWatch>;
  try {
    watcher = fsWatch(watchOptions.path, { recursive: true }, (_event, filename) => {
      noteChange(filename);
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

async function hashFile(path: string): Promise<string | undefined> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink() || !info.isFile()) {
      return undefined;
    }
    if (info.size > MAX_HASH_FILE_BYTES) {
      // Oversized files are never scanned by the engine either; treat as
      // unchanged so a planted multi-GB blob cannot OOM the watch process.
      return `oversized:${info.size}`;
    }
    const handle = await open(path, "r");
    try {
      const hash = createHash("sha256");
      const buffer = Buffer.alloc(64 * 1024);
      let remaining = Number(info.size);
      while (remaining > 0) {
        const { bytesRead } = await handle.read(
          buffer,
          0,
          Math.min(buffer.length, remaining),
          null,
        );
        if (bytesRead === 0) {
          break;
        }
        hash.update(buffer.subarray(0, bytesRead));
        remaining -= bytesRead;
      }
      return hash.digest("hex");
    } finally {
      await handle.close();
    }
  } catch {
    return undefined;
  }
}
