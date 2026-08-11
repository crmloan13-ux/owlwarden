import { dirname, join } from "node:path";

import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";
import { mkdirNoFollow, writeReplacing } from "../safe-write.js";

/** Default relative path under the project root ([ADR 0020](../../../docs/adr/0020-offline-osv-cache.md)). */
export const DEFAULT_OSV_INDEX = join(".owlwarden", "osv-index.json");

/**
 * Queries OSV for lockfile packages and writes a cached index file.
 *
 * Uses the same allowlisted HTTP client as `scan --osv`. Intended for connected
 * machines; air-gapped CI then scans with `--osv-db`.
 */
export async function runOsvUpdate(
  native: NativeEngine,
  path: string,
  out: string | undefined,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  let json: string;
  try {
    json = await native.buildOsvIndex(path);
  } catch (error) {
    stderr.write(
      `error: could not build OSV index: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    return EXIT.ERROR;
  }

  const destination = out ?? join(path, DEFAULT_OSV_INDEX);
  try {
    await mkdirNoFollow(dirname(destination));
    await writeReplacing(destination, `${json}\n`);
  } catch (error) {
    stderr.write(
      `error: could not write ${destination}: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    return EXIT.ERROR;
  }

  stderr.write(`wrote OSV index to ${destination}\n`);
  return EXIT.CLEAN;
}
