import { lstat, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { readFile } from "node:fs/promises";

/**
 * Writes `contents` to `path` without following a symlink at the destination.
 *
 * Writes a sibling temp file, then `rename`s over `path`. On Unix, rename
 * replaces a symlink inode itself rather than writing through it — so a planted
 * link to `~/.ssh/…` cannot be used as a write gadget via `--out` /
 * `--write-baseline`.
 */
export async function writeReplacing(path: string, contents: string): Promise<void> {
  const parent = dirname(path) || ".";
  const temp = join(
    parent,
    `.owlwarden-write-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`,
  );
  try {
    await writeFile(temp, contents, { encoding: "utf8", flag: "wx" });
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true }).catch(() => undefined);
    throw error;
  }
}

/**
 * Reads a file only if it is within `maxBytes`. Refuses symlinks so a planted
 * link cannot pull outside content into a baseline parse.
 */
export async function readFileBounded(path: string, maxBytes: number): Promise<string> {
  const info = await lstat(path);
  if (info.isSymbolicLink()) {
    throw new Error("refusing to read through a symlink");
  }
  if (info.size > maxBytes) {
    throw new Error(`file is ${info.size} bytes; maximum is ${maxBytes}`);
  }
  const text = await readFile(path, "utf8");
  if (text.length > maxBytes) {
    throw new Error(`file is ${text.length} bytes; maximum is ${maxBytes}`);
  }
  return text;
}
