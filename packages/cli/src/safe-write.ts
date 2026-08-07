import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

/**
 * Writes `contents` to `path` without following a symlink at the destination.
 *
 * Writes a sibling temp file, then `rename`s over `path`. On Unix, rename
 * replaces a symlink inode itself rather than writing through it — so a planted
 * link to `~/.ssh/…` cannot be used as a write gadget via `--out` /
 * `--write-baseline`.
 *
 * Also refuses when any existing ancestor directory is a symlink — otherwise
 * the temp write would follow into an attacker-chosen tree.
 */
export async function writeReplacing(path: string, contents: string): Promise<void> {
  const parent = dirname(path) || ".";
  await refuseSymlinkAncestors(parent);
  await mkdir(parent, { recursive: true });
  // Re-check after create: a race could have replaced a newly-created
  // directory with a symlink before we write (mirrors the Rust helper).
  await refuseSymlinkAncestors(parent);
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
 * Refuses a write whose directory path goes through a symlinked directory.
 *
 * Walks from `path` upward until the first existing node. A symlink there
 * means the write would follow into an attacker-chosen tree. A real directory
 * means stop — walking further would trip over system volume aliases such as
 * macOS `/var` → `/private/var`.
 */
export async function refuseSymlinkAncestors(path: string): Promise<void> {
  let current = resolve(path);
  for (;;) {
    try {
      const info = await lstat(current);
      if (info.isSymbolicLink()) {
        throw new Error("refusing to write under a symlinked directory");
      }
      return;
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error
          ? (error as { code?: string }).code
          : undefined;
      if (code !== "ENOENT") {
        throw error;
      }
    }
    const parent = dirname(current);
    if (parent === current) {
      return;
    }
    current = parent;
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
