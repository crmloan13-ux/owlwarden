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
 * Missing parents are created with [`mkdirNoFollow`] — never
 * `mkdir({ recursive: true })`, which follows intermediate directory symlinks.
 */
export async function writeReplacing(path: string, contents: string): Promise<void> {
  const parent = dirname(path) || ".";
  await mkdirNoFollow(parent);
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
 * Creates `dir` and any missing parents without following directory symlinks.
 *
 * Node's recursive `mkdir` will walk through an intermediate symlink (e.g.
 * create `nested` inside the target of `link` when asked for `link/nested`).
 * This refuses a symlinked ancestor, then creates only the missing suffix one
 * real directory at a time. Existing ancestors above that point are not
 * re-checked — walking into system volume aliases such as macOS
 * `/var` → `/private/var` would false-positive.
 */
export async function mkdirNoFollow(dir: string): Promise<void> {
  const abs = resolve(dir);
  // Fail fast if the first existing ancestor is already a symlink.
  await refuseSymlinkAncestors(abs);

  const missing: string[] = [];
  let current = abs;
  for (;;) {
    try {
      await lstat(current);
      break;
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error
          ? (error as { code?: string }).code
          : undefined;
      if (code !== "ENOENT") {
        throw error;
      }
    }
    missing.push(current);
    const parent = dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  missing.reverse();

  for (const component of missing) {
    await mkdir(component);
    const created = await lstat(component);
    if (created.isSymbolicLink()) {
      throw new Error("refusing to write under a symlinked directory");
    }
    if (!created.isDirectory()) {
      throw new Error(`not a directory: ${component}`);
    }
  }

  // Race: a just-created component may have been swapped for a symlink.
  await refuseSymlinkAncestors(abs);
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
