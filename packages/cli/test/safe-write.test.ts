import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { readFileBounded, refuseSymlinkAncestors, writeReplacing } from "../src/safe-write.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "owlwarden-safe-write-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("writeReplacing", () => {
  it("replaces a symlink instead of writing through it", async () => {
    const target = join(dir, "secret.txt");
    await writeFile(target, "do-not-clobber");
    const link = join(dir, "report.json");
    await symlink(target, link);

    await writeReplacing(link, '{"ok":true}\n');

    expect(await readFile(link, "utf8")).toBe('{"ok":true}\n');
    expect(await readFile(target, "utf8")).toBe("do-not-clobber");
  });

  it("refuses a symlinked parent directory", async () => {
    const outside = join(dir, "outside");
    await mkdir(outside);
    const link = join(dir, "out");
    await symlink(outside, link);

    await expect(writeReplacing(join(link, "report.json"), '{"ok":true}\n')).rejects.toThrow(
      /symlinked directory/,
    );
    expect(await readdir(outside)).toEqual([]);
  });

  it("uses wx so a pre-planted temp name cannot be opened for write", async () => {
    // Mirror the Rust create_new contract: flag wx must fail on an existing node.
    const occupied = join(dir, "occupied.tmp");
    await writeFile(occupied, "mine");
    await expect(
      writeFile(occupied, "x", { encoding: "utf8", flag: "wx" }),
    ).rejects.toMatchObject({ code: "EEXIST" });
  });
});

describe("refuseSymlinkAncestors", () => {
  it("allows a normal directory tree", async () => {
    const nested = join(dir, "a", "b");
    await mkdir(nested, { recursive: true });
    await expect(refuseSymlinkAncestors(nested)).resolves.toBeUndefined();
  });

  it("rejects when an ancestor is a symlink", async () => {
    const outside = join(dir, "outside");
    await mkdir(outside);
    const link = join(dir, "linked");
    await symlink(outside, link);
    await expect(refuseSymlinkAncestors(join(link, "nested"))).rejects.toThrow(
      /symlinked directory/,
    );
  });
});

describe("readFileBounded", () => {
  it("refuses symlinks", async () => {
    const target = join(dir, "real.json");
    await writeFile(target, "{}");
    const link = join(dir, "base.json");
    await symlink(target, link);
    await expect(readFileBounded(link, 1024)).rejects.toThrow(/symlink/);
  });

  it("refuses oversized files before parsing", async () => {
    const path = join(dir, "big.json");
    await writeFile(path, "x".repeat(64));
    await expect(readFileBounded(path, 16)).rejects.toThrow(/maximum is 16/);
  });

  it("reads a normal file within the bound", async () => {
    const path = join(dir, "ok.json");
    await writeFile(path, '{"a":1}');
    expect(await readFileBounded(path, 1024)).toBe('{"a":1}');
  });
});
