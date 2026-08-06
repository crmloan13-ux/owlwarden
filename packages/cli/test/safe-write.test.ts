import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { readFileBounded, writeReplacing } from "../src/safe-write.js";

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
});
