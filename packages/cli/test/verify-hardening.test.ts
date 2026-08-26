import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { describe, expect, it } from "vitest";

import { checkPatchPaths, patchTargets } from "../src/commands/verify.js";
import { EXIT } from "../src/exit.js";
import { run } from "../src/run.js";

/**
 * `verify` from an attacker's point of view.
 *
 * The patch handed to this command is the *agent's* output. An agent optimising
 * for a quiet scanner has an obvious interest in writing somewhere the scanner
 * does not look, and `verify` is the one command in the tool whose job is to
 * take that output and apply it. So these tests are written as attempts rather
 * than as checks: each one is a thing a hostile patch would try.
 */

function capture(): Writable & { text(): string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      chunks.push(chunk.toString());
      callback();
    },
  });
  return Object.assign(stream, { text: () => chunks.join("") });
}

async function cli(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const stdout = capture();
  const stderr = capture();
  const code = await run(argv, { stdout, stderr });
  return { code, out: stdout.text(), err: stderr.text() };
}

function hasGit(): boolean {
  return spawnSync("git", ["--version"]).status === 0;
}

/** A minimal well-formed diff writing `body` to `target`. */
function patchCreating(target: string, body: string): string {
  const lines = body.split("\n").filter((line) => line.length > 0);
  return [
    "--- /dev/null",
    `+++ b/${target}`,
    `@@ -0,0 +1,${lines.length} @@`,
    ...lines.map((line) => `+${line}`),
    "",
  ].join("\n");
}

describe("verify: patch path validation", () => {
  it("reads the targets out of both diff headers", () => {
    const patch = ["--- a/app/one.ts", "+++ b/app/two.ts", "--- /dev/null", "+++ b/new.ts"].join(
      "\n",
    );
    expect(patchTargets(patch)).toEqual(["app/one.ts", "app/two.ts", "new.ts"]);
    expect(patchTargets("no headers at all")).toEqual([]);
  });

  it("refuses every shape that would write outside the project", () => {
    // Each of these is a real escape technique, and each is named in the error
    // rather than collapsed into "refused".
    const escapes: readonly [string, RegExp][] = [
      ["../../../../etc/cron.d/evil", /`\.\.` component/],
      ["a/../../outside.ts", /`\.\.` component/],
      ["/etc/passwd", /absolute path/],
      ["/root/.ssh/authorized_keys", /absolute path/],
      ["C:\\Windows\\System32\\drivers\\etc\\hosts", /absolute path/],
      [".git/config", /under \.git/],
      [".git/hooks/post-checkout", /under \.git/],
      ["app/.git/hooks/pre-commit", /under \.git/],
    ];
    for (const [target, why] of escapes) {
      const result = checkPatchPaths(patchCreating(target, "payload"));
      expect(result.ok, `${target} must be refused`).toBe(false);
      if (!result.ok) expect(result.message).toMatch(why);
    }
  });

  it("accepts the ordinary shapes a real fix has", () => {
    for (const target of [
      "app/api/users/route.ts",
      "packages/api/src/db.ts",
      "src/lib/crypto.mjs",
      ".claude/settings.json",
    ]) {
      expect(checkPatchPaths(patchCreating(target, "x")).ok, target).toBe(true);
    }
  });

  it("refuses a patch that is not a diff, and one that rewrites the world", () => {
    expect(checkPatchPaths("just some prose").ok).toBe(false);
    const many = Array.from({ length: 40 }, (_, index) =>
      patchCreating(`file${index}.ts`, "x"),
    ).join("");
    const result = checkPatchPaths(many);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).toContain("over the");
  });

  it("a NUL byte in a path is refused rather than truncated", () => {
    // A path git would treat as one thing and a check as another.
    const result = checkPatchPaths(`--- /dev/null\n+++ b/app/ok.ts\u0000/../../evil\n@@ -0,0 +1 @@\n+x\n`);
    expect(result.ok).toBe(false);
  });
});

describe("verify: end to end refusals", () => {
  it("does not write outside the project even when git would allow it", async () => {
    if (!hasGit()) return;

    const outside = await mkdtemp(join(tmpdir(), "owlwarden-outside-"));
    const root = await mkdtemp(join(tmpdir(), "owlwarden-project-"));
    try {
      await writeFile(join(root, "package.json"), "{}");
      await mkdir(join(root, "app"), { recursive: true });
      await writeFile(join(root, "app/id.ts"), "export const a = 1\n");

      const patchFile = join(root, "escape.patch");
      // The path is relative, so it looks innocent in a review; `..` is what
      // does the work.
      await writeFile(
        patchFile,
        patchCreating(`../../${join(outside, "owned.txt").replace(/^\//, "")}`, "owned"),
      );

      const result = await cli(["verify", root, "--patch", patchFile]);
      expect(result.code).toBe(EXIT.ERROR);
      expect(result.err).toMatch(/refusing a patch/);

      await expect(readFile(join(outside, "owned.txt"), "utf8")).rejects.toThrow();
    } finally {
      await rm(outside, { recursive: true, force: true });
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  it("does not follow a symlink out of the project", async () => {
    if (!hasGit() || process.platform === "win32") return;

    const outside = await mkdtemp(join(tmpdir(), "owlwarden-outside-"));
    const root = await mkdtemp(join(tmpdir(), "owlwarden-project-"));
    try {
      await writeFile(join(outside, "secret.ts"), "export const real = 'untouched'\n");
      await writeFile(join(root, "package.json"), "{}");
      await mkdir(join(root, "app"), { recursive: true });
      // A symlink checked into the project, pointing at a file outside it.
      await symlink(join(outside, "secret.ts"), join(root, "app/linked.ts"));

      const patchFile = join(root, "through-link.patch");
      await writeFile(
        patchFile,
        [
          "--- a/app/linked.ts",
          "+++ b/app/linked.ts",
          "@@ -1 +1 @@",
          "-export const real = 'untouched'",
          "+export const real = 'overwritten'",
          "",
        ].join("\n"),
      );

      await cli(["verify", root, "--patch", patchFile]);

      // Whatever verify decided, the file outside the project is unchanged.
      expect(await readFile(join(outside, "secret.ts"), "utf8")).toContain("untouched");
    } finally {
      await rm(outside, { recursive: true, force: true });
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  it("refuses a patch larger than the limit rather than reading it into memory twice", async () => {
    const root = await mkdtemp(join(tmpdir(), "owlwarden-project-"));
    try {
      await writeFile(join(root, "package.json"), "{}");
      const patchFile = join(root, "huge.patch");
      await writeFile(patchFile, `+++ b/a.ts\n${"+x\n".repeat(2_000_000)}`);
      const result = await cli(["verify", root, "--patch", patchFile]);
      expect(result.code).toBe(EXIT.ERROR);
      expect(result.err).toContain("patch limit");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});
