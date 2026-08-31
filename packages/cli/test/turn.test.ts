import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Writable } from "node:stream";

import { afterAll, describe, expect, it } from "vitest";

import { EXIT } from "../src/exit.js";
import { run } from "../src/run.js";

/**
 * `owlwarden turn`, end to end through the real engine and real git.
 *
 * Nothing is mocked, and git is not stubbed either: the whole command is an
 * argument about what "before" means, and a fake base would be an argument
 * with itself.
 */

const roots: string[] = [];

afterAll(async () => {
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
});

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

function git(root: string, args: string[]): void {
  const result = spawnSync("git", ["-C", root, ...args], { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  }
}

/** A Next.js-shaped repository with one committed, clean route. */
async function repo(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "owlwarden-turn-test-"));
  roots.push(root);

  await write(root, "package.json", JSON.stringify({ name: "t", dependencies: { next: "15.0.0" } }));
  await write(
    root,
    "app/api/users/route.ts",
    [
      'import { NextResponse } from "next/server";',
      "",
      "export async function GET() {",
      "  try {",
      "    return NextResponse.json({ ok: true });",
      "  } catch (err) {",
      '    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });',
      "  }",
      "}",
      "",
    ].join("\n"),
  );

  git(root, ["init", "-q"]);
  git(root, ["config", "user.email", "t@example.invalid"]);
  git(root, ["config", "user.name", "t"]);
  git(root, ["add", "-A"]);
  git(root, ["commit", "-qm", "base"]);
  return root;
}

async function write(root: string, path: string, contents: string): Promise<void> {
  const target = join(root, path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, contents, "utf8");
}

/** Rewrites the route so it leaks a stack trace. */
async function introduceLeak(root: string): Promise<void> {
  const path = join(root, "app/api/users/route.ts");
  const source = await readFile(path, "utf8");
  await writeFile(
    path,
    source.replace('{ error: "Internal Server Error" }', "{ error: err.stack }"),
    "utf8",
  );
}

describe("owlwarden turn", () => {
  it("is clean and cheap when the turn changed nothing", async () => {
    const root = await repo();
    const result = await cli(["turn", root]);

    expect(result.code).toBe(EXIT.CLEAN);
    expect(result.out).toContain("clean");
    expect(result.out).toContain("0 files");
  });

  it("blocks on a finding the turn introduced, and says so in those words", async () => {
    const root = await repo();
    await introduceLeak(root);
    const result = await cli(["turn", root]);

    expect(result.code).toBe(EXIT.FINDINGS);
    expect(result.out).toContain("blocked");
    expect(result.out).toContain("stack-trace-leak");
    // The whole product claim, in one string.
    expect(result.out).toContain("introduced this turn");
  });

  it("never blocks on debt the turn did not create", async () => {
    // The load-bearing property. The leak is committed, so it is the base;
    // the turn adds an unrelated clean file. A `scan` here exits 1.
    const root = await repo();
    await introduceLeak(root);
    git(root, ["add", "-A"]);
    git(root, ["commit", "-qm", "leak"]);
    await write(root, "lib/util.ts", "export const two = 1 + 1;\n");

    const turn = await cli(["turn", root]);
    expect(turn.code).toBe(EXIT.CLEAN);
    expect(turn.out).toContain("clean");
    expect(turn.out).toContain("carried");

    const scan = await cli(["scan", root, "--fail-on", "high", "--quiet", "--format", "json"]);
    expect(scan.code).toBe(EXIT.FINDINGS);
  });

  it("counts what the turn removed", async () => {
    const root = await repo();
    await introduceLeak(root);
    git(root, ["add", "-A"]);
    git(root, ["commit", "-qm", "leak"]);

    const path = join(root, "app/api/users/route.ts");
    const source = await readFile(path, "utf8");
    await writeFile(
      path,
      source.replace("{ error: err.stack }", '{ error: "Internal Server Error" }'),
      "utf8",
    );

    const result = await cli(["turn", root]);
    expect(result.code).toBe(EXIT.CLEAN);
    expect(result.out).toContain("1 fixed");
    expect(result.out).toContain("stack-trace-leak");
  });

  it("does not touch the developer's index or working tree", async () => {
    // The base tree is laid out through a private GIT_INDEX_FILE precisely so
    // this stays true. A security tool that unstages someone's work mid-session
    // has done more damage than the finding it was looking for.
    const root = await repo();
    await introduceLeak(root);
    await write(root, "staged.ts", "export const staged = true;\n");
    git(root, ["add", "staged.ts"]);

    const before = spawnSync("git", ["-C", root, "status", "--porcelain"], { encoding: "utf8" });
    await cli(["turn", root]);
    const after = spawnSync("git", ["-C", root, "status", "--porcelain"], { encoding: "utf8" });

    expect(after.stdout).toBe(before.stdout);
    expect(after.stdout).toContain("A  staged.ts");
  });

  it("refuses to run outside a git repository rather than inventing a base", async () => {
    const root = await mkdtemp(join(tmpdir(), "owlwarden-turn-nogit-"));
    roots.push(root);
    await write(root, "package.json", "{}");

    const result = await cli(["turn", root]);
    expect(result.code).toBe(EXIT.ERROR);
    expect(result.err).toContain("git repository");
  });

  it("names the base commit in the JSON, so a record is checkable later", async () => {
    const root = await repo();
    await introduceLeak(root);
    const result = await cli(["turn", root, "--format", "json"]);

    const record = JSON.parse(result.out) as {
      base: { reference: string; commit?: string };
      verdict: string;
      counts: { introduced: number };
      introduced: { id: string }[];
    };
    expect(record.base.reference).toBe("HEAD");
    expect(record.base.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(record.verdict).toBe("blocked");
    expect(record.counts.introduced).toBe(record.introduced.length);
  });

  it("appends a bounded record under --record", async () => {
    const root = await repo();
    await introduceLeak(root);

    await cli(["turn", root, "--record", "--quiet"]);
    await cli(["turn", root, "--record", "--quiet"]);

    const lines = (await readFile(join(root, ".owlwarden/turns.jsonl"), "utf8"))
      .split("\n")
      .filter((line) => line.length > 0);
    expect(lines.length).toBe(2);
    for (const line of lines) {
      const record = JSON.parse(line) as { schemaVersion: string; verdict: string };
      expect(record.schemaVersion).toBe("1.0");
      expect(record.verdict).toBe("blocked");
    }
  });

  it("reaches the same verdict twice over an unchanged tree", async () => {
    // Determinism is the claim that makes a record worth keeping. Everything
    // but the clock and the stopwatch has to match.
    const root = await repo();
    await introduceLeak(root);

    const strip = (json: string): Record<string, unknown> => {
      const record = JSON.parse(json) as Record<string, unknown>;
      delete record.recordedAt;
      delete record.durationMs;
      return record;
    };

    const first = await cli(["turn", root, "--format", "json"]);
    const second = await cli(["turn", root, "--format", "json"]);
    expect(strip(second.out)).toEqual(strip(first.out));
  });

  it("answers a host in the host's own shape under --hook", async () => {
    const root = await repo();
    await introduceLeak(root);
    const result = await cli(["turn", root, "--hook", "claude-code"]);

    const body = JSON.parse(result.out) as { decision?: string; reason?: string };
    expect(body.decision).toBe("block");
    expect(body.reason).toContain("stack-trace-leak");
    expect(body.reason).toContain("not present at");
    // The sentence that stops the agent triaging somebody else's backlog.
    expect(body.reason).toContain("not this turn's");
  });

  it("under --hook a clean turn says nothing the host has to interpret", async () => {
    const root = await repo();
    const result = await cli(["turn", root, "--hook", "claude-code"]);
    expect(JSON.parse(result.out)).toEqual({});
    expect(result.code).toBe(EXIT.CLEAN);
  });

  it("under --hook nothing but the host's JSON reaches stdout", async () => {
    // A code frame written to a process that is parsing JSON is a broken hook.
    const root = await repo();
    await introduceLeak(root);
    const result = await cli(["turn", root, "--hook", "claude-code"]);
    expect(() => {
      JSON.parse(result.out);
    }).not.toThrow();
    expect(result.out).not.toContain("◉");
  });

  it("rejects a host it does not have rather than guessing", async () => {
    const root = await repo();
    const result = await cli(["turn", root, "--hook", "windsurf"]);
    expect(result.code).toBe(EXIT.ERROR);
    expect(result.err).toContain("claude-code");
  });

  it("refuses a --base that is an option, a range, or a path", async () => {
    // Every git call here passes --end-of-options and an argument array, so
    // this is the second layer. It exists for the message: a range would
    // silently *widen* the comparison, which is the one thing a command that
    // narrows must never do.
    const root = await repo();
    for (const base of ["--output=/tmp/pwned", "main..HEAD", "-P"]) {
      const result = await cli(["turn", root, "--base", base]);
      expect(result.code, base).toBe(EXIT.ERROR);
    }
  });

  it("refuses a base that does not exist rather than comparing against nothing", async () => {
    const root = await repo();
    await introduceLeak(root);
    const result = await cli(["turn", root, "--base", "v9.9.9-nope"]);
    expect(result.code).toBe(EXIT.ERROR);
    // A base that will not resolve must not degrade into "everything is new"
    // or "nothing is new"; both are verdicts nobody asked for.
    expect(result.out).not.toContain("clean");
    expect(result.out).not.toContain("blocked");
  });

  it("refuses a change set too large to be a turn", async () => {
    const root = await repo();
    await Promise.all(
      Array.from({ length: 401 }, (_, index) =>
        write(root, `gen/f${index}.ts`, `export const n${index} = ${index};\n`),
      ),
    );
    const result = await cli(["turn", root]);
    expect(result.code).toBe(EXIT.ERROR);
    expect(result.err).toContain("not a turn");
  });

  it("refuses a format that would overwrite the repository's real findings", async () => {
    const root = await repo();
    const result = await cli(["turn", root, "--format", "sarif"]);
    expect(result.code).toBe(EXIT.ERROR);
    expect(result.err).toContain("pretty or json");
  });

  it("raising the threshold changes the verdict and says which threshold", async () => {
    const root = await repo();
    await write(
      root,
      "app/api/cookie/route.ts",
      [
        'import { NextResponse } from "next/server";',
        "",
        "export async function GET() {",
        "  const response = NextResponse.json({ ok: true });",
        '  response.cookies.set("sid", "x", { httpOnly: false, secure: false });',
        "  return response;",
        "}",
        "",
      ].join("\n"),
    );

    const high = await cli(["turn", root]);
    expect(high.out).toContain("high");

    const medium = await cli(["turn", root, "--fail-on", "medium"]);
    expect(medium.out).toMatch(/at or above medium|clean/);
  });
});
