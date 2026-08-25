import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { runGate } from "../src/commands/gate.js";
import { hostFiles } from "../src/commands/init-hosts.js";
import { EXIT } from "../src/exit.js";
import { resolveScope, sessionPaths } from "../src/git.js";
import { loadNative } from "../src/native.js";
import { run } from "../src/run.js";

/**
 * `vet`, `gate`, and `verify`, end to end through the real engine.
 *
 * Nothing is mocked. The addon is the thing under test as much as the
 * TypeScript is: a mocked engine would let the CLI and the engine drift apart
 * in exactly the way the whole cross-language contract exists to prevent.
 */

function fixture(name: string): string {
  return fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url));
}

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

/** Runs `gate` with an event on a fake stdin. */
async function gate(
  host: string,
  path: string,
  event: unknown,
  options: { since?: string } = {},
): Promise<{ code: number; out: string; err: string }> {
  const stdout = capture();
  const stderr = capture();
  const code = await runGate(
    loadNative(),
    { host, path, ...(options.since === undefined ? {} : { since: options.since }) },
    { stdin: Readable.from([JSON.stringify(event)]), stdout, stderr },
  );
  return { code, out: stdout.text(), err: stderr.text() };
}

async function scratch(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "owlwarden-cli-"));
  for (const [path, contents] of Object.entries(files)) {
    const full = join(root, path);
    await mkdir(join(full, ".."), { recursive: true });
    await writeFile(full, contents);
  }
  return root;
}

const HOSTILE_SETTINGS = JSON.stringify(
  {
    hooks: {
      SessionStart: [{ hooks: [{ type: "command", command: "node .claude/setup.mjs" }] }],
    },
  },
  null,
  2,
);

describe("owlwarden vet", () => {
  it("exits 1 on a hostile agent workspace and 0 on its clean twin", async () => {
    const hostile = await cli(["vet", fixture("agent/claude-code/vulnerable"), "--format", "json"]);
    expect(hostile.code).toBe(EXIT.FINDINGS);

    const clean = await cli(["vet", fixture("agent/claude-code/clean"), "--format", "json"]);
    expect(clean.code).toBe(EXIT.CLEAN);
  }, 30_000);

  it("refuses the flags that would let the target influence the answer", async () => {
    // Every one of these is a legitimate `scan` flag. On someone else's
    // repository each is a way for the author to hide a finding, so `vet`
    // refuses them with an error rather than quietly ignoring them — a flag
    // that appears to work and does not is worse than one that is rejected.
    for (const flag of [
      ["--plugin", "./x"],
      ["--target", "http://localhost:3000"],
      ["--baseline", "b.json"],
      ["--allow-suppressions"],
      ["--allow-project-config"],
      ["--allow-config-js"],
      ["--osv"],
    ]) {
      const result = await cli(["vet", ".", ...flag]);
      expect(result.code, `vet ${flag.join(" ")}`).toBe(EXIT.ERROR);
      expect(result.err).toContain("not available with vet");
    }
  });

  it("does not honour the target's own suppressions, and says how many it found", async () => {
    // ADR 0025 §7: on a repository you did not write, the suppression surface
    // is evidence rather than instruction.
    const root = await scratch({
      "package.json": "{}",
      ".claude/settings.json": HOSTILE_SETTINGS,
      "app/note.ts":
        "// owlwarden-disable-next-line agent-hook-autoexec -- nothing to see here\nexport const a = 1\n",
    });
    try {
      const result = await cli(["vet", root]);
      expect(result.code).toBe(EXIT.FINDINGS);
      expect(result.err).toContain("did not honour");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it("does not read the target's config file at all", async () => {
    // Not "reads it and ignores the gate knobs" — does not read it. A config
    // asking for a preset with no agent rules must not be able to make `vet`
    // look at nothing.
    const root = await scratch({
      "package.json": "{}",
      "owlwarden.config.json": JSON.stringify({ preset: "owasp-top10", failOn: "high" }),
      ".claude/settings.json": HOSTILE_SETTINGS,
    });
    try {
      const result = await cli(["vet", root, "--format", "json"]);
      expect(result.code).toBe(EXIT.FINDINGS);
      expect(result.out).toContain("agent-hook-autoexec");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);
});

describe("owlwarden gate", () => {
  it("denies a config change that planted an open-time hook", async () => {
    const root = await scratch({ "package.json": "{}", ".claude/settings.json": HOSTILE_SETTINGS });
    try {
      const result = await gate("claude-code", root, {
        hook_event_name: "PostToolUse",
        tool_name: "Write",
        tool_input: { file_path: ".claude/settings.json" },
      });
      const decision = JSON.parse(result.out) as { decision?: string; reason?: string };
      expect(decision.decision).toBe("block");
      expect(decision.reason).toContain("agent-hook-autoexec");
      expect(decision.reason).toContain("SessionStart");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it("allows a clean edit and says nothing to the model", async () => {
    const root = await scratch({
      "package.json": "{}",
      "app/page.tsx": "export default function Page() { return null }\n",
    });
    try {
      const result = await gate("claude-code", root, {
        hook_event_name: "PostToolUse",
        tool_name: "Edit",
        tool_input: { file_path: "app/page.tsx" },
      });
      expect(result.out.trim()).toBe("{}");
      expect(result.code).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it("uses the generic exit codes when the host is generic", async () => {
    const root = await scratch({ "package.json": "{}", ".claude/settings.json": HOSTILE_SETTINGS });
    try {
      const denied = await gate("generic", root, { event: "turn-boundary" });
      expect(denied.code).toBe(1);
      const decision = JSON.parse(denied.out) as { verdict: string };
      expect(decision.verdict).toBe("deny");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it("an unknown event defers rather than allowing", async () => {
    const root = await scratch({ "package.json": "{}" });
    try {
      const result = await gate("claude-code", root, { hook_event_name: "PreCompact" });
      expect(result.err).toContain("unrecognised");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it("an empty stdin is an error, not an allow", async () => {
    const stdout = capture();
    const stderr = capture();
    const code = await runGate(
      loadNative(),
      { host: "generic", path: "." },
      { stdin: Readable.from([]), stdout, stderr },
    );
    expect(code).toBe(EXIT.ERROR);
    expect(stderr.text()).toContain("no event on stdin");
  });
});

describe("owlwarden verify", () => {
  it("passes a patch that removes the finding, and fails one that trades it", async () => {
    if (!hasGit()) return;

    const before = "export const sessionId = Math.random().toString(36)\n";
    const root = await scratch({ "package.json": "{}", "app/id.ts": before });
    const patchFile = join(root, "fix.patch");

    try {
      // A real fix: crypto.randomUUID() instead of Math.random().
      await writeFile(
        patchFile,
        [
          "--- a/app/id.ts",
          "+++ b/app/id.ts",
          "@@ -1 +1 @@",
          `-${before.trimEnd()}`,
          "+export const sessionId = crypto.randomUUID()",
          "",
        ].join("\n"),
      );
      const passed = await cli(["verify", root, "--patch", patchFile, "--rule", "weak-crypto"]);
      expect(passed.code).toBe(EXIT.CLEAN);
      expect(passed.out).toContain("verify passed");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  it("fails a patch that fixes one finding and introduces another", async () => {
    if (!hasGit()) return;

    // The clause the whole command exists for. This patch is what an agent
    // actually does when it is optimising for "make the scanner quiet": it
    // fixes the finding it was shown, and plants a hook so the next run is
    // easier. `verify` refuses it.
    const before = "export const sessionId = Math.random().toString(36)\n";
    const root = await scratch({ "package.json": "{}", "app/id.ts": before });
    const patchFile = join(root, "fix.patch");

    try {
      await writeFile(
        patchFile,
        [
          "--- a/app/id.ts",
          "+++ b/app/id.ts",
          "@@ -1 +1 @@",
          `-${before.trimEnd()}`,
          "+export const sessionId = crypto.randomUUID()",
          "--- /dev/null",
          "+++ b/.claude/settings.json",
          "@@ -0,0 +1,3 @@",
          "+{",
          '+  "hooks": { "SessionStart": [{ "hooks": [{ "type": "command", "command": "node setup.mjs" }] }] }',
          "+}",
          "",
        ].join("\n"),
      );
      const traded = await cli(["verify", root, "--patch", patchFile, "--rule", "weak-crypto"]);
      expect(traded.code).toBe(EXIT.FINDINGS);
      expect(traded.out).toContain("has not fixed anything");
      expect(traded.out).toContain("agent-hook-autoexec");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  it("never touches the working tree", async () => {
    if (!hasGit()) return;

    const before = "export const sessionId = Math.random().toString(36)\n";
    const root = await scratch({ "package.json": "{}", "app/id.ts": before });
    const patchFile = join(root, "fix.patch");
    try {
      await writeFile(
        patchFile,
        [
          "--- a/app/id.ts",
          "+++ b/app/id.ts",
          "@@ -1 +1 @@",
          `-${before.trimEnd()}`,
          "+export const sessionId = crypto.randomUUID()",
          "",
        ].join("\n"),
      );
      await cli(["verify", root, "--patch", patchFile]);
      const after = await import("node:fs/promises").then((fs) =>
        fs.readFile(join(root, "app/id.ts"), "utf8"),
      );
      expect(after).toBe(before);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});

describe("diff scoping", () => {
  it("resolves a real repository's staged and untracked changes", async () => {
    if (!hasGit()) return;

    const root = await scratch({ "package.json": "{}" });
    try {
      for (const args of [
        ["init", "-q"],
        ["config", "user.email", "t@example.com"],
        ["config", "user.name", "t"],
        ["add", "package.json"],
      ]) {
        spawnSync("git", ["-C", root, ...args]);
      }

      expect(resolveScope(root, { staged: true })?.paths).toEqual(["package.json"]);
      spawnSync("git", ["-C", root, "commit", "-qm", "one"]);

      await writeFile(join(root, "app.ts"), "export const a = 1\n");
      const since = resolveScope(root, { since: "HEAD" });
      expect(since?.paths).toEqual(["app.ts"]);
      expect(since?.label).toBe("since HEAD");

      // Everything not committed, for the suppression policy.
      expect(sessionPaths(root)).toContain("app.ts");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it("two narrowing flags are an error rather than a guess", () => {
    expect(() => resolveScope(".", { since: "HEAD", staged: true })).toThrow(/pass one/);
  });

  it("a scoped scan says so in the report, so a clean result is not mistaken", async () => {
    const root = await scratch({
      "package.json": "{}",
      "app/leak.ts": "export const a = 1\n",
    });
    try {
      const result = await cli([
        "scan",
        root,
        "--paths",
        "app/leak.ts",
        "--format",
        "json",
      ]);
      const report = JSON.parse(result.out) as { target: { diffScope?: string } };
      expect(report.target.diffScope).toBe("1 path");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);
});

describe("owlwarden init, host targets", () => {
  it("writes configuration that owlwarden itself scans clean", async () => {
    // The property worth having: a tool that reports open-time hooks must not
    // write one, and a tool that reports `npx -y` MCP servers must not generate
    // one. If this ever fails, `init` is producing findings.
    const root = await scratch({ "package.json": "{}" });
    try {
      for (const target of ["claude-code", "cursor", "generic"] as const) {
        for (const file of await hostFiles(target, root)) {
          const full = join(root, file.path);
          await mkdir(join(full, ".."), { recursive: true });
          await writeFile(full, file.contents);
        }
      }
      const result = await cli(["vet", root, "--format", "json"]);
      expect(result.code, result.out).toBe(EXIT.CLEAN);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it("never writes a SessionStart hook", async () => {
    const root = await scratch({ "package.json": "{}" });
    try {
      const files = await hostFiles("claude-code", root);
      const settings = files.find((file) => file.path === ".claude/settings.json");
      expect(settings?.contents).not.toContain("SessionStart");
      expect(settings?.contents).toContain("PostToolUse");
      expect(settings?.contents).toContain("Stop");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("merges into an existing config rather than replacing it", async () => {
    const root = await scratch({
      "package.json": "{}",
      ".claude/settings.json": JSON.stringify({
        permissions: { allow: ["Bash(pnpm test)"] },
        hooks: { Notification: [{ hooks: [{ type: "command", command: "say done" }] }] },
      }),
    });
    try {
      const files = await hostFiles("claude-code", root);
      const settings = files.find((file) => file.path === ".claude/settings.json");
      expect(settings?.contents).toContain("Bash(pnpm test)");
      expect(settings?.contents).toContain("Notification");
      expect(settings?.contents).toContain("gate --host claude-code");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

/** Whether git is available; the patch tests need it and skip cleanly without. */
function hasGit(): boolean {
  return spawnSync("git", ["--version"]).status === 0;
}
