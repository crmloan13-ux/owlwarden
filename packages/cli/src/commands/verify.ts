import { spawnSync } from "node:child_process";
import { cp, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Report } from "@dointhai/owlwarden-sdk";

import type { ScanOptions, VerifyCliOptions } from "../args.js";
import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";
import { runScan, type ScanCapture } from "./scan.js";

/**
 * `owlwarden verify --patch <file>` — does this fix actually fix it?
 *
 * # The clause that makes this worth having
 *
 * Exits 0 only if the originating finding is gone **and no new finding at or
 * above the threshold appeared**. The second half is the point: a patch that
 * trades a `stack-trace-leak` for an `open-redirect` has not fixed anything,
 * and an agent applying its own patches will produce exactly that trade if
 * nothing checks for it ([ADR 0026](../../../docs/adr/0026-deterministic-agent-gate.md) §6).
 *
 * # Why a scratch copy
 *
 * The patch is applied to a copy of the tree, never to the developer's working
 * directory. `verify` answers a question; it does not edit your code. An agent
 * loop that wants the change applied does that itself, after the answer.
 */

/** Largest patch accepted. A unified diff is text a human could read. */
const MAX_PATCH_BYTES = 4 * 1024 * 1024;

/** Runs the verification and returns the exit code. */
export async function runVerify(
  native: NativeEngine,
  options: VerifyCliOptions,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  let patch: string;
  try {
    const contents = await readFile(options.patch, "utf8");
    if (Buffer.byteLength(contents) > MAX_PATCH_BYTES) {
      stderr.write(`error: ${options.patch} is over the ${MAX_PATCH_BYTES}-byte patch limit\n`);
      return EXIT.ERROR;
    }
    patch = contents;
  } catch (error) {
    stderr.write(
      `error: could not read ${options.patch}: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    return EXIT.ERROR;
  }

  const before = await scanInto(native, options.path, stderr);
  if (before === undefined) return EXIT.ERROR;

  const scratch = await mkdtemp(join(tmpdir(), "owlwarden-verify-"));
  try {
    // `git` is not required: `cp -r` of the project into a scratch directory
    // keeps this working on a tree that is not a repository, which is the case
    // for a freshly generated project.
    await cp(options.path, join(scratch, "project"), {
      recursive: true,
      filter: (source) => !source.includes(`${"node_modules"}`) && !source.includes("/.git/"),
    });
    const root = join(scratch, "project");

    const applied = applyPatch(root, patch);
    if (!applied.ok) {
      stderr.write(`error: the patch did not apply cleanly: ${applied.message}\n`);
      return EXIT.ERROR;
    }

    const after = await scanInto(native, root, stderr);
    if (after === undefined) return EXIT.ERROR;

    return report(options, before, after, stdout);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

/** The verdict, printed and returned as an exit code. */
function report(
  options: VerifyCliOptions,
  before: Report,
  after: Report,
  stdout: NodeJS.WritableStream,
): number {
  const threshold = options.failOn ?? "medium";
  const key = (finding: Report["findings"][number]): string =>
    `${finding.id}@${JSON.stringify(finding.location)}`;

  const previous = new Set(before.findings.map(key));
  const resolved = before.findings.filter(
    (finding) => !after.findings.some((other) => key(other) === key(finding)),
  );
  const introduced = after.findings.filter((finding) => !previous.has(key(finding)));

  const blocking = introduced.filter(
    (finding) => severityRank(finding.severity) <= severityRank(threshold) && finding.confidence !== "possible",
  );

  const targeted =
    options.rule === undefined
      ? resolved.length > 0
      : resolved.some((finding) => finding.id === options.rule);

  stdout.write(`resolved: ${resolved.length}\n`);
  for (const finding of resolved.slice(0, 20)) {
    stdout.write(`  - ${finding.id} ${locationOf(finding)}\n`);
  }
  stdout.write(`introduced: ${introduced.length}\n`);
  for (const finding of introduced.slice(0, 20)) {
    stdout.write(`  + ${finding.severity} ${finding.id} ${locationOf(finding)}\n`);
  }

  if (blocking.length > 0) {
    stdout.write(
      `\nverify failed: the patch introduced ${blocking.length} finding(s) at or above ` +
        `${threshold}. A fix that trades one vulnerability for another has not fixed anything.\n`,
    );
    return EXIT.FINDINGS;
  }
  if (!targeted) {
    stdout.write(
      options.rule === undefined
        ? "\nverify failed: the patch resolved nothing.\n"
        : `\nverify failed: ${options.rule} is still reported after the patch.\n`,
    );
    return EXIT.FINDINGS;
  }

  stdout.write("\nverify passed: the finding is gone and nothing new appeared.\n");
  return EXIT.CLEAN;
}

function locationOf(finding: Report["findings"][number]): string {
  const location = finding.location;
  return "path" in location ? `${location.path}:${location.line}` : location.url;
}

function severityRank(severity: string): number {
  return ["high", "medium", "low", "info"].indexOf(severity);
}

/** Applies a unified diff with `git apply`, in the scratch tree. */
function applyPatch(root: string, patch: string): { ok: true } | { ok: false; message: string } {
  const result = spawnSync("git", ["apply", "--unsafe-paths", "--directory", ".", "-p1", "-"], {
    cwd: root,
    input: patch,
    encoding: "utf8",
  });
  if (result.error) {
    return {
      ok: false,
      message: `${result.error.message}. verify needs git on PATH to apply a patch.`,
    };
  }
  if (result.status !== 0) {
    return { ok: false, message: (result.stderr ?? "").trim() || "git apply refused it" };
  }
  return { ok: true };
}

/** Scans one tree and returns the report, or `undefined` on failure. */
async function scanInto(
  native: NativeEngine,
  path: string,
  stderr: NodeJS.WritableStream,
): Promise<Report | undefined> {
  const capture: ScanCapture = {};
  const options: ScanOptions = {
    path,
    preset: "quick",
    failOn: "info",
    minConfidence: "possible",
    color: false,
    unicode: false,
    quiet: true,
    hyperlinks: false,
    reportSuppressions: false,
    allowConfigJs: false,
    ci: false,
    allowProjectConfig: false,
    allowSuppressions: false,
    allowBaseline: false,
    scope: [],
    plugins: [],
    allowPlugins: false,
    requireSignedPlugins: false,
    fix: false,
    fixUnsafe: false,
    dryRun: false,
    allowDirty: false,
    allowActive: false,
    osv: false,
    offline: false,
    staged: false,
    paths: [],
    vet: false,
    formats: [],
  };
  const code = await runScan(native, options, stderr, nullStream(), capture);
  if (capture.report === undefined && code === EXIT.ERROR) return undefined;
  return capture.report;
}

/** A sink that swallows the scan's own output; `verify` prints its own. */
function nullStream(): NodeJS.WritableStream {
  return {
    write: () => true,
  } as unknown as NodeJS.WritableStream;
}
