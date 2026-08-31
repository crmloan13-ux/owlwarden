import { spawnSync } from "node:child_process";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { reportSchema, turnReportSchema, type Report, type TurnReport } from "@dointhai/owlwarden-sdk";

import type { ScanOptions, TurnCliOptions } from "../args.js";
import { EXIT } from "../exit.js";
import { GitError, isRepository, resolveScope } from "../git.js";
import type { NativeEngine } from "../native.js";
import { runScan, type ScanCapture } from "./scan.js";

/**
 * `owlwarden turn` — what did *this* turn change?
 *
 * # The shape of the answer
 *
 * Scan the working tree at the paths the turn touched. Scan the same paths as
 * they stand at the base commit. Diff the two by fingerprint. Report only what
 * the turn introduced, in full; name what it carried and fixed, in one line
 * each. The gate is the same one `scan` uses, applied only to the introduced
 * set ([`owlwarden_core::turn`]).
 *
 * # Why the base scan, rather than reading the diff hunks
 *
 * Attributing findings to added lines is cheaper and answers a narrower
 * question. It cannot see the turn that deleted a middleware and made forty
 * routes internet-reachable, and it cannot count what the turn *fixed*, which
 * is the only line in this tool that reports something going right.
 *
 * A scan is deterministic and the base is a commit, so the second scan is
 * answering a question with one correct answer. That is worth two scans of a
 * handful of files.
 *
 * # How the base tree is materialised
 *
 * `read-tree` into a **temporary index**, then `checkout-index` into a
 * temporary work tree. Two git commands, no external tools, and nothing under
 * the user's root is written at any point — `--record` aside. `GIT_INDEX_FILE`
 * is what keeps the developer's staged changes out of it: without it,
 * `checkout` against a tree rewrites the real index, and a security tool that
 * unstages someone's work mid-session has done more damage than the finding it
 * was looking for.
 *
 * Not `git worktree add`, which writes into `.git/`; not `cp -r`, which on a
 * repository with a build directory copies gigabytes of artefacts nobody asked
 * about. Measured at 0.15s over 1,057 files, against 0.57s for
 * `git archive | tar` and minutes for the copy.
 */

/**
 * Most files a turn may touch before this stops being a turn.
 *
 * A rebase, a merge, or a `format-all` commit is not a turn, and copying and
 * scanning both sides of one buys nothing: every finding will read as carried
 * or introduced en masse, and the verdict a developer wanted — *did what I just
 * did break something* — is not in there. Past this, say so and stop.
 */
const MAX_TURN_FILES = 400;

/** Records kept in `.owlwarden/turns.jsonl`. Older ones are dropped on write. */
const MAX_RECORDS = 200;

/** Where `--record` writes. Under `.owlwarden/`, next to the seal. */
const RECORD_PATH = ".owlwarden/turns.jsonl";

/** Runs the turn verdict and returns the exit code. */
export async function runTurn(
  native: NativeEngine,
  options: TurnCliOptions,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  const started = Date.now();

  if (!isRepository(options.path)) {
    stderr.write(
      "error: turn needs a git repository — the verdict is a comparison, and the\n" +
        "  base of the comparison is a commit. Use `owlwarden scan` outside one.\n",
    );
    return EXIT.ERROR;
  }

  let paths: string[];
  try {
    const scope = resolveScope(options.path, { since: options.base });
    paths = scope?.paths ?? [];
  } catch (error) {
    stderr.write(
      `error: ${error instanceof GitError ? error.message : String(error)}\n` +
        "  in CI this is usually a shallow clone: set fetch-depth: 0 on checkout\n",
    );
    return EXIT.ERROR;
  }

  if (paths.length > MAX_TURN_FILES) {
    stderr.write(
      `error: ${paths.length} files differ from ${options.base}, over the ${MAX_TURN_FILES}-file ` +
        "limit for a turn.\n  That is a merge or a reformat, not a turn; run `owlwarden scan` " +
        "on the result instead.\n",
    );
    return EXIT.ERROR;
  }

  const commit = resolveCommit(options.path, options.base);

  // Nothing changed. Report it as the clean turn it is rather than scanning
  // the repository twice to discover that the answer is zero.
  if (paths.length === 0) {
    return emit(
      native,
      options,
      await verdict(native, options, emptyReport(), emptyReport(), commit, 0, started, []),
      stdout,
      stderr,
    );
  }

  const after = await scanTree(native, options, options.path, paths, stderr);
  if (after === undefined) return EXIT.ERROR;

  const scratch = await mkdtemp(join(tmpdir(), "owlwarden-turn-"));
  try {
    const laid = await checkoutBase(options.path, scratch, options.base);
    if (!laid.ok) {
      stderr.write(`error: ${laid.message}\n`);
      return EXIT.ERROR;
    }
    const before = await scanTree(native, options, laid.root, paths, stderr);
    if (before === undefined) return EXIT.ERROR;

    const record = await verdict(native, options, before, after, commit, paths.length, started, []);
    return emit(native, options, record, stdout, stderr);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

/** Builds the verdict by handing both reports to the engine. */
async function verdict(
  native: NativeEngine,
  options: TurnCliOptions,
  before: Report,
  after: Report,
  commit: string | undefined,
  filesChanged: number,
  started: number,
  notes: string[],
): Promise<TurnReport | undefined> {
  const envelope = JSON.parse(
    await native.turn(
      JSON.stringify({
        projectRoot: options.path,
        beforeReportJson: JSON.stringify(before),
        afterReportJson: JSON.stringify(after),
        baseRef: options.base,
        ...(commit === undefined ? {} : { baseCommit: commit }),
        filesChanged,
        durationMs: Date.now() - started,
        failOn: options.failOn,
        minConfidence: options.minConfidence,
        ...(options.failOnExposure === undefined
          ? {}
          : { failOnExposure: options.failOnExposure }),
        surface: options.surface,
        notes,
      }),
    ),
  ) as { ok: boolean; turn?: unknown; error?: { message: string; help: string } };

  if (!envelope.ok || envelope.turn === undefined) return undefined;
  const parsed = turnReportSchema.safeParse(envelope.turn);
  return parsed.success ? parsed.data : undefined;
}

/** Renders the verdict, records it if asked, and returns the exit code. */
async function emit(
  native: NativeEngine,
  options: TurnCliOptions,
  record: TurnReport | undefined,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  if (record === undefined) {
    stderr.write(
      "error: the engine could not produce a turn verdict.\n" +
        "  The CLI and the native addon may be from different releases; reinstall owlwarden.\n",
    );
    return EXIT.ERROR;
  }

  if (options.record) {
    const written = await appendRecord(options.path, record);
    if (written !== undefined) {
      stderr.write(`error: could not write ${RECORD_PATH}: ${written}\n`);
      return EXIT.ERROR;
    }
  }

  // Under `--hook` the audience is a host, not a person: it gets the host's
  // own JSON on stdout and the host's own exit code, and nothing else. A code
  // frame written to a process that is parsing JSON is a broken hook.
  if (options.hook !== undefined) {
    const encoded = JSON.parse(native.encodeTurnHook(JSON.stringify(record), options.hook)) as {
      stdout: string;
      stderr: string | null;
      exitCode: number;
    };
    stdout.write(encoded.stdout);
    if (encoded.stderr !== null && encoded.stderr.length > 0) {
      stderr.write(`${encoded.stderr}\n`);
    }
    return encoded.exitCode;
  }

  if (!options.quiet) {
    stdout.write(
      native.renderTurn(
        JSON.stringify(record),
        JSON.stringify({
          format: options.format,
          color: options.color,
          unicode: options.unicode,
          hyperlinks: false,
          prettyJson: options.format === "json",
        }),
      ),
    );
  }

  return record.verdict === "blocked" ? EXIT.FINDINGS : EXIT.CLEAN;
}

/**
 * Materialises the base tree in a scratch directory.
 *
 * The whole tree rather than only the changed paths: framework detection,
 * route resolution, and the auth-gate recognition behind `exposure` all read
 * files the turn did not touch, and a `before` scan that could not find
 * `package.json` would report a different framework from the `after` scan and
 * turn every finding into a fixed-and-introduced pair.
 *
 * Files the turn created are absent here, which is exactly right: their
 * findings then read as introduced rather than carried.
 */
async function checkoutBase(
  root: string,
  scratch: string,
  base: string,
): Promise<{ ok: true; root: string } | { ok: false; message: string }> {
  const target = join(scratch, "project");
  const index = join(scratch, "index");
  try {
    await mkdir(target, { recursive: true });
  } catch (error) {
    return {
      ok: false,
      message: `could not create a scratch tree: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }

  // A private index, so the developer's staged changes are never touched.
  const env = { ...process.env, GIT_INDEX_FILE: index };
  const read = spawnSync("git", ["-C", root, "read-tree", "--end-of-options", base], {
    encoding: "utf8",
    env,
  });
  if (read.status !== 0) {
    return {
      ok: false,
      message: `could not read the tree at ${base}: ${(read.stderr ?? "").trim() || "git refused"}`,
    };
  }

  const checkout = spawnSync(
    "git",
    ["-C", root, `--work-tree=${target}`, "checkout-index", "-a", "-f"],
    { encoding: "utf8", env },
  );
  if (checkout.status !== 0) {
    return {
      ok: false,
      message: `could not lay out ${base}: ${(checkout.stderr ?? "").trim() || "git refused"}`,
    };
  }

  return { ok: true, root: target };
}

/** Scans one tree, narrowed to the paths the turn touched. */
async function scanTree(
  native: NativeEngine,
  options: TurnCliOptions,
  root: string,
  paths: string[],
  stderr: NodeJS.WritableStream,
): Promise<Report | undefined> {
  const capture: ScanCapture = {};
  const scan: ScanOptions = {
    path: root,
    preset: options.preset,
    // Both sides are collected at the floor and filtered by the turn gate
    // afterwards. Filtering here would hide a carried finding on one side only
    // when the two scans disagreed about a borderline confidence, and a
    // finding that vanishes from `before` reads as introduced.
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
    paths,
    vet: false,
    formats: [],
  };
  const code = await runScan(native, scan, stderr, sink(), capture);
  if (capture.report === undefined && code === EXIT.ERROR) return undefined;
  return capture.report;
}

/**
 * Appends one record, keeping the file bounded.
 *
 * JSONL rather than a file per turn: an agent working for an hour produces
 * dozens, and a directory that grows a file per minute is a directory somebody
 * gitignores, at which point the audit trail is gone.
 *
 * Returns an error message, or `undefined` on success.
 */
async function appendRecord(root: string, record: TurnReport): Promise<string | undefined> {
  const path = join(root, RECORD_PATH);
  const line = `${JSON.stringify(record)}\n`;
  try {
    await mkdir(dirname(path), { recursive: true });
    await appendFile(path, line, "utf8");

    const contents = await readFile(path, "utf8");
    const lines = contents.split("\n").filter((entry) => entry.length > 0);
    if (lines.length > MAX_RECORDS) {
      await writeFile(path, `${lines.slice(-MAX_RECORDS).join("\n")}\n`, "utf8");
    }
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

/** The commit a ref resolves to, or `undefined` when git cannot say. */
function resolveCommit(root: string, reference: string): string | undefined {
  const result = spawnSync("git", ["-C", root, "rev-parse", "--verify", "--end-of-options", reference], {
    encoding: "utf8",
  });
  if (result.status !== 0) return undefined;
  const commit = (result.stdout ?? "").trim();
  return /^[0-9a-f]{7,64}$/.test(commit) ? commit : undefined;
}

/** A report over nothing, for the turn that touched nothing. */
function emptyReport(): Report {
  return reportSchema.parse({
    schemaVersion: "1.0",
    tool: { name: "owlwarden", version: "0.0.0" },
    scannedAt: new Date(0).toISOString(),
    durationMs: 0,
    target: { project: ".", scope: [], filesScanned: 0, routesProbed: 0, preset: "quick" },
    summary: { high: 0, medium: 0, low: 0, info: 0 },
    findings: [],
    suppressedCount: 0,
    truncated: false,
    errors: [],
  });
}

/** Swallows the inner scans' own output; `turn` prints its own verdict. */
function sink(): NodeJS.WritableStream {
  return { write: () => true } as unknown as NodeJS.WritableStream;
}
