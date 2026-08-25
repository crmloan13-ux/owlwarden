import { readFile } from "node:fs/promises";

import { EXIT } from "../exit.js";
import { GitError, isRepository, resolveScope, sessionPaths } from "../git.js";
import type { NativeEngine } from "../native.js";

/**
 * `owlwarden gate` — the hook entry point.
 *
 * # What this file is responsible for
 *
 * Three things the engine must not do: read stdin, run git, and write to a
 * process's streams. Everything else — parsing the host's event, scanning what
 * it names, choosing a verdict, encoding the answer — happens in Rust, once,
 * shared with the standalone binary.
 *
 * # Why it never throws
 *
 * A hook that throws shows a developer a stack trace in the middle of their
 * session, and a host that sees a crashed hook has no verdict to act on. Every
 * failure here becomes a decision instead: `ask` before a command runs, `allow`
 * afterwards, with a loud line on stderr
 * ([ADR 0026](../../../docs/adr/0026-deterministic-agent-gate.md) §2).
 */

/** Everything `gate` needs. */
export interface GateOptions {
  /** Adapter id: `claude-code`, `cursor`, `generic`. */
  host: string;
  /** Project root. */
  path: string;
  /** Severity at or above which the gate denies. */
  failOn?: string;
  /** Confidence at or above which a finding counts. */
  minConfidence?: string;
  /** Scan only what changed since this ref, at a turn boundary. */
  since?: string;
  /** Read the event from this file instead of stdin. For tests and for hosts
   * that pass a path. */
  eventFile?: string;
}

/** What the native side returns. */
interface GateResponse {
  ok: boolean;
  stdout: string;
  stderr?: string;
  exitCode: number;
}

/** Streams, injected so the whole command is testable in-process. */
export interface GateStreams {
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
}

/**
 * Milliseconds the gate is allowed before it gives up on itself.
 *
 * A hook sits on a developer's keystroke path. Past this the right answer is
 * the failure posture, not a slower correct one — a gate that pauses a session
 * for five seconds gets uninstalled, and an uninstalled gate catches nothing.
 */
const DEFAULT_TIMEOUT_MS = 5_000;

/** Largest event payload read from stdin. */
const MAX_EVENT_BYTES = 1024 * 1024;

/** Runs one gate event and returns the exit code the host expects. */
export async function runGate(
  native: NativeEngine,
  options: GateOptions,
  streams: GateStreams,
): Promise<number> {
  const event = await readEvent(options, streams.stdin);
  if (event === undefined) {
    streams.stderr.write("owlwarden gate: no event on stdin\n");
    streams.stdout.write("{}\n");
    return EXIT.ERROR;
  }

  const request = buildRequest(native, options, event);
  const response = await withTimeout(
    native.gate(JSON.stringify(request)),
    timeoutMs(),
    () =>
      JSON.stringify({
        ok: false,
        stdout: "{}",
        stderr: `owlwarden gate timed out after ${timeoutMs()}ms`,
        // 2 is "could not run" everywhere else in the CLI; the Rust side maps
        // the same condition to `ask` or `allow` per event, and this is the
        // path where we never reached it.
        exitCode: EXIT.ERROR,
      } satisfies GateResponse),
  );

  let decoded: GateResponse;
  try {
    decoded = JSON.parse(response) as GateResponse;
  } catch {
    streams.stderr.write("owlwarden gate: the engine returned something unparseable\n");
    streams.stdout.write("{}\n");
    return EXIT.ERROR;
  }

  streams.stdout.write(decoded.stdout);
  if (decoded.stderr !== undefined && decoded.stderr.length > 0) {
    streams.stderr.write(`${decoded.stderr}\n`);
  }
  return decoded.exitCode;
}

/** The gate's own timeout, overridable for slow machines and large trees. */
function timeoutMs(): number {
  const raw = process.env.OWLWARDEN_GATE_TIMEOUT_MS;
  if (raw === undefined) return DEFAULT_TIMEOUT_MS;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_TIMEOUT_MS;
}

/** Builds the native request, resolving what only the CLI can. */
function buildRequest(
  native: NativeEngine,
  options: GateOptions,
  event: string,
): Record<string, unknown> {
  void native;
  const root = options.path;

  // At a turn boundary the event names nothing, so the scope is the diff. Any
  // other event carries its own paths, and the Rust adapter has already pulled
  // them out — passing a git diff on top would widen a scan the host asked to
  // narrow.
  let scopedPaths: string[] = [];
  if (options.since !== undefined && isRepository(root)) {
    try {
      scopedPaths = resolveScope(root, { since: options.since })?.paths ?? [];
    } catch (error) {
      // A missing ref is not worth failing a hook over: the fallback is a wider
      // scan, which is the safe direction.
      if (!(error instanceof GitError)) throw error;
    }
  }

  return {
    host: options.host,
    event,
    projectRoot: root,
    scopedPaths,
    // Everything not committed. A suppression written during the session is
    // reported and not honoured; one the team committed still works.
    sessionPaths: sessionPaths(root),
    ...(options.failOn === undefined ? {} : { failOn: options.failOn }),
    ...(options.minConfidence === undefined ? {} : { minConfidence: options.minConfidence }),
    // Off by default, because the default should be the one that keeps people
    // from removing the hook.
    failClosed: process.env.OWLWARDEN_GATE_FAIL === "closed",
  };
}

/** Reads the event from a file or from stdin, bounded. */
async function readEvent(
  options: GateOptions,
  stdin: NodeJS.ReadableStream,
): Promise<string | undefined> {
  if (options.eventFile !== undefined) {
    try {
      return await readFile(options.eventFile, "utf8");
    } catch {
      return undefined;
    }
  }

  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    size += buffer.length;
    if (size > MAX_EVENT_BYTES) break;
    chunks.push(buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8").trim();
  return text.length > 0 ? text : undefined;
}

/** Resolves `promise`, or `fallback()` once `ms` has passed. */
async function withTimeout(
  promise: Promise<string>,
  ms: number,
  fallback: () => string,
): Promise<string> {
  let timer: NodeJS.Timeout | undefined;
  const expiry = new Promise<string>((resolve) => {
    timer = setTimeout(() => resolve(fallback()), ms);
    // The timer must not hold the process open once the scan wins the race.
    timer.unref?.();
  });
  try {
    return await Promise.race([promise, expiry]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
