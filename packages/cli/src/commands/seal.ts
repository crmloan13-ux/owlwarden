import type { NativeEngine } from "../native.js";
import type { SealCliOptions } from "../args.js";
import { EXIT } from "../exit.js";

/** The shape the engine answers with. */
interface SealResponse {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Runs `owlwarden seal`.
 *
 * A thin wrapper on purpose. Every decision — what counts as drift, whether the
 * surface may be sealed at all, what the diff says — lives in the engine, so
 * this CLI and the standalone binary cannot answer differently. What is decided
 * here is the one thing Node owns: whether a human is present.
 */
export async function runSeal(
  native: NativeEngine,
  options: SealCliOptions,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  const request = {
    projectRoot: options.path,
    mode: options.mode,
    json: options.json,
    // `--yes` or a real terminal. Nothing else counts as a human, and the
    // engine refuses to write without one: whatever wrote the drift can also
    // run `seal`, and raising that cost is the point.
    attended: options.yes || process.stdin.isTTY === true,
    accept: options.accept,
    ...(options.trust === undefined ? {} : { trust: options.trust }),
    requireSigned: options.requireSigned,
    ascii: options.ascii,
  };

  let raw: string;
  try {
    raw = await native.seal(JSON.stringify(request));
  } catch (error) {
    stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
    return EXIT.ERROR;
  }

  let response: SealResponse;
  try {
    response = JSON.parse(raw) as SealResponse;
  } catch {
    stderr.write("error: the engine returned a seal response this build cannot read\n");
    return EXIT.ERROR;
  }

  if (response.stdout) stdout.write(response.stdout);
  if (response.stderr) stderr.write(response.stderr);
  return response.exitCode;
}
