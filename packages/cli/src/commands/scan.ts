import { writeFile } from "node:fs/promises";

import { formatConfigError, resolveConfig } from "@dointhai/owlwarden-config";
import { reportSchema, shouldFail, type Report } from "@dointhai/owlwarden-sdk";

import type { ScanOptions } from "../args.js";
import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";

/** The envelope the addon returns. Errors are data, not thrown strings. */
interface Envelope {
  ok: boolean;
  report?: unknown;
  error?: { code: string; message: string; help: string };
}

/**
 * Runs a scan and prints the report.
 *
 * Returns the process exit code rather than exiting, so the whole path is
 * testable without spawning a process.
 */
export async function runScan(
  native: NativeEngine,
  options: ScanOptions,
  stderr: NodeJS.WritableStream,
  stdout: NodeJS.WritableStream,
): Promise<number> {
  const resolved = await resolveConfig(options.path);
  if (!resolved.ok) {
    stderr.write(`error: ${formatConfigError(resolved.error)}\n`);
    return EXIT.ERROR;
  }

  // Flags beat config; config beats defaults. One place, so the precedence is
  // not something you have to reconstruct by reading three files.
  const config = resolved.config;
  const preset = options.preset ?? config.preset;
  const format = options.format ?? config.format;
  const failOn = options.failOn ?? config.failOn;
  const minConfidence = options.minConfidence ?? config.minConfidence;

  if (!options.quiet && format === "pretty") {
    writeBanner(native, options, stderr);
  }

  const envelope = JSON.parse(
    native.scan(
      JSON.stringify({
        projectRoot: options.path,
        preset,
        // The engine filters by confidence at the source, so a report never
        // carries findings the user asked not to see.
        minConfidence,
      }),
    ),
  ) as Envelope;

  if (!envelope.ok || envelope.report === undefined) {
    const error = envelope.error;
    stderr.write(
      error
        ? `error: ${error.message}\n  see ${error.help}\n`
        : "error: the engine returned no report and no reason\n",
    );
    return EXIT.ERROR;
  }

  const parsed = reportSchema.safeParse(envelope.report);
  if (!parsed.success) {
    // The addon and the CLI disagree about the report format, which means they
    // are from different releases. Say that, rather than crashing on a missing
    // field somewhere further down.
    stderr.write(
      `error: this CLI cannot read the engine's report format.\n` +
        `  CLI expects schema 1.x, engine reports ${native.schemaVersion()}.\n` +
        `  Reinstall owlwarden so both come from the same release.\n`,
    );
    return EXIT.ERROR;
  }

  await emit(native, envelope.report, parsed.data, options, format, stdout, stderr);

  return shouldFail(parsed.data, failOn, minConfidence) ? EXIT.FINDINGS : EXIT.CLEAN;
}

/**
 * Renders and writes the report.
 *
 * `raw` is the object exactly as the engine produced it, and that is what goes
 * to the renderer — `validated` has been through zod, which strips keys it does
 * not know about, and a newer engine's extra fields would vanish.
 */
async function emit(
  native: NativeEngine,
  raw: unknown,
  validated: Report,
  options: ScanOptions,
  format: "pretty" | "json",
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): Promise<void> {
  const toFile = options.out !== undefined;
  const rendered = native.render(
    JSON.stringify(raw),
    JSON.stringify({
      format,
      // Colour in a file is noise for whoever opens it next.
      color: options.color && !toFile,
      unicode: options.unicode,
      hyperlinks: options.hyperlinks,
      prettyJson: toFile,
    }),
  );

  if (options.out !== undefined) {
    await writeFile(options.out, `${rendered}\n`, "utf8");
    if (!options.quiet) {
      const count = validated.findings.length;
      stderr.write(`wrote ${count} finding${count === 1 ? "" : "s"} to ${options.out}\n`);
    }
    return;
  }

  stdout.write(`${rendered}\n`);
}

/** Writes the banner to stderr, and never lets a decoration failure matter. */
function writeBanner(
  native: NativeEngine,
  options: ScanOptions,
  stderr: NodeJS.WritableStream,
): void {
  if (process.stderr.isTTY !== true) return;
  try {
    stderr.write(
      native.banner(JSON.stringify({ color: options.color, unicode: options.unicode })),
    );
  } catch {
    // Decoration is not worth failing a scan over.
  }
}
