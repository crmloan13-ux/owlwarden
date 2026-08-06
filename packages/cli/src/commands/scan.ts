import { formatConfigError, resolveConfig } from "@dointhai/owlwarden-config";
import { reportSchema, shouldFail, type Report } from "@dointhai/owlwarden-sdk";

import type { ScanOptions } from "../args.js";
import { EXIT } from "../exit.js";
import type { NativeEngine } from "../native.js";
import { readFileBounded, writeReplacing } from "../safe-write.js";

/** Must match `owlwarden_core::baseline::MAX_BASELINE_BYTES`. */
const MAX_BASELINE_BYTES = 50_000 * 512;

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
  const resolved = await resolveConfig(options.path, {
    allowConfigJs: options.allowConfigJs,
  });
  if (!resolved.ok) {
    stderr.write(`error: ${formatConfigError(resolved.error)}\n`);
    return EXIT.ERROR;
  }

  if (resolved.skippedExecutable !== undefined && !options.quiet) {
    stderr.write(
      `note: skipped executable config ${resolved.skippedExecutable}\n` +
        `  pass --allow-config-js to load it (never on an untrusted tree)\n`,
    );
  }

  // Flags beat config; config beats defaults. Under `--ci`, project config must
  // not set the gate knobs (preset / fail-on / min-confidence) unless the
  // operator opted in — a hostile PR's owlwarden.config.json could otherwise
  // silence the build with `{ "minConfidence": "confirmed" }`.
  const config = resolved.config;
  const trustProjectGates = !options.ci || options.allowProjectConfig;
  const preset = options.preset ?? (trustProjectGates ? config.preset : "quick");
  const format = options.format ?? (trustProjectGates ? config.format : "json");
  const failOn = options.failOn ?? (trustProjectGates ? config.failOn : "info");
  const minConfidence =
    options.minConfidence ?? (trustProjectGates ? config.minConfidence : "possible");

  // These notes go to stderr even under `--ci --quiet`: stdout stays one JSON
  // object, and CI logs need to show why the gate ignored project mute switches.
  if (
    options.ci &&
    !options.allowProjectConfig &&
    resolved.source.kind !== "defaults"
  ) {
    stderr.write(
      "note: --ci ignores project config for preset/fail-on/min-confidence\n" +
        "  pass flags explicitly, or --allow-project-config on a trusted tree\n",
    );
  }

  // Under `--ci`, a checked-in baseline the pipeline always loads is a mute
  // switch unless the operator opted in.
  if (options.ci && options.baseline !== undefined && !options.allowBaseline) {
    stderr.write(
      "error: --baseline under --ci requires --allow-baseline\n" +
        "  omit --baseline on untrusted PRs, or pass --allow-baseline on a trusted tree\n",
    );
    return EXIT.ERROR;
  }

  const honorSuppressions = !options.ci || options.allowSuppressions;
  if (options.ci && !options.allowSuppressions) {
    stderr.write(
      "note: --ci ignores inline suppressions\n" +
        "  pass --allow-suppressions on a trusted tree\n",
    );
  }

  if (!options.quiet && format === "pretty") {
    writeBanner(native, options, stderr);
  }

  let baselineJson: string | undefined;
  if (options.baseline !== undefined) {
    try {
      baselineJson = await readFileBounded(options.baseline, MAX_BASELINE_BYTES);
    } catch (error) {
      stderr.write(
        `error: could not read baseline ${options.baseline}: ${
          error instanceof Error ? error.message : String(error)
        }\n`,
      );
      return EXIT.ERROR;
    }
  }

  const envelope = JSON.parse(
    native.scan(
      JSON.stringify({
        projectRoot: options.path,
        preset,
        // The engine filters by confidence at the source, so a report never
        // carries findings the user asked not to see.
        minConfidence,
        honorSuppressions,
        ...(baselineJson !== undefined ? { baselineJson } : {}),
        ...(options.writeBaseline !== undefined
          ? { writeBaseline: options.writeBaseline }
          : {}),
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

  if (options.writeBaseline !== undefined && !options.quiet) {
    stderr.write(`wrote baseline to ${options.writeBaseline}\n`);
  }

  try {
    await emit(native, envelope.report, parsed.data, options, format, stdout, stderr);
  } catch (error) {
    const where = options.out ?? "report";
    stderr.write(
      `error: could not write ${where}: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    return EXIT.ERROR;
  }

  // Human listing goes to stderr so `--format json` on stdout stays one object.
  // The JSON report already carries `suppressions` for agents and CI.
  if (options.reportSuppressions) {
    writeSuppressions(parsed.data, stderr);
  }

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
    await writeReplacing(options.out, `${rendered}\n`);
    if (!options.quiet) {
      const count = validated.findings.length;
      stderr.write(`wrote ${count} finding${count === 1 ? "" : "s"} to ${options.out}\n`);
    }
    return;
  }

  stdout.write(`${rendered}\n`);
}

/** Prints every suppression so stale ones cannot rot unnoticed. */
function writeSuppressions(report: Report, stdout: NodeJS.WritableStream): void {
  const records = report.suppressions ?? [];
  if (records.length === 0) {
    stdout.write("No inline suppressions found.\n");
    return;
  }
  stdout.write(`\n${records.length} suppression(s)\n`);
  for (const record of records) {
    // Missing-reason directives never hide a finding; do not call them "active".
    const flags = record.missingReason
      ? "missing-reason"
      : record.stale
        ? "stale"
        : "active";
    const reason = record.reason === "" ? "(no reason)" : record.reason;
    stdout.write(`  ${record.path}:${record.line}  ${record.rule}  [${flags}]\n`);
    stdout.write(`    ${reason}\n`);
  }
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
