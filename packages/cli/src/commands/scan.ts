import { formatConfigError, resolveConfig } from "@dointhai/owlwarden-config";
import { reportSchema, shouldFail, type Report } from "@dointhai/owlwarden-sdk";
import { lstat } from "node:fs/promises";
import { join } from "node:path";

import type { ReportFormat, ScanOptions } from "../args.js";
import { EXIT } from "../exit.js";
import { applyFixes } from "../fix.js";
import type { NativeEngine } from "../native.js";
import { readFileBounded, writeReplacing } from "../safe-write.js";

/** Must match `owlwarden_core::baseline::MAX_BASELINE_BYTES`. */
const MAX_BASELINE_BYTES = 50_000 * 512;

/** The envelope the addon returns. Errors are data, not thrown strings. */
interface Envelope {
  ok: boolean;
  report?: unknown;
  error?: { code: string; message: string; help: string };
  /** Present when `--allow-active` ran; method/URL/status only. */
  audit?: Array<{ method: string; url: string; status?: number }>;
}

/** Optional output from {@link runScan} for callers that need the report object. */
export interface ScanCapture {
  report?: Report;
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
  capture?: ScanCapture,
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
  const formats = resolveFormats(options, trustProjectGates ? config.format : "json");
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

  // Under `--ci`, a WASM module named on the command line still has to be
  // opted into explicitly — the plugin itself is sandboxed, but a hostile PR
  // should not be able to add one to a trusted pipeline just by adding a path.
  if (options.ci && options.plugins.length > 0 && !options.allowPlugins) {
    stderr.write(
      "error: --plugin under --ci requires --allow-plugins\n" +
        "  omit --plugin on untrusted PRs, or pass --allow-plugins on a trusted tree\n",
    );
    return EXIT.ERROR;
  }

  if (!options.quiet && formats.includes("pretty")) {
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
    await native.scan(
      JSON.stringify({
        projectRoot: options.path,
        preset,
        // The engine filters by confidence after correlation, so a Possible
        // static finding can still be raised to Confirmed by a live probe.
        minConfidence,
        honorSuppressions,
        ...(baselineJson !== undefined ? { baselineJson } : {}),
        ...(options.writeBaseline !== undefined
          ? { writeBaseline: options.writeBaseline }
          : {}),
        ...(options.target !== undefined ? { target: options.target } : {}),
        ...(options.scope.length > 0 ? { scope: options.scope } : {}),
        ...(options.plugins.length > 0 ? { plugins: options.plugins } : {}),
        ...(options.ci ? { ci: true } : {}),
        ...(options.allowPlugins ? { allowPlugins: true } : {}),
        ...(options.requireSignedPlugins ? { requireSignedPlugins: true } : {}),
        ...(options.allowActive ? { allowActive: true } : {}),
        ...osvScanFields(options),
        ...(options.dirtyPaths !== undefined && options.dirtyPaths.length > 0
          ? { dirtyPaths: options.dirtyPaths }
          : {}),
        ...(options.previousReportJson !== undefined
          ? { previousReportJson: options.previousReportJson }
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

  if (capture !== undefined) {
    capture.report = parsed.data;
  }

  if (options.writeBaseline !== undefined && !options.quiet) {
    stderr.write(`wrote baseline to ${options.writeBaseline}\n`);
  }

  if (options.allowActive && envelope.audit !== undefined && envelope.audit.length > 0) {
    stderr.write(`request audit (${envelope.audit.length})\n`);
    for (const entry of envelope.audit.slice(0, 1_000)) {
      const status = entry.status === undefined ? "-" : String(entry.status);
      stderr.write(`  ${entry.method} ${entry.url} → ${status}\n`);
    }
  }

  try {
    await emitAll(native, envelope.report, parsed.data, options, formats, stdout, stderr);
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

  if (options.fix) {
    const fixResult = await applyFixes({
      projectRoot: options.path,
      report: parsed.data,
      fixUnsafe: options.fixUnsafe,
      dryRun: options.dryRun,
      allowDirty: options.allowDirty,
      stderr,
    });
    for (const error of fixResult.errors) {
      stderr.write(`error: ${error}\n`);
    }
    if (fixResult.errors.some((message) => message.includes("working tree is not clean"))) {
      return EXIT.ERROR;
    }
    if (!options.quiet) {
      stderr.write(
        `fix: ${fixResult.applied} applied, ${fixResult.skipped} skipped` +
          `${options.dryRun ? " (dry-run)" : ""}\n`,
      );
    }
    // Re-scan after real writes so we never claim success without checking.
    if (!options.dryRun && fixResult.written.length > 0) {
      const verify = JSON.parse(
        await native.scan(
          JSON.stringify({
            projectRoot: options.path,
            preset,
            minConfidence,
            honorSuppressions,
            ...(baselineJson !== undefined ? { baselineJson } : {}),
            ...(options.plugins.length > 0 ? { plugins: options.plugins } : {}),
            ...(options.ci ? { ci: true } : {}),
            ...(options.allowPlugins ? { allowPlugins: true } : {}),
            ...(options.requireSignedPlugins ? { requireSignedPlugins: true } : {}),
            ...osvScanFields(options),
          }),
        ),
      ) as Envelope;
      if (!verify.ok || verify.report === undefined) {
        stderr.write(
          `error: re-scan after --fix failed: ${
            verify.error?.message ?? "the engine returned no report"
          }\n`,
        );
        return EXIT.ERROR;
      }
      const verified = reportSchema.safeParse(verify.report);
      if (!verified.success) {
        stderr.write("error: re-scan after --fix returned an unreadable report\n");
        return EXIT.ERROR;
      }
      const remaining = verified.data.findings.filter((finding) =>
        fixResult.written.some((path) => {
          if (!("path" in finding.location)) return false;
          return path.endsWith(finding.location.path) || path.includes(finding.location.path);
        }),
      );
      if (!options.quiet) {
        stderr.write(
          `re-scan: ${verified.data.findings.length} finding(s) remain` +
            `${remaining.length > 0 ? ` (${remaining.length} still in rewritten files)` : ""}\n`,
        );
      }
      return shouldFail(verified.data, failOn, minConfidence) ? EXIT.FINDINGS : EXIT.CLEAN;
    }
    if (fixResult.errors.length > 0 && fixResult.written.length === 0 && !options.dryRun) {
      return EXIT.ERROR;
    }
  }

  return shouldFail(parsed.data, failOn, minConfidence) ? EXIT.FINDINGS : EXIT.CLEAN;
}

/**
 * Resolves the format list: CLI stacks beat config; config beats the default.
 */
function resolveFormats(options: ScanOptions, configDefault: ReportFormat): ReportFormat[] {
  if (options.formats !== undefined) return options.formats;
  if (options.format !== undefined) return [options.format];
  return [configDefault];
}

function isMachineFormat(format: ReportFormat): boolean {
  return format !== "pretty";
}

function machineExtension(format: ReportFormat): string {
  switch (format) {
    case "json":
      return ".json";
    case "sarif":
      return ".sarif";
    case "junit":
      return ".xml";
    case "pretty":
      throw new Error("pretty is not a machine format");
  }
}

/**
 * Renders each requested format from one report (ADR 0022).
 *
 * `raw` is the object exactly as the engine produced it — that is what goes
 * to the renderer. `validated` has been through zod, which strips keys it does
 * not know about, and a newer engine's extra fields would vanish.
 */
async function emitAll(
  native: NativeEngine,
  raw: unknown,
  validated: Report,
  options: ScanOptions,
  formats: ReportFormat[],
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): Promise<void> {
  const machineFormats = formats.filter(isMachineFormat);
  if (machineFormats.length > 1 && options.out === undefined) {
    throw new Error("multiple machine formats require --out");
  }

  for (const format of formats) {
    const outPath = await resolveOutputPath(options.out, format, machineFormats.length);
    const toFile = outPath !== undefined;
    const rendered = native.render(
      JSON.stringify(raw),
      JSON.stringify({
        format,
        color: options.color && !toFile && format === "pretty",
        unicode: options.unicode,
        hyperlinks: options.hyperlinks,
        prettyJson: toFile && format === "json",
      }),
    );

    if (toFile) {
      await writeReplacing(outPath, `${rendered}\n`);
      if (!options.quiet) {
        const count = validated.findings.length;
        stderr.write(`wrote ${count} finding${count === 1 ? "" : "s"} to ${outPath}\n`);
      }
      continue;
    }

    streamFor(format, formats, stdout, stderr).write(`${rendered}\n`);
  }
}

/** Picks stdout vs stderr so at most one machine document hits stdout. */
function streamFor(
  format: ReportFormat,
  formats: ReportFormat[],
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): NodeJS.WritableStream {
  if (format === "pretty") {
    return formats.length === 1 ? stdout : stderr;
  }
  return stdout;
}

/** Maps `--out` to a destination path for one machine format. */
async function resolveOutputPath(
  out: string | undefined,
  format: ReportFormat,
  machineCount: number,
): Promise<string | undefined> {
  if (format === "pretty" || out === undefined) return undefined;
  if (machineCount === 1) return out;

  const ext = machineExtension(format);
  if (out.endsWith("/") || out.endsWith("\\")) {
    return join(out, `report${ext}`);
  }
  try {
    const info = await lstat(out);
    if (info.isDirectory()) {
      return join(out, `report${ext}`);
    }
  } catch (error) {
    const code =
      error && typeof error === "object" && "code" in error
        ? (error as { code?: string }).code
        : undefined;
    if (code !== "ENOENT") {
      throw error;
    }
  }
  return `${out}${ext}`;
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

/** OSV / offline fields for the native `ScanRequest`. */
function osvScanFields(options: ScanOptions): Record<string, unknown> {
  const enabled = options.osv || options.osvDb !== undefined;
  if (!enabled && !options.offline) {
    return {};
  }
  const fields: Record<string, unknown> = {};
  if (enabled) {
    fields["osv"] = true;
  }
  if (options.osvDb !== undefined) {
    fields["osvDb"] = options.osvDb;
  }
  if (options.offline) {
    fields["osvOffline"] = true;
  }
  return fields;
}
