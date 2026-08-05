import { parseArgs, type ParseArgsConfig } from "node:util";

import { confidenceSchema, severitySchema, type Confidence, type Severity } from "@dointhai/owlwarden-sdk";

/**
 * Argument parsing, on top of Node's own `parseArgs`.
 *
 * No argument-parsing dependency: a security tool's install footprint is part
 * of its argument, and `parseArgs` covers a surface this size. What it does not
 * give us is validation of *values*, so that happens here — and unknown flags
 * are an error, never a shrug, because a mistyped `--presset` that silently
 * scanned with the default preset would be a false sense of coverage.
 */

/** Flags that apply to every command. */
interface CommonFlags {
  help: boolean;
  version: boolean;
}

/** A parsed command line. */
export type Cli =
  | { command: "scan"; options: ScanOptions }
  | { command: "rules"; json: boolean }
  | { command: "coverage"; json: boolean; color: boolean; unicode: boolean }
  | { command: "explain"; rule: string; json: boolean }
  | { command: "help" }
  | { command: "version" };

/** Everything `scan` needs, before config is merged in. */
export interface ScanOptions {
  /** Project root. */
  path: string;
  /** Unset means "whatever the config file says". */
  preset?: string;
  format?: "pretty" | "json";
  failOn?: Severity;
  minConfidence?: Confidence;
  out?: string;
  color: boolean;
  unicode: boolean;
  quiet: boolean;
  hyperlinks: boolean;
}

/** A command line we could not make sense of. */
export class ArgError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArgError";
  }
}

const OPTIONS = {
  preset: { type: "string" },
  format: { type: "string" },
  out: { type: "string" },
  "fail-on": { type: "string" },
  "min-confidence": { type: "string" },
  ci: { type: "boolean", default: false },
  "no-color": { type: "boolean", default: false },
  ascii: { type: "boolean", default: false },
  hyperlinks: { type: "boolean", default: false },
  quiet: { type: "boolean", short: "q", default: false },
  json: { type: "boolean", default: false },
  help: { type: "boolean", short: "h", default: false },
  version: { type: "boolean", short: "V", default: false },
} as const satisfies NonNullable<ParseArgsConfig["options"]>;

/** The raw `parseArgs` call, wrapped so its return type can be named. */
function parseRaw(argv: string[]) {
  return parseArgs({
    args: argv,
    options: OPTIONS,
    allowPositionals: true,
    // Unknown flags throw. See the note at the top of the file.
    strict: true,
  });
}

/**
 * Parses `argv` (already stripped of `node` and the script path).
 *
 * @throws {ArgError} for an unknown flag, a missing value, or a value outside
 * the accepted set.
 */
export function parse(argv: string[]): Cli {
  let parsed: ReturnType<typeof parseRaw>;
  try {
    parsed = parseRaw(argv);
  } catch (error) {
    throw new ArgError(error instanceof Error ? error.message : String(error));
  }

  const { values, positionals } = parsed;
  const common: CommonFlags = { help: values.help, version: values.version };
  const [command, ...rest] = positionals;

  if (common.version) return { command: "version" };
  if (common.help || command === undefined || command === "help") {
    return { command: "help" };
  }

  switch (command) {
    case "scan":
      return { command: "scan", options: scanOptions(values, rest) };
    case "rules":
      return { command: "rules", json: values.json };
    case "coverage":
      return {
        command: "coverage",
        json: values.json,
        color: !values["no-color"] && useColorByDefault(),
        unicode: !values.ascii,
      };
    case "explain": {
      const rule = rest[0];
      if (rule === undefined) {
        throw new ArgError("explain requires a rule id, e.g. `owlwarden explain stack-trace-leak`");
      }
      return { command: "explain", rule, json: values.json };
    }
    default:
      throw new ArgError(`unknown command ${JSON.stringify(command)}`);
  }
}

type Values = ReturnType<typeof parseRaw>["values"];

function scanOptions(values: Values, positionals: string[]): ScanOptions {
  if (positionals.length > 1) {
    throw new ArgError(`scan takes at most one path, got ${positionals.length}`);
  }

  // --ci is a shorthand, not a mode. Everything it does is reachable with the
  // individual flags, so there is no second code path that only runs in CI.
  const ci = values.ci;
  const format = enumValue(
    "--format",
    ci ? (values.format ?? "json") : values.format,
    ["pretty", "json"] as const,
  );

  const options: ScanOptions = {
    path: positionals[0] ?? ".",
    color: !values["no-color"] && !ci && useColorByDefault(),
    unicode: !values.ascii,
    quiet: values.quiet || ci,
    hyperlinks: values.hyperlinks,
  };

  // Assigned conditionally because `exactOptionalPropertyTypes` distinguishes
  // "absent" from "present and undefined", and absent is what tells the config
  // layer it may supply the value.
  if (values.preset !== undefined) options.preset = values.preset;
  if (format !== undefined) options.format = format;
  if (values.out !== undefined) options.out = values.out;
  if (values["fail-on"] !== undefined) {
    options.failOn = parseWith(severitySchema, "--fail-on", values["fail-on"], [
      "high",
      "medium",
      "low",
      "info",
    ]);
  }
  if (values["min-confidence"] !== undefined) {
    options.minConfidence = parseWith(
      confidenceSchema,
      "--min-confidence",
      values["min-confidence"],
      ["confirmed", "likely", "possible"],
    );
  }

  return options;
}

function parseWith<T>(
  schema: { safeParse(value: unknown): { success: true; data: T } | { success: false } },
  flag: string,
  raw: string,
  accepted: readonly string[],
): T {
  const result = schema.safeParse(raw);
  if (!result.success) {
    throw new ArgError(
      `invalid value ${JSON.stringify(raw)} for ${flag}; expected one of: ${accepted.join(", ")}`,
    );
  }
  return result.data;
}

function enumValue<const T extends readonly string[]>(
  flag: string,
  raw: string | undefined,
  accepted: T,
): T[number] | undefined {
  if (raw === undefined) return undefined;
  if (!accepted.includes(raw)) {
    throw new ArgError(
      `invalid value ${JSON.stringify(raw)} for ${flag}; expected one of: ${accepted.join(", ")}`,
    );
  }
  return raw;
}

/**
 * Whether to colour by default.
 *
 * `NO_COLOR` is a user preference and is honoured unconditionally; see
 * https://no-color.org.
 */
function useColorByDefault(): boolean {
  if (process.env["NO_COLOR"] !== undefined && process.env["NO_COLOR"] !== "") return false;
  return process.stdout.isTTY === true;
}
