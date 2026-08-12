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
  | { command: "watch"; options: ScanOptions }
  | { command: "rules"; json: boolean }
  | { command: "coverage"; json: boolean; color: boolean; unicode: boolean }
  | { command: "explain"; rule: string; json: boolean }
  | { command: "mcp"; path: string }
  | { command: "init"; agentRules: boolean; workflow: boolean; mcp: boolean; force: boolean; out?: string }
  | { command: "plugin-scaffold"; name: string }
  | { command: "plugin-inspect"; path: string }
  | { command: "osv-update"; path: string; out?: string }
  | { command: "help" }
  | { command: "version" };

/** A scan report rendering target. */
export type ReportFormat = "pretty" | "json" | "sarif" | "junit" | "md";

/** Everything `scan` / `watch` needs, before config is merged in. */
export interface ScanOptions {
  /** Project root. */
  path: string;
  /** Unset means "whatever the config file says". */
  preset?: string;
  /** First stacked `--format`, kept for callers that still read one value. */
  format?: ReportFormat;
  /** Stacked `--format` values from the CLI (deduped, order preserved). */
  formats?: ReportFormat[];
  failOn?: Severity;
  minConfidence?: Confidence;
  out?: string;
  /** Path to a baseline file; only new findings are reported. */
  baseline?: string;
  /** Write the current findings to this baseline path. */
  writeBaseline?: string;
  /** List every inline suppression and flag stale ones. */
  reportSuppressions: boolean;
  /**
   * Allow `import()` of `owlwarden.config.{js,mjs,ts,mts}` from the scan
   * target. Off by default so a hostile tree cannot get code execution.
   */
  allowConfigJs: boolean;
  /**
   * True when `--ci` was passed. CI ignores project-config values for
   * `preset` / `failOn` / `minConfidence` unless {@link allowProjectConfig}
   * is set — otherwise a hostile PR can silence the gate with JSON alone.
   */
  ci: boolean;
  /**
   * Let project config set preset / fail-on / min-confidence even under
   * `--ci`. Off by default. Never enable on an untrusted tree.
   */
  allowProjectConfig: boolean;
  /**
   * Honour inline suppressions under `--ci`. Off by default so a PR cannot
   * silence findings with a comment. Local scans (no `--ci`) always honour
   * them.
   */
  allowSuppressions: boolean;
  /**
   * Permit `--baseline` under `--ci`. Off by default — a checked-in baseline
   * the pipeline always loads is otherwise a mute switch for new findings.
   */
  allowBaseline: boolean;
  /**
   * Live target URL for passive dynamic probing. Operator intent only —
   * never taken from project config (ADR 0014).
   */
  target?: string;
  /** Extra scope allowlist entries. Empty means the target's origin. */
  scope: string[];
  /**
   * Paths to WASM plugin directories (or bare `.wasm` files with a sidecar
   * manifest) to load alongside the first-party detectors. Sandboxed
   * (wasmtime), source-only — see `ARCHITECTURE.md` §6.
   */
  plugins: string[];
  /**
   * Permit `--plugin` under `--ci`. Off by default — a hostile PR should not
   * be able to smuggle a WASM module into the pipeline just by adding a path.
   */
  allowPlugins: boolean;
  /**
   * Refuse plugins without a verified detached ed25519 signature (ADR 0021).
   */
  requireSignedPlugins: boolean;
  /**
   * Apply Safe remediations (highlight replacements) after the scan.
   * Never applies to `Possible` findings. Requires a clean git tree unless
   * {@link allowDirty}.
   */
  fix: boolean;
  /** Also apply `Unsafe` remediations when {@link fix} is set. */
  fixUnsafe: boolean;
  /** With {@link fix}, show what would change without writing. */
  dryRun: boolean;
  /** With {@link fix}, allow a dirty git working tree. */
  allowDirty: boolean;
  /**
   * Permit state-changing HTTP methods in the dynamic engine. No first-party
   * detector uses this yet; the flag exists so the gate is testable.
   */
  allowActive: boolean;
  /**
   * Opt into Google OSV advisory lookup for lockfile dependencies.
   * Sends package name+version to api.osv.dev — never source code.
   */
  osv: boolean;
  /**
   * Path to a cached OSV index (`--osv-db`). File-backed; no network.
   */
  osvDb?: string;
  /**
   * With `--osv`, require `--osv-db` (fail closed). Air-gapped CI posture.
   */
  offline: boolean;
  color: boolean;
  unicode: boolean;
  quiet: boolean;
  hyperlinks: boolean;
  /** Incremental watch: project-relative paths that changed since the last scan. */
  dirtyPaths?: string[];
  /** Incremental watch: previous report JSON for finding merge. */
  previousReportJson?: string;
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
  format: { type: "string", multiple: true },
  out: { type: "string" },
  baseline: { type: "string" },
  "write-baseline": { type: "string" },
  "fail-on": { type: "string" },
  "min-confidence": { type: "string" },
  "report-suppressions": { type: "boolean", default: false },
  "allow-config-js": { type: "boolean", default: false },
  "allow-project-config": { type: "boolean", default: false },
  "allow-suppressions": { type: "boolean", default: false },
  "allow-baseline": { type: "boolean", default: false },
  target: { type: "string" },
  scope: { type: "string", multiple: true },
  plugin: { type: "string", multiple: true },
  "allow-plugins": { type: "boolean", default: false },
  "require-signed-plugins": { type: "boolean", default: false },
  fix: { type: "boolean", default: false },
  "fix-unsafe": { type: "boolean", default: false },
  "dry-run": { type: "boolean", default: false },
  "allow-dirty": { type: "boolean", default: false },
  "allow-active": { type: "boolean", default: false },
  osv: { type: "boolean", default: false },
  "osv-db": { type: "string" },
  offline: { type: "boolean", default: false },
  ci: { type: "boolean", default: false },
  "no-color": { type: "boolean", default: false },
  ascii: { type: "boolean", default: false },
  hyperlinks: { type: "boolean", default: false },
  quiet: { type: "boolean", short: "q", default: false },
  json: { type: "boolean", default: false },
  "agent-rules": { type: "boolean", default: false },
  workflow: { type: "boolean", default: false },
  mcp: { type: "boolean", default: false },
  force: { type: "boolean", default: false },
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
    case "watch":
      return { command: "watch", options: scanOptions(values, rest) };
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
    case "mcp": {
      if (rest.length > 1) {
        throw new ArgError(`mcp takes at most one path, got ${rest.length}`);
      }
      return { command: "mcp", path: rest[0] ?? "." };
    }
    case "init": {
      const selected = values["agent-rules"] || values.workflow || values.mcp;
      const parsedInit: Extract<Cli, { command: "init" }> = {
        command: "init",
        agentRules: selected ? values["agent-rules"] : true,
        workflow: selected ? values.workflow : true,
        mcp: selected ? values.mcp : true,
        force: values.force,
      };
      if (values.out !== undefined) parsedInit.out = values.out;
      return parsedInit;
    }
    case "plugin": {
      const sub = rest[0];
      if (sub === "inspect") {
        const path = rest[1];
        if (!path) {
          throw new ArgError("plugin inspect requires a path");
        }
        return { command: "plugin-inspect", path };
      }
      if (sub !== "scaffold") {
        throw new ArgError("usage: owlwarden plugin scaffold <name> | plugin inspect <path>");
      }
      const name = rest[1];
      if (!name) {
        throw new ArgError("plugin scaffold requires a name");
      }
      return { command: "plugin-scaffold", name };
    }
    case "osv": {
      if (rest[0] !== "update") {
        throw new ArgError("usage: owlwarden osv update [PATH] [--out FILE]");
      }
      const path = rest[1] ?? ".";
      return values.out === undefined
        ? { command: "osv-update", path }
        : { command: "osv-update", path, out: values.out };
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

  // `--ci` sets machine-readable defaults and refuses project-controlled mute
  // switches (config gates, suppressions, baseline) unless explicitly allowed.
  const ci = values.ci;
  const formats = parseFormats(
    "--format",
    ci ? (values.format ?? "json") : values.format,
    ["pretty", "json", "sarif", "junit", "md"] as const,
  );

  const scope = values.scope ?? [];
  if (scope.length > 64) {
    throw new ArgError("--scope accepts at most 64 entries");
  }

  const options: ScanOptions = {
    path: positionals[0] ?? ".",
    color: !values["no-color"] && !ci && useColorByDefault(),
    unicode: !values.ascii,
    quiet: values.quiet || ci,
    hyperlinks: values.hyperlinks,
    reportSuppressions: values["report-suppressions"],
    allowConfigJs: values["allow-config-js"],
    ci,
    allowProjectConfig: values["allow-project-config"],
    allowSuppressions: values["allow-suppressions"],
    allowBaseline: values["allow-baseline"],
    scope,
    plugins: values.plugin ?? [],
    allowPlugins: values["allow-plugins"],
    requireSignedPlugins: values["require-signed-plugins"],
    fix: values.fix,
    fixUnsafe: values["fix-unsafe"],
    dryRun: values["dry-run"],
    allowDirty: values["allow-dirty"],
    allowActive: values["allow-active"],
    osv: values.osv,
    offline: values.offline,
  };

  if (options.offline && values["osv-db"] === undefined) {
    throw new ArgError("--offline requires --osv-db");
  }
  if (values["osv-db"] !== undefined) {
    options.osvDb = values["osv-db"];
  }

  if (options.fixUnsafe && !options.fix) {
    throw new ArgError("--fix-unsafe requires --fix");
  }
  if (options.dryRun && !options.fix) {
    throw new ArgError("--dry-run requires --fix");
  }
  if (options.allowDirty && !options.fix) {
    throw new ArgError("--allow-dirty requires --fix");
  }
  if (options.fix && options.ci) {
    throw new ArgError("--fix cannot be combined with --ci (autofix is a local operation)");
  }

  // Assigned conditionally because `exactOptionalPropertyTypes` distinguishes
  // "absent" from "present and undefined", and absent is what tells the config
  // layer it may supply the value.
  if (values.preset !== undefined) options.preset = values.preset;
  if (formats !== undefined) {
    options.formats = formats;
    const [first] = formats;
    if (first !== undefined) options.format = first;
  }
  if (values.out !== undefined) options.out = values.out;
  if (values.baseline !== undefined) options.baseline = values.baseline;
  if (values["write-baseline"] !== undefined) options.writeBaseline = values["write-baseline"];
  if (values.target !== undefined) options.target = values.target;
  if (options.target === undefined && options.scope.length > 0) {
    throw new ArgError("--scope requires --target");
  }
  if (options.allowActive && options.target === undefined) {
    throw new ArgError("--allow-active requires --target");
  }
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

function parseFormats<const T extends readonly string[]>(
  flag: string,
  raw: string | string[] | undefined,
  accepted: T,
): T[number][] | undefined {
  if (raw === undefined) return undefined;
  const list = Array.isArray(raw) ? raw : [raw];
  const seen = new Set<string>();
  const result: T[number][] = [];
  for (const item of list) {
    if (!accepted.includes(item)) {
      throw new ArgError(
        `invalid value ${JSON.stringify(item)} for ${flag}; expected one of: ${accepted.join(", ")}`,
      );
    }
    if (seen.has(item)) continue;
    seen.add(item);
    result.push(item);
  }
  return result;
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
