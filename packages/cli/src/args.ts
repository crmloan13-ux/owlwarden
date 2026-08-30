import { parseArgs, type ParseArgsConfig } from "node:util";

import {
  confidenceSchema,
  exposureSchema,
  severitySchema,
  type Confidence,
  type Exposure,
  type Severity,
} from "@dointhai/owlwarden-sdk";

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
  | { command: "vet"; options: ScanOptions }
  | { command: "gate"; options: GateCliOptions }
  | { command: "verify"; options: VerifyCliOptions }
  | { command: "rules"; json: boolean }
  | { command: "coverage"; json: boolean; color: boolean; unicode: boolean }
  | { command: "explain"; rule: string; json: boolean }
  | { command: "mcp"; path: string }
  | {
      command: "init";
      hosts: ("claude-code" | "cursor" | "generic")[];
      agentRules: boolean;
      workflow: boolean;
      mcp: boolean;
      force: boolean;
      out?: string;
    }
  | { command: "plugin-scaffold"; name: string }
  | { command: "plugin-inspect"; path: string }
  | { command: "osv-update"; path: string; out?: string }
  | { command: "seal"; options: SealCliOptions }
  | { command: "effective"; options: EffectiveCliOptions }
  | { command: "help" }
  | { command: "version" };

/** A scan report rendering target. */
export type ReportFormat = "pretty" | "json" | "sarif" | "junit" | "md" | "agent";

/** Everything `owlwarden effective` needs. */
export interface EffectiveCliOptions {
  /** Project root. */
  path: string;
  /** Which host's resolution order to follow. */
  host: string;
  /** Restrict the answer to one key. */
  key?: string;
  /** Emit JSON instead of text. */
  json: boolean;
  /** Also read the user and managed tiers. */
  includeUserConfig: boolean;
  /** Use box-drawing characters. */
  unicode: boolean;
}

/** What `owlwarden seal` should do. */
export type SealMode = "write" | "verify" | "diff" | "accept";

/** Everything `owlwarden seal` needs. */
export interface SealCliOptions {
  /** Project root. */
  path: string;
  /** What to do. */
  mode: SealMode;
  /** Emit JSON instead of text. */
  json: boolean;
  /** Proceed without a terminal. */
  yes: boolean;
  /** `--accept <fingerprint> --reason <text>` pairs, in the order given. */
  accept: { fingerprint: string; reason: string }[];
  /** A trust root file for the detached signature. Never inside the tree. */
  trust?: string;
  /** Refuse an unsigned or badly-signed seal. */
  requireSigned: boolean;
  /** Restrict output to ASCII. */
  ascii: boolean;
}

/** Everything `owlwarden gate` needs. */
export interface GateCliOptions {
  /** Adapter id. */
  host: string;
  /** Project root. */
  path: string;
  failOn?: string;
  minConfidence?: string;
  /** At a turn boundary, scan what changed since this ref. */
  since?: string;
  /** Read the event from a file rather than stdin. */
  eventFile?: string;
}

/** Everything `owlwarden verify` needs. */
export interface VerifyCliOptions {
  /** Project root. */
  path: string;
  /** The unified diff to apply. */
  patch: string;
  /** The rule the patch is supposed to resolve. */
  rule?: string;
  /** Severity at or above which a *new* finding fails the verification. */
  failOn?: string;
}

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
  /**
   * Exposure at or above which findings fail the run, independently of
   * {@link failOn}. Unset leaves the gate off.
   */
  failOnExposure?: Exposure;
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
  /** Scan only what changed since this git ref. */
  since?: string;
  /** Scan only what is staged. */
  staged: boolean;
  /** Scan only these project-relative paths. */
  paths: string[];
  /** `--format agent`: token ceiling for the report. */
  budget?: number;
  /** `--format agent`: hard cap on findings, applied before the budget. */
  maxFindings?: number;
  /**
   * True for `owlwarden vet`: the target is not yours.
   *
   * Every mechanism built to make adoption realistic on a legacy repository —
   * config, baseline, inline suppressions, plugins — is, in the hands of the
   * repository's author, a mechanism for hiding a finding. On your own
   * repository that trade is correct and deliberate. On someone else's it is
   * not a trade at all, so `vet` treats the target's suppression surface as
   * evidence rather than as instruction
   * ([ADR 0025](../../../docs/adr/0025-agent-surface-and-supply-chain.md) §7).
   */
  vet: boolean;
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
  "fail-on-exposure": { type: "string" },
  verify: { type: "boolean", default: false },
  diff: { type: "boolean", default: false },
  accept: { type: "string", multiple: true },
  reason: { type: "string", multiple: true },
  trust: { type: "string" },
  "require-signed-seal": { type: "boolean", default: false },
  yes: { type: "boolean", default: false },
  key: { type: "string" },
  "include-user-config": { type: "boolean", default: false },
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
  since: { type: "string" },
  staged: { type: "boolean", default: false },
  paths: { type: "string", multiple: true },
  budget: { type: "string" },
  "max-findings": { type: "string" },
  host: { type: "string" },
  event: { type: "string" },
  patch: { type: "string" },
  rule: { type: "string" },
  "claude-code": { type: "boolean", default: false },
  cursor: { type: "boolean", default: false },
  generic: { type: "boolean", default: false },
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
    case "vet":
      return { command: "vet", options: vetOptions(values, rest) };
    case "gate":
      return { command: "gate", options: gateOptions(values, rest) };
    case "verify":
      return { command: "verify", options: verifyOptions(values, rest) };
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
      const hosts: ("claude-code" | "cursor" | "generic")[] = [];
      if (values["claude-code"]) hosts.push("claude-code");
      if (values.cursor) hosts.push("cursor");
      if (values.generic) hosts.push("generic");

      // A host flag selects the host wiring and nothing else. `init` with no
      // flags keeps its old meaning — agent rules, workflow, Cursor MCP — so an
      // existing script does not change behaviour under a new version.
      const legacy = values["agent-rules"] || values.workflow || values.mcp;
      const anything = legacy || hosts.length > 0;
      const parsedInit: Extract<Cli, { command: "init" }> = {
        command: "init",
        hosts,
        agentRules: anything ? values["agent-rules"] : true,
        workflow: anything ? values.workflow : true,
        mcp: anything ? values.mcp : true,
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
    case "seal":
      return { command: "seal", options: sealOptions(values, rest) };
    case "effective": {
      if (rest.length > 1) {
        throw new ArgError(`effective takes at most one path, got ${rest.length}`);
      }
      const host = values.host ?? "claude-code";
      const options: EffectiveCliOptions = {
        path: rest[0] ?? ".",
        host,
        json: values.json,
        includeUserConfig: values["include-user-config"],
        unicode: !values.ascii,
      };
      if (values.key !== undefined) options.key = values.key;
      return { command: "effective", options };
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
    ["pretty", "json", "sarif", "junit", "md", "agent"] as const,
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
    staged: values.staged,
    paths: (values.paths ?? []).flatMap((entry) =>
      entry.split(",").map((path) => path.trim()).filter((path) => path.length > 0),
    ),
    vet: false,
  };

  const narrowings =
    Number(values.since !== undefined) + Number(values.staged) + Number(options.paths.length > 0);
  if (narrowings > 1) {
    throw new ArgError(
      "--since, --staged, and --paths each narrow the scan a different way; pass one",
    );
  }
  if (values.since !== undefined) options.since = values.since;
  if (values.budget !== undefined) options.budget = positiveInt("--budget", values.budget);
  if (values["max-findings"] !== undefined) {
    options.maxFindings = positiveInt("--max-findings", values["max-findings"]);
  }

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
  if (values["fail-on-exposure"] !== undefined) {
    options.failOnExposure = parseWith(
      exposureSchema,
      "--fail-on-exposure",
      values["fail-on-exposure"],
      ["internet", "authenticated", "internal", "unknown"],
    );
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

/**
 * `vet` is `scan` with a fixed posture for the case where the target is not
 * yours.
 *
 * The posture is not a set of defaults the user can drift away from — it is the
 * command. Every knob that could hide a finding is nailed shut here rather than
 * merely defaulted, because the whole value of `vet` is that its answer does
 * not depend on what the scanned repository asked for.
 */
function vetOptions(values: Values, positionals: string[]): ScanOptions {
  if (positionals.length > 1) {
    throw new ArgError(`vet takes at most one path, got ${positionals.length}`);
  }
  for (const [flag, set] of [
    ["--plugin", (values.plugin ?? []).length > 0],
    ["--target", values.target !== undefined],
    ["--osv", values.osv],
    ["--baseline", values.baseline !== undefined],
    ["--allow-suppressions", values["allow-suppressions"]],
    ["--allow-project-config", values["allow-project-config"]],
    ["--allow-config-js", values["allow-config-js"]],
  ] as const) {
    if (set) {
      throw new ArgError(
        `${flag} is not available with vet: the point of vet is that the target repository ` +
          "cannot influence the result. Use `owlwarden scan` on a tree you trust.",
      );
    }
  }

  const formats = parseFormats("--format", values.format, [
    "pretty",
    "json",
    "sarif",
    "junit",
    "md",
    "agent",
  ] as const);

  const options: ScanOptions = {
    path: positionals[0] ?? ".",
    preset: "agent-surface",
    failOn: "high",
    minConfidence: "likely",
    color: !values["no-color"] && useColorByDefault(),
    unicode: !values.ascii,
    quiet: values.quiet,
    hyperlinks: values.hyperlinks,
    reportSuppressions: true,
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
    offline: true,
    staged: false,
    paths: [],
    vet: true,
  };
  if (formats !== undefined) {
    options.formats = formats;
    const [first] = formats;
    if (first !== undefined) options.format = first;
  }
  if (values.out !== undefined) options.out = values.out;
  // `--fail-on` is the one knob left, because it is the operator's decision
  // rather than the target's: someone vetting a repository may reasonably want
  // to see medium findings fail too.
  if (values["fail-on"] !== undefined) {
    options.failOn = parseWith(severitySchema, "--fail-on", values["fail-on"], [
      "high",
      "medium",
      "low",
      "info",
    ]);
  }
  if (values["fail-on-exposure"] !== undefined) {
    options.failOnExposure = parseWith(
      exposureSchema,
      "--fail-on-exposure",
      values["fail-on-exposure"],
      ["internet", "authenticated", "internal", "unknown"],
    );
  }
  return options;
}

function sealOptions(values: Values, positionals: string[]): SealCliOptions {
  if (positionals.length > 1) {
    throw new ArgError(`seal takes at most one path, got ${positionals.length}`);
  }
  const fingerprints = values.accept ?? [];
  const reasons = values.reason ?? [];
  if (fingerprints.length !== reasons.length) {
    // The same rule suppressions live under. An acceptance nobody can explain
    // is an acceptance nobody decided, and a seal is precisely where the
    // decision is supposed to be written down.
    throw new ArgError(
      "every --accept needs its own --reason: pass them in pairs, " +
        '`--accept <fingerprint> --reason "why this is deliberate"`',
    );
  }
  const accept = fingerprints.map((fingerprint, index) => {
    const reason = reasons[index] ?? "";
    if (reason.trim() === "") {
      throw new ArgError(`--accept ${fingerprint} needs a non-empty --reason`);
    }
    return { fingerprint, reason };
  });

  const modes: SealMode[] = [];
  if (values.verify) modes.push("verify");
  if (values.diff) modes.push("diff");
  if (accept.length > 0) modes.push("accept");
  if (modes.length > 1) {
    throw new ArgError("seal takes at most one of --verify, --diff, --accept");
  }

  const options: SealCliOptions = {
    path: positionals[0] ?? ".",
    mode: modes[0] ?? "write",
    json: values.json,
    yes: values.yes,
    accept,
    requireSigned: values["require-signed-seal"],
    ascii: values.ascii,
  };
  if (values.trust !== undefined) options.trust = values.trust;
  return options;
}

function gateOptions(values: Values, positionals: string[]): GateCliOptions {
  const host = values.host;
  if (host === undefined) {
    throw new ArgError(
      "gate requires --host (claude-code, cursor, or generic). `generic` is owlwarden's own " +
        "event and decision JSON and works with any host that can run a process.",
    );
  }
  if (!["claude-code", "cursor", "generic"].includes(host)) {
    throw new ArgError(
      `unknown --host ${JSON.stringify(host)}; expected one of: claude-code, cursor, generic`,
    );
  }
  if (positionals.length > 1) {
    throw new ArgError(`gate takes at most one path, got ${positionals.length}`);
  }

  const options: GateCliOptions = { host, path: positionals[0] ?? "." };
  if (values["fail-on"] !== undefined) options.failOn = values["fail-on"];
  if (values["min-confidence"] !== undefined) options.minConfidence = values["min-confidence"];
  if (values.since !== undefined) options.since = values.since;
  if (values.event !== undefined) options.eventFile = values.event;
  return options;
}

function verifyOptions(values: Values, positionals: string[]): VerifyCliOptions {
  const patch = values.patch;
  if (patch === undefined) {
    throw new ArgError("verify requires --patch <file>, a unified diff to apply and re-scan");
  }
  if (positionals.length > 1) {
    throw new ArgError(`verify takes at most one path, got ${positionals.length}`);
  }
  const options: VerifyCliOptions = { path: positionals[0] ?? ".", patch };
  if (values.rule !== undefined) options.rule = values.rule;
  if (values["fail-on"] !== undefined) options.failOn = values["fail-on"];
  return options;
}

/** Parses a positive integer flag value. */
function positiveInt(flag: string, raw: string): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new ArgError(`invalid value ${JSON.stringify(raw)} for ${flag}; expected a positive integer`);
  }
  return parsed;
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
