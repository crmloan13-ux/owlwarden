import { createRequire } from "node:module";

/**
 * The native addon's surface, written out here rather than imported from the
 * generated `.d.ts`.
 *
 * Two reasons. First, `tsc` then does not depend on a completed Rust build, so
 * a fresh clone can typecheck before it can compile. Second, this file *is* the
 * ABI contract: if the Rust side changes a signature, the mismatch shows up as
 * a runtime shape check below rather than as an undefined function three call
 * frames deep.
 */
export interface NativeEngine {
  /** Runs a passive scan. Takes a JSON `ScanRequest`, returns a JSON envelope. */
  scan(requestJson: string): Promise<string>;

  /**
   * Runs one gate event: parse the host's payload, scan what it names, decide,
   * and encode the answer in the host's own shape.
   *
   * Takes a JSON gate request and returns `{ stdout, stderr, exitCode }`. Never
   * rejects for a gate failure — a hook that throws shows a developer a stack
   * trace mid-session, and the failure posture (`ask` before execution, `allow`
   * after) is the answer instead.
   */
  gate(requestJson: string): Promise<string>;

  /**
   * Runs one `owlwarden seal` invocation: write, verify, diff, or accept.
   *
   * Takes a JSON seal request and returns `{ ok, stdout, stderr, exitCode }`.
   * The decision logic is shared with the standalone binary, so the two cannot
   * disagree about what counts as drift.
   */
  seal(requestJson: string): Promise<string>;

  /**
   * Builds a lockfile-scoped OSV index JSON string for `owlwarden osv update`.
   * Queries api.osv.dev (online).
   */
  buildOsvIndex(projectRoot: string): Promise<string>;

  /** Renders a report to text. Takes JSON report + JSON render options. */
  render(reportJson: string, optionsJson: string): string;
  /** The whole rule catalogue, as JSON. */
  listRules(): string;
  /** The available presets, as JSON. */
  listPresets(): string;
  /** One rule's full write-up as JSON, or `null` if there is no such rule. */
  explainRule(ruleId: string): string | null;
  /** What the shipped rules cover, and what they do not, as JSON. */
  coverage(): string;
  /** The coverage table rendered for a terminal. */
  renderCoverage(optionsJson: string): string;
  /** The startup banner. The caller decides whether to show it. */
  banner(optionsJson: string): string;
  /** Engine version — the same string that appears in `report.tool.version`. */
  engineVersion(): string;
  /** Report schema version the addon produces. */
  schemaVersion(): string;
}

/** The addon could not be loaded, or is not the addon we expected. */
export class NativeLoadError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "NativeLoadError";
  }
}

const REQUIRED_EXPORTS = [
  "scan",
  "gate",
  "seal",
  "buildOsvIndex",
  "render",
  "listRules",
  "listPresets",
  "explainRule",
  "coverage",
  "renderCoverage",
  "banner",
  "engineVersion",
  "schemaVersion",
] as const satisfies readonly (keyof NativeEngine)[];

let cached: NativeEngine | undefined;

/**
 * Loads the compiled engine.
 *
 * `createRequire` rather than `import`: the addon's loader is CommonJS and
 * picks the right prebuilt `.node` for the platform, which is exactly the job
 * `require` does well.
 *
 * @throws {NativeLoadError} when there is no build for this platform, or when
 * the addon that loaded is missing functions we need — which means the CLI and
 * the addon are from different releases.
 */
export function loadNative(): NativeEngine {
  if (cached) return cached;

  const require = createRequire(import.meta.url);
  let loaded: unknown;
  try {
    loaded = require("@dointhai/owlwarden-core-native");
  } catch (error) {
    throw new NativeLoadError(
      `could not load the owlwarden engine for ${process.platform}-${process.arch}.\n` +
        "If you installed with --no-optional, reinstall without it. If this platform " +
        "has no prebuilt binary, build from source: " +
        "https://github.com/suthat/owlwarden#building-from-source",
      { cause: error },
    );
  }

  const missing = REQUIRED_EXPORTS.filter(
    (name) => typeof (loaded as Record<string, unknown>)[name] !== "function",
  );
  if (missing.length > 0) {
    throw new NativeLoadError(
      `the installed engine is missing ${missing.join(", ")}. ` +
        "The CLI and the native addon are from different releases; reinstall owlwarden.",
    );
  }

  cached = loaded as NativeEngine;
  return cached;
}
