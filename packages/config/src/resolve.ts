import { lstat, readFile } from "node:fs/promises";
import { basename, isAbsolute, join, resolve as resolvePath } from "node:path";
import { pathToFileURL } from "node:url";

import { configSchema, ruleOverrideSchema, type OwlwardenConfig } from "./schema.js";

/**
 * Config file names that are data only. Always safe to load from a hostile
 * scan target — nothing here is executed.
 */
export const JSON_CONFIG_FILES = ["owlwarden.config.json"] as const;

/**
 * Config file names that Node would execute. Loaded only when the caller
 * passes `allowConfigJs: true` — scanning an untrusted tree must never
 * `import()` attacker-controlled modules.
 */
export const EXECUTABLE_CONFIG_FILES = [
  "owlwarden.config.ts",
  "owlwarden.config.mts",
  "owlwarden.config.mjs",
  "owlwarden.config.js",
] as const;

/**
 * Lookup order when executable configs are allowed: executable first (legacy
 * preference), then JSON. Without the flag only {@link JSON_CONFIG_FILES} are
 * considered.
 */
export const CONFIG_FILES = [...EXECUTABLE_CONFIG_FILES, ...JSON_CONFIG_FILES] as const;

/** Cap on config file size before we refuse to parse it. */
export const MAX_CONFIG_BYTES = 256 * 1024;

/** Where the config came from. Reported by `--verbose` so it is never a mystery. */
export type ConfigSource =
  | { kind: "file"; path: string }
  | { kind: "package.json"; path: string }
  | { kind: "defaults" };

/** Why config loading failed. */
export type ConfigError =
  | { kind: "invalid"; path: string; issues: string[] }
  | { kind: "unreadable"; path: string; message: string }
  | { kind: "unloadable-typescript"; path: string; message: string }
  | { kind: "too-large"; path: string; size: number; max: number };

/** Options that change how aggressively we load project config. */
export interface ResolveConfigOptions {
  /**
   * When true, `owlwarden.config.{js,mjs,ts,mts}` may be `import()`ed.
   * Default false — a hostile scan target must not get code execution by
   * placing a config module in the tree.
   */
  allowConfigJs?: boolean;
}

/** Either a config or a reason there isn't one. Never throws for user error. */
export type ConfigResult =
  | {
      ok: true;
      config: OwlwardenConfig;
      source: ConfigSource;
      /** Executable config found but skipped because `allowConfigJs` was false. */
      skippedExecutable?: string;
      /**
       * A config path that exists but is a symlink, and so was not read.
       *
       * Refusing to follow it is the right call — a link is how a hostile tree
       * points config resolution at content outside itself. Doing it *silently*
       * was not: `owlwarden.config.json -> ../shared/owlwarden.config.json` is
       * an ordinary monorepo layout, and the author of that link has no way to
       * discover their `preset` never applied.
       */
      skippedSymlink?: string;
    }
  | { ok: false; error: ConfigError };

/**
 * Loads and validates the config for a project.
 *
 * Missing config is not an error — zero-config is the headline use case, and
 * the defaults are the same ones the schema declares.
 *
 * Executable configs are opt-in. Without {@link ResolveConfigOptions.allowConfigJs}
 * only JSON (and the `owlwarden` key in package.json) is read.
 */
export async function resolveConfig(
  cwd: string,
  options: ResolveConfigOptions = {},
): Promise<ConfigResult> {
  const root = isAbsolute(cwd) ? cwd : resolvePath(process.cwd(), cwd);
  const allowConfigJs = options.allowConfigJs === true;

  const skipped: Skipped = {};

  const candidates = allowConfigJs ? CONFIG_FILES : JSON_CONFIG_FILES;

  if (!allowConfigJs) {
    for (const name of EXECUTABLE_CONFIG_FILES) {
      const path = join(root, name);
      if ((await classify(path)) === "file") {
        skipped.executable = path;
        break;
      }
    }
  }

  for (const name of candidates) {
    const path = join(root, name);
    const kind = await classify(path);
    if (kind === "absent") continue;
    if (kind !== "file") {
      // Present, deliberately not read. Record the first one and keep looking:
      // a symlinked `.json` beside a real `.mjs` should still load the `.mjs`.
      skipped.symlink ??= path;
      continue;
    }

    const loaded = name.endsWith(".json") ? await loadJson(path) : await loadModule(path);
    if (!loaded.ok) return loaded;

    return withSkip(validate(loaded.value, { kind: "file", path }), skipped);
  }

  const fromPackage = await loadPackageJsonKey(root);
  if (!fromPackage.ok) return fromPackage;
  if (fromPackage.value !== undefined) {
    return withSkip(
      validate(fromPackage.value, {
        kind: "package.json",
        path: join(root, "package.json"),
      }),
      skipped,
    );
  }

  return withSkip(validate({}, { kind: "defaults" }), skipped);
}

/** Config paths that were present and deliberately not read. */
interface Skipped {
  executable?: string;
  symlink?: string;
}

function withSkip(result: ConfigResult, skipped: Skipped): ConfigResult {
  if (!result.ok) return result;
  return {
    ...result,
    ...(skipped.executable === undefined ? {} : { skippedExecutable: skipped.executable }),
    ...(skipped.symlink === undefined ? {} : { skippedSymlink: skipped.symlink }),
  };
}

/** Runs the schema and turns zod issues into lines a human can act on. */
function validate(value: unknown, source: ConfigSource): ConfigResult {
  const parsed = configSchema.safeParse(value);
  if (parsed.success) {
    return { ok: true, config: parsed.data, source };
  }

  const path = source.kind === "defaults" ? "<defaults>" : source.path;
  const issues = parsed.error.issues.map((issue) => {
    const where = issue.path.length > 0 ? issue.path.join(".") : "(root)";
    if (issue.code === "unrecognized_keys") {
      return issue.keys.map((key) => `${where}: ${unrecognisedKey(key, issue.path)}`).join("\n  ");
    }
    return `${where}: ${issue.message}`;
  });
  return { ok: false, error: { kind: "invalid", path, issues } };
}

/**
 * Explains an unrecognised key, naming the intended one when it is a near miss.
 *
 * Worth the twenty lines: the keys that get misspelled are `failOn` and
 * `minConfidence`, both of which are camel-case in a file format where nothing
 * else is, and both of which fail permissively when they do not apply.
 */
function unrecognisedKey(key: string, at: readonly PropertyKey[]): string {
  const known = at.length === 0 ? Object.keys(configSchema.shape) : Object.keys(ruleOverrideSchema.shape);
  const suggestion = known.find(
    (candidate) =>
      candidate.toLowerCase() === key.toLowerCase() || editDistanceAtMostTwo(candidate, key),
  );
  return suggestion === undefined
    ? `unknown key "${key}"; known keys are ${known.join(", ")}`
    : `unknown key "${key}" — did you mean "${suggestion}"?`;
}

/**
 * True when `a` and `b` are within two single-character edits.
 *
 * Bounded rather than a full Levenshtein because the answer past two is not
 * used, and because bounding it keeps a pathological key from costing anything:
 * the strings compared are a config key and a schema key, but only one of those
 * two is under the config author's control.
 */
function editDistanceAtMostTwo(a: string, b: string): boolean {
  if (Math.abs(a.length - b.length) > 2) return false;

  const previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    let diagonal = previous[0] ?? 0;
    previous[0] = i;
    let best = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const value = Math.min(
        (previous[j] ?? 0) + 1,
        (previous[j - 1] ?? 0) + 1,
        diagonal + cost,
      );
      diagonal = previous[j] ?? 0;
      previous[j] = value;
      best = Math.min(best, value);
    }
    // Every cell in this row already exceeds the bound, and rows only grow.
    if (best > 2) return false;
  }
  return (previous[b.length] ?? Infinity) <= 2;
}

type Loaded = { ok: true; value: unknown } | { ok: false; error: ConfigError };

async function loadJson(path: string): Promise<Loaded> {
  try {
    const text = await readFileBounded(path);
    if (!text.ok) return text;
    return { ok: true, value: JSON.parse(text.value) };
  } catch (error) {
    return {
      ok: false,
      error: { kind: "unreadable", path, message: messageOf(error) },
    };
  }
}

/**
 * Imports a config module and takes its default export.
 *
 * Only called when the caller opted into executable config. `.ts` relies on
 * Node's own type stripping; on a Node that does not strip types we say so
 * plainly rather than bundling a TypeScript compiler.
 *
 * A module with no `default` is validated as its own namespace, so
 * `export const preset = "deep"` works. That is leniency in a place where it
 * costs nothing: the strict schema still rejects any name it does not know, so
 * there is no shape that loads and then quietly does nothing.
 */
async function loadModule(path: string): Promise<Loaded> {
  try {
    const module: unknown = await import(pathToFileURL(path).href);
    const value =
      typeof module === "object" && module !== null && "default" in module
        ? module.default
        : module;
    return { ok: true, value };
  } catch (error) {
    const message = messageOf(error);
    const isTypeStripping =
      path.endsWith(".ts") ||
      path.endsWith(".mts") ||
      message.includes("ERR_UNKNOWN_FILE_EXTENSION");

    if (isTypeStripping && message.includes("ERR_UNKNOWN_FILE_EXTENSION")) {
      return {
        ok: false,
        error: {
          kind: "unloadable-typescript",
          path,
          message: `this Node (${process.version}) cannot import TypeScript directly. Use Node 22.18+ or rename the file to ${basename(path).replace(/\.m?ts$/, ".mjs")}.`,
        },
      };
    }
    return { ok: false, error: { kind: "unreadable", path, message } };
  }
}

/** Reads the optional `owlwarden` key from package.json. */
async function loadPackageJsonKey(
  root: string,
): Promise<{ ok: true; value: unknown } | { ok: false; error: ConfigError }> {
  const path = join(root, "package.json");
  if ((await classify(path)) !== "file") return { ok: true, value: undefined };

  let parsed: unknown;
  try {
    const text = await readFileBounded(path);
    if (!text.ok) {
      // Broken/oversized package.json must not block a scan — fall back.
      return { ok: true, value: undefined };
    }
    parsed = JSON.parse(text.value);
  } catch {
    return { ok: true, value: undefined };
  }

  if (typeof parsed === "object" && parsed !== null && "owlwarden" in parsed) {
    return { ok: true, value: parsed.owlwarden };
  }
  return { ok: true, value: undefined };
}

async function readFileBounded(
  path: string,
): Promise<{ ok: true; value: string } | { ok: false; error: ConfigError }> {
  // `lstat` so a planted symlink cannot pull a file from outside the project
  // into config parsing (and cannot hide a hostile JSON behind a link).
  const info = await lstat(path);
  if (info.isSymbolicLink()) {
    return {
      ok: false,
      error: {
        kind: "unreadable",
        path,
        message: "refusing to read through a symlink",
      },
    };
  }
  if (!info.isFile()) {
    return {
      ok: false,
      error: { kind: "unreadable", path, message: "not a regular file" },
    };
  }
  if (info.size > MAX_CONFIG_BYTES) {
    return {
      ok: false,
      error: {
        kind: "too-large",
        path,
        size: info.size,
        max: MAX_CONFIG_BYTES,
      },
    };
  }
  const value = await readFile(path, "utf8");
  if (value.length > MAX_CONFIG_BYTES) {
    return {
      ok: false,
      error: {
        kind: "too-large",
        path,
        size: value.length,
        max: MAX_CONFIG_BYTES,
      },
    };
  }
  return { ok: true, value };
}

/**
 * What is at `path`, without following a link to find out.
 *
 * `lstat` rather than `stat` so a planted symlink cannot pull a file from
 * outside the project into config resolution. The three-way answer is the
 * point: "absent" and "present but not a regular file" lead to the same
 * decision and need different reporting.
 */
async function classify(path: string): Promise<"absent" | "file" | "other"> {
  try {
    return (await lstat(path)).isFile() ? "file" : "other";
  } catch {
    return "absent";
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** One line describing a config failure, ready to print. */
export function formatConfigError(error: ConfigError): string {
  switch (error.kind) {
    case "invalid":
      return `invalid config in ${error.path}\n  ${error.issues.join("\n  ")}`;
    case "unreadable":
      return `cannot read ${error.path}: ${error.message}`;
    case "unloadable-typescript":
      return `cannot load ${error.path}: ${error.message}`;
    case "too-large":
      return `config ${error.path} is ${error.size} bytes; maximum is ${error.max}`;
  }
}
