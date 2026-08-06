import { readFile, stat } from "node:fs/promises";
import { basename, isAbsolute, join, resolve as resolvePath } from "node:path";
import { pathToFileURL } from "node:url";

import { configSchema, type OwlwardenConfig } from "./schema.js";

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

  let skippedExecutable: string | undefined;

  if (allowConfigJs) {
    for (const name of CONFIG_FILES) {
      const path = join(root, name);
      if (!(await exists(path))) continue;

      const loaded = name.endsWith(".json")
        ? await loadJson(path)
        : await loadModule(path);
      if (!loaded.ok) return loaded;

      return withSkip(
        validate(loaded.value, { kind: "file", path }),
        skippedExecutable,
      );
    }
  } else {
    for (const name of EXECUTABLE_CONFIG_FILES) {
      const path = join(root, name);
      if (await exists(path)) {
        skippedExecutable = path;
        break;
      }
    }
    for (const name of JSON_CONFIG_FILES) {
      const path = join(root, name);
      if (!(await exists(path))) continue;

      const loaded = await loadJson(path);
      if (!loaded.ok) return loaded;

      return withSkip(
        validate(loaded.value, { kind: "file", path }),
        skippedExecutable,
      );
    }
  }

  const fromPackage = await loadPackageJsonKey(root);
  if (!fromPackage.ok) return fromPackage;
  if (fromPackage.value !== undefined) {
    return withSkip(
      validate(fromPackage.value, {
        kind: "package.json",
        path: join(root, "package.json"),
      }),
      skippedExecutable,
    );
  }

  return withSkip(validate({}, { kind: "defaults" }), skippedExecutable);
}

function withSkip(result: ConfigResult, skippedExecutable: string | undefined): ConfigResult {
  if (!result.ok || skippedExecutable === undefined) return result;
  return { ...result, skippedExecutable };
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
    return `${where}: ${issue.message}`;
  });
  return { ok: false, error: { kind: "invalid", path, issues } };
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
  if (!(await exists(path))) return { ok: true, value: undefined };

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
  const info = await stat(path);
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

async function exists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
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
