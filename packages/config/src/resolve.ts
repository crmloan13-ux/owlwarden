import { readFile, stat } from "node:fs/promises";
import { basename, isAbsolute, join, resolve as resolvePath } from "node:path";
import { pathToFileURL } from "node:url";

import { configSchema, type OwlwardenConfig } from "./schema.js";

/**
 * Config file names, in the order we look for them.
 *
 * We look in the project root only, and never walk up. Walking up means a
 * config two directories above — possibly outside the repository — can change
 * what a scan does, which is the kind of surprise a security tool cannot
 * afford. If you need shared config in a monorepo, import it from the root and
 * re-export it.
 */
export const CONFIG_FILES = [
  "owlwarden.config.ts",
  "owlwarden.config.mts",
  "owlwarden.config.mjs",
  "owlwarden.config.js",
  "owlwarden.config.json",
] as const;

/** Where the config came from. Reported by `--verbose` so it is never a mystery. */
export type ConfigSource =
  | { kind: "file"; path: string }
  | { kind: "package.json"; path: string }
  | { kind: "defaults" };

/** Why config loading failed. */
export type ConfigError =
  | { kind: "invalid"; path: string; issues: string[] }
  | { kind: "unreadable"; path: string; message: string }
  | { kind: "unloadable-typescript"; path: string; message: string };

/** Either a config or a reason there isn't one. Never throws for user error. */
export type ConfigResult =
  | { ok: true; config: OwlwardenConfig; source: ConfigSource }
  | { ok: false; error: ConfigError };

/**
 * Loads and validates the config for a project.
 *
 * Missing config is not an error — zero-config is the headline use case, and
 * the defaults are the same ones the schema declares.
 */
export async function resolveConfig(cwd: string): Promise<ConfigResult> {
  const root = isAbsolute(cwd) ? cwd : resolvePath(process.cwd(), cwd);

  for (const name of CONFIG_FILES) {
    const path = join(root, name);
    if (!(await exists(path))) continue;

    const loaded = name.endsWith(".json")
      ? await loadJson(path)
      : await loadModule(path);
    if (!loaded.ok) return loaded;

    return validate(loaded.value, { kind: "file", path });
  }

  const fromPackage = await loadPackageJsonKey(root);
  if (!fromPackage.ok) return fromPackage;
  if (fromPackage.value !== undefined) {
    return validate(fromPackage.value, {
      kind: "package.json",
      path: join(root, "package.json"),
    });
  }

  return validate({}, { kind: "defaults" });
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
    return { ok: true, value: JSON.parse(await readFile(path, "utf8")) };
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
 * `.ts` config relies on Node's own type stripping. On a Node that does not
 * strip types, the import fails with `ERR_UNKNOWN_FILE_EXTENSION`, and we say
 * so plainly instead of letting a raw module error surface — we are not going
 * to bundle a TypeScript compiler into a security tool's dependency tree to
 * paper over it.
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
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch {
    // A project can have a package.json we cannot parse and still be worth
    // scanning; the scan is what the user asked for, so fall back to defaults.
    return { ok: true, value: undefined };
  }

  if (typeof parsed === "object" && parsed !== null && "owlwarden" in parsed) {
    return { ok: true, value: parsed.owlwarden };
  }
  return { ok: true, value: undefined };
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
  }
}
