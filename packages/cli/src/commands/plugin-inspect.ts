/**
 * `owlwarden plugin inspect <path>` — show what a plugin claims before load.
 *
 * Reads and validates `owlwarden.plugin.json` only. Does not instantiate WASM
 * (ADR 0018). A signed remote registry remains later work.
 */

import { lstat, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";

import { pluginManifestSchema } from "@dointhai/owlwarden-sdk";

import { EXIT } from "../exit.js";
import { inspectArtifactStatus } from "../plugin-integrity.js";
import { readFileBounded, refuseSymlinkAncestors } from "../safe-write.js";

/** Largest manifest we will parse — matches `limits::plugin::MAX_MANIFEST_BYTES`. */
const MAX_MANIFEST_BYTES = 64 * 1024;

/** Nesting depth after `JSON.parse` — blocks a hostile `[[[[…]]]]` bomb. */
const MAX_MANIFEST_DEPTH = 32;

/** Walks a parsed value and refuses nesting deeper than `MAX_MANIFEST_DEPTH`. */
function assertBoundedDepth(value: unknown, depth = 0): void {
  if (depth > MAX_MANIFEST_DEPTH) {
    throw new Error(`JSON nesting exceeds ${MAX_MANIFEST_DEPTH}`);
  }
  if (Array.isArray(value)) {
    const limit = Math.min(value.length, 256);
    for (let i = 0; i < limit; i += 1) {
      assertBoundedDepth(value[i], depth + 1);
    }
    return;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.values(value as Record<string, unknown>);
    const limit = Math.min(entries.length, 256);
    for (let i = 0; i < limit; i += 1) {
      assertBoundedDepth(entries[i], depth + 1);
    }
  }
}

/**
 * Resolves `input` under `cwd` without following symlinks yet.
 *
 * Rejects `..` escapes and absolute paths outside the working directory so a
 * hostile argv cannot point inspect at `/etc/passwd` or a sibling repo.
 */
function resolveUnderCwd(input: string, cwd: string): string {
  const base = resolve(cwd);
  const candidate = resolve(base, input);
  const rel = relative(base, candidate);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`path escapes working directory: ${input}`);
  }
  return candidate;
}

/**
 * Resolves a plugin path to its manifest file (still under `cwd`).
 *
 * Accepts a directory containing `owlwarden.plugin.json`, or the manifest
 * file itself. Symlink destinations are checked after resolution.
 */
async function resolveManifestPath(input: string, cwd: string): Promise<string> {
  const absolute = resolveUnderCwd(input, cwd);
  let manifest: string;
  try {
    const stats = await lstat(absolute);
    if (stats.isDirectory()) {
      manifest = join(absolute, "owlwarden.plugin.json");
    } else if (basename(absolute) === "owlwarden.plugin.json" || absolute.endsWith(".json")) {
      manifest = absolute;
    } else if (absolute.endsWith(".wasm")) {
      // Bare .wasm next to a sidecar manifest — look beside it.
      manifest = join(dirname(absolute), "owlwarden.plugin.json");
    } else {
      manifest = join(absolute, "owlwarden.plugin.json");
    }
  } catch {
    // Missing path: still derive the conventional manifest location lexically.
    if (absolute.endsWith(".wasm")) {
      manifest = join(dirname(absolute), "owlwarden.plugin.json");
    } else if (basename(absolute) === "owlwarden.plugin.json" || absolute.endsWith(".json")) {
      manifest = absolute;
    } else {
      manifest = join(absolute, "owlwarden.plugin.json");
    }
  }
  return resolveUnderCwd(relative(resolve(cwd), manifest), cwd);
}

/**
 * Confirms the real path of the manifest stays under `cwd`.
 *
 * `realpath` follows every symlink hop; comparing against `realpath(cwd)`
 * blocks a directory symlink that points outside the working tree. The leaf
 * itself must not be a symlink either — `readFileBounded` refuses those.
 */
async function assertManifestInsideCwd(manifestPath: string, cwd: string): Promise<string> {
  await refuseSymlinkAncestors(manifestPath);
  const real = await realpath(manifestPath);
  const base = await realpath(cwd);
  const rel = relative(base, real);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`manifest real path escapes working directory: ${manifestPath}`);
  }
  return real;
}

/** Runs the inspect command. */
export async function runPluginInspect(
  path: string,
  cwd: string,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  let manifestPath: string;
  try {
    manifestPath = await resolveManifestPath(path, cwd);
    manifestPath = await assertManifestInsideCwd(manifestPath, cwd);
  } catch (error) {
    stderr.write(
      `error: cannot resolve plugin manifest at ${path}: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    return EXIT.ERROR;
  }

  let raw: string;
  try {
    raw = await readFileBounded(manifestPath, MAX_MANIFEST_BYTES);
  } catch (error) {
    stderr.write(
      `error: cannot read ${manifestPath}: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    return EXIT.ERROR;
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
    assertBoundedDepth(json);
  } catch (error) {
    stderr.write(
      `error: invalid JSON in ${manifestPath}: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    return EXIT.ERROR;
  }

  const parsed = pluginManifestSchema.safeParse(json);
  if (!parsed.success) {
    stderr.write(`error: invalid plugin manifest ${manifestPath}\n`);
    for (const issue of parsed.error.issues.slice(0, 16)) {
      stderr.write(`  ${issue.path.join(".") || "(root)"}: ${issue.message}\n`);
    }
    return EXIT.ERROR;
  }

  const manifest = parsed.data;
  const caps = manifest.capabilities;
  stdout.write(`plugin ${manifest.id}@${manifest.version}\n`);
  stdout.write(`manifest: ${manifestPath}\n`);
  if (manifest.license) {
    stdout.write(`license: ${manifest.license}\n`);
  }
  stdout.write("capabilities:\n");
  stdout.write(`  source: ${caps.source}\n`);
  stdout.write(`  network: ${caps.network}\n`);
  stdout.write(`  active: ${caps.active}\n`);
  if (caps.network || caps.active) {
    stdout.write(
      "note: this host refuses network/active plugins at load time (source-only).\n",
    );
  }
  stdout.write(`rules (${manifest.rules.length}):\n`);
  for (const rule of manifest.rules.slice(0, 256)) {
    stdout.write(
      `  ${rule.id}  ${rule.severity}/${rule.maxConfidence}  ${rule.title}\n`,
    );
  }

  const artifact = await inspectArtifactStatus(dirname(manifestPath), manifest);
  stdout.write(`artifact: ${artifact.modulePath}\n`);
  stdout.write(`digest: ${artifact.digest}\n`);
  stdout.write(`signature: ${artifact.signature}\n`);

  stdout.write(
    "\nNo WASM was loaded. Review capabilities, then: owlwarden scan --plugin <path>\n",
  );
  return EXIT.CLEAN;
}
