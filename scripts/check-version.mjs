#!/usr/bin/env node
/**
 * Asserts that every published version agrees, and matches the release tag.
 *
 * The version lives in seven files, and npm publishes are immutable: a wrong
 * number cannot be replaced, only deprecated and superseded. That makes a
 * mismatch the one release mistake with no clean recovery, so it is checked
 * before anything is uploaded rather than discovered afterwards.
 *
 * Five of the seven are manifests, where a stale number is at least loud: the
 * publish fails, or the package is visibly the wrong version. The other two are
 * worse, and are the reason this file grew:
 *
 * - `action/action.yml` carries the *default* `version` input, which is the
 *   `owlwarden@…` that every CI job resolves when the caller does not pin one.
 *   A stale default does not fail anything. It quietly runs last release's
 *   rules in every repository using the Action, for as long as nobody notices.
 * - `mcp/server.json` is what the MCP registry serves to hosts.
 *
 * Neither is published by `npm publish`, so neither is covered by the failure
 * that catches the rest. They are checked here instead.
 *
 *   node scripts/check-version.mjs            # all seven agree
 *   node scripts/check-version.mjs v0.1.0     # ...and equal the tag
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const MANIFESTS = [
  "packages/cli/package.json",
  "packages/sdk/package.json",
  "packages/config/package.json",
  "crates/napi/package.json",
];

/** Reads the `version` field of a JSON manifest. */
async function jsonVersion(relative) {
  const raw = await readFile(join(root, relative), "utf8");
  const parsed = JSON.parse(raw);
  if (typeof parsed.version !== "string") {
    throw new Error(`${relative} has no string "version"`);
  }
  return parsed.version;
}

/**
 * Reads `version` from the `[workspace.package]` table of the root Cargo.toml.
 *
 * Deliberately not a TOML parser: one field in one known table is not worth a
 * dependency in a project that argues about every one it takes.
 */
async function cargoVersion() {
  const raw = await readFile(join(root, "Cargo.toml"), "utf8");
  const table = raw.split(/^\[/m).find((section) => section.startsWith("workspace.package]"));
  const match = table?.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match?.[1]) {
    throw new Error("Cargo.toml [workspace.package] has no version");
  }
  return match[1];
}

/**
 * Reads the default of the Action's `version` input.
 *
 * Also deliberately not a YAML parser, for the same reason as above — but with
 * a stricter match, because there are several `default:` keys in that file and
 * picking the wrong one would make this check pass while measuring nothing.
 */
async function actionDefaultVersion() {
  const raw = await readFile(join(root, "action/action.yml"), "utf8");
  const block = raw.match(/^ {2}version:\n(?: {4}.*\n)+/m)?.[0];
  const match = block?.match(/^ {4}default: "([^"]+)"/m);
  if (!match?.[1]) {
    throw new Error("action/action.yml has no default for the `version` input");
  }
  return match[1];
}

/**
 * Reads the two versions in the MCP registry descriptor, which must agree with
 * each other as well as with everything else: one names the server, the other
 * names the npm package the host is told to run.
 */
async function mcpVersions(relative) {
  const parsed = JSON.parse(await readFile(join(root, relative), "utf8"));
  const npm = parsed.packages?.find((entry) => entry.registryType === "npm");
  if (!npm) {
    throw new Error(`${relative} has no npm package entry`);
  }
  return { server: parsed.version, package: npm.version };
}

const found = new Map();
for (const relative of MANIFESTS) {
  found.set(relative, await jsonVersion(relative));
}
found.set("Cargo.toml", await cargoVersion());
found.set("action/action.yml (version input default)", await actionDefaultVersion());

const mcp = await mcpVersions("mcp/server.json");
found.set("mcp/server.json (server)", mcp.server);
found.set("mcp/server.json (npm package)", mcp.package);

const distinct = new Set(found.values());
const problems = [];

if (distinct.size !== 1) {
  problems.push("versions disagree:");
  for (const [file, version] of found) problems.push(`  ${version}  ${file}`);
}

const [tag] = process.argv.slice(2);
if (tag !== undefined) {
  const expected = tag.replace(/^v/, "");
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(expected)) {
    problems.push(`tag ${tag} is not a semver release tag`);
  }
  for (const [file, version] of found) {
    if (version !== expected) {
      problems.push(`${file} is ${version}, but the tag says ${expected}`);
    }
  }
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}

const version = [...distinct][0];
console.log(`version ${version} is consistent across ${found.size} manifests`);
