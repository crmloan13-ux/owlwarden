#!/usr/bin/env node
/**
 * Asserts that every published version agrees, and matches the release tag.
 *
 * The version lives in five files, and npm publishes are immutable: a wrong
 * number cannot be replaced, only deprecated and superseded. That makes a
 * mismatch the one release mistake with no clean recovery, so it is checked
 * before anything is uploaded rather than discovered afterwards.
 *
 *   node scripts/check-version.mjs            # all five agree
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

const found = new Map();
for (const relative of MANIFESTS) {
  found.set(relative, await jsonVersion(relative));
}
found.set("Cargo.toml", await cargoVersion());

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
