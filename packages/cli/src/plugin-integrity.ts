/**
 * Local plugin artifact digest + ed25519 signature checks (ADR 0021).
 *
 * Mirrors `crates/plugin-host/src/integrity.rs` for `plugin inspect` — no WASM load.
 */

import {
  createHash,
  createPublicKey,
  verify,
  type KeyObject,
} from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";

import type { PluginManifest } from "@dointhai/owlwarden-sdk";

import { readFileBounded } from "./safe-write.js";

const MAX_PLUGIN_BYTES = 8 * 1024 * 1024;
const MAX_SIG_BYTES = 256;
const MAX_TRUST_FILE_BYTES = 64 * 1024;
const MAX_TRUST_KEYS = 32;
const TRUST_REL = ".owlwarden/plugin-trust.json";

export type DigestStatus = "ok" | "mismatch" | "absent";
export type SignatureStatus = "verified" | "untrusted" | "absent";

export interface ArtifactStatus {
  digest: DigestStatus;
  signature: SignatureStatus;
  modulePath: string;
}

/** Resolves the WASM module path beside a manifest directory. */
export function modulePath(manifestDir: string, manifest: PluginManifest): string {
  const relative = manifest.artifact?.path ?? "plugin.wasm";
  return join(manifestDir, relative);
}

/**
 * Inspects digest and detached signature without loading WASM.
 *
 * `trustRootDir` is the operator's project. Omitting it — which is what
 * `plugin inspect` does, since it is given a plugin path and no project —
 * leaves `OWLWARDEN_PLUGIN_TRUST` as the only source of keys. It is never
 * derived from `manifestDir`; see {@link loadTrustRoots}.
 */
export async function inspectArtifactStatus(
  manifestDir: string,
  manifest: PluginManifest,
  trustRootDir?: string,
): Promise<ArtifactStatus> {
  const module = modulePath(manifestDir, manifest);
  let wasm: Buffer;
  try {
    wasm = await readBinaryBounded(module, MAX_PLUGIN_BYTES);
  } catch {
    return { digest: "absent", signature: "absent", modulePath: module };
  }

  const digest = digestStatus(manifest, wasm);
  const signature = await signatureStatus(trustRootDir, wasm, module);
  return { digest, signature, modulePath: module };
}

async function readBinaryBounded(path: string, maxBytes: number): Promise<Buffer> {
  const info = await lstat(path);
  if (info.isSymbolicLink()) {
    throw new Error("refusing to read through a symlink");
  }
  if (info.size > maxBytes) {
    throw new Error(`file is ${info.size} bytes; maximum is ${maxBytes}`);
  }
  const bytes = await readFile(path);
  if (bytes.byteLength > maxBytes) {
    throw new Error(`file is ${bytes.byteLength} bytes; maximum is ${maxBytes}`);
  }
  return bytes;
}

function digestStatus(manifest: PluginManifest, wasm: Buffer): DigestStatus {
  const expected = manifest.artifact?.sha256;
  if (expected === undefined) {
    return "absent";
  }
  const actual = createHash("sha256").update(wasm).digest("hex");
  return actual.toLowerCase() === expected.toLowerCase() ? "ok" : "mismatch";
}

async function signatureStatus(
  trustRootDir: string | undefined,
  wasm: Buffer,
  moduleFile: string,
): Promise<SignatureStatus> {
  const sigPath = `${moduleFile}.sig`;
  let sigText: string;
  try {
    sigText = await readFileBounded(sigPath, MAX_SIG_BYTES);
  } catch {
    return "absent";
  }
  const signature = Buffer.from(sigText.trim(), "base64");
  if (signature.length === 0 || signature.length > 128) {
    return "untrusted";
  }

  const digest = createHash("sha256").update(wasm).digest();
  const keys = await loadTrustRoots(trustRootDir);
  if (keys.length === 0) {
    return "untrusted";
  }
  for (const key of keys) {
    const publicKey = ed25519PublicKey(key);
    if (publicKey !== undefined && verify(null, digest, publicKey, signature)) {
      return "verified";
    }
  }
  return "untrusted";
}

/**
 * The fixed SubjectPublicKeyInfo prefix for an Ed25519 key.
 *
 * `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (32 bytes) }`. Every
 * byte of it is determined by the algorithm, so the whole encoding is this
 * constant followed by the raw key — asserted against Node's own export in
 * `plugin-trust.test.ts` rather than trusted from a comment.
 */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Wraps 32 raw public-key bytes in the DER encoding Node will accept.
 *
 * # Why not `format: "raw"`
 *
 * That is what this used to be, with a cast to get it past `@types/node`. The
 * types were right: Node rejects `format: "raw"` for `createPublicKey`, so this
 * threw for every key, returned `undefined` for every key, and
 * `plugin inspect` could not report `verified` for any signature ever made. It
 * failed in the safe direction, which is exactly why nobody noticed — an
 * always-`untrusted` signature line looks like an unconfigured trust root.
 *
 * The cast was the bug. It silenced the one thing that knew.
 */
function ed25519PublicKey(raw: Buffer): KeyObject | undefined {
  if (raw.byteLength !== 32) {
    return undefined;
  }
  try {
    return createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
  } catch {
    return undefined;
  }
}

/**
 * The keys an operator has said they trust.
 *
 * # Why the plugin's own directory is not one of them
 *
 * It used to be — `<plugin>/.owlwarden/plugin-trust.json` and the same path one
 * level up, mirroring the Rust host, which had the same bug. Both are inside
 * the artifact being verified, so a plugin could generate a key, sign itself,
 * ship the public half beside the signature, and be reported `verified`. On
 * this side that is worse than in the loader: `plugin inspect` exists to be
 * read by a person deciding whether to trust a plugin at all, and it was
 * printing the plugin's own claim about itself as if it were a finding.
 *
 * `trustRootDir` is the operator's project when there is one. `inspect` is
 * handed a plugin path and no project, so it passes `undefined` and the
 * environment is the only source — which is why an unconfigured `inspect`
 * reports `untrusted` rather than `verified`.
 */
async function loadTrustRoots(trustRootDir: string | undefined): Promise<Buffer[]> {
  const keys: Buffer[] = [...parseEnvTrust()];
  if (trustRootDir !== undefined) {
    keys.push(...(await readTrustFile(join(trustRootDir, TRUST_REL))));
  }
  return keys.slice(0, MAX_TRUST_KEYS);
}

function parseEnvTrust(): Buffer[] {
  const raw = process.env["OWLWARDEN_PLUGIN_TRUST"];
  if (raw === undefined || raw === "") {
    return [];
  }
  const keys: Buffer[] = [];
  for (const entry of raw.split(":").slice(0, MAX_TRUST_KEYS)) {
    if (entry === "") {
      continue;
    }
    const key = parseTrustHex(entry);
    if (key !== undefined) {
      keys.push(key);
    }
  }
  return keys;
}

async function readTrustFile(path: string): Promise<Buffer[]> {
  let raw: string;
  try {
    raw = await readFileBounded(path, MAX_TRUST_FILE_BYTES);
  } catch {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (parsed === null || typeof parsed !== "object" || !("keys" in parsed)) {
    return [];
  }
  const list = parsed.keys;
  if (!Array.isArray(list)) {
    return [];
  }
  const keys: Buffer[] = [];
  for (const entry of list.slice(0, MAX_TRUST_KEYS)) {
    if (typeof entry !== "string") {
      continue;
    }
    const key = parseTrustHex(entry);
    if (key !== undefined) {
      keys.push(key);
    }
  }
  return keys;
}

function parseTrustHex(hex: string): Buffer | undefined {
  if (hex.length !== 64 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return undefined;
  }
  return Buffer.from(hex, "hex");
}
