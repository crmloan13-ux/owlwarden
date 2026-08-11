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
import { dirname, join } from "node:path";

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

/** Inspects digest and detached signature without loading WASM. */
export async function inspectArtifactStatus(
  manifestDir: string,
  manifest: PluginManifest,
): Promise<ArtifactStatus> {
  const module = modulePath(manifestDir, manifest);
  let wasm: Buffer;
  try {
    wasm = await readBinaryBounded(module, MAX_PLUGIN_BYTES);
  } catch {
    return { digest: "absent", signature: "absent", modulePath: module };
  }

  const digest = digestStatus(manifest, wasm);
  const signature = await signatureStatus(manifestDir, wasm, module);
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
  manifestDir: string,
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
  const keys = await loadTrustRoots(manifestDir);
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

function ed25519PublicKey(raw: Buffer): KeyObject | undefined {
  if (raw.byteLength !== 32) {
    return undefined;
  }
  try {
    // Node's raw ed25519 import; cast keeps @types/node from rejecting `format: "raw"`.
    return createPublicKey({
      key: raw,
      format: "raw",
      type: "ed25519",
    } as unknown as Parameters<typeof createPublicKey>[0]);
  } catch {
    return undefined;
  }
}

async function loadTrustRoots(manifestDir: string): Promise<Buffer[]> {
  const keys: Buffer[] = [];
  keys.push(...parseEnvTrust());
  for (const trustPath of trustFilePaths(manifestDir)) {
    keys.push(...(await readTrustFile(trustPath)));
    if (keys.length >= MAX_TRUST_KEYS) {
      break;
    }
  }
  return keys.slice(0, MAX_TRUST_KEYS);
}

function trustFilePaths(manifestDir: string): string[] {
  return [join(manifestDir, TRUST_REL), join(dirname(manifestDir), TRUST_REL)];
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
