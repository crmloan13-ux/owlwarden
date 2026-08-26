import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { PluginManifest } from "@dointhai/owlwarden-sdk";

import { inspectArtifactStatus } from "../src/plugin-integrity.js";

/**
 * Where `plugin inspect` will accept a trust root from.
 *
 * This is the half of ADR 0021 that a person reads. The loader's answer decides
 * whether a plugin runs; this one decides whether someone believes it should,
 * and it used to print the plugin's own claim about itself: trust roots were
 * read from the plugin's directory and from that directory's parent, so a
 * plugin could sign itself with a key it generated, ship the public half beside
 * the signature, and be reported `verified`.
 */

const WASM = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

let dir: string;
const savedEnv = process.env["OWLWARDEN_PLUGIN_TRUST"];

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "owlwarden-trust-"));
  delete process.env["OWLWARDEN_PLUGIN_TRUST"];
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  if (savedEnv === undefined) delete process.env["OWLWARDEN_PLUGIN_TRUST"];
  else process.env["OWLWARDEN_PLUGIN_TRUST"] = savedEnv;
});

function keypair(): { publicHex: string; privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"] } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "jwk" });
  const publicHex = Buffer.from(raw.x as string, "base64url").toString("hex");
  return { publicHex, privateKey };
}

const manifest: PluginManifest = {
  schemaVersion: 1,
  id: "demo",
  version: "1.0.0",
  capabilities: { source: true, network: false, active: false },
  artifact: { path: "plugin.wasm", sha256: createHash("sha256").update(WASM).digest("hex") },
  rules: [],
};

/** Writes a plugin directory with a valid detached signature. */
async function plantSignedPlugin(): Promise<{ pluginDir: string; publicHex: string }> {
  const pluginDir = join(dir, "vendor", "thing");
  await mkdir(pluginDir, { recursive: true });
  await writeFile(join(pluginDir, "plugin.wasm"), WASM);

  const { publicHex, privateKey } = keypair();
  const digest = createHash("sha256").update(WASM).digest();
  await writeFile(
    join(pluginDir, "plugin.wasm.sig"),
    edSign(null, digest, privateKey).toString("base64"),
  );
  return { pluginDir, publicHex };
}

async function trustAt(at: string, publicHex: string): Promise<void> {
  await mkdir(join(at, ".owlwarden"), { recursive: true });
  await writeFile(
    join(at, ".owlwarden", "plugin-trust.json"),
    JSON.stringify({ keys: [publicHex] }),
  );
}

describe("the raw key is wrapped the way Node expects", () => {
  it("produces exactly the SPKI encoding Node exports for the same key", () => {
    // The hardcoded DER prefix is the whole reason signature verification works
    // on this side, and a wrong byte in it would fail closed and silently — the
    // failure mode that hid the previous bug for a whole release. So it is
    // checked against Node's own encoder rather than against a comment.
    const { publicKey } = generateKeyPairSync("ed25519");
    const raw = Buffer.from(publicKey.export({ format: "jwk" }).x ?? "", "base64url");
    const prefix = Buffer.from("302a300506032b6570032100", "hex");

    expect(Buffer.concat([prefix, raw]).equals(publicKey.export({ format: "der", type: "spki" }))).toBe(
      true,
    );
  });

  it("verifies a signature this suite made, which is what the old code could not", async () => {
    // Before the fix `plugin inspect` returned `untrusted` for every valid
    // signature, because `createPublicKey({ format: "raw" })` throws on every
    // Node. A single positive case is the whole regression test.
    const { pluginDir, publicHex } = await plantSignedPlugin();
    process.env["OWLWARDEN_PLUGIN_TRUST"] = publicHex;

    expect((await inspectArtifactStatus(pluginDir, manifest)).signature).toBe("verified");
  });
});

describe("a plugin may not supply the key that vouches for it", () => {
  it("reports untrusted when the trust file is inside the plugin", async () => {
    const { pluginDir, publicHex } = await plantSignedPlugin();
    await trustAt(pluginDir, publicHex);

    const status = await inspectArtifactStatus(pluginDir, manifest);
    expect(status.digest).toBe("ok");
    expect(status.signature).toBe("untrusted");
  });

  it("reports untrusted when the trust file is beside the plugin directory", async () => {
    const { pluginDir, publicHex } = await plantSignedPlugin();
    await trustAt(dirname(pluginDir), publicHex);

    const status = await inspectArtifactStatus(pluginDir, manifest);
    expect(status.signature).toBe("untrusted");
  });

  it("reports untrusted when both places hold the key", async () => {
    const { pluginDir, publicHex } = await plantSignedPlugin();
    await trustAt(pluginDir, publicHex);
    await trustAt(dirname(pluginDir), publicHex);

    const status = await inspectArtifactStatus(pluginDir, manifest);
    expect(status.signature).toBe("untrusted");
  });
});

describe("the operator's roots still verify", () => {
  it("verifies against a trust file in the project the caller names", async () => {
    const { pluginDir, publicHex } = await plantSignedPlugin();
    const project = join(dir, "project");
    await mkdir(project, { recursive: true });
    await trustAt(project, publicHex);

    const status = await inspectArtifactStatus(pluginDir, manifest, project);
    expect(status.signature).toBe("verified");
  });

  it("verifies against OWLWARDEN_PLUGIN_TRUST with no project at all", async () => {
    const { pluginDir, publicHex } = await plantSignedPlugin();
    process.env["OWLWARDEN_PLUGIN_TRUST"] = publicHex;

    const status = await inspectArtifactStatus(pluginDir, manifest);
    expect(status.signature).toBe("verified");
  });

  it("does not verify against a different key in the environment", async () => {
    const { pluginDir } = await plantSignedPlugin();
    process.env["OWLWARDEN_PLUGIN_TRUST"] = keypair().publicHex;

    const status = await inspectArtifactStatus(pluginDir, manifest);
    expect(status.signature).toBe("untrusted");
  });

  it("ignores a malformed entry in the environment rather than trusting everything", async () => {
    const { pluginDir, publicHex } = await plantSignedPlugin();
    process.env["OWLWARDEN_PLUGIN_TRUST"] = `not-hex::${publicHex}`;

    const status = await inspectArtifactStatus(pluginDir, manifest);
    // The good key is still in the list; the junk entry is dropped, not fatal.
    expect(status.signature).toBe("verified");
  });
});

describe("the digest is independent of the signature", () => {
  it("reports a mismatch even when the signature verifies over the real bytes", async () => {
    const { pluginDir, publicHex } = await plantSignedPlugin();
    process.env["OWLWARDEN_PLUGIN_TRUST"] = publicHex;

    const lying = { ...manifest, artifact: { path: "plugin.wasm", sha256: "0".repeat(64) } };
    const status = await inspectArtifactStatus(pluginDir, lying);
    expect(status.digest).toBe("mismatch");
    expect(status.signature).toBe("verified");
  });

  it("reports absent for both when there is no module to read", async () => {
    const empty = join(dir, "empty");
    await mkdir(empty, { recursive: true });

    const status = await inspectArtifactStatus(empty, manifest);
    expect(status.digest).toBe("absent");
    expect(status.signature).toBe("absent");
  });

  it("reports untrusted for a signature that is not valid base64 of the right length", async () => {
    const { pluginDir, publicHex } = await plantSignedPlugin();
    process.env["OWLWARDEN_PLUGIN_TRUST"] = publicHex;
    await writeFile(join(pluginDir, "plugin.wasm.sig"), "not-a-signature");

    const status = await inspectArtifactStatus(pluginDir, manifest);
    expect(status.signature).toBe("untrusted");
  });

  it("reports untrusted rather than verified when no roots are configured", async () => {
    const { pluginDir } = await plantSignedPlugin();

    // The honest answer for a valid signature by an unknown author.
    const status = await inspectArtifactStatus(pluginDir, manifest);
    expect(status.signature).toBe("untrusted");
  });
});

describe("the shared signature vector", () => {
  /**
   * The same bytes `crates/plugin-host/tests/trust_scope.rs` asserts on.
   *
   * Two implementations of "verify this signature" is one more than can be kept
   * correct by review, and 1.1 shipped after finding a different bug in each.
   * A vector neither side generates is what makes them one contract instead of
   * two opinions.
   */
  it("verifies here exactly as it does in the Rust host", async () => {
    const vector = JSON.parse(
      await readFile(new URL("../../../fixtures/plugin-signature-vector.json", import.meta.url), "utf8"),
    ) as {
      publicKeyHex: string;
      wasmHex: string;
      digestHex: string;
      signatureBase64: string;
    };

    const wasm = Buffer.from(vector.wasmHex, "hex");
    expect(createHash("sha256").update(wasm).digest("hex")).toBe(vector.digestHex);

    const pluginDir = join(dir, "vector");
    await mkdir(pluginDir, { recursive: true });
    await writeFile(join(pluginDir, "plugin.wasm"), wasm);
    await writeFile(join(pluginDir, "plugin.wasm.sig"), vector.signatureBase64);

    const vectorManifest = {
      ...manifest,
      artifact: { path: "plugin.wasm", sha256: vector.digestHex },
    };

    process.env["OWLWARDEN_PLUGIN_TRUST"] = vector.publicKeyHex;
    const trusted = await inspectArtifactStatus(pluginDir, vectorManifest);
    expect(trusted.digest).toBe("ok");
    expect(trusted.signature).toBe("verified");

    // The same bytes with nobody trusted must not verify — otherwise the test
    // above would pass on an implementation that verifies everything.
    delete process.env["OWLWARDEN_PLUGIN_TRUST"];
    expect((await inspectArtifactStatus(pluginDir, vectorManifest)).signature).toBe("untrusted");
  });
});
